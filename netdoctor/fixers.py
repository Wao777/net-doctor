# -*- coding: utf-8 -*-
"""修复动作实现。

分档：
  SAFE      稳健档 —— 可逆、无需重启、无副作用，默认参与自动修复
  ADVANCED  进阶档 —— 影响面大（协议栈/防火墙重置），需二次确认，可能需重启
所有动作执行前由上层统一调用 BackupManager 落盘配置快照。
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import fixids as F
from .backup import BackupManager
from .models import FixAction, FixMode, FixOutcome
from .netstate import NetState
from .util import (Logger, is_admin, query_services, reg_delete, reg_write,
                   run, set_service_auto)

# --------------------------------------------------------------------------
# 上下文
# --------------------------------------------------------------------------


@dataclass
class FixContext:
    """修复动作执行上下文。"""

    state: NetState
    backup: BackupManager
    logger: Logger
    params: Dict[str, Any] = field(default_factory=dict)

    def adapter_names(self) -> List[str]:
        names = self.params.get("adapter_names")
        if names:
            return list(names)
        real = [a for a in self.state.physical_adapters if not a.is_virtual and a.up]
        if not real:
            real = [a for a in self.state.physical_adapters if a.up]
        return [a.name for a in real if a.name]

    def all_adapter_names(self) -> List[str]:
        names = self.params.get("all_adapter_names")
        if names:
            return list(names)
        return [a.name for a in self.state.physical_adapters if a.name and not a.is_virtual]


# --------------------------------------------------------------------------
# 注册表
# --------------------------------------------------------------------------

ACTIONS: Dict[str, FixAction] = {}
_HANDLERS: Dict[str, Callable[[FixContext], FixOutcome]] = {}


def action(
    fix_id: str,
    title: str,
    description: str,
    mode: FixMode = FixMode.SAFE,
    needs_reboot: bool = False,
    default_selected: bool = True,
):
    """把一个执行函数注册为修复动作。"""

    def wrapper(fn: Callable[[FixContext], FixOutcome]) -> Callable[[FixContext], FixOutcome]:
        ACTIONS[fix_id] = FixAction(
            id=fix_id,
            title=title,
            description=description,
            mode=mode,
            needs_reboot=needs_reboot,
            default_selected=default_selected,
        )
        _HANDLERS[fix_id] = fn
        return fn

    return wrapper


def get_action(fix_id: str) -> Optional[FixAction]:
    return ACTIONS.get(fix_id)


def all_actions() -> List[FixAction]:
    return list(ACTIONS.values())


# --------------------------------------------------------------------------
# 执行辅助
# --------------------------------------------------------------------------

def _guard() -> Optional[FixOutcome]:
    if not is_admin():
        return FixOutcome(
            fix_id="", title="", ok=False,
            message="需要管理员权限才能执行修复，请以管理员身份重新运行本程序。",
        )
    return None


def _exec(ctx: FixContext, args: List[str], timeout: float = 30.0,
          tolerate: bool = False, label: str = "") -> tuple:
    """执行一条修复命令，返回 (是否成功, 输出摘要, 命令行文本)。"""
    if label:
        ctx.logger.log(f"执行：{label}", "FIX")
    res = run(args, timeout=timeout)
    ctx.logger.command(res)
    ok = res.ok or tolerate
    return ok, (res.output.strip()[:200] or f"rc={res.returncode}"), res.cmd


# --------------------------------------------------------------------------
# 稳健档动作
# --------------------------------------------------------------------------

@action(F.FIX_DNS_FLUSH, "刷新 DNS 解析缓存",
        "清空本机 DNS 缓存，解决域名解析到错误/过期地址导致的“能上内网却打不开网页”。")
def fix_dns_flush(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    ok, msg, cmd = _exec(ctx, ["ipconfig", "/flushdns"], label="清空 DNS 缓存")
    return FixOutcome(F.FIX_DNS_FLUSH, "刷新 DNS 解析缓存", ok,
                      "DNS 缓存已清空" if ok else f"失败：{msg}", [cmd])


@action(F.FIX_DNS_REGISTER, "重新注册 DNS 记录",
        "向 DNS 服务器重新注册本机名称记录，修复本机名解析异常。")
def fix_dns_register(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    ok, msg, cmd = _exec(ctx, ["ipconfig", "/registerdns"], timeout=60, tolerate=True,
                         label="重新注册 DNS")
    return FixOutcome(F.FIX_DNS_REGISTER, "重新注册 DNS 记录", ok, msg or "已提交注册", [cmd])


@action(F.FIX_DNS_SET_PUBLIC, "DNS 切换为公共 DNS",
        "把 DNS 改为阿里公共 DNS（223.5.5.5 / 223.6.6.6），用于当前 DNS 服务器不可达的情况。"
        "原配置已备份，可一键回滚。", default_selected=False)
def fix_dns_set_public(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    pair = ctx.params.get("dns_pair") or F.PUBLIC_DNS[0]
    cmds: List[str] = []
    ok_all = True
    for name in ctx.adapter_names():
        ok1, m1, c1 = _exec(ctx, ["netsh", "interface", "ipv4", "set", "dnsservers",
                                  f"name={name}", "static", pair[0], "primary"],
                            timeout=20, label=f"{name} 主 DNS")
        ok2, m2, c2 = _exec(ctx, ["netsh", "interface", "ipv4", "add", "dnsservers",
                                  f"name={name}", pair[1], "index=2"],
                            timeout=20, tolerate=True, label=f"{name} 备 DNS")
        cmds += [c1, c2]
        ok_all = ok_all and ok1
    msg = f"已设置 DNS 为 {pair[0]} / {pair[1]}" if ok_all else "部分网卡设置失败，详见日志"
    return FixOutcome(F.FIX_DNS_SET_PUBLIC, "DNS 切换为公共 DNS", ok_all, msg, cmds)


@action(F.FIX_DHCP_RENEW, "重新获取 IP 地址（DHCP 续租）",
        "释放当前 IP 租约并重新向路由器申请地址，修复 169.254 自动私有地址、"
        "IP 冲突、租约失效等问题。")
def fix_dhcp_renew(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    cmds: List[str] = []
    _ok, m1, c1 = _exec(ctx, ["ipconfig", "/release"], timeout=40, tolerate=True, label="释放 IP 租约")
    cmds.append(c1)
    ok, m2, c2 = _exec(ctx, ["ipconfig", "/renew"], timeout=120, tolerate=True, label="重新申请 IP")
    cmds.append(c2)
    detail = f"释放：{m1[:60]} | 续租：{m2[:80]}"
    return FixOutcome(F.FIX_DHCP_RENEW, "重新获取 IP 地址（DHCP 续租）", ok, detail, cmds)


@action(F.FIX_DHCP_AUTO, "网卡切回自动获取（DHCP）",
        "把被改成静态 IP / 静态 DNS 的网卡恢复为自动获取，修复错误静态配置导致的断网。")
def fix_dhcp_auto(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    cmds: List[str] = []
    ok_all = True
    for name in ctx.adapter_names():
        ok1, m1, c1 = _exec(ctx, ["netsh", "interface", "ipv4", "set", "address",
                                  f"name={name}", "source=dhcp"], timeout=30, label=f"{name} 改为 DHCP")
        ok2, m2, c2 = _exec(ctx, ["netsh", "interface", "ipv4", "set", "dnsservers",
                                  f"name={name}", "source=dhcp"], timeout=20, tolerate=True,
                            label=f"{name} DNS 改为自动")
        cmds += [c1, c2]
        ok_all = ok_all and ok1
    return FixOutcome(F.FIX_DHCP_AUTO, "网卡切回自动获取（DHCP）", ok_all,
                      "已切回自动获取" if ok_all else "部分网卡切换失败，详见日志", cmds)


@action(F.FIX_PROXY_DISABLE, "关闭系统代理与 PAC",
        "关闭被意外开启的 IE/系统代理、清空 PAC 脚本、重置 WinHTTP 代理地址。"
        "流氓软件或失效的代理客户端是“浏览器打不开网页但 QQ 能上”的常见元凶。")
def fix_proxy_disable(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    cmds: List[str] = []
    changed: List[str] = []
    if reg_write("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                 "ProxyEnable", 0):
        changed.append("ProxyEnable=0")
    if reg_delete("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                  "AutoConfigURL"):
        changed.append("已清除 PAC 脚本地址")
    ok, msg, cmd = _exec(ctx, ["netsh", "winhttp", "reset", "proxy"], timeout=20, tolerate=True,
                         label="重置 WinHTTP 代理")
    cmds.append(cmd)
    detail = "；".join(changed) or "无变化"
    return FixOutcome(F.FIX_PROXY_DISABLE, "关闭系统代理与 PAC", True,
                      f"{detail}；winhttp: {msg[:80]}", cmds)


@action(F.FIX_ENV_PROXY_CLEAR, "清理代理环境变量",
        "删除 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY 等环境变量，避免命令行程序被失效代理拦截。")
def fix_env_proxy_clear(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    removed: List[str] = []
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        for hive in ("HKCU", "HKLM"):
            sub = "Environment" if hive == "HKCU" else r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
            if reg_read(hive, sub, var) is not None:
                if reg_delete(hive, sub, var):
                    removed.append(f"{hive}:{var}")
            try:
                os.environ.pop(var, None)
            except Exception:
                pass
    detail = "已删除 " + ", ".join(removed) if removed else "未发现代理环境变量"
    return FixOutcome(F.FIX_ENV_PROXY_CLEAR, "清理代理环境变量", True, detail, [])


@action(F.FIX_HOSTS_RESTORE, "还原 hosts 文件",
        "把 hosts 恢复为 Windows 默认内容，清理第三方软件写入的域名劫持/屏蔽条目。")
def fix_hosts_restore(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    from .util import hosts_path

    target = hosts_path()
    ctx.backup.backup_hosts()
    try:
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(F.DEFAULT_HOSTS)
        return FixOutcome(F.FIX_HOSTS_RESTORE, "还原 hosts 文件", True,
                          "已还原为默认内容（原文件已备份）", [f"write {target}"])
    except PermissionError:
        return FixOutcome(F.FIX_HOSTS_RESTORE, "还原 hosts 文件", False,
                          "无写入权限（hosts 为系统只读文件），请以管理员身份运行", [])
    except Exception as exc:  # noqa: BLE001
        return FixOutcome(F.FIX_HOSTS_RESTORE, "还原 hosts 文件", False, f"失败：{exc}", [])


@action(F.FIX_SERVICE_START, "启动关键网络服务",
        "把被停止或禁用的网络相关服务（DHCP/DNS/网络连接/位置感知等）恢复为自动启动并立即运行。")
def fix_service_start(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    services = ctx.params.get("services") or [name for _disp, name in F.CRITICAL_SERVICES]
    ctx.backup.backup_services(services)

    states = query_services(services)
    cmds: List[str] = []
    started: List[str] = []
    failed: List[str] = []
    skipped: List[str] = []

    for svc in services:
        state, start_type = states.get(svc, ("", ""))
        if state == "RUNNING" and start_type in ("AUTO", ""):
            skipped.append(svc)
            continue
        ok = set_service_auto(svc)
        cmds.append(f"Set-Service -Name {svc} -StartupType Automatic; Start-Service -Name {svc}")
        (started if ok else failed).append(svc)
        ctx.logger.log(f"服务 {svc}：{'已启动' if ok else '启动失败'}", "FIX")

    detail = (f"已启动：{', '.join(started) or '无'}；"
              f"无需处理：{', '.join(skipped) or '无'}；"
              f"失败：{', '.join(failed) or '无'}")
    return FixOutcome(F.FIX_SERVICE_START, "启动关键网络服务", not failed, detail, cmds)


@action(F.FIX_ADAPTER_RESTART, "重启网络适配器",
        "禁用后重新启用网卡，相当于“拔插网线”，可修复网卡驱动卡死、状态假连接。"
        "执行瞬间会短暂断网（约 3~8 秒）。")
def fix_adapter_restart(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    names = ctx.params.get("adapter_names") or ctx.adapter_names()
    cmds: List[str] = []
    ok_all = True
    for name in names:
        ok1, m1, c1 = _exec(ctx, ["netsh", "interface", "set", "interface",
                                  f"name={name}", "admin=disable"], timeout=25, label=f"禁用 {name}")
        cmds.append(c1)
        time.sleep(2.0)
        ok2, m2, c2 = _exec(ctx, ["netsh", "interface", "set", "interface",
                                  f"name={name}", "admin=enable"], timeout=25, label=f"启用 {name}")
        cmds.append(c2)
        ok_all = ok_all and ok1 and ok2
    time.sleep(3.0)
    return FixOutcome(F.FIX_ADAPTER_RESTART, "重启网络适配器", ok_all,
                      f"已重启 {len(names)} 块网卡" if ok_all else "部分网卡重启失败，详见日志", cmds)


@action(F.FIX_ARP_FLUSH, "清空 ARP 缓存",
        "清除局域网地址映射缓存，修复网关 MAC 变化、ARP 欺骗导致的断网。")
def fix_arp_flush(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    ok, msg, cmd = _exec(ctx, ["netsh", "interface", "ip", "delete", "arpcache"],
                         timeout=20, tolerate=True, label="清空 ARP 缓存")
    return FixOutcome(F.FIX_ARP_FLUSH, "清空 ARP 缓存", True, msg[:120], [cmd])


@action(F.FIX_NETBIOS_RESET, "重置 NetBIOS 名称缓存",
        "清理 NetBIOS 名称缓存，修复局域网名称解析异常。")
def fix_netbios_reset(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    ok, msg, cmd = _exec(ctx, ["nbtstat", "-R"], timeout=20, tolerate=True, label="重置 NetBIOS 缓存")
    return FixOutcome(F.FIX_NETBIOS_RESET, "重置 NetBIOS 名称缓存", True, msg[:120], [cmd])


@action(F.FIX_MTU_RESET, "MTU 恢复标准值 1500",
        "把网卡的 MTU 恢复为标准 1500，修复分片黑洞导致的“部分网站打不开/加载卡住”。")
def fix_mtu_reset(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    ctx.backup.backup_mtu()
    cmds: List[str] = []
    ok_all = True
    for name in ctx.adapter_names():
        ok, msg, cmd = _exec(ctx, ["netsh", "interface", "ipv4", "set", "subinterface",
                                   name, "mtu=1500", "store=persistent"],
                             timeout=20, label=f"{name} MTU=1500")
        cmds.append(cmd)
        ok_all = ok_all and ok
    return FixOutcome(F.FIX_MTU_RESET, "MTU 恢复标准值 1500", ok_all,
                      "已重置 MTU" if ok_all else "部分网卡重置失败，详见日志", cmds)


@action(F.FIX_ROUTE_REFRESH, "重建默认路由",
        "删除异常默认路由并重新获取，修复 VPN/加速器残留路由劫持导致的断网。")
def fix_route_refresh(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    ctx.backup.backup_routes()
    cmds: List[str] = []
    _ok, m1, c1 = _exec(ctx, ["route", "delete", "0.0.0.0"], timeout=20, tolerate=True,
                        label="删除默认路由")
    cmds.append(c1)
    _ok2, m2, c2 = _exec(ctx, ["ipconfig", "/renew"], timeout=120, tolerate=True,
                         label="重新获取地址与路由")
    cmds.append(c2)
    return FixOutcome(F.FIX_ROUTE_REFRESH, "重建默认路由", True,
                      f"已清除旧默认路由并重新获取：{m2[:100]}", cmds)


@action(F.FIX_POWERSAVE_OFF, "关闭网卡节能断流",
        "关闭“允许计算机关闭此设备以节约电源”，修复空闲时网卡被系统断电导致的随机掉线。")
def fix_powersave_off(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    names = ctx.params.get("all_adapter_names") or ctx.all_adapter_names()
    ctx.backup.backup_power_management(names)
    cmds: List[str] = []
    ok_all = True
    for name in names:
        script = (f"try{{Set-NetAdapterPowerManagement -Name '{name}' "
                  f"-AllowComputerToTurnOffDevice Disabled -ErrorAction Stop; 'OK'}}catch{{'FAIL'}}")
        res = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=25)
        ctx.logger.command(res)
        ok = "OK" in res.stdout
        ok_all = ok_all and ok
        cmds.append(res.cmd)
    return FixOutcome(F.FIX_POWERSAVE_OFF, "关闭网卡节能断流", ok_all,
                      "已关闭节能断流" if ok_all else "部分网卡设置失败（可能不支持该电源选项）", cmds)


@action(F.FIX_TIME_SYNC, "同步系统时间",
        "校时：系统时间偏差过大会导致 HTTPS 证书校验失败，表现为“所有网站都打不开”。")
def fix_time_sync(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    cmds: List[str] = []
    _ok0, m0, c0 = _exec(ctx, ["w32tm", "/config", "/syncfromflags:manual",
                               "/manualpeerlist:ntp.aliyun.com,ntp.tencent.com",
                               "/update"], timeout=20, tolerate=True, label="配置 NTP 源")
    cmds.append(c0)
    _ok1, m1, c1 = _exec(ctx, ["net", "start", "w32time"], timeout=30, tolerate=True, label="启动时间服务")
    cmds.append(c1)
    ok, m2, c2 = _exec(ctx, ["w32tm", "/resync", "/force"], timeout=30, tolerate=True, label="立即校时")
    cmds.append(c2)
    return FixOutcome(F.FIX_TIME_SYNC, "同步系统时间", ok, f"校时结果：{m2[:120]}", cmds)


# --------------------------------------------------------------------------
# 进阶档动作（默认不勾选，需二次确认）
# --------------------------------------------------------------------------

@action(F.FIX_WINSOCK_RESET, "重置 Winsock 目录（进阶）",
        "重置网络套接字接口，修复 LSP 劫持、Winsock 目录损坏。执行后需要重启系统才生效。",
        mode=FixMode.ADVANCED, needs_reboot=True, default_selected=False)
def fix_winsock_reset(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    ctx.backup.backup_winsock()
    ok, msg, cmd = _exec(ctx, ["netsh", "winsock", "reset"], timeout=40, label="重置 Winsock")
    return FixOutcome(F.FIX_WINSOCK_RESET, "重置 Winsock 目录（进阶）", ok,
                      "Winsock 已重置，需重启系统生效" if ok else f"失败：{msg}",
                      [cmd], needs_reboot=True)


@action(F.FIX_TCPIP_RESET, "重置 TCP/IP 协议栈（进阶）",
        "把 TCP/IP 协议栈恢复出厂状态，修复协议栈损坏。执行后需要重启系统才生效。",
        mode=FixMode.ADVANCED, needs_reboot=True, default_selected=False)
def fix_tcpip_reset(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    ctx.backup.backup_netsh_ip_dump()
    cmds: List[str] = []
    ok_all = True
    for args in (["netsh", "int", "ip", "reset"],
                 ["netsh", "int", "ipv4", "reset"],
                 ["netsh", "int", "ipv6", "reset"]):
        ok, msg, cmd = _exec(ctx, args, timeout=60, tolerate=True, label=" ".join(args[:3]))
        cmds.append(cmd)
        ok_all = ok_all and ok
    return FixOutcome(F.FIX_TCPIP_RESET, "重置 TCP/IP 协议栈（进阶）", ok_all,
                      "协议栈已重置，需重启系统生效", cmds, needs_reboot=True)


@action(F.FIX_ADVFW_RESET, "重置 Windows 防火墙策略（进阶）",
        "把防火墙恢复为默认策略，修复被错误规则全量阻断的情况。"
        "注意：会清除你自定义的所有防火墙规则。",
        mode=FixMode.ADVANCED, needs_reboot=True, default_selected=False)
def fix_advfw_reset(ctx: FixContext) -> FixOutcome:
    guard = _guard()
    if guard:
        return guard
    ctx.backup.backup_firewall()
    ok, msg, cmd = _exec(ctx, ["netsh", "advfirewall", "reset"], timeout=40, label="重置防火墙")
    return FixOutcome(F.FIX_ADVFW_RESET, "重置 Windows 防火墙策略（进阶）", ok,
                      "防火墙已恢复默认策略" if ok else f"失败：{msg}", [cmd], needs_reboot=True)


# --------------------------------------------------------------------------
# 调度
# --------------------------------------------------------------------------

def run_fix(fix_id: str, ctx: FixContext) -> FixOutcome:
    """执行一个修复动作；任何异常都转成失败结果，不向上抛。"""
    handler = _HANDLERS.get(fix_id)
    act = ACTIONS.get(fix_id)
    if handler is None or act is None:
        return FixOutcome(fix_id, fix_id, False, "未注册的修复动作")
    ctx.logger.log(f"开始修复：{act.title}", "FIX")
    try:
        out = handler(ctx)
    except Exception as exc:  # noqa: BLE001
        out = FixOutcome(fix_id, act.title, False, f"执行异常：{exc}")
    if out.fix_id == "":
        out.fix_id = fix_id
    if not out.title:
        out.title = act.title
    out.needs_reboot = out.needs_reboot or act.needs_reboot
    (ctx.logger.ok if out.ok else ctx.logger.error)(
        f"{act.title}：{'成功' if out.ok else '失败'} - {out.message[:120]}")
    return out


def run_fixes(fix_ids: List[str], ctx: FixContext, progress=None) -> List[FixOutcome]:
    """批量执行修复动作。"""
    outcomes: List[FixOutcome] = []
    total = len(fix_ids)
    for idx, fix_id in enumerate(fix_ids, 1):
        if progress:
            try:
                progress(idx, total, fix_id)
            except Exception:
                pass
        outcomes.append(run_fix(fix_id, ctx))
    return outcomes
