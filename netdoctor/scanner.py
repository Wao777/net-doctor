# -*- coding: utf-8 -*-
"""扫描引擎：遍历所有可能导致断网的情况，产出疑似原因清单。

分类代号：
  A 链路层      B IP 配置    C DNS       D 协议栈     E 代理/VPN
  F 系统服务    G 路由       H 防火墙    I 系统环境    J 连通性结论
所有检查均为只读操作，不做任何修改。
"""
from __future__ import annotations

import email.utils
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import urllib.request

from . import fixids as F
from . import diagnose, netstate, probes
from .models import (Finding, FixMode, HealthLevel, ProbeResult, ScanReport,
                     Severity, Verdict)
from .netstate import Adapter, NetState
from .util import Logger, hosts_path, now_str, query_services, reg_read, run

INET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
ENV_KEY_HKLM = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"


# --------------------------------------------------------------------------
# 环境采集（一次采集，供各检查复用）
# --------------------------------------------------------------------------

def _is_absent(ad: Adapter) -> bool:
    """设备记录存在但硬件不可见（Not Present）——不能算作可用网卡。"""
    st = (ad.status or "").lower()
    return ("not present" in st) or ("不存在" in ad.status)


@dataclass
class Env:
    state: NetState
    online: bool = False               # 当前是否具备外网连通性（由探针结论回填）
    hosts_lines: List[str] = field(default_factory=list)
    services: Dict[str, Tuple[str, str]] = field(default_factory=dict)  # 服务名 -> (状态, 启动类型)
    proxy_enable: Any = None
    proxy_server: str = ""
    proxy_override: str = ""
    auto_config: str = ""
    env_proxies: List[str] = field(default_factory=list)
    winhttp_proxy: str = ""
    firewall_text: str = ""
    av_products: List[str] = field(default_factory=list)
    winsock_count: int = 0
    powersave_adapters: List[str] = field(default_factory=list)
    time_skew: Optional[float] = None

    @property
    def has_wireless(self) -> bool:
        return any(a.is_wireless for a in self.real_adapters)

    @property
    def real_adapters(self) -> List[Adapter]:
        """排除虚拟网卡与「设备残留」后的物理网卡。"""
        phys = [a for a in self.state.physical_adapters if not a.is_virtual]
        usable = [a for a in phys if not _is_absent(a)]
        if usable:
            return usable
        return phys

    @property
    def active_adapters(self) -> List[Adapter]:
        return [a for a in self.real_adapters if a.up]


def _read_hosts() -> List[str]:
    path = hosts_path()
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as fh:
                return fh.readlines()
        except (UnicodeDecodeError, LookupError):
            continue
        except Exception:
            return []
    return []


def _service_states(names: List[str]) -> Dict[str, Tuple[str, str]]:
    """批量查询服务状态（走 CIM/Get-Service，不依赖 sc.exe）。"""
    return query_services(names)


def _check_time_skew(logger: Optional[Logger] = None) -> Optional[float]:
    """用 HTTP 响应头的服务器时间与本机时间比对，返回偏差秒数。"""
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request("http://www.msftconnecttest.com/connecttest.txt",
                                     method="HEAD",
                                     headers={"User-Agent": "NetDoctor/1.0"})
        with opener.open(req, timeout=6) as resp:
            header = resp.headers.get("Date")
        if not header:
            return None
        server_dt = email.utils.parsedate_to_datetime(header)
        if server_dt.tzinfo is None:
            server_dt = server_dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - server_dt).total_seconds()
    except Exception:
        return None


def _winsock_entry_count() -> int:
    res = run(["netsh", "winsock", "show", "catalog"], timeout=25)
    if not res.ok:
        return 0
    return sum(1 for ln in res.stdout.splitlines() if re.match(r"^\s*(条目|Entry)", ln.strip(), re.I))


def _powersave_adapters(names: List[str]) -> List[str]:
    """返回启用了"允许关闭以省电"的网卡名。"""
    if not names:
        return []
    quoted = ",".join(f"'{n}'" for n in names)
    script = (
        f"foreach($n in @({quoted})){{"
        f"try{{$p=Get-NetAdapterPowerManagement -Name $n -ErrorAction Stop;"
        f"if($p.AllowComputerToTurnOffDevice -eq 'Enabled'){{$n}}}}catch{{}}}}"
    )
    res = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=30)
    return [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]


def collect_env(state: NetState, logger: Optional[Logger] = None, deep: bool = True) -> Env:
    env = Env(state=state)
    env.hosts_lines = _read_hosts()

    if logger:
        logger.log("检查关键网络服务状态…")
    svc_names = [svc for _disp, svc in F.CRITICAL_SERVICES] + ["MpsSvc", "Winmgmt"]
    env.services = _service_states(svc_names)
    if logger:
        bad = [n for n, (s, t) in env.services.items()
               if s and s != "RUNNING" or t == "DISABLED"]
        logger.ok(f"已检查 {len(env.services)} 个服务"
                  + (f"，异常：{', '.join(bad)}" if bad else "，全部正常"))

    env.proxy_enable = reg_read("HKCU", INET_KEY, "ProxyEnable")
    env.proxy_server = str(reg_read("HKCU", INET_KEY, "ProxyServer") or "")
    env.proxy_override = str(reg_read("HKCU", INET_KEY, "ProxyOverride") or "")
    env.auto_config = str(reg_read("HKCU", INET_KEY, "AutoConfigURL") or "")
    if not env.proxy_server:
        env.proxy_server = str(reg_read("HKLM", INET_KEY, "ProxyServer") or "")

    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        if os.environ.get(var):
            env.env_proxies.append(f"{var}={os.environ[var]}")
        elif reg_read("HKCU", "Environment", var) or reg_read("HKLM", ENV_KEY_HKLM, var):
            env.env_proxies.append(f"{var}=（注册表）")

    if deep:
        res = run(["netsh", "winhttp", "show", "proxy"], timeout=10)
        env.winhttp_proxy = res.output
        if logger:
            logger.command(res)

        res = run(["netsh", "advfirewall", "show", "allprofiles"], timeout=20)
        env.firewall_text = res.output
        if logger:
            logger.command(res)

        av = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                  "try{(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
                  "-ErrorAction Stop).displayName}catch{}"], timeout=25)
        # Windows 自带的 Defender 不算「第三方安全软件」，否则每台机器都会误报
        env.av_products = [
            ln.strip() for ln in av.stdout.splitlines()
            if ln.strip() and not re.search(r"defender|microsoft security|windows security",
                                            ln, re.I)
        ]

        env.winsock_count = _winsock_entry_count()
        if logger:
            logger.log(f"Winsock 目录条目数：{env.winsock_count}")

        env.powersave_adapters = _powersave_adapters([a.name for a in env.real_adapters])
        env.time_skew = _check_time_skew(logger)
    return env


# --------------------------------------------------------------------------
# A 链路层
# --------------------------------------------------------------------------

def check_link(env: Env) -> List[Finding]:
    out: List[Finding] = []
    real = env.real_adapters

    if not real:
        out.append(Finding(
            id="A.no-adapter", category="A", category_name="链路层",
            title="未检测到可用的网络适配器",
            detail="系统中没有找到物理网卡。可能是驱动未安装、网卡被移除，或系统网络组件损坏。",
            severity=Severity.CRITICAL,
            manual_hint="1) 打开「设备管理器」查看「网络适配器」是否有黄色感叹号；\n"
                        "2) 有则右键卸载设备后点击「扫描检测硬件改动」重装驱动；\n"
                        "3) 若设备管理器里完全没有网卡，请检查主板/网卡硬件与 BIOS 设置。",
        ))
        return out

    if not env.active_adapters:
        names = "、".join(a.name for a in real)
        out.append(Finding(
            id="A.all-down", category="A", category_name="链路层",
            title="所有网卡都处于未连接状态",
            detail=f"检测到网卡：{names}，但均未建立链路。最常见原因是网线未插好/路由器未上电。",
            severity=Severity.CRITICAL,
            fix_id=F.FIX_ADAPTER_RESTART,
            manual_hint="1) 检查网线两端是否插紧，网口指示灯是否闪烁；\n"
                        "2) 换一根网线或换路由器上的另一个 LAN 口；\n"
                        "3) 无线网卡请确认已连接到 Wi-Fi。",
            data={"adapter_names": [a.name for a in real]},
        ))

    for ad in real:
        st = (ad.status or "").lower()
        if st == "disabled" or "已禁用" in ad.status:
            out.append(Finding(
                id=f"A.disabled:{ad.name}", category="A", category_name="链路层",
                title=f"网卡「{ad.name}」被禁用",
                detail="该网卡在系统中处于「已禁用」状态，无法收发数据。",
                severity=Severity.HIGH,
                fix_id=F.FIX_ADAPTER_RESTART,
                manual_hint=f"在「网络连接」中右键「{ad.name}」选择「启用」。",
                data={"adapter_names": [ad.name], "adapter_name": ad.name},
            ))
        elif "not present" in st or "不存在" in ad.status:
            out.append(Finding(
                id=f"A.notpresent:{ad.name}", category="A", category_name="链路层",
                title=f"网卡「{ad.name}」的设备记录存在但硬件不可见",
                detail="系统里保留了该网卡的记录，但当前检测不到对应硬件。"
                       "常见于已经拔出的 USB 网卡、被关闭的无线网卡或驱动残留。"
                       "如果你本来就没有使用这块网卡，可以忽略此项。",
                severity=Severity.INFO,
                manual_hint="若确认不再使用：设备管理器 → 查看 → 显示隐藏的设备，"
                            "在「网络适配器」下卸载该灰色设备。",
                data={"adapter_name": ad.name},
            ))
        elif not ad.up:
            if ad.is_wireless:
                out.append(Finding(
                    id=f"A.wifi:{ad.name}", category="A", category_name="链路层",
                    title=f"无线网卡「{ad.name}」未连接",
                    detail="无线网卡处于未连接状态，需要连接一个可用的 Wi-Fi。",
                    severity=Severity.MEDIUM,
                    manual_hint="点击任务栏网络图标，选择并连接可用 Wi-Fi；"
                                "若列表为空，确认 WLAN AutoConfig 服务已启动。",
                    data={"adapter_name": ad.name},
                ))
            else:
                out.append(Finding(
                    id=f"A.linkdown:{ad.name}", category="A", category_name="链路层",
                    title=f"有线网卡「{ad.name}」网线未连通",
                    detail="网卡未检测到链路信号，通常为网线未插好、网线损坏或路由器端口故障。",
                    severity=Severity.HIGH,
                    manual_hint="1) 重新插拔网线；2) 更换网线；3) 更换路由器的 LAN 端口。",
                    data={"adapter_name": ad.name},
                ))
        # 链路速率异常（半双工/低速）
        if ad.up and ad.link_speed:
            m = re.search(r"(\d+)\s*(Mbps|Gbps|Kbps)", ad.link_speed, re.I)
            if m:
                val = float(m.group(1))
                unit = m.group(2).lower()
                mbps = val * 1000 if unit == "gbps" else (val / 1000 if unit == "kbps" else val)
                if 0 < mbps <= 10:
                    out.append(Finding(
                        id=f"A.lowspeed:{ad.name}", category="A", category_name="链路层",
                        title=f"网卡「{ad.name}」协商速率偏低（{ad.link_speed}）",
                        detail="链路速率明显低于正常水平，多见于网线老化、水晶头接触不良或双工协商错误，"
                               "会造成丢包、断流。",
                        severity=Severity.LOW,
                        manual_hint="更换合格的超五类/六类网线；在网卡属性「高级」里把"
                                    "「速度和双工」改为「自动协商」。",
                        data={"adapter_name": ad.name},
                    ))
    return out


# --------------------------------------------------------------------------
# B IP 配置
# --------------------------------------------------------------------------

def check_ip(env: Env) -> List[Finding]:
    out: List[Finding] = []
    active = env.active_adapters

    if len(active) > 1:
        names = "、".join(a.name for a in active)
        out.append(Finding(
            id="B.multi-adapter", category="B", category_name="IP 配置",
            title="多块网卡同时处于连接状态",
            detail=f"当前活动的网卡有：{names}。多个出口同时存在时容易出现路由抢占、"
                   "时通时断，或内网/外网访问互相干扰。",
            severity=Severity.MEDIUM,
            manual_hint="只保留一个上网出口：在「网络连接」里禁用其余的网卡"
                        "（例如同时插网线又连 Wi-Fi 时，禁用其中一个）。",
            data={"adapter_names": [a.name for a in active]},
        ))

    for ad in active:
        ips = [ip for ip in ad.ipv4 if ip]

        if not ips:
            out.append(Finding(
                id=f"B.noip:{ad.name}", category="B", category_name="IP 配置",
                title=f"网卡「{ad.name}」没有 IPv4 地址",
                detail="网卡已连接但未获取到 IP 地址，DHCP 请求可能失败或地址池已耗尽。",
                severity=Severity.HIGH,
                fix_id=F.FIX_DHCP_RENEW,
                manual_hint="在网卡属性中确认「自动获取 IP 地址」；或手动指定同网段静态 IP。",
                data={"adapter_names": [ad.name], "adapter_name": ad.name},
            ))
            continue

        for ip in ips:
            if ip.startswith("169.254."):
                out.append(Finding(
                    id=f"B.apipa:{ad.name}", category="B", category_name="IP 配置",
                    title=f"网卡「{ad.name}」获取到 169.254 自动私有地址",
                    detail=f"当前 IP 为 {ip}，这是 DHCP 服务器无响应时系统自动分配的地址，"
                           "意味着整条链路拿不到有效地址，必然无法上网。",
                    severity=Severity.CRITICAL,
                    fix_id=F.FIX_DHCP_RENEW,
                    manual_hint="1) 重启路由器/光猫；2) 若路由器 DHCP 关闭，请开启或改为静态 IP；"
                                "3) 检查是否达到路由器可分配地址上限。",
                    evidence=f"IPv4: {ip}",
                    data={"adapter_names": [ad.name], "adapter_name": ad.name},
                ))
            elif ip == "0.0.0.0":
                out.append(Finding(
                    id=f"B.zeroip:{ad.name}", category="B", category_name="IP 配置",
                    title=f"网卡「{ad.name}」IP 地址为 0.0.0.0",
                    detail="网卡未获得有效地址，属于异常配置。",
                    severity=Severity.HIGH,
                    fix_id=F.FIX_DHCP_RENEW,
                    data={"adapter_names": [ad.name], "adapter_name": ad.name},
                ))

        if not ad.gateway:
            out.append(Finding(
                id=f"B.nogw:{ad.name}", category="B", category_name="IP 配置",
                title=f"网卡「{ad.name}」没有默认网关",
                detail="缺少默认网关意味着本机不知道出口在哪，只能访问同网段设备。",
                severity=Severity.HIGH,
                fix_id=F.FIX_ROUTE_REFRESH,
                manual_hint="自动获取 IP 的情况下请重启路由器；静态配置时手动填写网关地址。",
                data={"adapter_names": [ad.name], "adapter_name": ad.name},
            ))

        if ad.dhcp and ad.dhcp.lower() == "disabled" and ips and any(not ip.startswith("169.254.") for ip in ips):
            out.append(Finding(
                id=f"B.static:{ad.name}", category="B", category_name="IP 配置",
                title=f"网卡「{ad.name}」使用静态 IP（DHCP 已关闭）",
                detail=f"静态地址为 {', '.join(ips)}。若该地址与当前网络网段不符，将无法上网。",
                severity=Severity.LOW,
                fix_id=F.FIX_DHCP_AUTO,
                manual_hint="若在家庭/办公网络，建议改回「自动获取 IP 地址」。",
                data={"adapter_names": [ad.name], "adapter_name": ad.name},
            ))
    return out


# --------------------------------------------------------------------------
# C DNS
# --------------------------------------------------------------------------

def check_dns(env: Env) -> List[Finding]:
    out: List[Finding] = []

    if not env.state.dns_servers:
        out.append(Finding(
            id="C.no-dns", category="C", category_name="DNS",
            title="未配置任何 DNS 服务器",
            detail="本机没有可用的 DNS 地址，域名将无法解析，表现为可以 ping 通 IP 但打不开网页。",
            severity=Severity.HIGH,
            fix_id=F.FIX_DHCP_AUTO,
            manual_hint="把网卡 DNS 设为「自动获取」，或手动填写 223.5.5.5 / 114.114.114.114。",
            data={"adapter_names": [a.name for a in env.active_adapters]},
        ))

    effective: List[str] = []
    for line in env.hosts_lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}\s+\S+", s):
            effective.append(s)

    if effective:
        # hosts 可能是用户自己有意添加的（屏蔽广告、加速访问），
        # 因此只在「当前确实上不了网」时才当作疑似原因；实测正常时仅作提示。
        if env.online:
            sev = Severity.INFO
        elif len(effective) >= 20:
            sev = Severity.MEDIUM
        else:
            sev = Severity.LOW
        sample = "；".join(effective[:3])
        online_note = ("当前实测可以正常上网，说明这些记录尚未影响你的网络，"
                       "本项仅作提示。\n" if env.online else "")
        out.append(Finding(
            id="C.hosts", category="C", category_name="DNS",
            title=f"hosts 文件存在 {len(effective)} 条自定义解析记录",
            detail=online_note
                   + "hosts 文件的优先级高于 DNS，被第三方软件（加速器、破解补丁、去广告工具）"
                   "写入的记录会把域名直接指向指定的 IP，可能造成「特定网站打不开」或"
                   "「所有网站都打不开」。\n"
                   "如果这些记录是你自己主动添加的（例如屏蔽广告、加速访问），请忽略此项。",
            severity=sev,
            fix_id=F.FIX_HOSTS_RESTORE,
            manual_hint=f"用记事本（管理员）打开 {hosts_path()}，删除可疑行（保留 localhost 相关）；\n"
                        f"或直接使用本工具的「还原 hosts 文件」（原文件会被备份，可回滚）。",
            evidence=sample,
        ))
    return out


# --------------------------------------------------------------------------
# D 协议栈
# --------------------------------------------------------------------------

def check_stack(env: Env, probe_list: List[ProbeResult]) -> List[Finding]:
    out: List[Finding] = []
    local = _probe(probe_list, "本机协议栈")

    if local is not None and not local.ok:
        out.append(Finding(
            id="D.local-stack", category="D", category_name="协议栈",
            title="本机 TCP/IP 协议栈无响应",
            detail="连 127.0.0.1 都无法 ping 通，说明网络协议栈本身异常，"
                   "任何网络操作都不可能成功。",
            severity=Severity.CRITICAL,
            fix_id=F.FIX_TCPIP_RESET,
            manual_hint="进阶修复会重置 TCP/IP 协议栈，执行后需要重启电脑。",
        ))

    if env.winsock_count >= 250:
        out.append(Finding(
            id="D.winsock", category="D", category_name="协议栈",
            title=f"Winsock 目录条目异常偏多（{env.winsock_count} 条）",
            detail="正常情况下 Winsock 目录条目数在几十条量级。条目异常增多通常意味着"
                   "安装了网络过滤类软件（VPN 客户端、下载加速器、安全软件）并残留了 LSP，"
                   "可能拦截或损坏网络请求。",
            severity=Severity.MEDIUM,
            fix_id=F.FIX_WINSOCK_RESET,
            manual_hint="进阶修复会执行 netsh winsock reset，执行后需重启系统。",
            evidence=f"条目数: {env.winsock_count}",
        ))
    return out


# --------------------------------------------------------------------------
# E 代理 / VPN
# --------------------------------------------------------------------------

def check_browser_path(env: Env, probe_list: List[ProbeResult]) -> List[Finding]:
    """「只有浏览器上不了网」的专项判定：直连能通，唯独经系统代理不通。"""
    browse = _probe(probe_list, diagnose.P_BROWSE)
    if browse is None or browse.ok:
        return []
    direct = _probe(probe_list, diagnose.P_HTTP) or _probe(probe_list, diagnose.P_TCP)
    if direct is None or not direct.ok:
        return []   # 直连也不通，属于更底层的故障，交给连通性结论处理
    return [Finding(
        id="E.browser-path", category="E", category_name="代理/VPN",
        title="浏览器走系统代理这条路不通（其他程序可正常上网）",
        detail="实测结果：直连访问网络正常，但按系统代理设置访问时全部失败。\n"
               "系统的代理开关指向的地址已经失效——浏览器、系统更新等走系统代理的程序会因此上不了网，"
               "而微信/QQ、网游这类不走系统代理的程序不受影响。这是「能上 QQ 打不开网页」最常见的成因。",
        severity=Severity.HIGH,
        fix_id=F.FIX_PROXY_DISABLE,
        manual_hint="1) 执行「关闭系统代理与 PAC」；\n"
                    "2) 若你确实在用代理软件，请确认它已启动并监听配置的端口；\n"
                    "3) 浏览器若装过代理类扩展，一并关闭后重启浏览器。",
        evidence=f"系统代理：{env.proxy_server or '（见注册表）'}；{browse.detail}",
        data={"adapter_names": [a.name for a in env.active_adapters]},
    )]


def check_proxy(env: Env) -> List[Finding]:
    out: List[Finding] = []

    if env.proxy_enable in (1, "1") and env.proxy_server:
        out.append(Finding(
            id="E.system-proxy", category="E", category_name="代理/VPN",
            title=f"系统代理已开启，指向 {env.proxy_server}",
            detail="如果这个代理程序已经退出或地址已失效，浏览器等走系统代理的软件就会全部断网，"
                   "而 QQ/微信这类不读系统代理的程序仍能正常使用——这是最典型的"
                   "「能上 QQ 打不开网页」成因。",
            severity=Severity.HIGH,
            fix_id=F.FIX_PROXY_DISABLE,
            manual_hint="「设置 → 网络和 Internet → 代理」中关闭「使用代理服务器」。",
            evidence=f"ProxyEnable=1, ProxyServer={env.proxy_server}",
        ))
    elif env.proxy_enable in (1, "1"):
        out.append(Finding(
            id="E.system-proxy-noserver", category="E", category_name="代理/VPN",
            title="系统代理开关已打开但未填写代理地址",
            detail="代理开关处于开启状态却没有可用地址，会导致所有走系统代理的程序无法联网。",
            severity=Severity.HIGH,
            fix_id=F.FIX_PROXY_DISABLE,
            evidence="ProxyEnable=1",
        ))

    if env.auto_config:
        out.append(Finding(
            id="E.pac", category="E", category_name="代理/VPN",
            title="配置了 PAC 自动代理脚本",
            detail=f"PAC 地址：{env.auto_config}。若该脚本无法访问或内容有误，浏览器将无法联网。",
            severity=Severity.MEDIUM,
            fix_id=F.FIX_PROXY_DISABLE,
            manual_hint="在 Internet 选项 → 连接 → 局域网设置 中取消「使用自动配置脚本」。",
            evidence=env.auto_config,
        ))

    if env.env_proxies:
        out.append(Finding(
            id="E.env-proxy", category="E", category_name="代理/VPN",
            title="存在代理环境变量",
            detail="命令行工具、开发环境会读取这些变量，代理失效时会连带失败。",
            severity=Severity.MEDIUM,
            fix_id=F.FIX_ENV_PROXY_CLEAR,
            evidence="; ".join(env.env_proxies[:4]),
        ))

    if env.winhttp_proxy and "direct" not in env.winhttp_proxy.lower() and "直接" not in env.winhttp_proxy:
        if ":" in env.winhttp_proxy and re.search(r"\d{1,3}(\.\d{1,3}){3}:\d+", env.winhttp_proxy):
            out.append(Finding(
                id="E.winhttp", category="E", category_name="代理/VPN",
                title="WinHTTP 代理指向具体地址",
                detail="系统级（服务/后台程序）的 HTTP 请求会走这个代理，代理失效将导致"
                       "系统更新、激活、部分软件无法联网。",
                severity=Severity.MEDIUM,
                fix_id=F.FIX_PROXY_DISABLE,
                evidence=env.winhttp_proxy.strip().splitlines()[-1][:120],
            ))

    virtual_up = [a for a in env.state.adapters
                  if a.is_virtual and a.up and not a.is_loopback]
    if virtual_up:
        names = "、".join(a.name for a in virtual_up)
        hijack = False
        for r in env.state.routes:
            alias = str(r.get("InterfaceAlias") or "")
            if any(alias and alias == a.name for a in virtual_up):
                hijack = True
        out.append(Finding(
            id="E.virtual-adapter", category="E", category_name="代理/VPN",
            title=f"检测到虚拟网卡处于连接状态：{names}",
            detail="VPN / 加速器 / 虚拟机 / 网游加速软件的虚拟网卡如果异常退出，"
                   "会留下无法使用的默认路由，直接导致整机断网。"
                   + ("当前默认路由已被虚拟网卡接管。" if hijack else ""),
            severity=Severity.HIGH if hijack else Severity.MEDIUM,
            fix_id=F.FIX_ROUTE_REFRESH,
            manual_hint="1) 彻底退出 VPN/加速器并断开连接；\n"
                        "2) 若已不用，在「网络连接」中禁用该虚拟网卡；\n"
                        "3) 执行本工具的「重建默认路由」。",
            data={"adapter_names": [a.name for a in env.active_adapters]},
        ))
    return out


# --------------------------------------------------------------------------
# F 系统服务
# --------------------------------------------------------------------------

def check_services(env: Env) -> List[Finding]:
    out: List[Finding] = []
    for disp, svc in F.CRITICAL_SERVICES:
        if svc == F.WIRELESS_SERVICE and not env.has_wireless:
            continue
        info = env.services.get(svc)
        if not info:
            continue
        st, start = info
        st_u = (st or "").upper()
        start_u = (start or "").upper()
        if not st_u:
            continue

        if start_u == "DISABLED":
            out.append(Finding(
                id=f"F.disabled:{svc}", category="F", category_name="系统服务",
                title=f"关键服务「{disp}」被设为禁用",
                detail=f"服务 {svc} 的启动类型是「禁用」"
                       + ("，当前也未运行。" if st_u != "RUNNING" else "（当前仍在运行）。")
                       + "禁用后重启系统将不再自动启动，会导致下次开机直接断网。",
                severity=Severity.HIGH if st_u != "RUNNING" else Severity.MEDIUM,
                fix_id=F.FIX_SERVICE_START,
                manual_hint=f"运行 services.msc，找到「{disp}」，把启动类型改为「自动」并启动。",
                evidence=f"{svc}: state={st_u}, start={start_u}",
                data={"services": [svc]},
            ))
            continue

        if st_u == "RUNNING":
            continue

        # ---- 服务已停止 ----
        always_on = svc in F.ALWAYS_ON_SERVICES
        if always_on:
            out.append(Finding(
                id=f"F.stopped:{svc}", category="F", category_name="系统服务",
                title=f"关键服务「{disp}」未运行",
                detail=f"服务 {svc} 当前状态为 {st_u}（启动类型 {start_u}）。"
                       "该服务需要常驻运行，停止会直接影响网络功能。",
                severity=Severity.CRITICAL if not env.online else Severity.HIGH,
                fix_id=F.FIX_SERVICE_START,
                manual_hint=f"运行 services.msc，找到「{disp}」，把启动类型改为「自动」并启动。",
                evidence=f"{svc}: state={st_u}, start={start_u}",
                data={"services": [svc]},
            ))
        elif not env.online:
            # 按需启动的服务在断网时值得关注，网络正常时不打扰用户
            out.append(Finding(
                id=f"F.stopped:{svc}", category="F", category_name="系统服务",
                title=f"服务「{disp}」未运行（按需启动）",
                detail=f"服务 {svc} 当前未运行，启动类型为 {start_u}。"
                       "该服务属于按需启动类型，网络正常时停止属正常现象；"
                       "但当前检测到网络异常，可以尝试启动它排除影响。",
                severity=Severity.MEDIUM,
                fix_id=F.FIX_SERVICE_START,
                manual_hint=f"运行 services.msc，找到「{disp}」，先点「启动」，"
                            "若需要可把启动类型改为「自动」。",
                evidence=f"{svc}: state={st_u}, start={start_u}",
                data={"services": [svc]},
            ))
    return out


# --------------------------------------------------------------------------
# G 路由
# --------------------------------------------------------------------------

def check_routes(env: Env, probe_list: List[ProbeResult]) -> List[Finding]:
    out: List[Finding] = []
    gws = env.state.default_gateways

    if not env.state.routes and not gws:
        out.append(Finding(
            id="G.no-default-route", category="G", category_name="路由",
            title="路由表中缺少默认路由",
            detail="没有 0.0.0.0/0 路由，数据包不知道往哪里发，除同网段外全部不可达。",
            severity=Severity.HIGH,
            fix_id=F.FIX_ROUTE_REFRESH,
            manual_hint="执行「重建默认路由」或重启路由器后重新获取 IP。",
        ))

    if len(env.state.routes) > 1:
        detail = "；".join(
            f"{r.get('InterfaceAlias', '?')} -> {r.get('NextHop', '?')} (metric {r.get('RouteMetric', '?')})"
            for r in env.state.routes
        )
        out.append(Finding(
            id="G.multi-default", category="G", category_name="路由",
            title=f"存在 {len(env.state.routes)} 条默认路由",
            detail="多条默认路由会按跃点数择优，若其中一条指向已失效的出口（常见于 VPN 残留），"
                   "就会出现随机断网。",
            severity=Severity.MEDIUM,
            fix_id=F.FIX_ROUTE_REFRESH,
            evidence=detail[:300],
        ))

    mtu = _probe(probe_list, "MTU 探测")
    if mtu is not None and not mtu.ok:
        out.append(Finding(
            id="G.mtu", category="G", category_name="路由",
            title="网络存在分片黑洞（MTU 偏小）",
            detail=f"{mtu.detail}。小于正常 1500 的 MTU 会让大包被丢弃，"
                   "表现为「小网页能开、视频/下载/图片加载失败或长时间卡住」。",
            severity=Severity.MEDIUM,
            fix_id=F.FIX_MTU_RESET,
            evidence=mtu.detail,
            data={"adapter_names": [a.name for a in env.active_adapters]},
        ))
    return out


# --------------------------------------------------------------------------
# H 防火墙 / 安全软件
# --------------------------------------------------------------------------

def check_firewall(env: Env) -> List[Finding]:
    out: List[Finding] = []
    text = env.firewall_text or ""

    if re.search(r"BlockOutbound", text, re.I) or "阻止出站" in text:
        out.append(Finding(
            id="H.block-outbound", category="H", category_name="防火墙/安全软件",
            title="Windows 防火墙出站策略为「全部阻止」",
            detail="防火墙把出站流量整体阻断，所有程序都无法访问网络。",
            severity=Severity.HIGH,
            fix_id=F.FIX_ADVFW_RESET,
            manual_hint="控制面板 → Windows Defender 防火墙 → 高级设置 → 属性，"
                        "把出站连接改为「允许」。",
        ))

    if env.av_products:
        out.append(Finding(
            id="H.av", category="H", category_name="防火墙/安全软件",
            title="检测到第三方安全软件：" + "、".join(env.av_products[:3]),
            detail="安全软件的「网络防护 / 流量监控」模块可能拦截流量，尤其是刚安装、"
                   "升级或规则冲突时。可临时退出该软件验证是否为元凶。",
            severity=Severity.INFO,
            manual_hint="临时退出安全软件的网络防护功能，再测试能否上网；"
                        "能通则把本机网络加入白名单或更换软件。",
            evidence="；".join(env.av_products[:3]),
        ))

    st, start = env.services.get("MpsSvc", ("", ""))
    if st and st.upper() != "RUNNING":
        out.append(Finding(
            id="H.mpsvc", category="H", category_name="防火墙/安全软件",
            title="Windows 防火墙服务（MpsSvc）未运行",
            detail="防火墙服务停止属于系统异常状态，部分网络功能（如网络发现、共享）会失效。",
            severity=Severity.LOW,
            fix_id=F.FIX_SERVICE_START,
            data={"services": ["MpsSvc"]},
        ))
    return out


# --------------------------------------------------------------------------
# I 系统环境
# --------------------------------------------------------------------------

def check_system(env: Env) -> List[Finding]:
    out: List[Finding] = []

    if env.time_skew is not None and abs(env.time_skew) > 300:
        mins = env.time_skew / 60
        out.append(Finding(
            id="I.time-skew", category="I", category_name="系统环境",
            title=f"系统时间偏差约 {mins:.0f} 分钟",
            detail="系统时间与网络时间偏差过大，会导致 HTTPS 证书校验失败，"
                   "所有网站都提示「连接不安全」或直接打不开，但 QQ 等仍正常。",
            severity=Severity.MEDIUM,
            fix_id=F.FIX_TIME_SYNC,
            manual_hint="设置 → 时间和语言 → 日期和时间，打开「自动设置时间」并立即同步。",
            evidence=f"偏差 {env.time_skew:.0f} 秒",
        ))

    if env.powersave_adapters:
        out.append(Finding(
            id="I.powersave", category="I", category_name="系统环境",
            title="网卡启用了节能断流：" + "、".join(env.powersave_adapters),
            detail="系统在空闲时会关闭网卡以省电，造成「挂机一会儿就掉线、动一下鼠标又恢复」。",
            severity=Severity.LOW,
            fix_id=F.FIX_POWERSAVE_OFF,
            manual_hint="设备管理器 → 网卡 → 属性 → 电源管理，"
                        "取消勾选「允许计算机关闭此设备以节约电源」。",
            data={"all_adapter_names": env.powersave_adapters},
        ))
    return out


# --------------------------------------------------------------------------
# J 连通性结论
# --------------------------------------------------------------------------

_J_LAYERS = [
    ("本机协议栈", "本机网络协议栈异常", Severity.CRITICAL, F.FIX_TCPIP_RESET,
     "重置 TCP/IP 协议栈（进阶），执行后需重启。"),
    ("默认网关", "内网不通：无法访问路由器/网关",
     Severity.HIGH, F.FIX_ADAPTER_RESTART,
     "1) 检查网线、路由器电源与指示灯；\n2) 重启路由器；\n3) 换 LAN 口或网线。"),
    ("公网IP", "内网正常但无法访问外网（出口异常）",
     Severity.HIGH, None,
     "1) 查看路由器 WAN 口是否获取到 IP、光猫是否有告警灯；\n"
     "2) 重启光猫与路由器（间隔 30 秒）；\n"
     "3) 若路由器 WAN 无地址，多为宽带线路/运营商问题，请联系运营商。"),
    ("DNS解析", "域名解析失败（DNS 问题）",
     Severity.HIGH, F.FIX_DNS_FLUSH,
     "1) 刷新 DNS 缓存；2) 把 DNS 改为 223.5.5.5 / 114.114.114.114；3) 检查 hosts。"),
    ("TCP 443", "HTTPS 端口被阻断",
     Severity.HIGH, None,
     "1) 检查安全软件/防火墙是否拦截 443；\n2) 若在公司网络，可能被上网行为管理设备限制。"),
    ("HTTP 访问", "应用层访问异常",
     Severity.MEDIUM, F.FIX_PROXY_DISABLE,
     "1) 关闭系统代理；2) 检查安全软件的网页防护；3) 更换浏览器验证。"),
]


def check_connectivity(probe_list: List[ProbeResult]) -> List[Finding]:
    """根据分层探针结果，给出「断在哪一层」的结论。"""
    out: List[Finding] = []
    if not probe_list:
        return out

    first_bad: Optional[Tuple[ProbeResult, tuple]] = None
    for name, title, sev, fix, hint in _J_LAYERS:
        p = _probe(probe_list, name)
        if p is None:
            continue
        if not p.ok:
            first_bad = (p, (name, title, sev, fix, hint))
            break

    if first_bad is None:
        return out

    p, (_n, title, sev, fix, hint) = first_bad
    detail = f"分层检测结果：{title}。{p.detail or ''}".strip()
    out.append(Finding(
        id=f"J.{p.name}", category="J", category_name="连通性结论",
        title=title, detail=detail, severity=sev,
        fix_id=fix, manual_hint=hint, evidence=p.detail,
    ))
    return out


def _probe(probe_list: List[ProbeResult], name: str) -> Optional[ProbeResult]:
    for p in probe_list:
        if p.name == name:
            return p
    return None


def _hosts_effective_count(lines: List[str]) -> int:
    n = 0
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#") and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}\s+\S+", s):
            n += 1
    return n


def _ctx_facts(state: NetState, env: Optional[Env] = None,
               hosts_count: Optional[int] = None) -> Dict[str, Any]:
    """收集判定引擎需要的环境事实。"""
    if hosts_count is None:
        hosts_count = _hosts_effective_count(env.hosts_lines) if env else 0
    return {
        "hosts_count": hosts_count,
        "powersave": list(getattr(env, "powersave_adapters", None) or []),
        "time_skew": getattr(env, "time_skew", None),
        "routes": len(getattr(state, "routes", None) or []),
        "winsock": int(getattr(env, "winsock_count", 0) or 0),
        "proxy_on": getattr(env, "proxy_enable", None) in (1, "1"),
        "adapters_up": len([a for a in state.physical_adapters if a.up]),
    }


def _filter_fix_ids(ids: List[str]) -> List[str]:
    """只保留稳健档且默认可选的修复动作（进阶档交用户手工勾选）。"""
    from .fixers import ACTIONS

    out: List[str] = []
    for fid in ids:
        act = ACTIONS.get(fid)
        if act is None:
            continue
        if act.mode != FixMode.SAFE or not act.default_selected:
            continue
        if fid not in out:
            out.append(fid)
    return out


# 实测正常时仍保留原始严重度的检出：它们代表**探针测到的真实缺陷**，不是配置噪声
_MEASURED_IDS = {"G.mtu", "I.time-skew"}


def _verdict_with_hints(probe_list: List[ProbeResult], findings: List[Finding],
                        facts: Dict[str, Any]) -> Verdict:
    """先判定网络是否正常，再按「健康度只由实测决定」的原则归并提示级条目。

    两趟都是纯计算（无 I/O），代价可忽略；这样「什么算提示」的规则只存在
    一处，判定引擎只负责读严重度。
    """
    v = diagnose.judge(probe_list, findings, facts)
    if v.online and v.level.rank < HealthLevel.LIMITED.rank:
        # 实测能正常上网 → 配置类检出（hosts/代理/静态IP/节能等）一律降为「提示」
        for f in findings:
            if f.id in _MEASURED_IDS or f.category == "J":
                continue
            f.severity = Severity.INFO
        v = diagnose.judge(probe_list, findings, facts)
    v.fix_ids = _filter_fix_ids(v.fix_ids)
    return v


def quick_check(logger: Optional[Logger] = None) -> ScanReport:
    """快速体检：秒级给出「网络是否正常、断在哪一环」的判定。

    只跑快速分层探针，不做全量检查；用于界面开屏即出结论，之后可再跑完整扫描。
    """
    log = logger or Logger()
    report = ScanReport(started_at=now_str())
    log.log("=" * 12 + " 快速体检 " + "=" * 12, "SCAN")
    state = NetState(source="failed")
    try:
        state = netstate.collect(log)
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"网络状态采集失败：{exc}")

    probe_list: List[ProbeResult] = []
    try:
        probe_list = probes.run_quick(state, log)
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"快速体检探针失败：{exc}")

    report.probes = probe_list
    try:
        report.verdict = _verdict_with_hints(
            probe_list, [], _ctx_facts(state, None, _hosts_effective_count(_read_hosts()))
        )
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"判定失败：{exc}")
    report.finished_at = now_str()
    log.log("快速体检结论：" + (report.verdict.level.label if report.verdict else "未知"), "SCAN")
    return report


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def scan(logger: Optional[Logger] = None, deep: bool = True) -> ScanReport:
    """执行一次完整扫描（全部只读）。"""
    log = logger or Logger()
    report = ScanReport(started_at=now_str())

    log.log("=" * 12 + " 开始扫描 " + "=" * 12, "SCAN")
    log.log("步骤 1/3：采集网络配置")
    try:
        state = netstate.collect(log)
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"网络状态采集失败：{exc}")
        state = NetState(source="failed")

    log.log("步骤 2/3：采集运行环境（服务/代理/防火墙）")
    try:
        env = collect_env(state, log, deep=deep)
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"环境采集失败：{exc}")
        env = Env(state=state)

    log.log("步骤 3/3：连通性探针")
    probe_list: List[ProbeResult] = []
    try:
        probe_list = probes.run_all(state, log, deep=deep)
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"连通性探测失败：{exc}")

    findings: List[Finding] = []
    # 把连通性结论回填给环境，供服务等检查判断「是否值得打扰用户」
    env.online = any(p.name in ("TCP 443", "HTTP 访问") and p.ok for p in probe_list)

    for checker in (check_link, check_ip, check_dns, check_services, check_proxy, check_system):
        try:
            findings.extend(checker(env))  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"{checker.__name__} 失败：{exc}")
    for checker2 in (check_stack, check_routes, check_browser_path):
        try:
            findings.extend(checker2(env, probe_list))  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"{checker2.__name__} 失败：{exc}")
    try:
        findings.extend(check_firewall(env))
        findings.extend(check_connectivity(probe_list))
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"结论推导失败：{exc}")

    report.findings = findings
    report.probes = probe_list

    # ---- 判定：先回答「网络是否正常」，再区分故障形态并给出分别处理的预案 ----
    # 实测正常时，配置类检出（hosts/代理/静态 IP/节能等）会被统一降为「提示」级，
    # 健康度不受它们影响 —— 详见 _verdict_with_hints / models.HealthLevel。
    try:
        report.verdict = _verdict_with_hints(probe_list, findings, _ctx_facts(state, env))
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"判定失败：{exc}")

    report.finished_at = now_str()
    report.info = {
        "adapters": [a.to_dict() for a in state.adapters],
        "default_gateways": state.default_gateways,
        "dns_servers": state.dns_servers,
        "source": state.source,
        "online": report.online,
        "verdict": report.verdict.to_dict() if report.verdict else None,
        "suspicious_count": len(report.suspicious),
    }
    log.log(f"扫描完成：判定「{report.verdict.level.label if report.verdict else '未知'}」，"
            f"{len(report.suspicious)} 条疑似原因，"
            f"{'网络可用' if report.online else '网络不可用'}", "SCAN")
    return report
