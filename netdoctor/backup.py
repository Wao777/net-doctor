# -*- coding: utf-8 -*-
"""备份与回滚。

原则：任何自动修复动作执行前，必须先落盘可还原的配置快照。
所有快照写入 <root>/<YYYYmmdd-HHMMSS>/，并记录 manifest.json 供回滚使用。
"""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .util import (Logger, ensure_dir, hosts_path, now_str, query_services,
                   reg_delete, reg_export_key, reg_import_key, reg_read,
                   restore_service_start_type, run, timestamp)

BACKUP_ROOT_NAME = "backups"

# IE / 系统代理设置所在注册表键
INET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


@dataclass
class BackupItem:
    """一条备份记录。"""

    id: str
    kind: str          # file | reg | nil | json
    desc: str
    backup: str = ""   # 备份文件相对路径
    target: str = ""   # 原始目标（文件路径 / 注册表键）
    existed: bool = True
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "desc": self.desc,
            "backup": self.backup.replace("\\", "/"),
            "target": self.target,
            "existed": self.existed,
            "extra": self.extra,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "BackupItem":
        return BackupItem(
            id=data.get("id", ""),
            kind=data.get("kind", ""),
            desc=data.get("desc", ""),
            backup=data.get("backup", ""),
            target=data.get("target", ""),
            existed=bool(data.get("existed", True)),
            extra=data.get("extra") or {},
        )


class BackupManager:
    """一次修复会话的备份管理器。"""

    def __init__(self, root: str, logger: Optional[Logger] = None) -> None:
        self.root = ensure_dir(root)
        self.logger = logger or Logger()
        self.session = ensure_dir(os.path.join(self.root, timestamp()))
        self.items: List[BackupItem] = []

    # ---------------- 内部工具 ----------------

    def _sub(self, name: str) -> str:
        return ensure_dir(os.path.join(self.session, name))

    def _rel(self, path: str) -> str:
        return os.path.relpath(path, self.session)

    def add(self, item: BackupItem) -> BackupItem:
        self.items.append(item)
        self.logger.ok(f"备份完成：{item.desc} -> {item.backup or item.target}")
        self.write_manifest()
        return item

    # ---------------- 各类型备份 ----------------

    def backup_file(self, item_id: str, desc: str, target: str) -> BackupItem:
        """备份任意文件。"""
        if not os.path.exists(target):
            return self.add(BackupItem(item_id, "nil", desc, "", target, existed=False))
        dest = os.path.join(self._sub("files"), f"{item_id}_{os.path.basename(target)}")
        try:
            shutil.copy2(target, dest)
            self.write_manifest()
            return self.add(BackupItem(item_id, "file", desc, self._rel(dest), target, existed=True))
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"备份失败 {desc}: {exc}")
            return self.add(BackupItem(item_id, "nil", desc + "（备份失败）", "", target, existed=False))

    def backup_hosts(self) -> BackupItem:
        return self.backup_file("hosts", "hosts 文件", hosts_path())

    def backup_registry_key(self, item_id: str, desc: str, hive: str, subkey: str) -> BackupItem:
        """用 winreg 递归导出注册表键。

        刻意不调用 reg.exe：一来可以绕过限制 reg.exe 的安全策略，
        二来导出内容是结构化 JSON，回滚时逐值写回，粒度比整键导入更安全。
        """
        data = reg_export_key(hive, subkey)
        if not data:
            return self.add(BackupItem(item_id, "nil", desc + "（不可读或无内容）", "",
                                       f"{hive}\\{subkey}"))
        dest = os.path.join(self._sub("json"), f"{item_id}.json")
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump({"hive": hive, "subkey": subkey, "data": data},
                      fh, ensure_ascii=False, indent=1)
        return self.add(BackupItem(item_id, "regjson", desc, self._rel(dest), f"{hive}\\{subkey}"))

    def backup_proxy(self) -> BackupItem:
        return self.backup_registry_key("proxy_reg", "系统代理设置（Internet Settings）", "HKCU", INET_SETTINGS_KEY)

    def backup_winhttp(self) -> BackupItem:
        """备份 winhttp 代理设置（文本）。"""
        res = run(["netsh", "winhttp", "show", "proxy"], timeout=10)
        self.logger.command(res)
        dest = os.path.join(self._sub("text"), "winhttp_proxy.txt")
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(res.output)
        self.write_manifest()
        return self.add(BackupItem("winhttp_proxy", "file", "WinHTTP 代理设置", self._rel(dest), "winhttp"))

    def snapshot_command(self, item_id: str, desc: str, args: List[str], filename: str,
                         timeout: float = 20.0) -> BackupItem:
        """把某条命令的输出存为快照（只读，用于人工比对）。"""
        res = run(args, timeout=timeout)
        dest = os.path.join(self._sub("text"), filename)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(f"# {desc}\n# 命令: {' '.join(args)}\n# 时间: {now_str()}\n\n")
            fh.write(res.output)
        self.write_manifest()
        return self.add(BackupItem(item_id, "file", desc, self._rel(dest), " ".join(args)))

    def backup_ip_config(self) -> BackupItem:
        return self.snapshot_command("ipconfig_all", "IP 配置快照 (ipconfig /all)",
                                     ["ipconfig", "/all"], "ipconfig_all.txt", timeout=20)

    def backup_routes(self) -> BackupItem:
        return self.snapshot_command("route_print", "路由表快照 (route print -4)",
                                     ["route", "print", "-4"], "route_print.txt", timeout=20)

    def backup_netsh_ip_dump(self) -> BackupItem:
        """备份可在紧急时用 `netsh -f` 整体还原的 IPv4 配置脚本。"""
        return self.snapshot_command("netsh_ipv4_dump", "IPv4 配置 dump（可用于整体还原）",
                                     ["netsh", "interface", "ipv4", "dump"], "netsh_ipv4_dump.txt", timeout=20)

    def backup_dns_config(self) -> BackupItem:
        return self.snapshot_command("dns_config", "DNS 服务器配置快照",
                                     ["netsh", "interface", "ipv4", "show", "dnsservers"],
                                     "dns_servers.txt", timeout=15)

    def backup_winsock(self) -> BackupItem:
        return self.snapshot_command("winsock_catalog", "Winsock 目录快照",
                                     ["netsh", "winsock", "show", "catalog"],
                                     "winsock_catalog.txt", timeout=25)

    def backup_mtu(self) -> BackupItem:
        return self.snapshot_command("mtu_config", "各接口 MTU 快照",
                                     ["netsh", "interface", "ipv4", "show", "subinterfaces"],
                                     "mtu.txt", timeout=15)

    def backup_services(self, services: List[str]) -> BackupItem:
        """记录服务的启动类型与当前状态，供回滚（不依赖 sc.exe）。"""
        snapshot = query_services(services)
        data: Dict[str, Any] = {}
        for svc in services:
            state, start_type = snapshot.get(svc, ("", ""))
            data[svc] = {"state": state, "start_type": start_type}
        dest = os.path.join(self._sub("json"), "services.json")
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        self.write_manifest()
        return self.add(BackupItem("services", "json", "关键服务启动类型快照",
                                   self._rel(dest), "service-snapshot", extra=data))

    def backup_power_management(self, adapter_names: List[str]) -> BackupItem:
        """记录网卡电源管理（允许关闭以省电）状态。"""
        data = {}
        for name in adapter_names:
            res = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                       f"(Get-NetAdapterPowerManagement -Name '{name}' -ErrorAction SilentlyContinue).AllowComputerToTurnOffDevice"],
                       timeout=15)
            val = res.stdout.strip() or "unknown"
            data[name] = val
        dest = os.path.join(self._sub("json"), "power.json")
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        self.write_manifest()
        return self.add(BackupItem("power", "json", "网卡电源管理状态",
                                   self._rel(dest), "powershell", extra=data))

    def backup_firewall(self) -> BackupItem:
        return self.snapshot_command("firewall_config", "防火墙配置快照",
                                     ["netsh", "advfirewall", "show", "allprofiles"],
                                     "firewall.txt", timeout=20)

    # ---------------- 一键全套 ----------------

    def backup_all(self, services: List[str], adapter_names: List[str],
                   include_advanced: bool = False) -> List[BackupItem]:
        """修复前推荐执行的全量备份。"""
        self.logger.log("开始备份关键网络配置…", "BACKUP")
        self.backup_hosts()
        self.backup_proxy()
        self.backup_winhttp()
        self.backup_ip_config()
        self.backup_routes()
        self.backup_netsh_ip_dump()
        self.backup_dns_config()
        self.backup_mtu()
        self.backup_services(services)
        if adapter_names:
            try:
                self.backup_power_management(adapter_names)
            except Exception as exc:  # noqa: BLE001
                self.logger.warn(f"电源管理快照失败（可忽略）：{exc}")
        if include_advanced:
            self.backup_winsock()
            self.backup_firewall()
        self.write_manifest()
        self.logger.ok(f"配置备份完成，共 {len(self.items)} 项 -> {self.session}")
        return self.items

    # ---------------- manifest ----------------

    def manifest_path(self) -> str:
        return os.path.join(self.session, "manifest.json")

    def write_manifest(self) -> None:
        payload = {
            "created_at": now_str(),
            "session": self.session,
            "items": [i.to_dict() for i in self.items],
        }
        try:
            with open(self.manifest_path(), "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
        except Exception as exc:  # noqa: BLE001
            self.logger.warn(f"写入 manifest 失败：{exc}")

    @staticmethod
    def load_manifest(session_dir: str) -> Dict[str, Any]:
        path = os.path.join(session_dir, "manifest.json")
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def list_sessions(root: str) -> List[str]:
        if not os.path.isdir(root):
            return []
        dirs = [os.path.join(root, d) for d in os.listdir(root)]
        dirs = [d for d in dirs if os.path.isfile(os.path.join(d, "manifest.json"))]
        return sorted(dirs, reverse=True)

    @staticmethod
    def restore(session_dir: str, logger: Optional[Logger] = None) -> List[str]:
        """按 manifest 逐项还原；返回失败说明列表。"""
        log = logger or Logger()
        data = BackupManager.load_manifest(session_dir)
        problems: List[str] = []
        for raw in data.get("items", []):
            item = BackupItem.from_dict(raw)
            backup_path = os.path.join(session_dir, item.backup) if item.backup else ""
            try:
                if item.kind == "file" and backup_path and os.path.exists(backup_path):
                    # 快照类（只读存档）不回写，仅还原真正的配置文件
                    if item.id in ("hosts",):
                        shutil.copy2(backup_path, item.target)
                        log.ok(f"已还原 {item.desc} -> {item.target}")
                    else:
                        log.log(f"跳过只读快照项：{item.desc}")
                elif item.kind == "regjson" and backup_path and os.path.exists(backup_path):
                    with open(backup_path, "r", encoding="utf-8") as fh:
                        blob = json.load(fh)
                    fails = reg_import_key(blob.get("hive", "HKCU"),
                                           blob.get("subkey", ""),
                                           blob.get("data") or {})
                    if fails:
                        problems.extend(fails[:5])
                        log.warn(f"注册表还原存在 {len(fails)} 项失败：{item.desc}")
                    else:
                        log.ok(f"已还原注册表：{item.desc}")
                elif item.kind == "reg" and backup_path and os.path.exists(backup_path):
                    # 兼容早期版本的 reg 文件备份
                    res = run(["reg", "import", backup_path], timeout=20)
                    log.command(res)
                    if not res.ok:
                        problems.append(f"{item.desc} 还原失败：{res.output.strip()[:120]}")
                    else:
                        log.ok(f"已还原注册表：{item.desc}")
                elif item.kind == "json" and item.id == "services":
                    for svc, info in (item.extra or {}).items():
                        st = (info or {}).get("start_type", "")
                        if not st:
                            continue
                        ok = restore_service_start_type(svc, st)
                        (log.ok if ok else log.warn)(
                            f"服务 {svc} 启动类型恢复为 {st}：{'成功' if ok else '失败'}")
                elif item.kind == "nil":
                    log.warn(f"{item.desc}：备份时不存在，跳过")
            except Exception as exc:  # noqa: BLE001
                problems.append(f"{item.desc} 还原异常：{exc}")
        log.ok("回滚流程结束")
        return problems
