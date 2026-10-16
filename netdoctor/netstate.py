# -*- coding: utf-8 -*-
"""网络状态采集：把本机网络配置抓成结构化快照。

优先走 PowerShell 的 NetTCPIP 模块（结构化、语言无关），
失败时降级到 netsh 文本解析（兼容更老的系统 / 被精简的 PowerShell）。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .util import Logger, run

PS = "powershell"
_PS_BASE = [
    PS,
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
]

# 一次性采集：网卡 / IP 配置 / 默认路由 / DNS
_PS_SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue';
[Console]::OutputEncoding=[Text.Encoding]::UTF8;
$out=[ordered]@{};
try { $out.adapters=@(Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,MediaConnectionState,LinkSpeed,ifIndex,MacAddress) } catch {}
try { $out.ipif=@(Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias,ifIndex,Dhcp,ConnectionState,NlMtu,ConnectionMetric) } catch {}
try {
  $out.ipcfg=@(Get-NetIPConfiguration | ForEach-Object {
    [ordered]@{
      Alias=$_.InterfaceAlias;
      ifIndex=$_.InterfaceIndex;
      Desc=$_.InterfaceDescription;
      IPv4=@($_.IPv4Address | ForEach-Object { $_.IPAddress });
      Prefix=@($_.IPv4Address | ForEach-Object { $_.PrefixLength });
      GW=@($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop });
      DNS=@(($_.DNSServer | Where-Object {$_.AddressFamily -eq 2}).ServerAddresses)
    }
  })
} catch {}
try { $out.routes=@(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0'} | Select-Object InterfaceAlias,ifIndex,NextHop,RouteMetric,DestinationPrefix) } catch {}
try { $out.dns=@(Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ifIndex,ServerAddresses) } catch {}
try { $out.dnssuffix=(Get-DnsClientGlobalSetting | Select-Object -First 1).SuffixSearchList } catch {}
try { $out.profile=@(Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,IPv4Connectivity,NetworkCategory) } catch {}
$json=$out | ConvertTo-Json -Depth 6 -Compress;
if (-not $json) { $json='{}' }
Write-Output $json
"""


@dataclass
class Adapter:
    """一块网络适配器。"""

    name: str = ""
    desc: str = ""
    status: str = ""            # Up / Disconnected / Disabled / Not Present
    media_state: str = ""       # Connected / Disconnected
    link_speed: str = ""
    ifindex: int = 0
    mac: str = ""
    dhcp: str = ""              # Enabled / Disabled
    connection_state: str = ""  # Connected / Disconnected
    mtu: Optional[int] = None
    metric: Optional[int] = None
    ipv4: List[str] = field(default_factory=list)
    prefix: List[int] = field(default_factory=list)
    gateway: List[str] = field(default_factory=list)
    dns: List[str] = field(default_factory=list)

    @property
    def is_loopback(self) -> bool:
        return "loopback" in self.name.lower() or "loopback" in self.desc.lower()

    @property
    def is_virtual(self) -> bool:
        """常见虚拟/隧道网卡（VPN、加速器、虚拟机），是路由劫持的高发来源。"""
        blob = f"{self.name} {self.desc}".lower()
        keys = (
            "tap", "tun", "vpn", "openvpn", "wireguard", "softether", "tap-windows",
            "vmware", "virtualbox", "hyper-v", "vethernet", "loopback", "npcap",
            "clash", "wintun", "zerotier", "tailscale", "sangfor", "easyconnect",
            "accelerator", "wi-fi direct", "bluetooth", "wan miniport",
        )
        return any(k in blob for k in keys)

    @property
    def is_wireless(self) -> bool:
        blob = f"{self.name} {self.desc}".lower()
        return any(k in blob for k in ("wi-fi", "wifi", "wlan", "wireless", "802.11", "无线"))

    @property
    def up(self) -> bool:
        return self.status.lower() in ("up", "connected") or self.media_state.lower() == "connected"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "desc": self.desc,
            "status": self.status,
            "media_state": self.media_state,
            "link_speed": self.link_speed,
            "ifindex": self.ifindex,
            "mac": self.mac,
            "dhcp": self.dhcp,
            "mtu": self.mtu,
            "ipv4": self.ipv4,
            "gateway": self.gateway,
            "dns": self.dns,
        }


@dataclass
class NetState:
    """一次完整的网络状态快照。"""

    adapters: List[Adapter] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)
    profiles: List[Dict[str, Any]] = field(default_factory=list)
    source: str = "unknown"
    raw: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    # ---------- 便捷查询 ----------

    @property
    def physical_adapters(self) -> List[Adapter]:
        """非环回网卡。"""
        return [a for a in self.adapters if not a.is_loopback]

    @property
    def active_adapters(self) -> List[Adapter]:
        return [a for a in self.adapters if a.up and not a.is_loopback]

    @property
    def default_gateways(self) -> List[str]:
        seen: List[str] = []
        for r in self.routes:
            nh = str(r.get("NextHop") or "").strip()
            if nh and nh not in seen and nh != "0.0.0.0":
                seen.append(nh)
        if not seen:
            for a in self.adapters:
                for gw in a.gateway:
                    if gw and gw not in seen:
                        seen.append(gw)
        return seen

    @property
    def dns_servers(self) -> List[str]:
        seen: List[str] = []
        for a in self.adapters:
            for d in a.dns:
                if d and d not in seen:
                    seen.append(d)
        return seen


# --------------------------------------------------------------------------
# PowerShell 采集
# --------------------------------------------------------------------------

def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _collect_powershell(logger: Optional[Logger] = None, timeout: float = 40.0) -> Optional[NetState]:
    res = run(_PS_BASE + ["-Command", _PS_SCRIPT], timeout=timeout)
    if logger:
        logger.command(res)
    if not res.ok or not res.stdout.strip():
        return None
    text = res.stdout.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start : end + 1])
    except Exception:
        return None
    if not isinstance(data, dict) or not data:
        return None

    state = NetState(source="powershell", raw=data)

    adapters: Dict[str, Adapter] = {}

    def _get_adapter(name: str, ifindex: int = 0) -> Adapter:
        key = name or f"#{ifindex}"
        if key not in adapters:
            adapters[key] = Adapter(name=name, ifindex=ifindex)
        return adapters[key]

    for item in _as_list(data.get("adapters")):
        if not isinstance(item, dict):
            continue
        ad = _get_adapter(str(item.get("Name") or ""), int(item.get("ifIndex") or 0))
        ad.desc = str(item.get("InterfaceDescription") or "")
        ad.status = str(item.get("Status") or "")
        ad.media_state = str(item.get("MediaConnectionState") or "")
        ad.link_speed = str(item.get("LinkSpeed") or "")
        ad.mac = str(item.get("MacAddress") or "")
        ad.ifindex = int(item.get("ifIndex") or ad.ifindex or 0)

    for item in _as_list(data.get("ipif")):
        if not isinstance(item, dict):
            continue
        ad = _get_adapter(str(item.get("InterfaceAlias") or ""), int(item.get("ifIndex") or 0))
        ad.dhcp = str(item.get("Dhcp") or "")
        ad.connection_state = str(item.get("ConnectionState") or "")
        mtu = item.get("NlMtu")
        ad.mtu = int(mtu) if isinstance(mtu, (int, float)) else None
        metric = item.get("ConnectionMetric")
        ad.metric = int(metric) if isinstance(metric, (int, float)) else None

    for item in _as_list(data.get("ipcfg")):
        if not isinstance(item, dict):
            continue
        ad = _get_adapter(str(item.get("Alias") or ""), int(item.get("ifIndex") or 0))
        if not ad.desc:
            ad.desc = str(item.get("Desc") or "")
        ad.ipv4 = [str(x) for x in _as_list(item.get("IPv4")) if x]
        ad.prefix = [int(x) for x in _as_list(item.get("Prefix")) if isinstance(x, (int, float))]
        ad.gateway = [str(x) for x in _as_list(item.get("GW")) if x]
        if item.get("DNS"):
            ad.dns = [str(x) for x in _as_list(item.get("DNS")) if x]

    for item in _as_list(data.get("dns")):
        if not isinstance(item, dict):
            continue
        alias = str(item.get("InterfaceAlias") or "")
        servers = [str(x) for x in _as_list(item.get("ServerAddresses")) if x]
        if alias in adapters and servers:
            adapters[alias].dns = servers
        elif alias and servers:
            _get_adapter(alias).dns = servers

    for key, ad in adapters.items():
        if ad.dns and not ad.ipv4:
            pass

    state.adapters = list(adapters.values())
    state.routes = [r for r in _as_list(data.get("routes")) if isinstance(r, dict)]
    state.profiles = [p for p in _as_list(data.get("profile")) if isinstance(p, dict)]
    return state


# --------------------------------------------------------------------------
# netsh 降级采集
# --------------------------------------------------------------------------

_IFACE_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+?)\s*$")


def _collect_netsh(logger: Optional[Logger] = None) -> NetState:
    state = NetState(source="netsh")
    res = run(["netsh", "interface", "ipv4", "show", "interfaces"], timeout=12)
    if logger:
        logger.command(res)
    if not res.ok:
        state.error = res.output or "netsh 调用失败"
        return state

    adapters: List[Adapter] = []
    for line in res.stdout.splitlines():
        m = _IFACE_RE.match(line)
        if not m:
            continue
        idx, metric, mtu, status, name = m.groups()
        try:
            ad = Adapter(
                name=name.strip(),
                ifindex=int(idx),
                metric=int(metric),
                mtu=int(mtu) if mtu.isdigit() else None,
                status="Up" if status.lower() == "connected" else status,
            )
        except ValueError:
            continue
        adapters.append(ad)
    state.adapters = adapters

    # DNS
    dns_res = run(["netsh", "interface", "ipv4", "show", "dnsservers"], timeout=12)
    if logger:
        logger.command(dns_res)
    current: Optional[Adapter] = None
    for line in dns_res.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        mq = re.search(r'"([^"]+)"', stripped)
        if mq and ("的 DNS" in stripped or "DNS 配置" in stripped or "DNS configuration" in stripped):
            target = mq.group(1)
            current = next((a for a in adapters if a.name == target), None)
            continue
        ip = re.search(r"((?:\d{1,3}\.){3}\d{1,3})", stripped)
        if ip and current is not None:
            current.dns.append(ip.group(1))

    # 默认网关：ipconfig 兜底
    cfg = run(["netsh", "interface", "ipv4", "show", "config"], timeout=12)
    if logger:
        logger.command(cfg)
    gateway_re = re.compile(r"(?:默认网关|Default Gateway)[^\d]*((?:\d{1,3}\.){3}\d{1,3}|无|None|空|blank)?")
    for gw in gateway_re.findall(cfg.stdout):
        if gw and gw not in ("无", "None", "空", "blank"):
            state.raw.setdefault("gateways", []).append(gw)

    return state


def collect(logger: Optional[Logger] = None) -> NetState:
    """采集网络状态；PowerShell 优先，失败降级 netsh。"""
    if logger:
        logger.log("采集网络状态（PowerShell NetTCPIP）…")
    state = _collect_powershell(logger)
    if state and state.adapters:
        if logger:
            logger.ok(f"采集成功：{len(state.adapters)} 块网卡 / {len(state.routes)} 条默认路由")
        return state
    if logger:
        logger.warn("PowerShell 采集不可用，降级为 netsh 文本解析")
    fallback = _collect_netsh(logger)
    if logger and fallback.adapters:
        logger.ok(f"降级采集成功：{len(fallback.adapters)} 块网卡")
    return fallback
