# -*- coding: utf-8 -*-
"""连通性探针：分层验证网络是否真的可用。

层次（由内到外）：
  1. 本机协议栈   127.0.0.1
  2. 默认网关     内网出口
  3. 公网 IP      绕过 DNS 直接验证出口
  4. DNS 解析     域名能否解析
  5. DNS 服务器   配置的 DNS 是否可达
  6. TCP 443      端口层能否建连
  7. HTTP(S)      应用层能否取到内容
  8. 浏览器路径   按系统代理设置访问（区分「只有浏览器上不去」与「全断」）
  9. MTU          是否存在分片黑洞
"""
from __future__ import annotations

import re
import socket
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Sequence

from .models import ProbeResult
from .netstate import NetState
from .util import CommandResult, Logger, reg_read, run

# 国内多运营商可达的公共 DNS，兼顾联通/电信/移动
PUBLIC_PING_TARGETS = ["223.5.5.5", "119.29.29.29", "114.114.114.114", "180.76.76.76"]

# DNS 解析与 HTTP 测试域名（多备选，避免单站故障误判）
TEST_DOMAINS = ["www.baidu.com", "www.qq.com", "www.aliyun.com"]

HTTP_TEST_URLS = [
    "http://www.msftconnecttest.com/connecttest.txt",
    "https://www.baidu.com/",
]

_MS_RE = re.compile(r"(\d+)\s*ms", re.IGNORECASE)


def _parse_latency(text: str) -> Optional[float]:
    if "时间<1" in text or "time<1" in text.lower():
        return 0.5
    m = _MS_RE.search(text)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def ping(host: str, timeout_ms: int = 1500, count: int = 1, fragment: bool = False,
         size: int = 32) -> CommandResult:
    """调用系统 ping；fragment=True 时禁止分片（用于 MTU 探测）。"""
    args = ["ping", "-n", str(count), "-w", str(timeout_ms)]
    if fragment:
        args += ["-f", "-l", str(size)]
    args.append(host)
    return run(args, timeout=max(6.0, timeout_ms / 1000.0 * count + 3))


def _ping_result(name: str, host: str, timeout_ms: int = 1500) -> ProbeResult:
    res = ping(host, timeout_ms=timeout_ms)
    ok = res.ok and res.returncode == 0
    latency = _parse_latency(res.output) if ok else None
    detail = host
    return ProbeResult(name=name, ok=ok, latency_ms=latency, detail=detail)


# --------------------------------------------------------------------------
# 各层探针
# --------------------------------------------------------------------------

def probe_local_stack() -> ProbeResult:
    return _ping_result("本机协议栈", "127.0.0.1", timeout_ms=1000)


def probe_gateway(state: NetState, timeout_ms: int = 1500) -> ProbeResult:
    gws = state.default_gateways
    if not gws:
        return ProbeResult("默认网关", False, None, "无默认网关")
    last = None
    for gw in gws:
        last = _ping_result("默认网关", gw, timeout_ms=timeout_ms)
        if last.ok:
            return last
    return last or ProbeResult("默认网关", False, None, "无默认网关")


def probe_public_ip(timeout_ms: int = 1500,
                    targets: Optional[Sequence[str]] = None) -> ProbeResult:
    for target in (targets or PUBLIC_PING_TARGETS):
        r = _ping_result("公网IP", target, timeout_ms=timeout_ms)
        if r.ok:
            return r
    return ProbeResult("公网IP", False, None,
                       "全部公共地址不可达：" + "/".join(targets or PUBLIC_PING_TARGETS))


def probe_dns_resolve(domains: Optional[Sequence[str]] = None) -> ProbeResult:
    for domain in (domains or TEST_DOMAINS):
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET)
            if infos:
                return ProbeResult("DNS解析", True, None, f"{domain} -> {infos[0][4][0]}")
        except Exception:
            continue
    return ProbeResult("DNS解析", False, None,
                       "域名解析全部失败：" + "/".join(domains or TEST_DOMAINS))


def probe_dns_servers(state: NetState) -> List[ProbeResult]:
    results: List[ProbeResult] = []
    for server in state.dns_servers:
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", server):
            continue
        r = _ping_result("DNS服务器", server, timeout_ms=1200)
        r.detail = f"DNS {server}"
        results.append(r)
    return results


def probe_tcp443() -> ProbeResult:
    for domain in TEST_DOMAINS:
        try:
            with socket.create_connection((domain, 443), timeout=3.0):
                return ProbeResult("TCP 443", True, None, f"{domain}:443 建连成功")
        except Exception:
            continue
    return ProbeResult("TCP 443", False, None, "443 端口建连全部失败")


def probe_http() -> ProbeResult:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for url in HTTP_TEST_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetDoctor/1.0"})
            with opener.open(req, timeout=6) as resp:
                body = resp.read(256)
                if resp.status < 400 and body:
                    return ProbeResult("HTTP 访问", True, None, f"{url} -> {resp.status}")
        except Exception:
            continue
    return ProbeResult("HTTP 访问", False, None, "HTTP/HTTPS 请求全部失败")


# ---- 系统代理（浏览器真正使用的出口） ----

_INET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def system_proxy_map() -> Dict[str, str]:
    """读取「浏览器实际使用」的系统代理（WinINET 注册表设置）。

    注意：只读注册表，不读 HTTP_PROXY 环境变量——环境变量只影响命令行工具，
    浏览器并不看它。这正是区分「浏览器上不了网」与「整机断网」的关键。
    """
    if reg_read("HKCU", _INET_KEY, "ProxyEnable") not in (1, "1"):
        return {}
    server = str(reg_read("HKCU", _INET_KEY, "ProxyServer") or "").strip()
    if not server:
        return {}
    proxies: Dict[str, str] = {}
    if "=" in server:
        for part in server.split(";"):
            if "=" not in part:
                continue
            scheme, _, addr = part.partition("=")
            scheme, addr = scheme.strip().lower(), addr.strip()
            if scheme in ("http", "https") and addr:
                proxies[scheme] = f"http://{addr}"
    else:
        proxies["http"] = f"http://{server}"
        proxies["https"] = f"http://{server}"
    return {k: v for k, v in proxies.items() if k in ("http", "https")}


def probe_via_system_proxy(urls: Optional[Sequence[str]] = None,
                           timeout: float = 6.0) -> Optional[ProbeResult]:
    """按系统代理设置访问测试站点，判断「浏览器那条路」是否通。

    仅当系统确实配置了代理时返回结果；没有代理则返回 None
    （此时浏览器与直连探针走同一条路，无需单独判定）。
    """
    proxies = system_proxy_map()
    if not proxies:
        return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
    desc = "、".join(f"{k}://{v.split('//', 1)[-1]}" for k, v in proxies.items())
    last = ""
    for url in (urls or HTTP_TEST_URLS):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetDoctor/1.0"})
            with opener.open(req, timeout=timeout) as resp:
                if resp.status < 400:
                    return ProbeResult("浏览器路径", True, None, f"经系统代理 {desc} 访问成功")
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {exc}"
            continue
    return ProbeResult("浏览器路径", False, None,
                       f"经系统代理 {desc} 访问失败（{last[:90]}）")


def probe_mtu(state: NetState, host: Optional[str] = None) -> ProbeResult:
    """用禁止分片的 ping 找最大可用 MTU，检测分片黑洞。"""
    target = host
    if not target:
        gws = state.default_gateways
        target = gws[0] if gws else "223.5.5.5"

    # 标准以太网 MTU 1500 对应 payload 1472
    if ping(target, timeout_ms=1500, fragment=True, size=1472).returncode == 0:
        return ProbeResult("MTU 探测", True, None, f"{target} 支持 1500 MTU")

    low, high = 1200, 1472
    while low < high:
        mid = (low + high + 1) // 2
        if ping(target, timeout_ms=1200, fragment=True, size=mid).returncode == 0:
            low = mid
        else:
            high = mid - 1
    best = low + 28
    if best <= 1300:
        return ProbeResult("MTU 探测", False, None, f"最大可用 MTU 仅约 {best}（正常应为 1500）")
    return ProbeResult("MTU 探测", True, None, f"最大可用 MTU 约 {best}")


# --------------------------------------------------------------------------
# 汇总执行
# --------------------------------------------------------------------------

def run_all(state: NetState, logger: Optional[Logger] = None, deep: bool = True) -> List[ProbeResult]:
    """执行全部探针，返回有序结果。"""
    results: List[ProbeResult] = []

    def step(label: str, fn, *a, **kw):
        if logger:
            logger.log(f"连通性探针：{label} …")
        r = fn(*a, **kw)
        results.append(r)
        if logger:
            (logger.ok if r.ok else logger.warn)(f"{r.name}: {r.status_text}  {r.detail}")
        return r

    step("本机协议栈", probe_local_stack)
    gw = step("默认网关", probe_gateway, state)
    step("公网IP", probe_public_ip)
    step("DNS解析", probe_dns_resolve)
    # 端口与应用层这两层必须测——判定「是否只是浏览器上不去」全靠它们
    step("TCP 443", probe_tcp443)
    step("HTTP 访问", probe_http)
    if deep:
        for r in probe_dns_servers(state):
            results.append(r)
            if logger:
                (logger.ok if r.ok else logger.warn)(f"{r.name}: {r.status_text}  {r.detail}")
        browse = probe_via_system_proxy()
        if browse is not None:
            step("浏览器路径", lambda: browse)
        if gw.ok:
            step("MTU 探测", probe_mtu, state)
    return results


def run_quick(state: NetState, logger: Optional[Logger] = None) -> List[ProbeResult]:
    """快速体检：只跑最能定性的几层，秒级回答「网络是否正常、断在哪一环」。

    刻意跳过慢项（DNS 服务器逐个 ping、MTU 二分探测），用于界面开屏即出结论。
    """
    results: List[ProbeResult] = []

    def step(label: str, fn, *a, **kw):
        if logger:
            logger.log(f"快速体检：{label} …")
        r = fn(*a, **kw)
        results.append(r)
        if logger:
            (logger.ok if r.ok else logger.warn)(f"{r.name}: {r.status_text}  {r.detail}")
        return r

    step("本机协议栈", probe_local_stack)
    step("默认网关", probe_gateway, state, 1200)
    step("公网IP", probe_public_ip, 1200, PUBLIC_PING_TARGETS[:2])
    step("DNS解析", probe_dns_resolve, TEST_DOMAINS[:2])
    step("TCP 443", probe_tcp443)
    step("HTTP 访问", probe_http)
    browse = probe_via_system_proxy(timeout=4.0)
    if browse is not None:
        step("浏览器路径", lambda: browse)
    return results
