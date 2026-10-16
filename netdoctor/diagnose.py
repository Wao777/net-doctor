# -*- coding: utf-8 -*-
"""网络体检判定引擎。

职责：在扫描结果之上给出一个**明确判定**，回答三件事：

  1. 当前网络是否正常？        —— HealthLevel（健康 / 受限 / 全断）
  2. 若不正常，断在哪一环？    —— fault（故障形态：协议栈·链路·内网·外网出口·
                                  域名解析·端口·代理·MTU·时间偏差）
  3. 这种形态该怎么处理？      —— steps / fix_ids（**不同形态分别处理**）

判定依据全部来自分层探针，判定顺序自上而下、命中即归类：

    本机协议栈 → 局域网/链路 → 公网出口 → 域名解析 → 端口/应用层 → 浏览器路径 → 实测缺陷

判定原则（重要）：

  · **健康度只由实测连通性决定**。探针证明能实际上网 → 判为「网络健康」。
  · 配置类检出（hosts 自定义记录、静态 IP、PAC、代理设置、代理环境变量、
    Winsock 条目偏多、网卡节能、多条默认路由等）**一律不压低健康度**——
    它们多半是用户自己的设置或无害残留，实测能上网即说明尚未造成问题；
    这类条目统一以「提示」级呈现，在被测出真实影响时才升级（例如 hosts 记录
    确实造成了解析失败）。
  · 只有**探针直接测到**的缺陷才升级健康度：MTU 分片黑洞、系统时间偏差、
    以及各层连通性失败。

其中「浏览器路径」探针专门用于区分**「只是浏览器上不了网」**与**「全断」**：
它按系统代理（注册表）配置去访问测试站点，若直连 IP/域名都通、唯独经代理不通，
即可确诊为「网络本身正常，但浏览器那条路被失效代理堵死」——这正是"能上QQ打不开网页"的典型成因。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from . import fixids as F
from .models import Finding, HealthLevel, ProbeResult, Severity, Verdict

# ---- 探针名（须与 probes.py 保持一致） ----
P_LOCAL = "本机协议栈"
P_GW = "默认网关"
P_PUB = "公网IP"
P_DNS = "DNS解析"
P_TCP = "TCP 443"
P_HTTP = "HTTP 访问"
P_BROWSE = "浏览器路径"
P_MTU = "MTU 探测"

# 判定用的分层顺序（前一层不通 → 后一层的结论就没有意义）
_LAYER_ORDER = (P_LOCAL, P_GW, P_PUB, P_DNS, P_TCP, P_HTTP, P_BROWSE)


# --------------------------------------------------------------------------
# 各故障形态的固定描述（影响面 / 处理步骤 / 首选修复动作）
# 动态部分（判定依据、分层快照）由 judge() 填充。
# --------------------------------------------------------------------------

_FAULTS: Dict[str, Dict[str, Any]] = {
    "normal": dict(
        level=HealthLevel.NORMAL,
        label="网络正常",
        scope="—",
        headline="网络连接正常，未发现影响上网的问题。",
        ok=["浏览器", "微信 / QQ", "下载与视频"],
        bad=[],
        steps=["无需处理，直接使用即可。"],
        playbook=[],
        professional=False,
    ),
    # ---------------- 完全断网 ----------------
    "stack": dict(
        level=HealthLevel.DOWN,
        label="完全断网 · 本机协议栈异常",
        scope="本机网络协议栈（最内层）",
        headline="本机 TCP/IP 协议栈本身无响应，任何网络操作都不可能成功。",
        ok=[],
        bad=["全部网络功能（含局域网）"],
        steps=[
            "1. 以管理员身份执行「重置 TCP/IP 协议栈」与「重置 Winsock 目录」。",
            "2. 两项都执行完后必须重启电脑，否则不生效。",
            "3. 重启后再体检一次；若依旧不通，多为系统网络组件损坏，建议重装网卡驱动或联系专业人员。",
        ],
        playbook=[F.FIX_TCPIP_RESET, F.FIX_WINSOCK_RESET, F.FIX_ADAPTER_RESTART],
        professional=True,
    ),
    "lan": dict(
        level=HealthLevel.DOWN,
        label="完全断网 · 局域网不通",
        scope="本机 ↔ 路由器（链路层/内网）",
        headline="连默认网关（路由器）都访问不到，故障在网卡、网线或路由器这一环。",
        ok=["本机内部通信"],
        bad=["全部外网访问", "局域网共享与打印"],
        steps=[
            "1. 有线：检查网线两端是否插紧、网口指示灯是否闪烁；无线：确认已连接可用 Wi-Fi。",
            "2. 执行「重新获取 IP 地址」「重启网络适配器」。",
            "3. 重启路由器（拔电 30 秒再插回），或换一根网线 / 换路由器上的另一个 LAN 口。",
            "4. 若换线换口都无效，可能是网卡硬件或路由器端口故障，建议联系专业人员。",
        ],
        playbook=[F.FIX_DHCP_RENEW, F.FIX_ADAPTER_RESTART, F.FIX_ROUTE_REFRESH],
        professional=True,
    ),
    "wan": dict(
        level=HealthLevel.DOWN,
        label="完全断网 · 外网出口不通",
        scope="路由器 ↔ 运营商（宽带出口）",
        headline="局域网是通的，但出不了公网——故障在路由器 WAN 侧或宽带线路。",
        ok=["局域网内设备互访", "路由器管理页面"],
        bad=["全部外网访问"],
        steps=[
            "1. 登录路由器管理页，查看 WAN 口是否获取到 IP 地址、是否显示「已连接」。",
            "2. 重启光猫与路由器（两者都拔电，等 30 秒再插回）。",
            "3. 确认宽带账号是否欠费、是否被运营商停网。",
            "4. 若 WAN 口无地址，或光猫 LOS 灯红色常亮，属线路/运营商问题，请拨打运营商客服报修。",
        ],
        playbook=[F.FIX_DHCP_RENEW, F.FIX_ROUTE_REFRESH],
        professional=True,
    ),
    # ---------------- 能连网但上网受限 ----------------
    "dns": dict(
        level=HealthLevel.LIMITED,
        label="能连网但上网受限 · 域名解析故障",
        scope="DNS 域名解析",
        headline="底层网络是通的，但域名解析不出来——最典型的「能上 QQ，却打不开网页」。",
        ok=["微信 / QQ 等直连 IP 的应用", "网游", "已建立的长连接"],
        bad=["浏览器打不开网页（提示「找不到服务器」「DNS_PROBE_FINISHED_NXDOMAIN」）",
             "所有依赖域名访问的软件"],
        steps=[
            "1. 执行「刷新 DNS 解析缓存」。",
            "2. 执行「DNS 切换为公共 DNS」（223.5.5.5 / 119.29.29.29）。",
            "3. 若 hosts 文件被第三方软件写入过记录，执行「还原 hosts 文件」。",
            "4. 仍不行的，在网卡属性里手动填写 DNS 服务器地址，或重启路由器。",
        ],
        playbook=[F.FIX_DNS_FLUSH, F.FIX_DNS_SET_PUBLIC, F.FIX_HOSTS_RESTORE, F.FIX_DHCP_AUTO],
        professional=False,
    ),
    "port": dict(
        level=HealthLevel.LIMITED,
        label="能连网但上网受限 · 端口/协议被阻断",
        scope="公网可达，但 TCP 443 / HTTP 被拦截",
        headline="能 ping 通公网地址，但 HTTPS(TCP 443) 与网页请求都建不了连接——被中间设备或安全软件拦了。",
        ok=["微信 / QQ 等直连应用"],
        bad=["浏览器 / HTTPS 网站", "系统更新与部分软件联网"],
        steps=[
            "1. 临时退出安全软件、防火墙的「网络防护 / 流量监控」，再试一次。",
            "2. 执行「关闭系统代理与 PAC」「清理代理环境变量」，排除代理劫持。",
            "3. 若在公司/学校网络，可能被上网行为管理设备限制 443 端口，请联系网络管理员。",
            "4. 以上都排除后仍不通，可尝试进阶修复「重置 Windows 防火墙策略」，然后重启。",
        ],
        playbook=[F.FIX_PROXY_DISABLE, F.FIX_ENV_PROXY_CLEAR, F.FIX_ADVFW_RESET],
        professional=False,
    ),
    "proxy-broken": dict(
        level=HealthLevel.LIMITED,
        label="能连网但上网受限 · 浏览器路径被代理堵死",
        scope="系统代理（浏览器等程序的上网出口）",
        headline="网络本身完全正常，但系统代理指向的地址已经失效——浏览器等走代理的程序因此打不开网页。",
        ok=["微信 / QQ、网游等不走系统代理的应用", "命令行直连（ping / nslookup）"],
        bad=["浏览器（Chrome / Edge / IE）", "系统更新、部分走代理的软件"],
        steps=[
            "1. 执行「关闭系统代理与 PAC」（同时清理 WinHTTP 代理与环境变量）。",
            "2. 若你确实需要代理（公司网络 / 代理软件），请先确认代理程序已启动并监听对应端口。",
            "3. 关掉代理后重启浏览器再试；浏览器若装过代理插件，也要一并关闭。",
        ],
        playbook=[F.FIX_PROXY_DISABLE, F.FIX_ENV_PROXY_CLEAR],
        professional=False,
    ),
    "app": dict(
        level=HealthLevel.LIMITED,
        label="能连网但上网受限 · 应用层访问异常",
        scope="HTTP / HTTPS 应用层",
        headline="链路与域名解析都正常，但网页请求拿不到内容——多为代理或安全软件的网页防护所致。",
        ok=["IP 直连类应用"],
        bad=["浏览器访问网页"],
        steps=[
            "1. 执行「关闭系统代理与 PAC」。",
            "2. 检查安全软件的「网页防护 / HTTPS 扫描」功能，临时关闭后重试。",
            "3. 换一个浏览器验证：若其他浏览器正常，问题在该浏览器自身的代理或扩展设置。",
        ],
        playbook=[F.FIX_PROXY_DISABLE, F.FIX_ENV_PROXY_CLEAR, F.FIX_DNS_FLUSH],
        professional=False,
    ),
    "mtu": dict(
        level=HealthLevel.LIMITED,
        label="能连网但上网受限 · 大包被丢弃（MTU 异常）",
        scope="链路 MTU（分片黑洞）",
        headline="小数据包能通、大包被丢——表现为「网页能开，但视频/图片/大文件加载失败或长时间卡住」。",
        ok=["纯文字网页", "小文件传输", "ping 小包"],
        bad=["视频播放", "大文件下载", "图片密集的网页", "VPN / 远程桌面"],
        steps=[
            "1. 执行「MTU 恢复标准值 1500」。",
            "2. 若使用了 VPN、加速器或运营商定制的 PPPoE 拨号，把 MTU 依次下调（1492 → 1454 → 1400）再测。",
            "3. 仍不行的，多为线路侧问题（运营商或中间设备限制），建议联系运营商。",
        ],
        playbook=[F.FIX_MTU_RESET],
        professional=False,
    ),
    "time-skew": dict(
        level=HealthLevel.LIMITED,
        label="能连网但上网受限 · 系统时间偏差",
        scope="系统时间（影响 HTTPS 证书校验）",
        headline="系统时间与网络时间偏差过大，HTTPS 证书校验必然失败，网站会提示「不安全」或直接打不开。",
        ok=["部分 HTTP 网站", "微信 / QQ"],
        bad=["HTTPS 网站（浏览器普遍提示证书错误）", "需要证书校验的软件与登录"],
        steps=[
            "1. 执行「同步系统时间」。",
            "2. 设置 → 时间和语言 → 日期和时间，打开「自动设置时间」并立即同步。",
            "3. 若时间每次开机都跑偏，多为主板 CMOS 电池没电，需要更换电池。",
        ],
        playbook=[F.FIX_TIME_SYNC],
        professional=False,
    ),
    # ---------------- 隐患类 ----------------
    # 说明：hosts 自定义记录、网卡节能、Winsock 条目偏多、多条默认路由等，
    # 都属于「可能是用户自定义设置 / 无害残留」的配置类检出。按判定原则，
    # 只要实测能正常上网，它们就不压低健康度，统一以「提示」级列出
    # （见 _hint_items / _hidden_risk 的注释），因此这里不再单列形态预案。
}


# --------------------------------------------------------------------------
# 工具
# --------------------------------------------------------------------------

def _index(probes: List[ProbeResult]) -> Dict[str, ProbeResult]:
    return {p.name: p for p in probes}


def _layer_snapshot(probes: List[ProbeResult]) -> List[Dict[str, Any]]:
    m = _index(probes)
    out: List[Dict[str, Any]] = []
    for name in _LAYER_ORDER:
        p = m.get(name)
        if p is None:
            continue
        out.append({"name": p.name, "ok": bool(p.ok), "detail": p.detail or "",
                    "latency_ms": p.latency_ms})
    return out


def _fill(v: Verdict, probes: List[ProbeResult], extra: str = "") -> Verdict:
    """补上判决依据与分层快照。"""
    ok = [d["name"] for d in v.layers if d["ok"]]
    bad = [d["name"] for d in v.layers if not d["ok"]]
    parts: List[str] = []
    if ok:
        parts.append("通过：" + "、".join(ok))
    if bad:
        parts.append("不通：" + "、".join(bad))
    v.detail = ("；".join(parts) + ("。" if parts else "")) + extra
    return v


def _make(fault: str, level: Optional[HealthLevel] = None) -> Verdict:
    d = _FAULTS[fault]
    return Verdict(
        level=level or d["level"],
        fault=fault,
        fault_label=d["label"],
        scope=d["scope"],
        headline=d["headline"],
        affects_ok=list(d["ok"]),
        affects_bad=list(d["bad"]),
        steps=list(d["steps"]),
        need_professional=bool(d["professional"]),
    )


def _playbook(fault: str) -> List[str]:
    return list(_FAULTS[fault]["playbook"])


# --------------------------------------------------------------------------
# 主判定
# --------------------------------------------------------------------------

def judge(
    probes: List[ProbeResult],
    findings: Optional[List[Finding]] = None,
    ctx: Optional[Dict[str, Any]] = None,
) -> Verdict:
    """给出网络体检判定。

    probes   : 分层探针结果（见 probes.py）
    findings : 扫描出的疑似原因，用于挑选「该形态下建议执行的修复动作」
    ctx      : 附加环境信息（hosts_count / powersave / time_skew / routes / winsock ...）
    """
    findings = list(findings or [])
    ctx = dict(ctx or {})
    m = _index(probes)

    local = m.get(P_LOCAL)
    gw = m.get(P_GW)
    pub = m.get(P_PUB)
    dns = m.get(P_DNS)
    tcp = m.get(P_TCP)
    http = m.get(P_HTTP)
    browse = m.get(P_BROWSE)
    mtu = m.get(P_MTU)

    def ok(p: Optional[ProbeResult]) -> bool:
        return bool(p is not None and p.ok)

    app_ok = ok(tcp) or ok(http)          # 公网应用层是否可达
    dns_ok = ok(dns)
    pub_ok = ok(pub)

    # ---------- 1. 判定故障形态 ----------
    if not app_ok:
        if local is not None and not local.ok:
            fault = "stack"
        elif gw is not None and not gw.ok and not pub_ok:
            fault = "lan"
        elif pub is not None and not pub.ok:
            fault = "wan"
        elif dns is not None and not dns_ok:
            # 公网 IP 能通、域名解析不了 → 「能上QQ打不开网页」
            fault = "dns"
        else:
            fault = "port"
    elif not dns_ok:
        fault = "dns"
    elif http is not None and not http.ok:
        # 端口能连上、域名也能解析，但网页请求拿不到内容 → 应用层被拦
        fault = "app"
    elif browse is not None and not browse.ok:
        # 直连能通、唯独经系统代理不通 → 只有浏览器上不了网
        fault = "proxy-broken"
    else:
        fault = "normal"

    v = _make(fault)
    v.layers = _layer_snapshot(probes)
    v.online = app_ok
    v.browse_ok = (browse.ok if browse is not None else (True if app_ok else None))

    # ---------- 2. 网络可用时，继续查「实测到的」缺陷 ----------
    if fault == "normal":
        measured = _hidden_risk(probes, ctx)
        if measured:
            v = _make(measured)
            v.layers = _layer_snapshot(probes)
            v.online = True
            v.browse_ok = True

    # ---------- 3. 挑选该形态下建议执行的修复动作 ----------
    v.fix_ids = _pick_fixes(v.fault, findings)

    # ---------- 4. 判定依据 ----------
    extra = ""
    if pub is not None and not pub.ok and (ok(tcp) or ok(http)):
        extra += "（公网 ICMP 不通但网页可访问，可能是路由器屏蔽了 ping，不影响上网）"
    if gw is not None and not gw.ok and pub_ok:
        extra += "（网关不响应 ICMP，属正常现象）"
    if fault == "proxy-broken" and browse is not None:
        extra += "　浏览器路径实测：" + (browse.detail or "")
    if fault == "mtu" and mtu is not None:
        extra += "　" + (mtu.detail or "")
    v = _fill(v, probes, extra)

    # ---------- 5. 提示级条目：实测正常时不压低健康度，只列出备查 ----------
    if v.level.rank <= HealthLevel.RISK.rank:
        hints = _hint_items(findings)
        if hints:
            v.steps = list(v.steps) + [
                "",
                "以下条目仅为提示（可能是你自己的自定义设置或无害残留），"
                "实测上网正常，说明尚未影响网络：",
            ]
            v.steps += [f"  · {f.title}" for f in hints[:8]]
            if len(hints) > 8:
                v.steps.append(f"  · 其余 {len(hints) - 8} 条见下方扫描清单")
            v.detail = (v.detail + "　" if v.detail else "") + \
                f"另检出 {len(hints)} 条提示级信息（不影响上网）。"
    return v


def _hidden_risk(probes: List[ProbeResult], ctx: Dict[str, Any]) -> str:
    """网络可用时，返回**探针直接测到**的缺陷形态；没有则返回 ""。

    只认实测结论（MTU 分片黑洞、系统时间偏差）。其余配置类检出——
    hosts 自定义记录、静态 IP、代理设置、Winsock 条目偏多、网卡节能、
    多条默认路由等——都可能是用户自己的设置或无害残留，实测能上网即说明
    尚未造成问题，一律归入「提示级」（见 _hint_items），不据此降低健康度。
    """
    skew = ctx.get("time_skew")
    if skew is not None and abs(float(skew)) > 300:
        return "time-skew"

    mtu = _index(probes).get(P_MTU)
    if mtu is not None and not mtu.ok:
        return "mtu"
    return ""


def _hint_items(findings: List[Finding]) -> List[Finding]:
    """提示级条目：可能是用户自定义设置，实测正常时只提示、不影响健康度。"""
    return [f for f in findings if f.severity is Severity.INFO]


def _pick_fixes(fault: str, findings: List[Finding]) -> List[str]:
    """该形态下建议执行的自动修复动作。

    规则：优先取「形态预案」中**确实被检出**的项；若一个都没检出，
    则回落到预案里最安全的前两项，供用户按需勾选。
    """
    play = _playbook(fault)
    if not play:
        return []
    detected = {f.fix_id for f in findings if f.fix_id}
    hit = [x for x in play if x in detected]
    if hit:
        return hit
    return play[:2]


# --------------------------------------------------------------------------
# 与修复流程对接：形态 → 复测后仍不通时的兜底说明
# --------------------------------------------------------------------------

def explain_unfixed(verdict: Optional[Verdict]) -> str:
    """给出「已修但仍不通」时针对该形态的进一步建议。"""
    if verdict is None:
        return ""
    if verdict.fault in ("stack", "lan", "wan"):
        return ("本机可修的项目已处理完，故障很可能在硬件或线路上：\n"
                "  · 光猫 / 路由器硬件故障，或 WAN 口未拨号成功；\n"
                "  · 网卡 / 主板 / 网线物理损坏；\n"
                "  · 宽带线路中断、欠费停机，或运营商侧故障；\n"
                "  · 企业网络的准入认证、上网行为管理未通过。\n"
                "建议重启光猫与路由器（拔电 30 秒）；仍不通请联系宽带运营商或专业人员，"
                "并把本工具生成的诊断报告一并提供给对方。")
    if verdict.fault in ("dns", "proxy-broken", "app", "port"):
        return ("本机侧能做的修复已执行完，请按以下顺序继续排查：\n"
                "  · 换一个浏览器 / 换个设备（手机连同一 Wi-Fi）验证是否同样异常；\n"
                "  · 若别的设备正常，问题在本机，可进一步重置浏览器代理插件或安全软件；\n"
                "  · 若别的设备也一样，问题在路由器或网络侧，请联系网络管理员或运营商。")
    if verdict.fault == "mtu":
        return ("把 MTU 依次下调后仍不通，多为线路侧限制，建议联系运营商确认。")
    return ""
