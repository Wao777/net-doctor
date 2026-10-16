# -*- coding: utf-8 -*-
"""判定引擎离线自测：用构造的探针结果验证各故障形态归类是否正确。

核心原则（v1.2.0 起）：
  **健康度只由实测连通性决定**。配置类检出（hosts 自定义记录、静态 IP、
  代理设置、网卡节能、Winsock 条目偏多等）只要实测能上网，就只做提示，
  不把健康度往下压。
"""
import sys

sys.path.insert(0, ".")
from netdoctor import diagnose as D          # noqa: E402
from netdoctor.models import Finding, ProbeResult, Severity  # noqa: E402

T = lambda n, ok, d="": ProbeResult(n, ok, None, d)  # noqa: E731


def P(local=True, gw=True, pub=True, dns=True, tcp=True, http=True,
      browse=None, mtu=None):
    out = [T("本机协议栈", local), T("默认网关", gw), T("公网IP", pub),
           T("DNS解析", dns), T("TCP 443", tcp), T("HTTP 访问", http)]
    if browse is not None:
        out.append(T("浏览器路径", browse))
    if mtu is not None:
        out.append(T("MTU 探测", mtu))
    return out


HOSTS_INFO = Finding("C.hosts", "C", "DNS", "hosts 文件存在 22 条自定义解析记录",
                     "", Severity.INFO, fix_id="fix.hosts.restore")
POWER_INFO = Finding("I.powersave", "I", "系统环境", "网卡启用了节能断流",
                     "", Severity.INFO, fix_id="fix.powersave.off")

CASES = [
    # ---- 实测正常：配置类检出不上抬健康度 ----
    ("全通 + 无检出", P(), {}, None, "normal", "normal"),
    ("全通 + hosts 22 条（提示级）", P(), {"hosts_count": 22},
     [HOSTS_INFO], "normal", "normal"),
    ("全通 + hosts + 节能（提示级）", P(), {"hosts_count": 22,
                                        "powersave": ["以太网"]},
     [HOSTS_INFO, POWER_INFO], "normal", "normal"),
    ("全通 + 代理正常", P(browse=True), {"proxy_on": True}, None, "normal", "normal"),
    # ---- 实测到缺陷：才降健康度 ----
    ("全通 + 系统代理失效（浏览器路径不通）", P(browse=False),
     {"proxy_on": True}, None, "proxy-broken", "limited"),
    ("全通 + MTU 黑洞", P(mtu=False), {}, None, "mtu", "limited"),
    ("全通 + 时间偏差", P(), {"time_skew": 900}, None, "time-skew", "limited"),
    # ---- 完全断网 / 受限 ----
    ("协议栈不通", P(local=False, gw=False, pub=False, dns=False, tcp=False, http=False),
     {}, None, "stack", "down"),
    ("网关不通", P(gw=False, pub=False, dns=False, tcp=False, http=False),
     {}, None, "lan", "down"),
    ("外网出口不通", P(pub=False, dns=True, tcp=False, http=False),
     {}, None, "wan", "down"),
    ("能上QQ打不开网页（DNS故障）", P(pub=True, dns=False, tcp=False, http=False),
     {}, None, "dns", "limited"),
    ("端口被阻断", P(dns=True, tcp=False, http=False), {}, None, "port", "limited"),
    ("应用层异常", P(dns=True, tcp=True, http=False), {}, None, "app", "limited"),
    # ---- 断网时，配置类检出要正常参与（不能只当提示）----
    ("断网 + 有 C.hosts 记录", P(pub=False, tcp=False, http=False),
     {"hosts_count": 22},
     [Finding("C.hosts", "C", "DNS", "hosts 记录", "", Severity.MEDIUM,
              fix_id="fix.hosts.restore")],
     "wan", "down"),
]

fails = 0
for name, probes, ctx, findings, want_fault, want_level in CASES:
    v = D.judge(probes, findings or [], ctx)
    ok = (v.fault == want_fault) and (v.level.key == want_level)
    if not ok:
        fails += 1
    print(f"{'PASS' if ok else 'FAIL'}  {name:<30} -> {v.fault:<13} {v.level.key:<8}"
          f" (期望 {want_fault}/{want_level})  修复项={v.fix_ids}")

# ---- 提示级条目要被写进结论，但不得影响健康度 ----
v = D.judge(P(), [HOSTS_INFO], {"hosts_count": 22})
joined = "\n".join(v.steps)
checks = [
    ("实测正常时健康度为 normal", v.level.key == "normal"),
    ("实测正常时不勾选任何修复项", v.fix_ids == []),
    ("提示级条目写进了结论", "hosts" in joined),
    ("判定依据标注了提示条数", "提示级信息" in v.detail),
]
for label, ok in checks:
    if not ok:
        fails += 1
    print(f"{'PASS' if ok else 'FAIL'}  {label}")

# ---- 修复项挑选：DNS 故障时若已检出 hosts 问题，应优先勾选该动作 ----
v = D.judge(P(pub=True, dns=False, tcp=False, http=False),
            [Finding("C.hosts", "C", "DNS", "hosts 记录", "", Severity.MEDIUM,
                     fix_id="fix.hosts.restore")], {"hosts_count": 22})
print("\nDNS 故障 + 检出 hosts：修复项 =", v.fix_ids)
print("结论：", "全部通过" if fails == 0 else f"{fails} 项不符合预期")
