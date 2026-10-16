# -*- coding: utf-8 -*-
"""诊断报告生成：纯文本 + 自包含 HTML。"""
from __future__ import annotations

import html
import os
from typing import List, Optional

from .models import Finding, FixOutcome, ProbeResult, ScanReport, Severity
from .util import ensure_dir, now_str, timestamp

_SEV_COLOR = {
    Severity.CRITICAL: "#d32f2f",
    Severity.HIGH: "#e65100",
    Severity.MEDIUM: "#f9a825",
    Severity.LOW: "#388e3c",
    Severity.INFO: "#546e7a",
}


def _sev_label(f: Finding) -> str:
    return f.severity.label


# --------------------------------------------------------------------------
# 文本报告
# --------------------------------------------------------------------------

def _verdict_lines(v) -> List[str]:
    """把判定结论拆成文本行。"""
    L: List[str] = []
    L.append(f"【{v.level.label}】{v.headline}")
    if v.scope and v.scope != "—":
        L.append(f"  故障范围：{v.scope}")
    if v.affects_bad:
        L.append("  已受影响：" + "、".join(v.affects_bad))
    if v.affects_ok:
        L.append("  仍然可用：" + "、".join(v.affects_ok))
    if v.detail:
        L.append(f"  判定依据：{v.detail}")
    if v.steps:
        L.append("  处理步骤：")
        for ln in v.steps:
            L.append("    " + ln)
    if v.fix_ids:
        L.append("  建议自动修复：" + "、".join(v.fix_ids))
    if v.need_professional:
        L.append("  ⚠ 建议联系专业人员或宽带运营商进一步核查。")
    return L


def build_text(report: ScanReport, outcomes: Optional[List[FixOutcome]] = None,
               verdict: str = "", backups: str = "") -> str:
    L: List[str] = []
    add = L.append

    add("=" * 68)
    add("  NetDoctor 断网诊断报告")
    add("=" * 68)
    add(f"生成时间：{now_str()}")
    add(f"扫描时段：{report.started_at} ~ {report.finished_at}")
    v = getattr(report, "verdict", None)
    add(f"体检判定：{v.level.label if v else ('已连通' if report.online else '不可用')}")
    add(f"疑似原因：共 {len(report.suspicious)} 条"
        f"（其中需处理 {len(report.concerning)} 条）")
    add("")

    if v is not None:
        add("-" * 68)
        add("一、体检判定")
        add("-" * 68)
        for ln in _verdict_lines(v):
            add(ln)
        add("")

    add("-" * 68)
    add("二、网络配置概览")
    add("-" * 68)
    add(f"数据来源：{report.info.get('source', '-')}")
    add(f"默认网关：{', '.join(report.info.get('default_gateways') or []) or '（无）'}")
    add(f"DNS 服务器：{', '.join(report.info.get('dns_servers') or []) or '（无）'}")
    for ad in report.info.get("adapters", []):
        add(f"  · [{ad.get('status') or '?'}] {ad.get('name')}  "
            f"IP={','.join(ad.get('ipv4') or []) or '-'}  "
            f"GW={','.join(ad.get('gateway') or []) or '-'}  "
            f"DNS={','.join(ad.get('dns') or []) or '-'}")
    add("")

    add("-" * 68)
    add("三、连通性分层检测")
    add("-" * 68)
    for p in report.probes:
        add(f"  [{'通' if p.ok else '断'}] {p.name:<10} {p.status_text:<12} {p.detail}")
    add("")

    add("-" * 68)
    add("四、疑似原因明细")
    add("-" * 68)
    if not report.suspicious:
        add("  未发现明显异常项。")
    for i, f in enumerate(report.suspicious, 1):
        add(f"{i:>2}. 【{_sev_label(f)}】{f.title}")
        add(f"    分类：{f.category} {f.category_name}    编号：{f.id}")
        for ln in (f.detail or "").splitlines():
            add(f"    说明：{ln}")
        if f.evidence:
            add(f"    证据：{f.evidence[:200]}")
        if f.fix_id:
            add(f"    自动修复：支持（动作 {f.fix_id}）")
        if f.manual_hint:
            add("    手动修复指引：")
            for ln in f.manual_hint.splitlines():
                add(f"      {ln}")
        add("")

    if outcomes:
        add("-" * 68)
        add("五、修复执行记录")
        add("-" * 68)
        for o in outcomes:
            add(f"  [{'成功' if o.ok else '失败'}] {o.title}")
            add(f"        {o.message}")
            if o.needs_reboot:
                add("        ⚠ 需要重启系统后生效")
            for c in o.commands[:6]:
                add(f"        $ {c}")
        add("")

    if verdict:
        add("-" * 68)
        add(("六" if outcomes else "五") + "、修复结论与建议")
        add("-" * 68)
        for ln in verdict.splitlines():
            add("  " + ln)
        add("")
        if backups:
            add(f"  配置备份位置：{backups}")
            add("  如需回滚：运行 NetDoctor，在界面中点击「回滚配置」。")
            add("")

    if report.errors:
        add("-" * 68)
        add("附：执行期间的告警")
        add("-" * 68)
        for e in report.errors:
            add("  ! " + e)

    add("")
    add("=" * 68)
    return "\n".join(L)


# --------------------------------------------------------------------------
# HTML 报告
# --------------------------------------------------------------------------

def build_html(report: ScanReport, outcomes: Optional[List[FixOutcome]] = None,
               verdict: str = "", backups: str = "") -> str:
    def esc(s) -> str:
        return html.escape(str(s or ""))

    rows = []
    for p in report.probes:
        cls = "ok" if p.ok else "bad"
        rows.append(
            f"<tr><td>{esc(p.name)}</td><td class='{cls}'>{esc(p.status_text)}</td>"
            f"<td class='mono'>{esc(p.detail)}</td></tr>"
        )
    probe_html = "\n".join(rows) or "<tr><td colspan='3'>无数据</td></tr>"

    cards = []
    for f in report.suspicious:
        color = _SEV_COLOR.get(f.severity, "#546e7a")
        hint = ""
        if f.manual_hint:
            hint = f"<div class='hint'><b>手动修复指引</b><pre>{esc(f.manual_hint)}</pre></div>"
        auto = ("<span class='tag auto'>可自动修复</span>" if f.fix_id
                else "<span class='tag manual'>需手动处理</span>")
        ev = f"<div class='ev mono'>{esc(f.evidence[:300])}</div>" if f.evidence else ""
        cards.append(f"""
        <div class="card" style="border-left-color:{color}">
          <div class="card-head">
            <span class="sev" style="background:{color}">{esc(f.severity.label)}</span>
            <span class="title">{esc(f.title)}</span>
            <span class="cat">{esc(f.category)} · {esc(f.category_name)}</span>
            {auto}
          </div>
          <div class="detail">{esc(f.detail)}</div>
          {ev}
          {hint}
        </div>""")
    cards_html = "\n".join(cards) or "<p>未发现明显异常项。</p>"

    out_rows = []
    for o in outcomes or []:
        st = "成功" if o.ok else "失败"
        cls = "ok" if o.ok else "bad"
        rb = " ⚠需重启" if o.needs_reboot else ""
        cmds = "".join(f"<div class='mono small'>$ {esc(c)}</div>" for c in o.commands[:6])
        out_rows.append(
            f"<tr><td>{esc(o.title)}</td><td class='{cls}'>{st}{rb}</td>"
            f"<td>{esc(o.message)}</td></tr>"
        )
    out_html = ""
    if out_rows:
        out_html = f"""
        <h2>修复执行记录</h2>
        <table><thead><tr><th>动作</th><th>结果</th><th>说明</th></tr></thead>
        <tbody>{''.join(out_rows)}</tbody></table>"""

    verdict_html = ""
    if verdict:
        verdict_html = f"""
        <h2>结论与建议</h2>
        <div class="verdict {'fail' if not report.online else 'pass'}"><pre>{esc(verdict)}</pre></div>
        {f"<p class='mono small'>配置备份：{esc(backups)}</p>" if backups else ""}"""

    err_html = ""
    if report.errors:
        err_html = ("<h2>执行告警</h2><ul>"
                    + "".join(f"<li class='mono small'>{esc(e)}</li>" for e in report.errors)
                    + "</ul>")

    v = getattr(report, "verdict", None)
    hero_html = ""
    if v is not None:
        color = v.level.color
        bad = "".join(f"<span class='chip bad'>{esc(x)}</span>" for x in v.affects_bad) or "—"
        good = "".join(f"<span class='chip ok'>{esc(x)}</span>" for x in v.affects_ok) or "—"
        steps = "".join(f"<li>{esc(s)}</li>" for s in v.steps)
        hero_html = f"""
  <div class="hero" style="border-left-color:{color}">
    <div class="hero-top">
      <span class="hero-level" style="background:{color}">{esc(v.level.label)}</span>
      <span class="hero-fault">{esc(v.fault_label)}</span>
    </div>
    <p class="hero-head">{esc(v.headline)}</p>
    <table class="kv">
      <tr><th>故障范围</th><td>{esc(v.scope)}</td></tr>
      <tr><th>已受影响</th><td>{bad}</td></tr>
      <tr><th>仍然可用</th><td>{good}</td></tr>
      <tr><th>判定依据</th><td class="mono small">{esc(v.detail)}</td></tr>
    </table>
    {f'<div class="steps"><b>处理步骤</b><ol>{steps}</ol></div>' if steps else ''}
    {'<div class="warnbox">⚠ 本形态的故障多半不在本机，建议联系专业人员或宽带运营商进一步核查。</div>'
     if v.need_professional else ''}
  </div>"""

    state_label = v.level.label if v is not None else ("已连通" if report.online else "不可用")
    state_color = v.level.color if v is not None else ("#2e7d32" if report.online else "#c62828")

    ad_rows = "".join(
        f"<tr><td>{esc(a.get('name'))}</td><td>{esc(a.get('status'))}</td>"
        f"<td class='mono'>{esc(', '.join(a.get('ipv4') or []) or '-')}</td>"
        f"<td class='mono'>{esc(', '.join(a.get('dns') or []) or '-')}</td></tr>"
        for a in report.info.get("adapters", [])
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetDoctor 断网诊断报告</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:32px 20px 64px; background:#f5f7fa; color:#1f2933;
         font:14px/1.7 "Microsoft YaHei","PingFang SC",system-ui,sans-serif; }}
  .wrap {{ max-width:960px; margin:0 auto; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  h2 {{ font-size:16px; margin:32px 0 12px; padding-left:10px; border-left:3px solid #2563eb; }}
  .sub {{ color:#66788a; font-size:13px; margin-bottom:20px; }}
  .pill {{ display:inline-block; padding:2px 12px; border-radius:999px; font-size:12px;
           font-weight:600; color:#fff; margin-right:8px; }}
  .stats {{ display:flex; gap:12px; flex-wrap:wrap; margin:16px 0 8px; }}
  .stat {{ background:#fff; border-radius:10px; padding:12px 18px; min-width:130px;
           box-shadow:0 1px 3px rgba(16,42,67,.08); }}
  .stat b {{ display:block; font-size:20px; }}
  .stat span {{ color:#66788a; font-size:12px; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:10px;
           overflow:hidden; box-shadow:0 1px 3px rgba(16,42,67,.08); }}
  th,td {{ padding:9px 12px; text-align:left; border-bottom:1px solid #eef2f6; font-size:13px;
           vertical-align:top; }}
  th {{ background:#eef2f7; font-weight:600; color:#33475b; }}
  tr:last-child td {{ border-bottom:none; }}
  .ok {{ color:#2e7d32; font-weight:600; }}
  .bad {{ color:#c62828; font-weight:600; }}
  .mono {{ font-family:Consolas,Menlo,monospace; }}
  .small {{ font-size:12px; color:#5b6b7c; }}
  .card {{ background:#fff; border-left:4px solid #999; border-radius:8px; padding:14px 16px;
           margin-bottom:12px; box-shadow:0 1px 3px rgba(16,42,67,.07); }}
  .card-head {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:6px; }}
  .card-head .title {{ font-weight:600; font-size:14.5px; }}
  .card-head .cat {{ color:#7b8a99; font-size:12px; }}
  .sev {{ color:#fff; font-size:11px; padding:1px 8px; border-radius:4px; }}
  .tag {{ font-size:11px; padding:1px 8px; border-radius:4px; }}
  .tag.auto {{ background:#e3f2fd; color:#1565c0; }}
  .tag.manual {{ background:#eceff1; color:#546e7a; }}
  .detail {{ color:#3e4c59; }}
  .ev {{ background:#f7f9fb; border-radius:6px; padding:6px 10px; margin-top:8px;
         color:#5b6b7c; font-size:12px; white-space:pre-wrap; }}
  .hint {{ margin-top:10px; background:#fffdf5; border:1px solid #f2e6c8; border-radius:6px;
           padding:8px 12px; }}
  .hint b {{ font-size:12.5px; color:#8a6d1f; }}
  .hint pre {{ margin:6px 0 0; font-size:12.5px; white-space:pre-wrap; color:#4a4132;
               font-family:inherit; }}
  .verdict {{ background:#fff; border-radius:10px; padding:14px 18px;
              box-shadow:0 1px 3px rgba(16,42,67,.08); border-left:4px solid #999; }}
  .verdict.pass {{ border-left-color:#2e7d32; }}
  .verdict.fail {{ border-left-color:#c62828; }}
  .verdict pre {{ margin:0; white-space:pre-wrap; font-family:inherit; }}
  .hero {{ background:#fff; border-radius:12px; padding:18px 22px; margin:16px 0 8px;
           box-shadow:0 1px 3px rgba(16,42,67,.10); border-left:5px solid #999; }}
  .hero-top {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:8px; }}
  .hero-level {{ color:#fff; font-size:13px; font-weight:700; padding:3px 12px; border-radius:6px; }}
  .hero-fault {{ color:#66788a; font-size:12.5px; }}
  .hero-head {{ margin:0 0 12px; font-size:15px; font-weight:600; line-height:1.6; }}
  .kv {{ width:100%; border-collapse:collapse; background:transparent; box-shadow:none; }}
  .kv th {{ width:88px; background:transparent; color:#7b8a99; font-weight:600; font-size:12.5px;
            border-bottom:1px solid #f0f4f8; padding:6px 10px 6px 0; vertical-align:top; }}
  .kv td {{ border-bottom:1px solid #f0f4f8; padding:6px 0; font-size:13px; }}
  .chip {{ display:inline-block; font-size:12px; padding:1px 8px; border-radius:4px; margin:0 4px 2px 0; }}
  .chip.ok {{ background:#e8f5e9; color:#2e7d32; }}
  .chip.bad {{ background:#ffebee; color:#c62828; }}
  .steps {{ margin-top:12px; background:#f8fafc; border-radius:8px; padding:10px 14px; }}
  .steps b {{ font-size:12.5px; color:#33475b; }}
  .steps ol {{ margin:6px 0 0; padding-left:22px; }}
  .steps li {{ font-size:13px; margin:3px 0; }}
  .warnbox {{ margin-top:12px; background:#fff7e6; border:1px solid #ffe0a3; color:#8a5a00;
              border-radius:8px; padding:8px 12px; font-size:12.5px; }}
  footer {{ margin-top:36px; color:#8b9aa8; font-size:12px; text-align:center; }}
</style></head><body><div class="wrap">
  <h1>NetDoctor 断网诊断报告</h1>
  <div class="sub">生成时间 {esc(now_str())} · 扫描时段 {esc(report.started_at)} ~ {esc(report.finished_at)}</div>
  <div class="stats">
    <div class="stat"><b style="color:{state_color}">{esc(state_label)}</b><span>体检判定</span></div>
    <div class="stat"><b>{len(report.concerning)}</b><span>需处理问题</span></div>
    <div class="stat"><b>{len(report.suspicious)}</b><span>检出条目</span></div>
    <div class="stat"><b>{len(report.probes)}</b><span>检测项</span></div>
  </div>
{hero_html}

  <h2>网络配置概览</h2>
  <table><thead><tr><th>网卡</th><th>状态</th><th>IPv4</th><th>DNS</th></tr></thead>
  <tbody>{ad_rows or "<tr><td colspan='4'>无数据</td></tr>"}</tbody></table>
  <p class="mono small">默认网关：{esc(', '.join(report.info.get('default_gateways') or []) or '（无）')}
     ｜ DNS：{esc(', '.join(report.info.get('dns_servers') or []) or '（无）')}
     ｜ 数据来源：{esc(report.info.get('source', '-'))}</p>

  <h2>连通性分层检测</h2>
  <table><thead><tr><th>层级</th><th>结果</th><th>说明</th></tr></thead>
  <tbody>{probe_html}</tbody></table>

  <h2>疑似原因明细</h2>
  {cards_html}
  {out_html}
  {verdict_html}
  {err_html}

  <footer>由 NetDoctor 自动生成 · 本报告仅包含本机网络配置的只读快照与诊断结论</footer>
</div></body></html>"""


# --------------------------------------------------------------------------
# 落盘
# --------------------------------------------------------------------------

def save(report: ScanReport, outcomes: Optional[List[FixOutcome]] = None,
         verdict: str = "", backups: str = "", out_dir: str = "reports") -> tuple:
    """写出文本与 HTML 报告，返回 (txt_path, html_path)。"""
    ensure_dir(out_dir)
    stamp = timestamp()
    txt_path = os.path.join(out_dir, f"NetDoctor-{stamp}.txt")
    html_path = os.path.join(out_dir, f"NetDoctor-{stamp}.html")

    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(build_text(report, outcomes, verdict, backups))
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(build_html(report, outcomes, verdict, backups))
    return txt_path, html_path
