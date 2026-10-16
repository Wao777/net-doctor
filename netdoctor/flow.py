# -*- coding: utf-8 -*-
"""编排层：把「扫描 → 备份 → 修复 → 复测 → 结论」串成一条完整流水线。

对外只暴露两个函数：
    plan_fixes(report)   -> 给出建议修复清单
    execute(...)         -> 执行修复并给出最终结论
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import fixids as F
from . import diagnose, scanner
from .backup import BackupManager
from .fixers import FixContext, ACTIONS, run_fixes
from .models import Finding, FixMode, FixOutcome, ProbeResult, ScanReport, Severity
from .netstate import NetState
from .util import Logger, ensure_dir, run

ProgressFn = Optional[Callable[[str, str], None]]


@dataclass
class FlowResult:
    """一次修复流程的最终结果。"""

    before: ScanReport
    after: Optional[ScanReport] = None
    backup_session: str = ""
    outcomes: List[FixOutcome] = field(default_factory=list)
    selected_findings: List[Finding] = field(default_factory=list)
    remaining_findings: List[Finding] = field(default_factory=list)
    verdict: str = ""
    need_professional: bool = False
    success: bool = False
    report_path: str = ""


# --------------------------------------------------------------------------
# 修复计划
# --------------------------------------------------------------------------

def plan_fixes(report: ScanReport, include_advanced: bool = False) -> List[Finding]:
    """从扫描结果里挑出可自动修复的项（按修复动作去重，保留最高优先级那条）。"""
    by_fix: Dict[str, Finding] = {}
    for f in report.suspicious:
        if not f.fix_id:
            continue
        act = ACTIONS.get(f.fix_id)
        if act is None:
            continue
        if act.mode == FixMode.ADVANCED and not include_advanced:
            continue
        if not act.default_selected:
            continue
        cur = by_fix.get(f.fix_id)
        if cur is None or f.severity.rank < cur.severity.rank:
            by_fix[f.fix_id] = f
    return sorted(by_fix.values(), key=lambda f: f.sort_key)


def manual_only(report: ScanReport) -> List[Finding]:
    return [f for f in report.suspicious if not f.fix_id]


def optional_advanced(report: ScanReport) -> List[Finding]:
    """进阶档候选：默认不勾选，需用户二次确认。"""
    out = []
    for f in report.suspicious:
        if not f.fix_id:
            continue
        act = ACTIONS.get(f.fix_id)
        if act and (act.mode == FixMode.ADVANCED or not act.default_selected):
            out.append(f)
    return out


# --------------------------------------------------------------------------
# 参数合并
# --------------------------------------------------------------------------

def _merge_params(findings: Sequence[Finding], fix_id: str) -> Dict[str, Any]:
    """把同一修复动作涉及的所有 finding 参数合并（网卡名/服务名去重）。"""
    params: Dict[str, Any] = {}
    adapters: List[str] = []
    all_adapters: List[str] = []
    services: List[str] = []
    for f in findings:
        if f.fix_id != fix_id:
            continue
        for name in f.data.get("adapter_names", []) or []:
            if name and name not in adapters:
                adapters.append(name)
        for name in f.data.get("all_adapter_names", []) or []:
            if name and name not in all_adapters:
                all_adapters.append(name)
        for svc in f.data.get("services", []) or []:
            if svc and svc not in services:
                services.append(svc)
    if adapters:
        params["adapter_names"] = adapters
    if all_adapters:
        params["all_adapter_names"] = all_adapters
    if services:
        params["services"] = services
    return params


# --------------------------------------------------------------------------
# 执行
# --------------------------------------------------------------------------

def _notify(progress: ProgressFn, stage: str, message: str) -> None:
    if progress:
        try:
            progress(stage, message)
        except Exception:
            pass


def execute(
    before: ScanReport,
    findings: Sequence[Finding],
    logger: Logger,
    backup_root: str,
    *,
    do_backup: bool = True,
    verify: bool = True,
    progress: ProgressFn = None,
) -> FlowResult:
    """执行修复计划：备份 -> 修复 -> 复测 -> 判定。"""
    result = FlowResult(before=before, selected_findings=list(findings))

    fix_ids: List[str] = []
    for f in findings:
        if f.fix_id and f.fix_id not in fix_ids:
            fix_ids.append(f.fix_id)

    if not fix_ids:
        result.verdict = "所选项目中没有可自动修复的内容，请按「手动修复指引」操作。"
        result.need_professional = bool(
            [f for f in before.suspicious if f.severity.rank <= Severity.HIGH.rank]
        )
        return result

    include_advanced = any(
        (ACTIONS.get(fid) and ACTIONS[fid].mode == FixMode.ADVANCED) for fid in fix_ids
    )

    # ---------- 0. 采集当前状态 ----------
    from . import netstate

    state = netstate.collect(logger)

    # ---------- 1. 备份 ----------
    mgr = BackupManager(backup_root, logger)
    result.backup_session = mgr.session
    if do_backup:
        _notify(progress, "backup", "正在备份网络配置…")
        mgr.backup_all(
            services=[name for _d, name in F.CRITICAL_SERVICES],
            adapter_names=[a.name for a in _real_adapters(state)],
            include_advanced=include_advanced,
        )
    else:
        logger.warn("已跳过备份（用户选择）")

    # ---------- 2. 修复 ----------
    ctxs: Dict[str, FixContext] = {}

    def _ctx_for(fix_id: str) -> FixContext:
        if fix_id not in ctxs:
            ctxs[fix_id] = FixContext(
                state=state,
                backup=mgr,
                logger=logger,
                params=_merge_params(findings, fix_id),
            )
        return ctxs[fix_id]

    total = len(fix_ids)

    def _progress(idx: int, tot: int, fix_id: str) -> None:
        act = ACTIONS.get(fix_id)
        _notify(progress, "fix", f"[{idx}/{tot}] {act.title if act else fix_id}")

    outcomes: List[FixOutcome] = []
    for idx, fix_id in enumerate(fix_ids, 1):
        _progress(idx, total, fix_id)
        outcomes.append(_run_one(fix_id, _ctx_for(fix_id)))
    result.outcomes = outcomes

    reboot_needed = any(o.needs_reboot for o in outcomes)
    if reboot_needed:
        logger.warn("部分修复动作需要重启系统后才生效")

    # ---------- 3. 复测 ----------
    if verify:
        _notify(progress, "verify", "正在复测网络连通性…")
        logger.log("修复后复测网络连通性…", "VERIFY")
        after = scanner.scan(logger, deep=True)
        result.after = after
        result.success = after.online
        result.remaining_findings = after.suspicious
    else:
        result.success = False

    # ---------- 4. 结论 ----------
    result.verdict, result.need_professional = _make_verdict(result, fix_ids, reboot_needed)
    logger.log("结论：" + result.verdict, "VERDICT")
    return result


def _real_adapters(state):
    """物理网卡优先（排除 VPN/虚拟机虚拟网卡）。"""
    out = [a for a in state.physical_adapters if not a.is_virtual]
    return out or state.physical_adapters


def _run_one(fix_id: str, ctx: FixContext) -> FixOutcome:
    from .fixers import run_fix

    return run_fix(fix_id, ctx)


# --------------------------------------------------------------------------
# 结论生成
# --------------------------------------------------------------------------

def _make_verdict(result: FlowResult, fix_ids: List[str], reboot_needed: bool) -> tuple:
    """生成最终结论文案与是否需要专业人员介入。"""
    before_ids = {f.id for f in result.selected_findings}
    after_ids = {f.id for f in (result.remaining_findings or [])}
    still_there = before_ids & after_ids
    fixed = before_ids - after_ids

    if result.after is None:
        failed = [o for o in result.outcomes if not o.ok]
        if failed:
            return (f"以下修复动作执行失败：{'、'.join(o.title for o in failed)}。"
                    "请按手动修复指引处理，或联系专业人员。", True)
        return ("修复动作已执行完毕。已跳过复测，请自行确认网络是否恢复。", False)

    if result.success:
        tip = "（部分修复需重启系统后完全生效，建议重启一次）" if reboot_needed else ""
        if fixed:
            return (f"修复成功，网络已恢复连通。{tip}\n共处理 {len(result.selected_findings)} 个问题。", False)
        return (f"网络当前连通，未发现需要处理的问题。{tip}", False)

    # ---- 仍不通 ----
    ok_fixed = [f for f in result.selected_findings if f.id in fixed]
    not_fixed = [f for f in result.selected_findings if f.id in still_there]

    lines: List[str] = ["复测后网络仍未连通。"]

    if ok_fixed and not not_fixed:
        lines.append(
            "本工具已成功修复检测到的全部已知问题（"
            + "、".join(f.title for f in ok_fixed)
            + "），但网络依旧不通。"
        )
        lines.append(
            "这通常意味着故障不在本机配置层面，可能原因：\n"
            "  · 宽带线路/光猫故障，或运营商侧断网；\n"
            "  · 路由器硬件故障或 WAN 口未拨号成功；\n"
            "  · 网卡/主板硬件故障、网线物理损坏；\n"
            "  · 企业网络的上网行为管理、准入认证未通过。\n"
        )
        lines.append("建议：先重启光猫与路由器（拔电 30 秒），若仍不通，请联系专业人员或宽带运营商核查线路。")
        extra = diagnose.explain_unfixed(getattr(result.after or result.before, "verdict", None))
        if extra:
            lines.append("")
            lines.append(extra)
        return ("\n".join(lines), True)

    if not_fixed:
        lines.append("以下问题未能修复：" + "、".join(f.title for f in not_fixed) + "。")
    if ok_fixed:
        lines.append("已修复：" + "、".join(f.title for f in ok_fixed) + "。")

    failed_out = [o for o in result.outcomes if not o.ok]
    if failed_out:
        lines.append("修复动作执行失败：" + "、".join(o.title for o in failed_out) + "。")

    if reboot_needed:
        lines.append("注意：协议栈重置类操作需要重启系统后才会生效，请重启后再测。")

    lines.append("请按各项「手动修复指引」处理；若仍无法解决，建议联系专业人员进一步判断。")
    need_pro = any(f.severity.rank <= Severity.HIGH.rank for f in not_fixed) or reboot_needed
    return ("\n".join(lines), need_pro)
