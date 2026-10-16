# -*- coding: utf-8 -*-
"""命令行界面：在任意 Windows 终端里可用的无界面模式。

用法示例：
    NetDoctor.exe                        # 打开图形界面（默认）
    NetDoctor.exe --quick                # 快速体检：秒级判定网络是否正常、断在哪一环
    NetDoctor.exe --scan                 # 只扫描并打印诊断结果
    NetDoctor.exe --fix                  # 扫描后询问是否修复
    NetDoctor.exe --fix --auto           # 全自动修复（不询问）
    NetDoctor.exe --json -o out.json     # 输出 JSON 结果
    NetDoctor.exe --restore              # 回滚最近一次修复
    NetDoctor.exe --restore 20261016-193000
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__, flow, report as report_mod, scanner
from .backup import BackupManager
from .fixers import ACTIONS
from .models import HealthLevel, Severity
from .util import Logger, app_dir, ensure_dir, is_admin, relaunch_as_admin

# ANSI 颜色
_R = "\033[0m"
_B = "\033[1m"
_RED = "\033[31m"
_GRN = "\033[32m"
_YEL = "\033[33m"
_BLU = "\033[34m"
_CYA = "\033[36m"
_GRY = "\033[90m"


def _enable_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7))
    except Exception:
        return False


def _configure_output() -> None:
    """决定控制台输出编码。

    背景：PyInstaller 打包后的程序会忽略 PYTHONUTF8 / PYTHONIOENCODING，
    在 MSYS/Git Bash 这类 UTF-8 终端下会把中文输出成 GBK 字节导致乱码。
    规则：
      · 终端明确是 UTF-8（MSYSTEM / LANG 含 UTF-8）或输出被重定向 -> 用 UTF-8
      · 原生 Windows 控制台（GBK 代码页）                          -> 保持系统编码
    """
    if os.name != "nt":
        return
    hint = " ".join(
        os.environ.get(k, "") for k in ("MSYSTEM", "LANG", "LC_ALL", "LC_CTYPE", "TERM")
    ).upper()
    wants_utf8 = ("UTF-8" in hint) or ("UTF8" in hint) or os.environ.get("PYTHONUTF8") == "1"
    try:
        is_tty = bool(sys.stdout.isatty())
    except Exception:
        is_tty = False
    if not (wants_utf8 or not is_tty):
        return
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass


_SEV_STYLE = {
    Severity.CRITICAL: (_RED + _B, "严重"),
    Severity.HIGH: (_RED, "高"),
    Severity.MEDIUM: (_YEL, "中"),
    Severity.LOW: (_GRN, "低"),
    Severity.INFO: (_GRY, "提示"),
}

_LEVEL_STYLE = {
    HealthLevel.NORMAL: _GRN + _B,
    HealthLevel.RISK: _YEL + _B,
    HealthLevel.LIMITED: _YEL + _B,
    HealthLevel.DOWN: _RED + _B,
}


def _p(text: str = "") -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("utf-8", "replace").decode("utf-8", "replace"))


def _hr(ch: str = "-", n: int = 66) -> None:
    _p(_GRY + ch * n + _R)


# --------------------------------------------------------------------------
# 参数
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="NetDoctor",
        description="断网急救箱 —— 自动排查并修复 Windows 断网原因",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--scan", action="store_true", help="只扫描，不修复")
    p.add_argument("--quick", action="store_true",
                   help="快速体检：只判定「网络是否正常、断在哪一环」，秒级出结论")
    p.add_argument("--fix", action="store_true", help="扫描后进入修复流程")
    p.add_argument("--auto", action="store_true", help="配合 --fix：不询问，直接修复全部可自动修复项")
    p.add_argument("--advanced", action="store_true", help="允许执行进阶修复（协议栈/防火墙重置，需重启）")
    p.add_argument("--no-backup", action="store_true", help="跳过配置备份（不推荐）")
    p.add_argument("--fast", action="store_true", help="快速模式：跳过较慢的深度检测项")
    p.add_argument("--json", action="store_true", help="以 JSON 输出结果（便于脚本消费）")
    p.add_argument("-o", "--out", default="", help="JSON 输出路径（配合 --json）")
    p.add_argument("--report-dir", default="", help="诊断报告输出目录")
    p.add_argument("--restore", nargs="?", const="__last__", default="",
                   help="回滚配置：不带值=最近一次，或指定备份会话目录名")
    p.add_argument("--gui", action="store_true", help="强制打开图形界面")
    p.add_argument("--version", action="version", version=f"NetDoctor {__version__}")
    return p


# --------------------------------------------------------------------------
# 打印
# --------------------------------------------------------------------------

def print_verdict(rep) -> None:
    """体检判定：网络是否正常 / 断在哪一环 / 这种形态怎么处理。"""
    v = getattr(rep, "verdict", None)
    _p()
    _hr("=")
    if v is None:
        _p(f"{_B}网络状态{_R}：" + (f"{_GRN}已连通{_R}" if rep.online else f"{_RED}不可用{_R}"))
        _hr("=")
        return

    color = _LEVEL_STYLE.get(v.level, _B)
    _p(f"{color}【{v.level.label}】{_R}{_B}{v.headline}{_R}")
    _hr("=")
    if v.scope and v.scope != "—":
        _p(f"  {_B}故障范围：{_R}{v.scope}")
    if v.affects_bad:
        _p(f"  {_RED}已受影响：{_R}" + "、".join(v.affects_bad))
    if v.affects_ok:
        _p(f"  {_GRN}仍然可用：{_R}" + "、".join(v.affects_ok))
    if v.detail:
        _p(f"  {_GRY}判定依据：{v.detail}{_R}")
    if v.steps and not v.healthy:
        _p(f"  {_B}处理步骤：{_R}")
        for ln in v.steps:
            _p(f"    {ln}")
    if v.fix_ids:
        names = "、".join((ACTIONS[x].title if x in ACTIONS else x) for x in v.fix_ids)
        _p(f"  {_CYA}建议自动修复：{_R}{names}")
    if v.need_professional:
        _p(f"  {_RED}⚠ 本机侧可修项有限，建议联系专业人员或宽带运营商。{_R}")
    _hr("=")


def print_probes(rep) -> None:
    _p()
    _p(f"{_B}【连通性分层检测】{_R}")
    if not rep.probes:
        _p(f"  {_GRY}（本次未执行探针）{_R}")
    for p in rep.probes:
        mark = f"{_GRN}通{_R}" if p.ok else f"{_RED}断{_R}"
        lat = p.status_text
        _p(f"  [{mark}] {p.name:<10} {lat:<12} {_GRY}{p.detail}{_R}")


def print_report(rep, show_hint: bool = True) -> None:
    _p()
    _hr("=")
    _p(f"{_B}NetDoctor 断网诊断结果{_R}   {_GRY}{rep.started_at} ~ {rep.finished_at}{_R}")
    _hr("=")
    print_verdict(rep)
    print_probes(rep)

    concerning = rep.concerning
    hints = [f for f in rep.suspicious if f.severity.rank > Severity.MEDIUM.rank]

    _p()
    _p(f"{_B}【疑似原因】{_R}" + (f"  共 {len(concerning)} 条" if concerning else ""))
    if not concerning:
        if rep.healthy:
            _p(f"  {_GRN}未发现影响上网的问题，无需处理。{_R}")
        else:
            _p(f"  {_GRN}未发现明显异常。{_R}")
    for i, f in enumerate(concerning, 1):
        color, label = _SEV_STYLE.get(f.severity, (_GRY, "?"))
        auto = f"{_CYA}[可自动修复]{_R}" if f.fix_id else f"{_GRY}[需手动]{_R}"
        _p(f" {i:>2}. {color}【{label}】{_R}{_B}{f.title}{_R}  {auto}")
        _p(f"     {_GRY}{f.category}·{f.category_name} | {f.id}{_R}")
        for ln in (f.detail or "").splitlines():
            _p(f"     {ln}")
        if f.evidence:
            _p(f"     {_GRY}证据：{f.evidence[:160]}{_R}")
        if show_hint and f.manual_hint:
            _p(f"     {_YEL}手动修复：{_R}")
            for ln in f.manual_hint.splitlines():
                _p(f"       {ln}")
        _p()

    if hints:
        _p(f"{_GRY}【其他提示】（不影响上网，仅供参考）：{len(hints)} 条{_R}")
        for f in hints:
            _p(f"  {_GRY}· {f.title}{_R}")
        _p()

    if rep.info.get("adapters"):
        _p(f"{_B}【网卡概览】{_R}")
        for a in rep.info["adapters"]:
            _p(f"  · {a.get('name')} [{a.get('status')}] "
               f"IP={','.join(a.get('ipv4') or []) or '-'} "
               f"GW={','.join(a.get('gateway') or []) or '-'}")
        _p()


def print_plan(plan: List) -> None:
    _p(f"{_B}【建议修复项】{_R}（共 {len(plan)} 项）")
    for i, f in enumerate(plan, 1):
        color, label = _SEV_STYLE.get(f.severity, (_GRY, "?"))
        _p(f"  {i:>2}. {color}[{label}]{_R} {f.title}")
    _p()


def print_outcomes(outcomes: List) -> None:
    _p(f"{_B}【修复执行结果】{_R}")
    for o in outcomes:
        mark = f"{_GRN}成功{_R}" if o.ok else f"{_RED}失败{_R}"
        rb = f" {_YEL}(需重启){_R}" if o.needs_reboot else ""
        _p(f"  [{mark}]{rb} {o.title}")
        _p(f"        {_GRY}{o.message[:160]}{_R}")
    _p()


def to_json(rep, result=None) -> str:
    payload = {
        "tool": "NetDoctor",
        "version": __version__,
        "scanned_at": rep.started_at,
        "finished_at": rep.finished_at,
        "online": rep.online,
        "health": rep.verdict.level.key if rep.verdict else None,
        "health_label": rep.verdict.level.label if rep.verdict else None,
        "verdict": rep.verdict.to_dict() if rep.verdict else None,
        "admin": is_admin(),
        "info": rep.info,
        "probes": [{"name": p.name, "ok": p.ok, "latency_ms": p.latency_ms, "detail": p.detail}
                   for p in rep.probes],
        "findings": [
            {
                "id": f.id,
                "category": f.category,
                "category_name": f.category_name,
                "severity": f.severity.key,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
                "fix_id": f.fix_id,
                "manual_hint": f.manual_hint,
            }
            for f in rep.suspicious
        ],
        "errors": rep.errors,
    }
    if result is not None:
        payload["repair"] = {
            "backup_session": result.backup_session,
            "success": result.success,
            "need_professional": result.need_professional,
            "verdict": result.verdict,
            "outcomes": [o.to_dict() for o in result.outcomes],
            "remaining": [f.id for f in result.remaining_findings],
        }
    return json.dumps(payload, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def _ask(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        ans = input(prompt + suffix).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if not ans:
        return default
    return ans in ("y", "yes", "是", "1", "true")


def cmd_restore(session: str, logger: Logger) -> int:
    root = os.path.join(app_dir(), "backups")
    if session == "__last__":
        sessions = BackupManager.list_sessions(root)
        if not sessions:
            _p(f"{_RED}没有找到任何备份会话：{root}{_R}")
            return 2
        session_dir = sessions[0]
    else:
        session_dir = session if os.path.isabs(session) else os.path.join(root, session)
    if not os.path.isdir(session_dir):
        _p(f"{_RED}备份会话不存在：{session_dir}{_R}")
        return 2

    _p(f"{_B}即将回滚配置：{_R}{session_dir}")
    if not _ask("确认执行回滚？", default=False):
        _p("已取消。")
        return 1
    problems = BackupManager.restore(session_dir, logger)
    if problems:
        _p(f"{_YEL}回滚存在以下问题：{_R}")
        for p in problems:
            _p("  ! " + p)
        return 3
    _p(f"{_GRN}回滚完成。{_R}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_output()
    _enable_ansi()

    log_dir = ensure_dir(os.path.join(app_dir(), "logs"))
    logger = Logger(os.path.join(log_dir, "netdoctor.log"))

    if args.restore:
        return cmd_restore(args.restore, logger)

    # ---- 快速体检：只判定「网络是否正常、断在哪一环」 ----
    if args.quick:
        rep = scanner.quick_check(logger)
        if args.json:
            text = to_json(rep)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    fh.write(text)
                _p(f"JSON 已写入 {args.out}")
            else:
                _p(text)
            return 0
        _p(f"{_B}{_CYA}NetDoctor 快速体检 v{__version__}{_R}")
        print_verdict(rep)
        print_probes(rep)
        _p(f"{_GRY}如需完整排查（服务/代理/防火墙/路由等 40 余项），请运行 --scan。{_R}")
        return 0

    # ---- 扫描 ----
    if not args.json:
        _p(f"{_B}{_CYA}NetDoctor 断网急救箱 v{__version__}{_R}")
        if not is_admin():
            _p(f"{_YEL}提示：当前不是管理员权限，扫描可以正常进行，但修复动作会失败。{_R}")
            _p(f"{_YEL}      建议用管理员身份运行：右键程序 → 以管理员身份运行{_R}")
        _p()

    rep = scanner.scan(logger, deep=not args.fast)

    result = None

    # ---- 修复 ----
    if args.fix or args.auto:
        plan = flow.plan_fixes(rep, include_advanced=args.advanced)
        manual = flow.manual_only(rep)

        if not args.json:
            print_report(rep, show_hint=not plan)
            if plan:
                print_plan(plan)
            if manual:
                _p(f"{_YEL}另有 {len(manual)} 项需手动处理（见上方指引）。{_R}")
                _p()

        if not plan:
            if args.json:
                _p(to_json(rep))
            else:
                _p(f"{_YEL}没有可自动修复的项目。{_R}")
                if manual:
                    _p("请按上方「手动修复」指引操作。")
            return 0

        go = True
        if not args.auto:
            _p(f"{_B}将先备份网络配置，再执行修复；修复会短暂影响网络。{_R}")
            go = _ask("是否继续？", default=True)
        if not go:
            if args.json:
                _p(to_json(rep))
            else:
                _p("已取消修复。")
            return 1

        if not is_admin():
            _p(f"{_RED}修复需要管理员权限。{_R}")
            _p("请以管理员身份重新打开终端后重试，或运行：")
            _p(f"  {_CYA}{os.path.abspath(sys.argv[0])} --fix --auto{_R}")
            return 4

        if not args.json:
            _p()
            _p(f"{_B}开始修复…{_R}")

        def _progress(stage: str, msg: str) -> None:
            if not args.json:
                _p(f"  {_GRY}[{stage}]{_R} {msg}")

        result = flow.execute(
            rep, plan, logger,
            backup_root=os.path.join(app_dir(), "backups"),
            do_backup=not args.no_backup,
            progress=_progress,
        )

        if not args.json:
            _hr()
            print_outcomes(result.outcomes)
            _hr("=")
            _p(f"{_B}【最终结论】{_R}")
            for ln in result.verdict.splitlines():
                _p("  " + ln)
            if result.backup_session:
                _p()
                _p(f"  配置备份：{result.backup_session}")
                _p(f"  如需回滚：NetDoctor.exe --restore")
            _hr("=")

    # ---- 输出 ----
    if args.json:
        text = to_json(rep, result)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
            _p(f"JSON 已写入 {args.out}")
        else:
            _p(text)
        return 0

    if not (args.fix or args.auto):
        print_report(rep)
        plan = flow.plan_fixes(rep, include_advanced=args.advanced)
        hint_n = sum(1 for f in rep.suspicious if f.severity.rank > Severity.MEDIUM.rank)
        if rep.verdict is not None and rep.verdict.healthy and not rep.concerning:
            tail = (f"（另有 {hint_n} 条提示，可能是你自己的自定义设置）" if hint_n else "")
            _p(f"{_GRN}网络正常，无需修复。{_R}{_GRY}{tail}{_R}")
        elif rep.verdict is not None and rep.verdict.healthy:
            _p(f"{_YEL}当前可以正常上网；上面的隐患项可按需处理。{_R}")
            if plan:
                _p(f"{_CYA}提示：可自动修复 {len(plan)} 项，运行 `NetDoctor.exe --fix` 进入修复流程。{_R}")
        elif plan:
            _p(f"{_CYA}提示：可自动修复 {len(plan)} 项，运行 `NetDoctor.exe --fix` 进入修复流程。{_R}")
        else:
            _p(f"{_YEL}提示：未发现可自动修复项，请按上方「处理步骤 / 手动指引」处理。{_R}")
        if rep.verdict is not None and rep.verdict.need_professional:
            _p(f"{_RED}⚠ 本形态的故障多半不在本机，建议直接联系专业人员或宽带运营商。{_R}")

    # ---- 报告 ----
    out_dir = args.report_dir or os.path.join(app_dir(), "reports")
    txt, htmlp = report_mod.save(
        rep,
        outcomes=result.outcomes if result else None,
        verdict=result.verdict if result else "",
        backups=result.backup_session if result else "",
        out_dir=out_dir,
    )
    _p()
    _p(f"{_GRY}诊断报告已生成：{txt}{_R}")
    _p(f"{_GRY}               {htmlp}{_R}")
    return 0
