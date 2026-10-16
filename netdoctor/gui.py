# -*- coding: utf-8 -*-
"""图形界面（tkinter）：体检判定 → 列全部疑似原因 → 勾选 → 备份修复 → 界面内呈现结论。

界面约定：
  · **结果一律在界面内呈现，不用弹窗**——判定结论、修复结果、回滚结果、报错
    都显示在右上「详情」区和底部状态条里；
  · 仅保留 3 个「确认」对话框（执行修复、进阶二次确认、回滚），因为它们拦的是
    会改动系统的操作，需要用户当下明确同意。

所有耗时操作放在后台线程执行，通过队列回传主线程刷新 UI，界面不卡死。
"""
from __future__ import annotations

import datetime
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional

from . import APP_TITLE, __version__, diagnose, flow, report as report_mod, scanner
from .backup import BackupManager
from .fixers import ACTIONS
from .models import Finding, FixMode, HealthLevel, Severity
from .util import Logger, app_dir, asset_path, ensure_dir, is_admin, relaunch_as_admin

_SEV_FG = {
    Severity.CRITICAL: "#c62828",
    Severity.HIGH: "#e65100",
    Severity.MEDIUM: "#b28704",
    Severity.LOW: "#2e7d32",
    Severity.INFO: "#546e7a",
}

FONT = ("Microsoft YaHei UI", 9)
FONT_B = ("Microsoft YaHei UI", 9, "bold")
FONT_TITLE = ("Microsoft YaHei UI", 13, "bold")
FONT_MONO = ("Consolas", 9)


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1000x730")
        self.minsize(880, 620)
        self._set_window_icon()

        self.report = None                 # type: Optional[object]
        self.result = None                 # type: Optional[object]
        self.plan: List[Finding] = []
        self.checked: set = set()
        self.busy = False
        self.last_report_paths: tuple = ()

        self.q: "queue.Queue[tuple]" = queue.Queue()
        log_dir = ensure_dir(os.path.join(app_dir(), "logs"))
        self.logger = Logger(os.path.join(log_dir, "netdoctor.log"))
        self.logger.bind(self._log_sink)

        self._build_style()
        self._build_ui()
        self.after(120, self._drain_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._welcome()

    # ------------------------------------------------------------------
    # 样式 / 布局
    # ------------------------------------------------------------------

    def _set_window_icon(self) -> None:
        """设置窗口与任务栏图标。

        exe 自身的图标由打包参数 ``--icon`` 内嵌；tkinter 窗口图标需另行指定，
        否则标题栏与任务栏显示的是 Tk 默认羽毛图标。图标文件缺失时静默跳过。
        """
        ico = asset_path("netdoctor.ico")
        if not ico:
            return
        try:
            self.iconbitmap(ico)
        except tk.TclError:
            pass

    def _build_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("TButton", font=FONT, padding=(10, 5))
        style.configure("Accent.TButton", font=FONT_B, padding=(12, 6))
        style.configure("Treeview", font=FONT, rowheight=24)
        style.configure("Treeview.Heading", font=FONT_B)
        style.configure("TLabelframe.Label", font=FONT_B)
        style.configure("TLabel", font=FONT)

    def _build_ui(self) -> None:
        # ---- 顶部标题栏 ----
        head = tk.Frame(self, bg="#1f2d3d", height=62)
        head.pack(fill="x")
        head.pack_propagate(False)
        tk.Label(head, text=f"断网急救箱  NetDoctor v{__version__}",
                 bg="#1f2d3d", fg="#ffffff", font=FONT_TITLE).pack(side="left", padx=16)
        self.lbl_admin = tk.Label(head, text="", bg="#1f2d3d", fg="#8fd3ff", font=FONT)
        self.lbl_admin.pack(side="right", padx=16)

        # ---- 体检判定横幅（回答「当前网络是否正常」） ----
        self.banner = tk.Frame(self, bg="#37474f", height=54)
        self.banner.pack(fill="x")
        self.banner.pack_propagate(False)
        self.lbl_banner_lv = tk.Label(self.banner, text="待体检", bg="#37474f", fg="#ffffff",
                                      font=("Microsoft YaHei UI", 11, "bold"))
        self.lbl_banner_lv.pack(side="left", padx=(16, 10))
        self.lbl_banner_txt = tk.Label(
            self.banner, text="点「开始体检」先判定当前网络是否正常，再自动做完整排查",
            bg="#37474f", fg="#dbe6f0", font=FONT, anchor="w")
        self.lbl_banner_txt.pack(side="left", fill="x", expand=True)
        self.lbl_banner_scope = tk.Label(self.banner, text="", bg="#37474f", fg="#9fb3c8", font=FONT)
        self.lbl_banner_scope.pack(side="right", padx=16)

        # ---- 工具栏 ----
        bar = ttk.Frame(self, padding=(12, 10, 12, 4))
        bar.pack(fill="x")
        self.btn_scan = ttk.Button(bar, text="开始体检", style="Accent.TButton", command=self._start_scan)
        self.btn_scan.pack(side="left")
        self.btn_fix = ttk.Button(bar, text="修复所选问题", command=self._do_fix, state="disabled")
        self.btn_fix.pack(side="left", padx=8)
        self.btn_restore = ttk.Button(bar, text="回滚配置…", command=self._restore_dialog)
        self.btn_restore.pack(side="left", padx=8)
        ttk.Button(bar, text="导出报告", command=self._export_report).pack(side="left", padx=8)
        ttk.Button(bar, text="打开数据目录", command=self._open_data_dir).pack(side="left", padx=8)
        self.btn_elevate = ttk.Button(bar, text="以管理员身份重启", command=self._elevate)
        self.btn_elevate.pack(side="right")

        # ---- 状态条 ----
        stat = ttk.Frame(self, padding=(12, 0, 12, 6))
        stat.pack(fill="x")
        self.lbl_status = ttk.Label(stat, text="就绪", foreground="#37474f")
        self.lbl_status.pack(side="left")
        self.prog = ttk.Progressbar(stat, mode="determinate", length=220, maximum=100)
        self.prog.pack(side="right")

        # ---- 主体：上为问题列表/详情，下为日志 ----
        pane = ttk.Panedwindow(self, orient="vertical")
        pane.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        top = ttk.Panedwindow(pane, orient="horizontal")
        pane.add(top, weight=4)

        # 左：问题列表
        left = ttk.Labelframe(top, text=" 疑似断网原因（勾选后点「修复所选问题」） ")
        cols = ("check", "sev", "cat", "title", "auto")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("check", text="选")
        self.tree.heading("sev", text="级别")
        self.tree.heading("cat", text="分类")
        self.tree.heading("title", text="问题描述")
        self.tree.heading("auto", text="可修复")
        self.tree.column("check", width=38, anchor="center", stretch=False)
        self.tree.column("sev", width=58, anchor="center", stretch=False)
        self.tree.column("cat", width=118, anchor="center", stretch=False)
        self.tree.column("title", width=430, anchor="w")
        self.tree.column("auto", width=76, anchor="center", stretch=False)
        vs = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Button-1>", self._on_click)
        for sev, fg in _SEV_FG.items():
            self.tree.tag_configure(sev.key, foreground=fg)
        top.add(left, weight=3)

        # 右：详情
        right = ttk.Labelframe(top, text=" 问题详情与处理方案 ")
        self.txt_detail = tk.Text(right, wrap="word", font=FONT, padx=10, pady=8,
                                  relief="flat", background="#fbfcfd")
        dvs = ttk.Scrollbar(right, orient="vertical", command=self.txt_detail.yview)
        self.txt_detail.configure(yscrollcommand=dvs.set, state="disabled")
        self.txt_detail.pack(side="left", fill="both", expand=True)
        dvs.pack(side="right", fill="y")
        self.txt_detail.tag_configure("h", font=("Microsoft YaHei UI", 11, "bold"))
        self.txt_detail.tag_configure("k", foreground="#546e7a", font=FONT_B)
        self.txt_detail.tag_configure("v", font=FONT)
        self.txt_detail.tag_configure("warn", foreground="#c62828", font=FONT_B)
        self.txt_detail.tag_configure("ok", foreground="#2e7d32", font=FONT_B)
        self.txt_detail.tag_configure("mono", font=FONT_MONO, foreground="#455a64")
        top.add(right, weight=2)

        # 下：日志
        bottom = ttk.Labelframe(pane, text=" 执行日志 ")
        self.txt_log = tk.Text(bottom, wrap="none", font=FONT_MONO, height=8,
                               relief="flat", background="#fbfcfd")
        lvs = ttk.Scrollbar(bottom, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=lvs.set, state="disabled")
        self.txt_log.pack(side="left", fill="both", expand=True)
        lvs.pack(side="right", fill="y")
        pane.add(bottom, weight=1)

        self._refresh_admin_label()

    # ------------------------------------------------------------------
    # 基础工具
    # ------------------------------------------------------------------

    def _refresh_admin_label(self) -> None:
        if is_admin():
            self.lbl_admin.config(text="● 管理员权限", fg="#7CFC98")
            self.btn_elevate.config(state="disabled")
        else:
            self.lbl_admin.config(text="● 普通权限（修复受限）", fg="#ffd479")
            self.btn_elevate.config(state="normal")

    def _log_sink(self, line: str) -> None:
        self.q.put(("log", line))

    def _set_banner(self, v=None, text: str = "", level: HealthLevel = None) -> None:
        """刷新健康度横幅。"""
        if v is not None:
            level, text = v.level, v.headline
            scope = v.scope if v.scope and v.scope != "—" else ""
        else:
            scope = ""
        color = level.color if level else "#37474f"
        label = level.label if level else "待体检"
        for w in (self.banner, self.lbl_banner_lv, self.lbl_banner_txt, self.lbl_banner_scope):
            w.config(bg=color)
        self.lbl_banner_lv.config(text=label, fg="#ffffff")
        self.lbl_banner_txt.config(text=text or "", fg="#ffffff")
        self.lbl_banner_scope.config(text=scope, fg="#e8f0f8")

    def _post(self, kind: str, payload=None) -> None:
        self.q.put((kind, payload))

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "status":
                    self.lbl_status.config(text=str(payload))
                elif kind == "progress":
                    self.prog.config(value=payload)
                elif kind == "verdict":
                    self._on_quick_verdict(payload)
                elif kind == "scan_done":
                    self._on_scan_done(payload)
                elif kind == "fix_done":
                    self._on_fix_done(payload)
                elif kind == "restore_done":
                    self._on_restore_done(payload)
                elif kind == "error":
                    self.busy = False
                    self._set_buttons(True)
                    self._show_notice("执行失败", str(payload), tag="warn",
                                      status="执行失败：" + str(payload)[:60])
        except queue.Empty:
            pass
        self.after(120, self._drain_queue)

    def _append_log(self, line: str) -> None:
        self.txt_log.config(state="normal")
        self.txt_log.insert("end", line + "\n")
        self.txt_log.see("end")
        if int(self.txt_log.index("end-1c").split(".")[0]) > 2000:
            self.txt_log.delete("1.0", "200.0")
        self.txt_log.config(state="disabled")

    def _set_buttons(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.btn_scan.config(state=state)
        self.btn_restore.config(state=state)
        if enabled:
            self.btn_fix.config(state="normal" if self.checked else "disabled")
        else:
            self.btn_fix.config(state="disabled")

    def _welcome(self) -> None:
        self._set_detail(
            "这里是断网急救箱。\n\n"
            "点左上角「开始体检」，程序会先用分层探针在几秒内给出判定：\n"
            "    当前网络是否正常？不正常的话断在哪一环？（全断 / 只有浏览器上不去 …）\n"
            "判定出来后会自动继续做完整排查，依次检查 10 大类共 40 余项可能导致断网的原因：\n"
            "    A 链路层     B IP 配置     C DNS         D 协议栈\n"
            "    E 代理/VPN   F 系统服务    G 路由        H 防火墙\n"
            "    I 系统环境   J 连通性结论\n\n"
            "扫描全部是只读操作，不会改动你的任何设置。\n"
            "完成后会把所有疑似原因列出来，并按本次故障形态给出对应处理方案；\n"
            "勾选需要处理的项目后点「修复所选问题」，程序会先备份网络配置再执行修复。",
            title="使用说明",
        )

    def _set_detail(self, text: str, title: str = "", tag: str = "v") -> None:
        self.txt_detail.config(state="normal")
        self.txt_detail.delete("1.0", "end")
        if title:
            self.txt_detail.insert("end", title + "\n\n", "h")
        self.txt_detail.insert("end", text, tag)
        self.txt_detail.config(state="disabled")

    def _show_notice(self, title: str, text: str, tag: str = "warn",
                     status: str = "") -> None:
        """把提示 / 错误直接呈现在界面上（本程序不使用任何结果类弹窗）。"""
        if status:
            self.lbl_status.config(text=status)
        self._set_detail(text, title=title, tag=tag)

    # ------------------------------------------------------------------
    # 扫描
    # ------------------------------------------------------------------

    def _start_scan(self) -> None:
        if self.busy:
            return
        self.busy = True
        self._set_buttons(False)
        self.checked.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.prog.config(value=3)
        self.lbl_status.config(text="正在体检：判定当前网络是否正常…")
        self._set_banner(text="正在体检，先用分层探针判定当前网络是否正常…")
        self._set_detail("正在体检…\n\n第一步：分层探针（秒级）判定当前网络是否正常、断在哪一环；\n"
                         "第二步：自动继续完整排查 40 余项。\n"
                         "完全断网的机器大约需要 30~60 秒。", title="体检中")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self) -> None:
        try:
            # 第一步：快速体检 → 先把判定结论送到界面
            quick = scanner.quick_check(self.logger)
            self._post("verdict", quick)
            # 第二步：完整排查
            rep = scanner.scan(self.logger, deep=True)
            if rep.verdict is None:
                rep.verdict = quick.verdict
            self._post("scan_done", rep)
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"扫描失败：{exc}")
            self._post("error", f"扫描失败：{exc}")

    def _on_quick_verdict(self, quick) -> None:
        v = getattr(quick, "verdict", None)
        if v is not None:
            self._set_banner(v)
        self.lbl_status.config(text=f"体检判定：{v.level.label if v else '未知'}　正在继续完整排查…")
        self.prog.config(value=25)
        self._set_detail(self._verdict_text(quick), title="体检判定（完整排查中…）")

    def _verdict_text(self, rep) -> str:
        v = getattr(rep, "verdict", None)
        if v is None:
            return "未能得出判定结论。"
        L = [v.headline, ""]
        if v.scope and v.scope != "—":
            L.append(f"故障范围：{v.scope}")
        if v.affects_bad:
            L.append("已受影响：" + "、".join(v.affects_bad))
        if v.affects_ok:
            L.append("仍然可用：" + "、".join(v.affects_ok))
        if v.detail:
            L.append("")
            L.append("判定依据：")
            L.append("  " + v.detail)
        if v.steps:
            L.append("")
            L.append("处理步骤：")
            L.extend(v.steps)
        if v.fix_ids:
            names = "、".join((ACTIONS[x].title if x in ACTIONS else x) for x in v.fix_ids)
            L.append("")
            L.append(f"建议自动修复：{names}")
        if v.need_professional:
            L.append("")
            L.append("⚠ 本形态的故障多半不在本机，建议联系专业人员或宽带运营商。")
        return "\n".join(L)

    def _on_scan_done(self, rep) -> None:
        self.report = rep
        self.plan = flow.plan_fixes(rep, include_advanced=False)

        # ---- 按故障形态决定默认勾选项（分别处理） ----
        v = getattr(rep, "verdict", None)
        if v is None:
            default_ids = {f.id for f in self.plan}
        elif v.fix_ids:
            default_ids = {f.id for f in rep.suspicious if f.fix_id in v.fix_ids}
        elif v.healthy:
            default_ids = set()          # 网络正常 → 默认不勾任何项
        else:
            default_ids = {f.id for f in self.plan}
        self.checked = default_ids

        for f in rep.suspicious:
            auto = "支持" if f.fix_id else "手动"
            self.tree.insert("", "end", iid=f.id,
                             values=("☑" if f.id in self.checked else "☐",
                                     f.severity.label, f"{f.category} {f.category_name}",
                                     f.title, auto),
                             tags=(f.severity.key,))

        self.busy = False
        self.prog.config(value=100)
        self._set_buttons(True)
        self.btn_fix.config(state="normal" if self.checked else "disabled")

        if v is not None:
            self._set_banner(v)
        n = len(rep.suspicious)
        concerning = len(rep.concerning)
        hints = n - concerning
        if v is not None:
            tail = f"，另有 {hints} 条提示" if hints else ""
            self.lbl_status.config(
                text=f"体检判定：{v.level.label}　|　需处理 {concerning} 项{tail}"
                     f"（已勾选 {len(self.checked)} 项，共检出 {n} 条）")
        else:
            self.lbl_status.config(text=f"扫描完成：发现 {n} 条疑似原因，已勾选 {len(self.checked)} 项")

        # ---- 详情区：展示判定结论（含处理步骤与提示清单） ----
        # 说明：本程序不使用弹窗呈现结果，全部结论都在这里显示；
        #       点击左侧任意一行可切换到该条目的详情与处理方案。
        self._set_detail(self._verdict_text(rep), title="体检判定")

    # ------------------------------------------------------------------
    # 列表交互
    # ------------------------------------------------------------------

    def _on_click(self, event) -> None:
        if self.busy:
            return
        if self.tree.identify("region", event.x, event.y) != "cell":
            return
        if self.tree.identify_column(event.x) != "#1":
            return
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if iid in self.checked:
            self.checked.discard(iid)
            self.tree.set(iid, "check", "☐")
        else:
            self.checked.add(iid)
            self.tree.set(iid, "check", "☑")
        self.btn_fix.config(state="normal" if self.checked else "disabled")
        self.lbl_status.config(text=f"已勾选 {len(self.checked)} 项")

    def _on_select(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel or not self.report:
            return
        fid = sel[0]
        f = next((x for x in self.report.suspicious if x.id == fid), None)
        if not f:
            return
        self._show_finding(f)

    def _show_finding(self, f: Finding) -> None:
        self.txt_detail.config(state="normal")
        self.txt_detail.delete("1.0", "end")
        self.txt_detail.insert("end", f.title + "\n", "h")
        self.txt_detail.insert("end", f"{f.category} · {f.category_name}    "
                                      f"严重度：{f.severity.label}    "
                                      f"编号：{f.id}\n\n", "k")
        self.txt_detail.insert("end", "【问题说明】\n", "k")
        self.txt_detail.insert("end", (f.detail or "-") + "\n\n", "v")
        if f.evidence:
            self.txt_detail.insert("end", "【检测证据】\n", "k")
            self.txt_detail.insert("end", f.evidence[:400] + "\n\n", "mono")
        if f.fix_id:
            act = ACTIONS.get(f.fix_id)
            name = act.title if act else f.fix_id
            tag = "warn" if (act and act.mode == FixMode.ADVANCED) else "ok"
            label = "【自动修复】" if not (act and act.mode == FixMode.ADVANCED) else "【自动修复（进阶·需二次确认）】"
            self.txt_detail.insert("end", label + "\n", tag)
            self.txt_detail.insert("end", f"  {name}\n", "v")
            if act and act.description:
                self.txt_detail.insert("end", f"  {act.description}\n", "v")
            if act and act.needs_reboot:
                self.txt_detail.insert("end", "  ⚠ 执行后需要重启系统才会生效。\n", "warn")
            self.txt_detail.insert("end", "\n")
        else:
            self.txt_detail.insert("end", "【自动修复】\n  本项无法自动修复，请按下方指引手动处理。\n\n", "warn")
        if f.manual_hint:
            self.txt_detail.insert("end", "【手动修复指引】\n", "k")
            self.txt_detail.insert("end", f.manual_hint + "\n", "v")
        self.txt_detail.config(state="disabled")

    # ------------------------------------------------------------------
    # 修复
    # ------------------------------------------------------------------

    def _do_fix(self) -> None:
        if self.busy or not self.report:
            return
        findings = [f for f in self.report.suspicious if f.id in self.checked]
        if not findings:
            self.lbl_status.config(text="请先勾选需要修复的问题（点击列表最左侧「选」列切换）")
            return

        advanced = [f for f in findings
                    if (ACTIONS.get(f.fix_id) if f.fix_id else None)
                    and ACTIONS[f.fix_id].mode == FixMode.ADVANCED]
        reboot_needed = any(
            ACTIONS[f.fix_id].needs_reboot for f in findings
            if f.fix_id and f.fix_id in ACTIONS
        )

        lines = [f"即将处理 {len(findings)} 项问题：", ""]
        for f in findings[:12]:
            lines.append(f"  · [{f.severity.label}] {f.title}")
        if len(findings) > 12:
            lines.append(f"  …… 以及另外 {len(findings) - 12} 项")
        lines += ["", "执行前会自动备份网络配置（hosts、代理、IP 配置、路由、服务启动类型等）。",
                  "修复过程中网络可能短暂中断。"]
        if advanced:
            lines += ["", f"⚠ 其中有 {len(advanced)} 项属于「进阶修复」（协议栈/防火墙重置），"
                          "会清除部分自定义设置，需二次确认。"]
        if reboot_needed:
            lines += ["⚠ 部分操作需要重启系统后才会生效。"]

        if not messagebox.askyesno("确认修复", "\n".join(lines), parent=self):
            return

        if advanced:
            names = "、".join(f.title for f in advanced)
            if not messagebox.askyesno(
                "二次确认（进阶修复）",
                f"以下进阶操作影响面较大：\n\n{names}\n\n"
                "重置协议栈 / 防火墙会清除相关的自定义配置，且需要重启系统。\n"
                "确认继续执行吗？",
                parent=self, icon="warning",
            ):
                return

        self.busy = True
        self._set_buttons(False)
        self.prog.config(value=5)
        self.lbl_status.config(text="正在备份并修复…")
        threading.Thread(target=self._fix_worker, args=(self.report, findings), daemon=True).start()

    def _fix_worker(self, rep, findings) -> None:
        try:
            def progress(stage: str, msg: str) -> None:
                self._post("status", msg)

            res = flow.execute(
                rep, findings, self.logger,
                backup_root=os.path.join(app_dir(), "backups"),
                do_backup=True,
                progress=progress,
            )
            self._post("fix_done", res)
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"修复过程异常：{exc}")
            self._post("error", f"修复过程异常：{exc}")

    def _on_fix_done(self, res) -> None:
        self.result = res
        self.busy = False
        self.prog.config(value=100)
        self._set_buttons(True)

        back = sum(1 for o in res.outcomes if o.ok)
        total = len(res.outcomes)
        self.lbl_status.config(text=f"修复完成：{back}/{total} 项成功，"
                                    f"{'网络已恢复' if res.success else '网络仍未恢复'}")

        # 修复后的最新判定（让顶部横幅反映当前真实状态）
        after_verdict = getattr(res.after or res.before, "verdict", None)
        if after_verdict is not None:
            self._set_banner(after_verdict)
        # 注意：不覆盖 self.report —— 左侧列表仍是修复前的条目，点行要能查到详情；
        #       导出报告时再优先取修复后的报告（见 _export_report）。

        # ---- 结论直接呈现在详情区（不使用弹窗） ----
        ok = res.success
        self.txt_detail.config(state="normal")
        self.txt_detail.delete("1.0", "end")
        self.txt_detail.insert("end",
                               "修复结果：网络已恢复连通\n" if ok else "修复结果：仍未连通\n", "h")
        self.txt_detail.insert("end", res.verdict + "\n\n", "ok" if ok else "warn")
        if res.outcomes:
            self.txt_detail.insert("end", "【动作明细】\n", "k")
            for o in res.outcomes:
                mark = "✔" if o.ok else "✘"
                self.txt_detail.insert("end", f"  {mark} {o.title}\n", "ok" if o.ok else "warn")
                self.txt_detail.insert("end", f"      {o.message[:160]}\n", "mono")
        # 已修好但仍不通 → 给出「该找谁」的兜底说明
        if not ok:
            extra = diagnose.explain_unfixed(after_verdict)
            if extra:
                self.txt_detail.insert("end", "\n【下一步建议】\n", "k")
                self.txt_detail.insert("end", extra + "\n", "v")
        if any(o.needs_reboot for o in res.outcomes):
            self.txt_detail.insert("end",
                                   "\n⚠ 部分操作需要重启系统后才会完全生效，建议重启一次。\n", "warn")

        # 导出报告
        paths = ()
        try:
            paths = report_mod.save(
                res.after or res.before,
                outcomes=res.outcomes,
                verdict=res.verdict,
                backups=res.backup_session,
                out_dir=os.path.join(app_dir(), "reports"),
            )
            self.last_report_paths = paths
        except Exception as exc:  # noqa: BLE001
            self.logger.warn(f"报告生成失败：{exc}")

        if res.backup_session:
            self.txt_detail.insert("end", f"\n【配置备份】\n  {res.backup_session}\n", "k")
            self.txt_detail.insert("end", "  如需撤销本次修复，点上方「回滚配置…」。\n", "v")
        if paths:
            self.txt_detail.insert("end", f"\n【诊断报告】\n  {paths[1]}\n", "k")
        self.txt_detail.config(state="disabled")
        self._set_buttons(True)

    # ------------------------------------------------------------------
    # 回滚
    # ------------------------------------------------------------------

    def _restore_dialog(self) -> None:
        if self.busy:
            return
        root = os.path.join(app_dir(), "backups")
        sessions = BackupManager.list_sessions(root)
        if not sessions:
            self._show_notice("没有备份", f"还没有任何配置备份，暂时无需回滚。\n\n备份目录：\n{root}",
                              tag="v", status="还没有任何配置备份")
            return

        dlg = tk.Toplevel(self)
        dlg.title("选择要回滚的备份")
        dlg.geometry("560x360")
        dlg.transient(self)
        dlg.grab_set()
        ttk.Label(dlg, text="选择一个备份会话，把网络配置恢复到当时的状态：",
                  font=FONT, padding=10).pack(anchor="w")
        lb = tk.Listbox(dlg, font=FONT_MONO, activestyle="dotbox")
        for s in sessions:
            manifest = BackupManager.load_manifest(s)
            lb.insert("end", f"{os.path.basename(s)}   （{manifest.get('created_at', '?')}，"
                             f"{len(manifest.get('items', []))} 项）")
        lb.pack(fill="both", expand=True, padx=10)
        lb.selection_set(0)

        def do_restore() -> None:
            sel = lb.curselection()
            if not sel:
                return
            target = sessions[sel[0]]
            if not messagebox.askyesno(
                "确认回滚",
                f"将把配置还原到：\n{os.path.basename(target)}\n\n"
                "还原内容包括 hosts、系统代理设置、服务启动类型等。\n"
                "确认继续？",
                parent=dlg,
            ):
                return
            dlg.destroy()
            self.busy = True
            self._set_buttons(False)
            self.lbl_status.config(text="正在回滚配置…")
            threading.Thread(target=self._restore_worker, args=(target,), daemon=True).start()

        box = ttk.Frame(dlg, padding=10)
        box.pack(fill="x")
        ttk.Button(box, text="回滚到此备份", command=do_restore).pack(side="right")
        ttk.Button(box, text="取消", command=dlg.destroy).pack(side="right", padx=8)

    def _restore_worker(self, session_dir: str) -> None:
        try:
            problems = BackupManager.restore(session_dir, self.logger)
            self._post("restore_done", problems)
        except Exception as exc:  # noqa: BLE001
            self._post("error", f"回滚失败：{exc}")

    def _on_restore_done(self, problems) -> None:
        self.busy = False
        self._set_buttons(True)
        self.prog.config(value=0)
        self.lbl_status.config(text="回滚完成" + ("（有告警）" if problems else ""))
        if problems:
            self._show_notice("回滚完成（有告警）",
                              "回滚已执行，但有以下问题：\n\n" + "\n".join(problems),
                              tag="warn")
        else:
            self._show_notice("回滚完成",
                              "网络配置已恢复到备份时的状态。\n\n"
                              "建议点「开始体检」重新扫描一次，确认当前状态。",
                              tag="ok")

    # ------------------------------------------------------------------
    # 其它
    # ------------------------------------------------------------------

    def _export_report(self) -> None:
        rep = self.report
        res = self.result
        if not rep:
            self.lbl_status.config(text="请先点「开始体检」执行一次扫描，再导出报告")
            return
        default = os.path.join(ensure_dir(os.path.join(app_dir(), "reports")),
                               f"NetDoctor-{datetime.datetime.now():%Y%m%d-%H%M%S}.html")
        path = filedialog.asksaveasfilename(
            parent=self, title="导出诊断报告", defaultextension=".html",
            initialfile=os.path.basename(default), initialdir=os.path.dirname(default),
            filetypes=[("HTML 报告", "*.html"), ("文本报告", "*.txt"), ("所有文件", "*.*")],
        )
        if not path:
            return
        base = (res.after or rep) if res else rep      # 修复过 → 优先导出修复后的现场
        try:
            if path.lower().endswith(".txt"):
                content = report_mod.build_text(
                    base,
                    outcomes=res.outcomes if res else None,
                    verdict=res.verdict if res else "",
                    backups=res.backup_session if res else "",
                )
            else:
                content = report_mod.build_html(
                    base,
                    outcomes=res.outcomes if res else None,
                    verdict=res.verdict if res else "",
                    backups=res.backup_session if res else "",
                )
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        except Exception as exc:  # noqa: BLE001
            self._show_notice("导出失败", str(exc), tag="warn", status="报告导出失败")
            return
        self.lbl_status.config(text=f"报告已导出：{path}")
        self._open_path(path)

    def _open_data_dir(self) -> None:
        self._open_path(app_dir())

    @staticmethod
    def _open_path(path: str) -> None:
        try:
            if os.path.isdir(path):
                os.startfile(path)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["cmd", "/c", "start", "", path], shell=False)
        except Exception:
            pass

    def _elevate(self) -> None:
        self.logger.log("请求以管理员身份重启…")
        if relaunch_as_admin():
            self._on_close()
        else:
            self._show_notice("提权失败",
                              "未能自动获取管理员权限。\n\n"
                              "请手动操作：右键 NetDoctor.exe → 「以管理员身份运行」。",
                              tag="warn", status="提权失败：请手动以管理员身份运行")

    def _on_close(self) -> None:
        try:
            self.destroy()
        except Exception:
            pass


def hide_console() -> None:
    """图形模式下隐藏附带的控制台窗口（打包为 console 版时仍希望界面干净）。"""
    if os.name != "nt":
        return
    try:
        import ctypes

        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
    except Exception:
        pass


def run() -> int:
    hide_console()
    app = App()
    app.mainloop()
    return 0
