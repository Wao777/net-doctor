# -*- coding: utf-8 -*-
"""NetDoctor 一键打包脚本。

用法：
    python build/build.py            # 同时产出单文件版与文件夹版
    python build/build.py onefile    # 只出单文件 exe
    python build/build.py onedir     # 只出文件夹版

产物：
    out/dist/onefile/NetDoctor.exe          —— 单文件，拷走即用
    out/dist/onedir/NetDoctor/NetDoctor.exe —— 文件夹版，启动更快、误报更少

说明：
  · 默认打 console 版（CLI 参数需要控制台）；图形模式启动时会自动隐藏控制台窗口。
  · 通过 manifest 申请管理员权限（修复类操作必需），启动时会触发 UAC 提示。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_DIR = os.path.join(ROOT, "build")
OUT_DIR = os.path.join(ROOT, "out", "dist")
WORK_DIR = os.path.join(ROOT, "out", "pybuild")
TRASH_DIR = os.path.join(ROOT, "out", "_trash")
# 单次批量删除超过该数量会被本机环境的保护策略拦下，故超限就不自动清理
PURGE_LIMIT = 50

ENTRY = os.path.join(ROOT, "app.py")
ICON = os.path.join(BUILD_DIR, "netdoctor.ico")
VERSION_FILE = os.path.join(BUILD_DIR, "version_info.txt")

# 明确排除用不到的重型/无关依赖，压缩体积。
# 注意：只排第三方库与用不到的标准库；http / urllib / email / html 等被本工具使用，绝不能排。
EXCLUDES = [
    "numpy", "pandas", "matplotlib", "scipy", "PIL",
    "PyQt5", "PyQt6", "PySide2", "PySide6", "wx",
    "setuptools", "pip", "pkg_resources", "lib2to3", "distutils",
    "pydoc_data", "doctest", "sqlite3", "urllib3", "requests",
    "tkinter.test", "test", "unittest",
]


def ensure_assets() -> None:
    if not os.path.exists(ICON):
        print("[build] 图标不存在，正在生成…")
        subprocess.run([sys.executable, os.path.join(BUILD_DIR, "make_icon.py")], check=True)
    if not os.path.exists(VERSION_FILE):
        raise SystemExit(f"缺少版本信息文件：{VERSION_FILE}")


def _move_aside(path: str, label: str) -> None:
    """把已存在的输出目录移开，而不是删除它。

    onedir 产物包含近千个文件，直接 rmtree 可能触发本机环境的批量删除保护；
    重命名只是元数据操作，既快又安全。
    """
    if not os.path.exists(path):
        return
    os.makedirs(TRASH_DIR, exist_ok=True)
    dest = os.path.join(TRASH_DIR, f"{label}-{time.strftime('%Y%m%d-%H%M%S')}")
    try:
        os.rename(path, dest)
        print(f"[build] 旧 {label} 已移开 -> {dest}")
    except OSError as exc:
        print(f"[build] 移开 {path} 失败（{exc}），跳过")
    _purge_trash()


def _purge_trash() -> None:
    """尽力清理历史垃圾目录。

    注意：onedir 产物含近千个文件，一次性 rmtree 可能触发本机环境的
    批量删除保护（单次 >50 文件即被拦下）。这里先数一遍文件数，
    超过阈值就保留不做删除，由人工/外部命令清理，避免拖垮整个构建。
    """
    if not os.path.isdir(TRASH_DIR):
        return
    total = 0
    for name in os.listdir(TRASH_DIR):
        target = os.path.join(TRASH_DIR, name)
        if os.path.isfile(target):
            total += 1
        else:
            for _root, _dirs, files in os.walk(target):
                total += len(files)
                if total > PURGE_LIMIT:
                    break
        if total > PURGE_LIMIT:
            break
    if total > PURGE_LIMIT:
        print(f"[build] out/_trash 内含约 {total}+ 个文件，跳过自动清理（避免触发批量删除保护）")
        return
    for name in os.listdir(TRASH_DIR):
        target = os.path.join(TRASH_DIR, name)
        try:
            if os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
            else:
                os.remove(target)
        except Exception:
            pass
    try:
        if not os.listdir(TRASH_DIR):
            os.rmdir(TRASH_DIR)
    except Exception:
        pass


def clean(modes) -> None:
    """只移开本次要重建的产物目录，避免把另一种形态的产物一并搬走。"""
    _move_aside(WORK_DIR, "pybuild")
    for mode in modes:
        _move_aside(os.path.join(OUT_DIR, mode), mode)


def build_one(mode: str) -> str:
    dist = os.path.join(OUT_DIR, mode)
    work = os.path.join(WORK_DIR, mode)
    spec_dir = work
    os.makedirs(dist, exist_ok=True)
    os.makedirs(spec_dir, exist_ok=True)

    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", "NetDoctor",
        "--icon", ICON,
        "--version-file", VERSION_FILE,
        "--uac-admin",
        "--console",
        # 图标既要内嵌为 exe 资源（--icon），也要作为数据文件随包分发，
        # 否则运行期 tkinter 无法用 iconbitmap 设置窗口图标。
        "--add-data", f"{ICON}{os.pathsep}assets",
        "--distpath", dist,
        "--workpath", work,
        "--specpath", spec_dir,
        "--paths", ROOT,
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "tkinter.filedialog",
        "--hidden-import", "tkinter.messagebox",
        "--hidden-import", "netdoctor.gui",
        "--hidden-import", "netdoctor.cli",
    ]
    for mod in EXCLUDES:
        args += ["--exclude-module", mod]
    args.append("--onefile" if mode == "onefile" else "--onedir")
    args.append(ENTRY)

    print("[build] " + " ".join(f'"{a}"' if " " in a else a for a in args))
    started = time.time()
    proc = subprocess.run(args, cwd=ROOT)
    if proc.returncode != 0:
        raise SystemExit(f"[build] {mode} 打包失败（退出码 {proc.returncode}）")
    print(f"[build] {mode} 打包完成，用时 {time.time() - started:.1f}s")

    target = os.path.join(dist, "NetDoctor.exe") if mode == "onefile" \
        else os.path.join(dist, "NetDoctor", "NetDoctor.exe")
    if not os.path.exists(target):
        raise SystemExit(f"[build] 未找到产物：{target}")
    size = os.path.getsize(target) / 1024 / 1024
    print(f"[build] 产物：{target}  ({size:.1f} MB)")
    return target


def main(argv) -> int:
    modes = argv or ["onefile", "onedir"]
    modes = [m for m in modes if m in ("onefile", "onedir")] or ["onefile", "onedir"]

    ensure_assets()
    clean(modes)
    results = [build_one(m) for m in modes]

    print("\n===== 打包结果 =====")
    for p in results:
        print("  " + p)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
