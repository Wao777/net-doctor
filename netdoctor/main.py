# -*- coding: utf-8 -*-
"""统一入口：根据启动参数决定进入图形界面还是命令行模式。

  · 无参数（如双击 exe）        -> 图形界面
  · 带 --gui                    -> 强制图形界面
  · 带任何其它参数              -> 命令行模式
"""
from __future__ import annotations

import sys
from typing import List, Optional

_GUI_FLAG = "--gui"


def _wants_gui(argv: List[str]) -> bool:
    if _GUI_FLAG in argv:
        return True
    return not argv


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if _wants_gui(args):
        args = [a for a in args if a != _GUI_FLAG]
        try:
            from .gui import run
        except Exception as exc:  # noqa: BLE001 - 无图形环境时降级到 CLI
            print(f"[NetDoctor] 无法启动图形界面（{exc}），改用命令行模式。")
            print("提示：如在无桌面环境运行，请使用 --scan / --fix 参数。")
            from .cli import main as cli_main

            return cli_main(["--scan"])

        return run()

    from .cli import main as cli_main

    return cli_main(args)
