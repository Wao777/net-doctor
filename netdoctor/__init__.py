# -*- coding: utf-8 -*-
"""NetDoctor —— Windows 断网原因自动诊断与修复工具。

设计目标：
  * 只读扫描 -> 汇总疑似原因 -> 弹窗告知 -> 备份 -> 自动修复 -> 复测 -> 兜底建议
  * 单文件可分发，任意 Windows 终端可运行（GUI 与 CLI 双形态）
  * 所有修复动作可回滚，危险动作默认不执行
"""

__version__ = "1.2.0"
__author__ = "NetDoctor"

APP_NAME = "NetDoctor"
APP_CN_NAME = "断网急救箱"
APP_TITLE = f"{APP_CN_NAME} NetDoctor v{__version__}"

# 备份根目录（相对 exe / 项目根）
BACKUP_DIRNAME = "backups"
REPORT_DIRNAME = "reports"
LOG_DIRNAME = "logs"
