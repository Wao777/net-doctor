# -*- coding: utf-8 -*-
"""NetDoctor 打包入口（PyInstaller 以此为起点）。

开发期也可直接运行：  python app.py --scan
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netdoctor.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
