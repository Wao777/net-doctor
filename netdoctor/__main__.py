# -*- coding: utf-8 -*-
"""允许 `python -m netdoctor` 直接运行。"""
from __future__ import annotations

import sys

from .main import main

if __name__ == "__main__":
    sys.exit(main())
