# -*- coding: utf-8 -*-
"""生成 NetDoctor 图标（icon.ico）。

纯标准库实现：直接构造 ICO（BMP 格式，多尺寸），无需 Pillow。
用法：python build/make_icon.py [输出路径]
"""
from __future__ import annotations

import math
import os
import struct
import sys

SIZES = [16, 24, 32, 48, 64, 128, 256]

BG_TOP = (0x1B, 0x4F, 0x8A)      # 深蓝
BG_BOTTOM = (0x0E, 0x7A, 0x9B)   # 青蓝
ARC = (0xFF, 0xFF, 0xFF)
DOT = (0xFF, 0xD5, 0x4F)         # 琥珀色圆点
BADGE = (0xE5, 0x39, 0x35)       # 红色"故障"标


def _blend(a, b, t):
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def _render(size: int) -> list:
    """渲染一张 size×size 的 RGBA 像素表（自下而上，BMP 约定）。"""
    cx, cy = size / 2.0, size / 2.0
    radius = size * 0.46
    # Wi-Fi 弧线圆心偏下，越靠外的弧越短
    arc_cx, arc_cy = size / 2.0, size * 0.80
    dot_r = max(1.0, size * 0.058)
    stroke = max(1.0, size * 0.085)

    arcs = [(0.34, 0.30), (0.58, 0.34), (0.82, 0.38)]  # (半径比例, 张角半宽比例)
    pixels = []
    for y in range(size):
        row = []
        for x in range(size):
            px, py = x + 0.5, y + 0.5
            r = math.hypot(px - cx, py - cy)
            if r > radius:
                row.append((0, 0, 0, 0))
                continue
            # 底色：上下渐变
            t = py / size
            base = _blend(BG_TOP, BG_BOTTOM, t)
            alpha = 255
            # 边缘抗锯齿
            if r > radius - 1.0:
                alpha = int(255 * max(0.0, radius - r))
            color = base

            # --- Wi-Fi 弧线 ---
            dx, dy = px - arc_cx, py - arc_cy
            dist = math.hypot(dx, dy)
            ang = math.degrees(math.atan2(dy, dx))  # -180..180，向上为 -90
            for rr, half in arcs:
                target = size * rr
                if abs(dist - target) <= stroke / 2.0:
                    # 只画朝上的扇形
                    if -90 - half * 90 <= ang <= -90 + half * 90:
                        color = ARC
                        break
            # --- 圆点 ---
            if math.hypot(dx, dy - size * 0.02) <= dot_r:
                color = DOT

            # --- 左下角"故障"角标（小尺寸省略，避免糊成一团）---
            if size >= 32:
                bx, by = size * 0.235, size * 0.775
                br = size * 0.185
                if math.hypot(px - bx, py - by) <= br:
                    if math.hypot(px - bx, py - by) >= br - max(1.0, size * 0.045):
                        color = (0xFF, 0xFF, 0xFF)
                    else:
                        color = BADGE
            row.append((color[0], color[1], color[2], alpha))
        pixels.append(row)
    return pixels


def _ico_image(size: int) -> bytes:
    """把一张位图编码为 ICO 内的 BMP 数据块。"""
    pixels = _render(size)
    # BITMAPINFOHEADER：height 为 2 倍（XOR + AND）
    header = struct.pack(
        "<IiiHHIIiiII",
        40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0,
    )
    body = bytearray()
    # 像素自下而上
    for y in range(size - 1, -1, -1):
        for x in range(size):
            r, g, b, a = pixels[y][x]
            body += bytes((b, g, r, a))
    # AND 掩码：32bpp 下每行仍需按 4 字节对齐，全 0 即可
    row_bytes = ((size + 31) // 32) * 4
    body += b"\x00" * (row_bytes * size)
    return header + bytes(body)


def build_ico(path: str) -> str:
    images = [(s, _ico_image(s)) for s in SIZES]
    out = bytearray()
    out += struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    for size, data in images:
        w = 0 if size >= 256 else size
        h = 0 if size >= 256 else size
        out += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    for _size, data in images:
        out += data
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(out)
    return path


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "netdoctor.ico")
    print("icon written:", build_ico(target))
