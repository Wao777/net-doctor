# -*- coding: utf-8 -*-
"""生成 README 用的界面截图。

为什么用演示数据：界面里会显示探针明细、网卡名、DNS/网关地址与 hosts 记录，
直接截真实运行结果等于把使用者的网络环境一起公开。这里改为**构造脱敏数据**，
但走的是真实的判定引擎（``diagnose.judge``）与真实的界面渲染路径
（``App._on_scan_done``），因此截图呈现的就是程序本来的样子。

用法：
    python build/make_screenshot.py                 # 输出到 docs/images/
    python build/make_screenshot.py <输出目录>

依赖：仅标准库（tkinter + ctypes + zlib），不需要 Pillow。
"""
from __future__ import annotations

import ctypes
import os
import struct
import sys
import time
import zlib
from ctypes import wintypes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from netdoctor import diagnose                                       # noqa: E402
from netdoctor.gui import App                                        # noqa: E402
from netdoctor.models import Finding, ProbeResult, ScanReport, Severity  # noqa: E402

# --------------------------------------------------------------------------
# 演示数据（不含任何真实网络信息）
# --------------------------------------------------------------------------


def _p(name: str, ok: bool, latency=None, detail: str = "") -> ProbeResult:
    return ProbeResult(name, ok, latency, detail)


def _report(probes, findings, ctx) -> ScanReport:
    rep = ScanReport(started_at="2026-01-01 10:24:00", finished_at="2026-01-01 10:24:36")
    rep.probes = probes
    rep.findings = findings
    rep.verdict = diagnose.judge(probes, findings, ctx)
    return rep


def demo_healthy() -> ScanReport:
    """场景一：网络健康 —— 配置类差异只做提示，横幅仍显示健康。"""
    probes = [
        _p("本机协议栈", True, 0.4, "127.0.0.1 响应正常"),
        _p("默认网关", True, 2.1, "网关可达"),
        _p("公网IP", True, 18.6, "公网地址可达"),
        _p("DNS解析", True, 24.3, "域名解析正常"),
        _p("TCP 443", True, 46.2, "HTTPS 端口连接成功"),
        _p("HTTP 访问", True, 87.5, "HTTP 200，返回 1234 字节"),
        _p("浏览器路径", True, 95.8, "经系统代理访问正常"),
        _p("MTU 探测", True, None, "最大可用 MTU ≥ 1472"),
    ]
    findings = [
        Finding("B.static", "B", "IP 配置", "网卡使用静态 IP 地址",
                "该网卡配置了固定的 IPv4 地址，而非自动获取。内网固定 IP 是常见的有意配置。",
                Severity.INFO, fix_id="fix.dhcp.auto",
                manual_hint="如非有意设置：网络和共享中心 → 更改适配器选项 → 属性 → IPv4 → 自动获取 IP。"),
        Finding("C.hosts", "C", "DNS", "hosts 文件存在自定义解析记录",
                "hosts 文件里存在自定义的域名映射记录，通常是用户主动添加的（屏蔽广告、加速访问），"
                "也可能是第三方软件写入。实测解析正常，说明当前未造成影响。",
                Severity.INFO, fix_id="fix.hosts.restore",
                manual_hint="如非本人添加，可用「还原 hosts 文件」恢复到系统默认内容（会先备份原文件）。",
                evidence="# 自定义解析记录（节选）\n127.0.0.1  ads.example.internal\n127.0.0.1  track.example.internal"),
        Finding("E.env-proxy", "E", "代理/VPN", "存在代理环境变量",
                "环境变量里设置了 HTTP_PROXY / HTTPS_PROXY。这类变量只影响命令行工具，"
                "不影响浏览器（浏览器只认系统代理设置）。",
                Severity.INFO, fix_id="fix.proxy.env",
                manual_hint="如不再需要：系统属性 → 高级 → 环境变量，删除对应的变量即可。"),
        Finding("G.multi-default", "G", "路由", "存在多条默认路由",
                "路由表中有不止一条默认路由（0.0.0.0/0）。多出现在装过 VPN / 虚拟网卡的机器上，"
                "实测未抢占正常出口。",
                Severity.INFO, fix_id="fix.route.refresh",
                manual_hint="若确实出现上网异常，可执行「重建默认路由」；正常时无需处理。"),
        Finding("I.powersave", "I", "系统环境", "网卡启用了节能断流",
                "网卡电源管理允许系统在空闲时关闭设备以省电。少数机器上会导致挂机后短暂掉线。",
                Severity.INFO, fix_id="fix.powersave.off",
                manual_hint="如遇到「挂机掉线、动一下鼠标就恢复」，可执行「关闭网卡节能断流」。"),
    ]
    return _report(probes, findings, {"hosts_count": 5, "powersave": ["以太网"], "proxy_env": True})


def demo_dns() -> ScanReport:
    """场景二：能连网但上网受限 · 域名解析故障（能上 QQ 打不开网页）。"""
    probes = [
        _p("本机协议栈", True, 0.4, "127.0.0.1 响应正常"),
        _p("默认网关", True, 2.3, "网关可达"),
        _p("公网IP", True, 19.4, "公网地址可达"),
        _p("DNS解析", False, None, "域名解析失败：无可用 DNS 响应"),
        _p("TCP 443", False, None, "域名无法解析，未能建立连接"),
        _p("HTTP 访问", False, None, "请求失败：无法解析主机名"),
    ]
    findings = [
        Finding("C.dns-unreachable", "C", "DNS", "配置的 DNS 服务器均无响应",
                "网卡上配置的 DNS 服务器地址都查询不到响应，域名因此无法解析。",
                Severity.HIGH, fix_id=None,
                manual_hint="1. 在网卡属性里把 DNS 改为自动获取，或填写公共 DNS（223.5.5.5 / 119.29.29.29）；\n"
                            "2. 保存后执行 ipconfig /flushdns 重新测试；\n"
                            "3. 若路由器下发的 DNS 有问题，重启路由器后再试。",
                evidence="查询 223.5.5.5 超时\n查询 119.29.29.29 超时"),
        Finding("J.dns", "J", "连通性结论", "域名解析失败（DNS 问题）",
                "分层探针显示：本机协议栈与公网出口均正常，但域名解析这一层失败，"
                "因此浏览器打不开网页，而微信 / QQ 等直连 IP 的应用仍可用。",
                Severity.HIGH, fix_id="fix.dns.flush",
                manual_hint="先执行「刷新 DNS 解析缓存」，再执行「DNS 切换为公共 DNS」。"),
        Finding("C.hosts", "C", "DNS", "hosts 文件存在自定义解析记录",
                "hosts 文件里存在自定义的域名映射记录，在解析异常的当前，这些记录可能影响解析结果。",
                Severity.MEDIUM, fix_id="fix.hosts.restore",
                manual_hint="如非本人添加，可用「还原 hosts 文件」恢复到系统默认内容（会先备份原文件）。",
                evidence="# 自定义解析记录（节选）\n127.0.0.1  ads.example.internal"),
    ]
    return _report(probes, findings, {"hosts_count": 5})


LOGS_HEALTHY = [
    "[体检] 分层探针开始 …",
    "[探针] 本机协议栈 127.0.0.1 … 通 (0.4 ms)",
    "[探针] 默认网关 … 通 (2.1 ms)",
    "[探针] 公网IP … 通 (18.6 ms)",
    "[探针] DNS解析 … 通 (24.3 ms)",
    "[探针] TCP 443 … 通 (46.2 ms)",
    "[探针] HTTP 访问 … 通 (87.5 ms)",
    "[判定] 健康度=网络健康 形态=normal",
    "[扫描] A 链路层 / B IP 配置 / C DNS / D 协议栈 … 完成",
    "[扫描] 共检出 5 条提示级信息，均不影响上网",
]

LOGS_DNS = [
    "[体检] 分层探针开始 …",
    "[探针] 本机协议栈 127.0.0.1 … 通 (0.4 ms)",
    "[探针] 默认网关 … 通 (2.3 ms)",
    "[探针] 公网IP … 通 (19.4 ms)",
    "[探针] DNS解析 … 不通",
    "[判定] 健康度=能连网但上网受限 形态=dns",
    "[扫描] C DNS 类检出 2 项，J 连通性结论 1 项",
    "[提示] 本形态建议：刷新 DNS 缓存 → 切换公共 DNS → 还原 hosts",
]

# --------------------------------------------------------------------------
# 抓图（PrintWindow + 手写 PNG 编码）
# --------------------------------------------------------------------------

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32

user32.GetWindowDC.restype = wintypes.HDC
user32.GetWindowDC.argtypes = [wintypes.HWND]
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
user32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
user32.GetAncestor.restype = wintypes.HWND

gdi32.CreateCompatibleDC.restype = wintypes.HDC
gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
gdi32.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
gdi32.SelectObject.restype = wintypes.HGDIOBJ
gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
gdi32.DeleteDC.argtypes = [wintypes.HDC]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 3)]


# GetDIBits 必须显式声明参数类型：句柄是 64 位指针，
# 若按默认 int 传递，句柄值较大时会抛 OverflowError。
gdi32.GetDIBits.argtypes = [
    wintypes.HDC, wintypes.HBITMAP, wintypes.UINT, wintypes.UINT,
    ctypes.c_void_p, ctypes.POINTER(BITMAPINFO), wintypes.UINT,
]
gdi32.GetDIBits.restype = ctypes.c_int


def grab_window(hwnd: int):
    """把窗口画到内存位图并取回 BGRA 像素（不依赖窗口是否在最前）。"""
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    width = int(rect.right - rect.left)
    height = int(rect.bottom - rect.top)
    if width <= 0 or height <= 0:
        raise RuntimeError("窗口尺寸异常，可能尚未显示")

    hdc = user32.GetWindowDC(hwnd)
    memdc = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, width, height)
    old = gdi32.SelectObject(memdc, bmp)
    try:
        # PW_RENDERFULLCONTENT(2)：从 DWM 取完整内容，避免标题栏留白
        user32.PrintWindow(hwnd, memdc, 2)

        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = width
        bmi.bmiHeader.biHeight = -height        # 负值 = 自顶向下
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = 0         # BI_RGB

        buf = ctypes.create_string_buffer(width * height * 4)
        gdi32.GetDIBits(memdc, bmp, 0, height, ctypes.cast(buf, ctypes.c_void_p),
                        ctypes.byref(bmi), 0)
        return width, height, buf.raw
    finally:
        gdi32.SelectObject(memdc, old)
        gdi32.DeleteObject(bmp)
        gdi32.DeleteDC(memdc)
        user32.ReleaseDC(hwnd, hdc)


def encode_png(width: int, height: int, bgra: bytes) -> bytes:
    """把 BGRA 像素编码成 PNG（丢弃 alpha，仅用标准库）。"""
    stride = width * 4
    raw = bytearray()
    for y in range(height):
        row = bgra[y * stride:(y + 1) * stride]
        line = bytearray(width * 3)
        line[0::3] = row[2::4]     # R
        line[1::3] = row[1::4]     # G
        line[2::3] = row[0::4]     # B
        raw.append(0)              # filter: none
        raw += line

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        crc = zlib.crc32(body) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + body + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def render(app: App, rep: ScanReport, logs) -> None:
    # 每次渲染前清空上一次的列表内容（_on_scan_done 只负责插入）
    for iid in app.tree.get_children():
        app.tree.delete(iid)
    app.txt_log.config(state="normal")
    app.txt_log.delete("1.0", "end")
    app.txt_log.config(state="disabled")
    for line in logs:
        app._append_log(line)
    app._on_scan_done(rep)          # 走真实的界面渲染路径
    app.update_idletasks()
    app.update()
    time.sleep(0.45)
    app.update()


def main() -> int:
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "docs", "images")
    os.makedirs(out_dir, exist_ok=True)

    marks = [
        ("gui-main.png", demo_healthy(), LOGS_HEALTHY),
        ("gui-diagnose.png", demo_dns(), LOGS_DNS),
    ]

    app = App()
    app.update()
    try:
        for name, rep, logs in marks:
            render(app, rep, logs)
            app.lift()
            app.attributes("-topmost", True)
            app.update()
            time.sleep(0.25)
            hwnd = user32.GetAncestor(app.winfo_id(), 2)   # GA_ROOT
            w, h, pixels = grab_window(hwnd)
            path = os.path.join(out_dir, name)
            with open(path, "wb") as fh:
                fh.write(encode_png(w, h, pixels))
            print(f"已生成 {os.path.relpath(path, ROOT)}  ({w}x{h})")
    finally:
        try:
            app.attributes("-topmost", False)
        except Exception:
            pass
        app.destroy()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
