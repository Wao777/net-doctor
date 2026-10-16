# -*- coding: utf-8 -*-
"""通用工具层：命令执行、权限判定、日志、注册表、路径解析。

本模块是被所有其它模块依赖的最底层，不引用项目内其它模块。
"""
from __future__ import annotations

import base64
import ctypes
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, List, Optional, Sequence, Union

IS_WINDOWS = sys.platform.startswith("win")

# 不弹出黑色控制台窗口
_CREATE_NO_WINDOW = 0x08000000

# Windows 中文控制台多为 cp936，部分工具输出 utf-8，逐级回退解码
_DECODE_CHAIN = ("utf-8", "gbk", "cp936", "mbcs", "latin-1")


def decode_bytes(raw: Optional[bytes]) -> str:
    """把命令输出的原始字节尽量无损地解码为字符串。"""
    if not raw:
        return ""
    for enc in _DECODE_CHAIN:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


@dataclass
class CommandResult:
    """一次外部命令调用的结果。"""

    cmd: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def output(self) -> str:
        parts = [p for p in (self.stdout.strip(), self.stderr.strip()) if p]
        return "\n".join(parts)

    def first_lines(self, n: int = 4) -> str:
        lines = [ln.rstrip() for ln in self.output.splitlines() if ln.strip()]
        return "\n".join(lines[:n])


def run(
    args: Union[str, Sequence[str]],
    timeout: float = 15.0,
    *,
    shell: bool = False,
    cwd: Optional[str] = None,
) -> CommandResult:
    """执行一条外部命令，永不抛异常（失败也返回 CommandResult）。"""
    if isinstance(args, str):
        # 字符串形式一律走 shell，方便调用 netsh / ipconfig 等系统内建命令
        display = args
        popen_args: Any = args
        use_shell = True
    else:
        display = subprocess.list2cmdline(list(args))
        popen_args = list(args)
        use_shell = shell

    creationflags = _CREATE_NO_WINDOW if IS_WINDOWS else 0
    started = time.time()
    try:
        proc = subprocess.run(
            popen_args,
            shell=use_shell,
            capture_output=True,
            timeout=timeout,
            cwd=cwd,
            creationflags=creationflags,
        )
        return CommandResult(
            cmd=display,
            returncode=proc.returncode,
            stdout=decode_bytes(proc.stdout),
            stderr=decode_bytes(proc.stderr),
            timed_out=False,
            elapsed=time.time() - started,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            cmd=display,
            returncode=-1,
            stdout=decode_bytes(getattr(exc, "stdout", b"")),
            stderr=f"命令超时（>{timeout:.0f}s）",
            timed_out=True,
            elapsed=time.time() - started,
        )
    except Exception as exc:  # noqa: BLE001 - 兜底，命令层不允许抛出
        return CommandResult(
            cmd=display,
            returncode=-1,
            stdout="",
            stderr=f"命令执行失败: {exc}",
            timed_out=False,
            elapsed=time.time() - started,
        )


# --------------------------------------------------------------------------
# 权限
# --------------------------------------------------------------------------

def is_admin() -> bool:
    """当前进程是否具备管理员权限。"""
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(extra_args: Optional[Sequence[str]] = None) -> bool:
    """以管理员身份重新拉起自身，成功发起请求则返回 True。"""
    if not IS_WINDOWS:
        return False

    if getattr(sys, "frozen", False):
        exe = sys.executable
        args = list(sys.argv[1:])
    else:
        exe = sys.executable
        args = [os.path.abspath(sys.argv[0])] + list(sys.argv[1:])

    if extra_args:
        args.extend(extra_args)

    params = subprocess.list2cmdline(args)
    try:
        # SW_SHOWNORMAL = 1
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return int(rc) > 32
    except Exception:
        return False


# --------------------------------------------------------------------------
# 路径
# --------------------------------------------------------------------------

def app_dir() -> str:
    """程序自身所在目录（打包后为 exe 目录，开发时为项目根）。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def project_root() -> str:
    """源码根目录（开发期是项目根；打包后回退到 exe 目录）。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def asset_path(name: str) -> Optional[str]:
    """定位随程序分发的资源文件（目前用于应用图标）。

    查找顺序（返回首个真实存在的路径，全缺则返回 None）：
      1. 打包单文件版解包目录：``sys._MEIPASS/assets/<name>``
         （文件夹版的 ``_MEIPASS`` 指向 ``_internal``，同样命中）
      2. exe 同级：``<exe目录>/assets/<name>`` —— 可放同名文件覆盖内置图标
      3. 源码根：``assets/<name>``
      4. 源码根：``build/<name>`` —— 开发期直接运行时的图标位置
    """
    candidates: List[str] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(os.path.join(meipass, "assets", name))
    candidates.append(os.path.join(app_dir(), "assets", name))
    root = project_root()
    candidates.append(os.path.join(root, "assets", name))
    candidates.append(os.path.join(root, "build", name))
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def timestamp(timespec: str = "seconds") -> str:
    return datetime.now().strftime(
        "%Y%m%d-%H%M%S" if timespec == "seconds" else "%Y-%m-%d %H:%M:%S"
    )


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def windows_dir() -> str:
    return os.environ.get("SystemRoot", r"C:\Windows")


def hosts_path() -> str:
    return os.path.join(windows_dir(), "System32", "drivers", "etc", "hosts")


# --------------------------------------------------------------------------
# 日志
# --------------------------------------------------------------------------

class Logger:
    """同时写内存、写文件、并回调给界面（GUI 实时显示）。"""

    def __init__(self, path: Optional[str] = None, echo: bool = False) -> None:
        self.lines: List[str] = []
        self.path = path
        self.echo = echo
        self._sink: Optional[Callable[[str], None]] = None
        if path:
            ensure_dir(os.path.dirname(path))
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(f"\n===== 会话开始 {now_str()} =====\n")

    def bind(self, sink: Callable[[str], None]) -> None:
        """绑定界面刷新回调。"""
        self._sink = sink
        for line in self.lines[-200:]:
            try:
                sink(line)
            except Exception:
                pass

    def log(self, message: str, level: str = "INFO") -> None:
        line = f"[{datetime.now().strftime('%H:%M:%S')}][{level}] {message}"
        self.lines.append(line)
        if self.echo:
            try:
                print(line)
            except Exception:
                pass
        if self.path:
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except Exception:
                pass
        if self._sink:
            try:
                self._sink(line)
            except Exception:
                pass

    def command(self, result: CommandResult, level: str = "CMD") -> None:
        self.log(f"$ {result.cmd}  -> rc={result.returncode}", level)
        out = result.output
        if out:
            for ln in out.splitlines()[:12]:
                self.log("  " + ln.rstrip(), level)

    def warn(self, message: str) -> None:
        self.log(message, "WARN")

    def error(self, message: str) -> None:
        self.log(message, "ERROR")

    def ok(self, message: str) -> None:
        self.log(message, "OK")


# --------------------------------------------------------------------------
# 注册表
# --------------------------------------------------------------------------

try:  # pragma: no cover - 非 Windows 环境下降级
    import winreg  # type: ignore
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore

HK = {
    "HKCU": getattr(winreg, "HKEY_CURRENT_USER", None) if winreg else None,
    "HKLM": getattr(winreg, "HKEY_LOCAL_MACHINE", None) if winreg else None,
}


def reg_read(hive: str, subkey: str, name: str) -> Optional[Any]:
    """读取注册表值，不存在返回 None。"""
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(HK[hive], subkey, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except Exception:
        return None


def reg_write(hive: str, subkey: str, name: str, value: Any, kind: Optional[int] = None) -> bool:
    """写入注册表值。"""
    if winreg is None:
        return False
    if kind is None:
        kind = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
    try:
        with winreg.CreateKeyEx(HK[hive], subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, kind, value)
        return True
    except Exception:
        return False


def reg_delete(hive: str, subkey: str, name: str) -> bool:
    """删除注册表值（不存在也算成功）。"""
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(HK[hive], subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
        return True
    except FileNotFoundError:
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# 注册表导出 / 导入（纯 winreg 实现，不依赖 reg.exe）
# 说明：不调用 reg.exe 可以让工具在限制 reg.exe 的安全策略下照常工作。
# --------------------------------------------------------------------------

def _value_to_json(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"__b64__": base64.b64encode(value).decode("ascii")}
    if isinstance(value, list):
        return list(value)
    return value


def _value_from_json(value: Any) -> Any:
    if isinstance(value, dict) and "__b64__" in value:
        return base64.b64decode(value["__b64__"])
    if isinstance(value, list):
        return list(value)
    return value


def reg_export_key(hive: str, subkey: str, max_depth: int = 6) -> Dict[str, Any]:
    """递归导出注册表键为可 JSON 序列化的字典。

    结构：{ "": {值名: {"t": 类型, "v": 值}}, 子键相对路径: {...} }
    """
    if winreg is None:
        return {}
    out: Dict[str, Any] = {}

    def walk(rel: str, handle: Any, depth: int) -> None:
        vals: Dict[str, Any] = {}
        i = 0
        while True:
            try:
                name, value, vtype = winreg.EnumValue(handle, i)
            except OSError:
                break
            vals[name] = {"t": int(vtype), "v": _value_to_json(value)}
            i += 1
        out[rel] = vals
        if depth >= max_depth:
            return
        j = 0
        while True:
            try:
                child = winreg.EnumKey(handle, j)
            except OSError:
                break
            try:
                with winreg.OpenKey(handle, child, 0, winreg.KEY_READ) as sub:
                    walk(f"{rel}\\{child}" if rel else child, sub, depth + 1)
            except Exception:
                pass
            j += 1

    try:
        with winreg.OpenKey(HK[hive], subkey, 0, winreg.KEY_READ) as key:
            walk("", key, 0)
    except FileNotFoundError:
        return {}
    except Exception:
        return out
    return out


def reg_import_key(hive: str, subkey: str, data: Dict[str, Any]) -> List[str]:
    """把 reg_export_key 导出的数据写回注册表；返回失败项说明列表。"""
    if winreg is None:
        return ["当前环境不支持注册表操作"]
    problems: List[str] = []
    for rel, vals in (data or {}).items():
        path = subkey + (("\\" + rel) if rel else "")
        try:
            with winreg.CreateKeyEx(HK[hive], path, 0, winreg.KEY_WRITE) as key:
                for name, item in (vals or {}).items():
                    try:
                        winreg.SetValueEx(key, name, 0, int(item.get("t", 1)),
                                          _value_from_json(item.get("v")))
                    except Exception as exc:  # noqa: BLE001
                        problems.append(f"{path}\\{name} 写入失败：{exc}")
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{path} 创建失败：{exc}")
    return problems


# --------------------------------------------------------------------------
# 服务查询（不依赖 sc.exe，避免被安全策略/安全软件拦截）
# --------------------------------------------------------------------------

def query_services(names: Sequence[str]) -> Dict[str, tuple]:
    """一次查询多个服务的 (状态, 启动类型)。

    优先 Win32_Service（CIM），失败降级 Get-Service；
    两者都不可用时退回到 sc.exe（在受限环境里可能失败）。
    返回形如 {"Dhcp": ("RUNNING", "AUTO")}。
    """
    result: Dict[str, tuple] = {}
    names = [n for n in names if n]
    if not names:
        return result
    if not IS_WINDOWS:
        return result

    quoted = ",".join(f"'{n}'" for n in names)
    filter_expr = " or ".join(f"Name='{n}'" for n in names)
    script = (
        f"$names=@({quoted});"
        f"try{{"
        f"Get-CimInstance Win32_Service -Filter \"{filter_expr}\" -ErrorAction Stop |"
        f"ForEach-Object {{ \"$($_.Name)|$($_.State)|$($_.StartMode)\" }}"
        f"}}catch{{"
        f"Get-Service -Name $names -ErrorAction SilentlyContinue |"
        f"ForEach-Object {{ \"$($_.Name)|$($_.Status)|$($_.StartType)\" }}"
        f"}}"
    )
    res = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=35)
    for line in res.stdout.splitlines():
        parts = [p.strip() for p in line.strip().split("|")]
        if len(parts) == 3 and parts[0]:
            result[parts[0]] = (parts[1].upper(), _norm_start_type(parts[2]))

    if result:
        return result

    # 兜底：sc.exe
    for name in names:
        q = run(["sc", "query", name], timeout=8)
        m = re.search(r"STATE\s*:\s*\d+\s+(\S+)", q.stdout)
        qc = run(["sc", "qc", name], timeout=8)
        m2 = re.search(r"START_TYPE\s*:\s*\d+\s+(\S+)", qc.stdout)
        if m or m2:
            result[name] = (m.group(1).upper() if m else "",
                            _norm_start_type(m2.group(1) if m2 else ""))
    return result


def _norm_start_type(value: str) -> str:
    """把 Auto / Automatic / AUTO_START 统一成 AUTO。"""
    v = (value or "").strip().upper()
    if v.startswith("AUTO"):
        return "AUTO"
    if v.startswith("MAN"):
        return "MANUAL"
    if v.startswith("DIS"):
        return "DISABLED"
    return v


def set_service_auto(name: str, timeout: float = 30.0) -> bool:
    """把服务设为自动启动并立即启动（不依赖 sc.exe）。"""
    script = (
        f"try{{Set-Service -Name '{name}' -StartupType Automatic -ErrorAction Stop;"
        f"Start-Service -Name '{name}' -ErrorAction Stop; 'OK'}}"
        f"catch{{'FAIL: '+$_.Exception.Message}}"
    )
    res = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=timeout)
    return "OK" in res.stdout


def restore_service_start_type(name: str, start_type: str, timeout: float = 20.0) -> bool:
    """按备份的启动类型还原服务（AUTO / MANUAL / DISABLED）。"""
    mapping = {"AUTO": "Automatic", "MANUAL": "Manual", "DISABLED": "Disabled",
               "AUTO_START": "Automatic", "DEMAND_START": "Manual"}
    value = mapping.get((start_type or "").upper())
    if not value:
        return False
    script = (f"try{{Set-Service -Name '{name}' -StartupType {value} -ErrorAction Stop; 'OK'}}"
              f"catch{{'FAIL: '+$_.Exception.Message}}")
    res = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=timeout)
    return "OK" in res.stdout
