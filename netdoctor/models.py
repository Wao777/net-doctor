# -*- coding: utf-8 -*-
"""数据模型：扫描发现项、修复动作、修复结果。"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class Severity(Enum):
    """问题严重度，决定在界面里的排序与配色。"""

    CRITICAL = ("critical", "严重", 0)
    HIGH = ("high", "高", 1)
    MEDIUM = ("medium", "中", 2)
    LOW = ("low", "低", 3)
    INFO = ("info", "提示", 4)

    def __init__(self, key: str, label: str, rank: int) -> None:
        self.key = key
        self.label = label
        self.rank = rank


class FixMode(Enum):
    """修复动作的档位。稳健档动作默认全部参与自动修复。"""

    SAFE = "safe"          # 稳健档：可逆、无需重启、无副作用
    ADVANCED = "advanced"  # 进阶档：影响力较大（协议栈重置等），需二次确认
    MANUAL = "manual"      # 仅提供手动指引，工具不自动执行


@dataclass
class Finding:
    """一条扫描结论（疑似导致断网的原因）。"""

    id: str                          # 唯一标识，如 "B.apipa"
    category: str                    # 分类代号 A~J
    category_name: str               # 分类中文名
    title: str                       # 问题标题（一句话）
    detail: str                      # 详情说明
    severity: Severity
    fix_id: Optional[str] = None     # 可执行的修复动作 id；None 表示只能手动处理
    manual_hint: str = ""            # 手动修复指引（分步骤文字）
    evidence: str = ""               # 原始证据（命令输出片段）
    data: Dict[str, Any] = field(default_factory=dict)  # 附加上下文（网卡名/服务名等）

    @property
    def auto_fixable(self) -> bool:
        return bool(self.fix_id)

    @property
    def sort_key(self) -> tuple:
        return (self.severity.rank, self.category, self.id)


@dataclass
class FixAction:
    """一个可执行的修复动作（元数据）。

    真正的执行体由 fixers.py 中的函数实现，通过 id 对齐。
    """

    id: str
    title: str
    description: str
    mode: FixMode = FixMode.SAFE
    needs_reboot: bool = False
    default_selected: bool = True


@dataclass
class FixOutcome:
    """单个修复动作的执行结果。"""

    fix_id: str
    title: str
    ok: bool
    message: str
    commands: List[str] = field(default_factory=list)
    needs_reboot: bool = False
    backups: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fix_id": self.fix_id,
            "title": self.title,
            "ok": self.ok,
            "message": self.message,
            "commands": self.commands,
            "needs_reboot": self.needs_reboot,
            "backups": self.backups,
        }


@dataclass
class ProbeResult:
    """一条连通性探针结果。"""

    name: str
    ok: bool
    latency_ms: Optional[float] = None
    detail: str = ""

    @property
    def status_text(self) -> str:
        if self.ok:
            if self.latency_ms is not None:
                return f"通 ({self.latency_ms:.0f} ms)"
            return "通"
        return "不通"


class HealthLevel(Enum):
    """网络体检的健康度（判定结论的档位）。

    判定原则：**健康度只由实测连通性决定**。能实际上网 → 健康（NORMAL）；
    反之才按「断在哪一层」落到 LIMITED / DOWN。
    配置类检出（hosts 自定义记录、静态 IP、代理设置、网卡节能等）即便存在，
    只要实测能正常上网，就统一降为「提示」级，不把健康度往下压。

    RISK 为保留档位（「在线但被实测到局部能力受损」时使用），当前判定逻辑下
    不会有形态落到该档——实测到的缺陷按严重程度归入 LIMITED 或 DOWN。
    """

    NORMAL = ("normal", "网络健康", "#2e7d32", 0)
    RISK = ("risk", "可以上网，但有隐患", "#b28704", 1)
    LIMITED = ("limited", "能连网，但上网受限", "#e65100", 2)
    DOWN = ("down", "完全断网", "#c62828", 3)

    def __init__(self, key: str, label: str, color: str, rank: int) -> None:
        self.key = key
        self.label = label
        self.color = color
        self.rank = rank


@dataclass
class Verdict:
    """网络体检判定结论：先回答「网络是否正常」，再说明属于哪种故障形态、怎么分别处理。"""

    level: HealthLevel                 # 健康度档位
    fault: str                         # 形态代号，如 dns / proxy-broken / wan
    fault_label: str                   # 形态名称（人话）
    scope: str                         # 故障发生的位置
    headline: str                      # 一句话结论
    detail: str = ""                   # 判定依据
    affects_ok: List[str] = field(default_factory=list)    # 目前仍然可用的功能
    affects_bad: List[str] = field(default_factory=list)   # 已经受影响的功能
    steps: List[str] = field(default_factory=list)         # 分形态的处理步骤
    fix_ids: List[str] = field(default_factory=list)       # 该形态下建议执行的自动修复动作
    need_professional: bool = False    # 是否建议联系专业人员
    layers: List[Dict[str, Any]] = field(default_factory=list)  # 分层结论快照
    online: bool = False               # 是否能实际上网
    browse_ok: Optional[bool] = None   # 浏览器那条路是否通（None=无法判定）

    @property
    def healthy(self) -> bool:
        return self.level is HealthLevel.NORMAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.key,
            "level_label": self.level.label,
            "fault": self.fault,
            "fault_label": self.fault_label,
            "scope": self.scope,
            "headline": self.headline,
            "detail": self.detail,
            "affects_ok": self.affects_ok,
            "affects_bad": self.affects_bad,
            "steps": self.steps,
            "fix_ids": self.fix_ids,
            "need_professional": self.need_professional,
            "layers": self.layers,
            "online": self.online,
            "browse_ok": self.browse_ok,
        }


@dataclass
class ScanReport:
    """一次完整扫描的汇总。"""

    started_at: str
    finished_at: str = ""
    findings: List[Finding] = field(default_factory=list)
    probes: List[ProbeResult] = field(default_factory=list)
    info: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    verdict: Optional["Verdict"] = None

    @property
    def suspicious(self) -> List[Finding]:
        """需要向用户展示的疑似原因（按严重度排序）。"""
        return sorted(self.findings, key=lambda f: f.sort_key)

    @property
    def concerning(self) -> List[Finding]:
        """真正值得用户处理的项（排除「提示」级噪声）。"""
        return [f for f in self.suspicious if f.severity.rank <= Severity.MEDIUM.rank]

    @property
    def auto_fixable(self) -> List[Finding]:
        return [f for f in self.suspicious if f.auto_fixable]

    @property
    def online(self) -> bool:
        """是否具备基本外网连通性（能实际打开网站，而非仅 ping 通）。"""
        if self.verdict is not None:
            return self.verdict.online
        for p in self.probes:
            if p.name in ("HTTP 访问", "TCP 443") and p.ok:
                return True
        return False

    @property
    def healthy(self) -> bool:
        return bool(self.verdict and self.verdict.healthy)
