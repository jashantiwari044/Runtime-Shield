"""Core data models for Runtime Shield.

Everything the engine passes around is defined here. Plain dataclasses -- no
pydantic requirement for the core, so `import shield` stays fast and dependency
light. The server layer adds pydantic on top for request validation.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Action(str, Enum):
    """What the shield decided to do about a call."""

    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "flag"      # allow, but record it as suspicious
    REDACT = "redact"  # outbound only: content was modified


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.value]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Stage(str, Enum):
    """Which guard produced a decision."""

    KILL_SWITCH = "kill_switch"
    RATE_LIMIT = "rate_limit"
    POLICY = "policy"
    INJECTION = "injection"
    COMMAND = "command"
    EGRESS = "egress"
    CHAIN = "chain"
    TRIFECTA = "trifecta"
    SECRETS = "secrets"
    PII = "pii"


@dataclass
class ToolCall:
    """An action an agent wants to take, before it happens."""

    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    agent: str = "default"
    tenant: str = "default"
    # A unit of agent work. Taint is tracked per session and never leaks
    # between them, so a long-lived agent does not accumulate false trifectas.
    session: str = "default"
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = field(default_factory=time.time)


@dataclass
class Finding:
    """One thing a guard noticed."""

    stage: Stage
    action: Action
    reason: str
    severity: Severity = Severity.INFO
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage.value,
            "action": self.action.value,
            "reason": self.reason,
            "severity": self.severity.value,
            "details": self.details,
        }


@dataclass
class Decision:
    """The shield's answer for one tool call.

    `allowed` is the only field callers strictly need:

        if not shield.check("exec", {"command": cmd}).allowed:
            refuse()
    """

    action: Action = Action.ALLOW
    reason: str = ""
    severity: Severity = Severity.INFO
    stage: Stage | None = None
    findings: list[Finding] = field(default_factory=list)
    latency_ms: float = 0.0
    call_id: str = ""

    @property
    def allowed(self) -> bool:
        return self.action is not Action.BLOCK

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "action": self.action.value,
            "reason": self.reason,
            "severity": self.severity.value,
            "stage": self.stage.value if self.stage else None,
            "findings": [f.to_dict() for f in self.findings],
            "latency_ms": round(self.latency_ms, 3),
            "call_id": self.call_id,
        }

    def __bool__(self) -> bool:
        # `if shield.check(...):` reads naturally as "if allowed".
        return self.allowed


@dataclass
class ScanResult:
    """The result of scanning text coming back from a tool or a model."""

    content: str
    original: str = ""
    findings: list[Finding] = field(default_factory=list)
    latency_ms: float = 0.0

    @property
    def modified(self) -> bool:
        return bool(self.original) and self.content != self.original

    @property
    def blocked(self) -> bool:
        return any(f.action is Action.BLOCK for f in self.findings)

    @property
    def allowed(self) -> bool:
        return not self.blocked

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content,
            "modified": self.modified,
            "blocked": self.blocked,
            "findings": [f.to_dict() for f in self.findings],
            "latency_ms": round(self.latency_ms, 3),
        }
