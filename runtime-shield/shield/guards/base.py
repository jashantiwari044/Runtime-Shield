"""Base class every guard implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..config import Config
from ..models import Action, Finding, Severity, Stage, ToolCall


class Guard(ABC):
    """An inbound guard: inspects a tool call before it runs."""

    stage: Stage

    @abstractmethod
    def check(self, call: ToolCall, config: Config) -> Finding | None:
        """Return a Finding to act on, or None to pass the call along."""

    def reset(self) -> None:  # noqa: B027 - optional hook, not every guard has state
        """Drop any per-agent state. Used by tests and the /v1/reset endpoint."""

    # -- helpers ---------------------------------------------------------

    def _block(self, reason: str, severity: Severity = Severity.HIGH, **details: Any) -> Finding:
        return Finding(self.stage, Action.BLOCK, reason, severity, details)

    def _flag(self, reason: str, severity: Severity = Severity.MEDIUM, **details: Any) -> Finding:
        return Finding(self.stage, Action.FLAG, reason, severity, details)

    def _allow(self, reason: str = "") -> Finding:
        return Finding(self.stage, Action.ALLOW, reason, Severity.INFO, {})

    def _decide(
        self,
        configured: str,
        reason: str,
        severity: Severity = Severity.HIGH,
        **details: Any,
    ) -> Finding:
        """Build a Finding honouring the guard's configured action."""
        action = Action.FLAG if str(configured).lower() == "flag" else Action.BLOCK
        return Finding(self.stage, action, reason, severity, details)


class OutboundGuard(ABC):
    """An outbound guard: inspects (and may rewrite) text coming back."""

    stage: Stage

    @abstractmethod
    def scan(self, text: str, config: Config) -> tuple[str, list[Finding]]:
        """Return (possibly rewritten text, findings)."""


def collect_strings(value: Any, depth: int = 0, limit: int = 200_000) -> list[str]:
    """Flatten nested arguments into the strings they contain.

    Bounded on both depth and total size so a hostile payload cannot make the
    guards quadratic.
    """
    out: list[str] = []
    total = 0

    def walk(node: Any, d: int) -> None:
        nonlocal total
        if d > 8 or total > limit:
            return
        if isinstance(node, str):
            out.append(node)
            total += len(node)
        elif isinstance(node, dict):
            for key, val in node.items():
                out.append(str(key))
                walk(val, d + 1)
        elif isinstance(node, (list, tuple, set)):
            for item in node:
                walk(item, d + 1)
        elif node is not None:
            out.append(str(node))

    walk(value, depth)
    return out


def flatten_arguments(arguments: dict[str, Any]) -> str:
    """Everything in the arguments as one searchable string."""
    return " ".join(collect_strings(arguments))
