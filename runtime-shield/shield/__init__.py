"""Runtime Shield — runtime security for AI agents.

Guardrails that sit between an agent and the actions it wants to take:
permissions, prompt-injection detection, dangerous-command blocking, SSRF and
egress control, multi-step attack detection, and secret/PII redaction on the
way back — with a tamper-evident audit log of every decision.

Quick start:

    from shield import Shield

    shield = Shield()
    decision = shield.check("exec", {"command": "rm -rf /"}, agent="my-agent")
    if decision.blocked:
        print(decision.reason)

    clean = shield.scan(tool_output).content
"""

from __future__ import annotations

from .config import (
    AgentConfig,
    Config,
    ConfigError,
    RuleConfig,
    find_config,
    load_config,
)
from .engine import Shield, ShieldError
from .models import (
    Action,
    Decision,
    Finding,
    ScanResult,
    Severity,
    Stage,
    ToolCall,
)

__version__ = "1.0.0"

__all__ = [
    "Shield",
    "ShieldError",
    "Decision",
    "ScanResult",
    "Finding",
    "ToolCall",
    "Action",
    "Severity",
    "Stage",
    "Config",
    "ConfigError",
    "AgentConfig",
    "RuleConfig",
    "load_config",
    "find_config",
    "__version__",
]


_default: Shield | None = None


def default_shield() -> Shield:
    """A lazily created process-wide Shield, for the module-level helpers."""
    global _default
    if _default is None:
        _default = Shield()
    return _default


def check(tool: str, arguments: dict | None = None, agent: str = "default") -> Decision:
    """Check a tool call against the default Shield."""
    return default_shield().check(tool, arguments, agent=agent)


def scan(text: str, agent: str = "default") -> ScanResult:
    """Scan text with the default Shield."""
    return default_shield().scan(text, agent=agent)
