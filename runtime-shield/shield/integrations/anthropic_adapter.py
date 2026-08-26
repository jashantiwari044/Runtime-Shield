"""Anthropic (Claude) integration.

    from anthropic import Anthropic
    from shield import Shield
    from shield.integrations.anthropic_adapter import guard_client

    client = guard_client(Anthropic(), Shield(), agent="research-agent")
    response = client.messages.create(model="claude-opus-5", max_tokens=1024, ...)

Blocked `tool_use` blocks are replaced with a `tool_result` explaining the
refusal, which Claude handles gracefully on the next turn.
"""

from __future__ import annotations

from typing import Any

from ..engine import Shield
from ..models import Decision
from . import normalize_tool_call


def check_message(shield: Shield, message: Any, agent: str = "default") -> list[Decision]:
    """Check every tool_use block in a Claude response."""
    blocked: list[Decision] = []
    for block in getattr(message, "content", None) or []:
        if getattr(block, "type", None) != "tool_use":
            continue
        name, arguments = normalize_tool_call(block)
        decision = shield.check(name, arguments, agent=agent)
        if decision.blocked:
            blocked.append(decision)
    return blocked


def tool_result_for(block: Any, decision: Decision) -> dict[str, Any]:
    """Build the `tool_result` to send back when a tool_use was blocked."""
    return {
        "type": "tool_result",
        "tool_use_id": getattr(block, "id", None) or "unknown",
        "is_error": True,
        "content": f"Blocked by Runtime Shield: {decision.reason}",
    }


def sanitize_message(shield: Shield, message: Any, agent: str = "default") -> Any:
    """Redact text blocks in a Claude response, in place."""
    for block in getattr(message, "content", None) or []:
        if getattr(block, "type", None) != "text":
            continue
        text = getattr(block, "text", None)
        if isinstance(text, str) and text:
            cleaned = shield.scan(text, tool="llm_response", agent=agent).content
            if cleaned != text:
                try:
                    block.text = cleaned
                except (AttributeError, TypeError):
                    pass
    return message


def guard_client(client: Any, shield: Shield, agent: str = "default") -> Any:
    """Return `client` with `messages.create` guarded."""
    messages = client.messages
    original = messages.create

    def create(*args: Any, **kwargs: Any) -> Any:
        for message in kwargs.get("messages", []) or []:
            content = message.get("content") if isinstance(message, dict) else None
            if isinstance(content, str) and content:
                decision = shield.check("llm_message", {"content": content}, agent=agent)
                if decision.blocked:
                    from ..engine import ShieldError
                    raise ShieldError(decision)

        response = original(*args, **kwargs)
        if kwargs.get("stream"):
            return response
        return sanitize_message(shield, response, agent=agent)

    messages.create = create  # type: ignore[method-assign]
    return client


__all__ = ["check_message", "sanitize_message", "tool_result_for", "guard_client"]
