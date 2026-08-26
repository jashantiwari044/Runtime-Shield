"""OpenAI-compatible integration (OpenAI, Azure, Groq, Together, Ollama, vLLM...).

Two ways in, pick whichever fits:

    # 1. Wrap the client — every completion is guarded automatically.
    from openai import OpenAI
    from shield import Shield
    from shield.integrations.openai_adapter import guard_client

    client = guard_client(OpenAI(), Shield(), agent="support-bot")
    response = client.chat.completions.create(model="gpt-4o", messages=[...])

    # 2. Or check a response you already have.
    from shield.integrations.openai_adapter import check_response
    blocked = check_response(shield, response, agent="support-bot")
"""

from __future__ import annotations

from typing import Any

from ..engine import Shield
from ..models import Decision
from . import guard_tool_calls


def check_response(shield: Shield, response: Any, agent: str = "default") -> list[Decision]:
    """Check every tool call the model proposed. Returns blocking decisions."""
    blocked: list[Decision] = []
    for choice in getattr(response, "choices", None) or []:
        message = getattr(choice, "message", None)
        for _, decision in guard_tool_calls(
            shield, getattr(message, "tool_calls", None) or [], agent=agent
        ):
            if decision.blocked:
                blocked.append(decision)
    return blocked


def sanitize_response(shield: Shield, response: Any, agent: str = "default") -> Any:
    """Strip blocked tool calls and redact message text, in place.

    The model is told why, so it can recover rather than silently retrying.
    """
    for choice in getattr(response, "choices", None) or []:
        message = getattr(choice, "message", None)
        if message is None:
            continue

        calls = getattr(message, "tool_calls", None) or []
        if calls:
            kept, refusals = [], []
            for raw, decision in guard_tool_calls(shield, calls, agent=agent):
                if decision.blocked:
                    refusals.append(decision.reason)
                else:
                    kept.append(raw)
            if refusals:
                try:
                    message.tool_calls = kept
                    note = "; ".join(refusals)
                    message.content = (
                        (getattr(message, "content", "") or "")
                        + f"\n[Runtime Shield blocked a tool call: {note}]"
                    ).strip()
                except (AttributeError, TypeError):
                    pass

        content = getattr(message, "content", None)
        if isinstance(content, str) and content:
            cleaned = shield.scan(content, tool="llm_response", agent=agent).content
            if cleaned != content:
                try:
                    message.content = cleaned
                except (AttributeError, TypeError):
                    pass
    return response


def guard_client(client: Any, shield: Shield, agent: str = "default") -> Any:
    """Return `client` with `chat.completions.create` guarded.

    Mutates the client's bound method, so existing references keep working.
    """
    completions = client.chat.completions
    original = completions.create

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
            return response  # streaming is passed through unguarded
        return sanitize_response(shield, response, agent=agent)

    completions.create = create  # type: ignore[method-assign]
    return client


__all__ = ["check_response", "sanitize_response", "guard_client"]
