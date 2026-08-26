"""Adapters that drop Runtime Shield into an existing agent stack.

Every adapter is optional and imports its framework lazily, so installing
Runtime Shield never drags in a framework you do not use.

    from shield import Shield
    from shield.integrations import guard_tool_calls, guard_functions

`guard_tool_calls` and `guard_functions` are framework-agnostic and work with
anything that produces `{name, arguments}` pairs — which is every tool-calling
model API in practice.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from typing import Any

from ..engine import Shield
from ..models import Decision


def normalize_tool_call(raw: Any) -> tuple[str, dict[str, Any]]:
    """Pull `(name, arguments)` out of whatever shape a provider used.

    Handles OpenAI (`function.name` / JSON-string `arguments`), Anthropic
    (`name` / dict `input`), and plain dicts.
    """
    def attr(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    function = attr(raw, "function")
    if function is not None:
        name = attr(function, "name", "") or ""
        arguments = attr(function, "arguments", {})
    else:
        name = attr(raw, "name", "") or ""
        arguments = attr(raw, "input", None)
        if arguments is None:
            arguments = attr(raw, "arguments", {})

    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments or "{}")
        except json.JSONDecodeError:
            arguments = {"_raw": arguments}
    if not isinstance(arguments, dict):
        arguments = {"_value": arguments}

    return str(name), arguments


def guard_tool_calls(
    shield: Shield,
    tool_calls: Iterable[Any],
    agent: str = "default",
    tenant: str = "default",
) -> list[tuple[Any, Decision]]:
    """Check a batch of proposed tool calls. Returns `(call, decision)` pairs."""
    results = []
    for raw in tool_calls or []:
        name, arguments = normalize_tool_call(raw)
        results.append((raw, shield.check(name, arguments, agent=agent, tenant=tenant)))
    return results


def guard_functions(
    shield: Shield,
    functions: dict[str, Callable],
    agent: str = "default",
) -> dict[str, Callable]:
    """Wrap a `{name: callable}` tool registry so every call is checked.

    Works with any framework that keeps tools in a dict — LangChain, CrewAI,
    AutoGen, LlamaIndex, or your own loop.
    """
    return shield.wrap_tools(functions, agent=agent)


__all__ = ["normalize_tool_call", "guard_tool_calls", "guard_functions"]
