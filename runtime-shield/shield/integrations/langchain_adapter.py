"""LangChain / LangGraph integration.

    from shield import Shield
    from shield.integrations.langchain_adapter import guard_tools

    tools = guard_tools(Shield(), [search_tool, shell_tool], agent="researcher")
    agent = create_react_agent(llm, tools)

A blocked tool returns an error string to the model rather than raising, so the
agent can reason about the refusal and choose something else.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..engine import Shield


def guard_tool(shield: Shield, tool: Any, agent: str = "default") -> Any:
    """Wrap one LangChain tool's `_run`/`_arun` with a shield check."""
    name = getattr(tool, "name", None) or type(tool).__name__

    for attribute in ("_run", "run", "invoke"):
        original = getattr(tool, attribute, None)
        if not callable(original):
            continue

        def guarded(*args: Any, __original=original, **kwargs: Any) -> Any:
            arguments = dict(kwargs)
            if args and isinstance(args[0], dict):
                arguments.update(args[0])
            elif args:
                arguments["input"] = args[0]

            decision = shield.check(name, arguments, agent=agent)
            if decision.blocked:
                return f"Blocked by Runtime Shield: {decision.reason}"

            output = __original(*args, **kwargs)
            if isinstance(output, str):
                return shield.scan(output, tool=name, agent=agent).content
            return output

        try:
            setattr(tool, attribute, guarded)
        except (AttributeError, TypeError, ValueError):
            continue
        break

    return tool


def guard_tools(shield: Shield, tools: Sequence[Any], agent: str = "default") -> list[Any]:
    """Wrap a list of LangChain tools."""
    return [guard_tool(shield, tool, agent=agent) for tool in tools]


class ShieldCallbackHandler:
    """LangChain callback that records every tool start against the shield.

        agent.invoke(payload, config={"callbacks": [ShieldCallbackHandler(shield)]})

    Raises ShieldError on a blocked tool, which LangChain surfaces to the agent.
    """

    def __init__(self, shield: Shield, agent: str = "default", raise_on_block: bool = True) -> None:
        self.shield = shield
        self.agent = agent
        self.raise_on_block = raise_on_block
        self.blocked: list[Any] = []

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
        name = (serialized or {}).get("name", "unknown_tool")
        decision = self.shield.check(name, {"input": input_str}, agent=self.agent)
        if decision.blocked:
            self.blocked.append(decision)
            if self.raise_on_block:
                from ..engine import ShieldError
                raise ShieldError(decision)

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        if isinstance(output, str):
            self.shield.scan(output, agent=self.agent)

    def __getattr__(self, _name: str) -> Any:
        # LangChain probes for many optional callbacks; ignore the rest.
        return lambda *args, **kwargs: None


__all__ = ["guard_tool", "guard_tools", "ShieldCallbackHandler"]
