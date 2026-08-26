"""Policy — filesystem containment, per-agent permissions, and YAML rules.

This guard replaces the single biggest source of false positives in the old
engine, which treated *any* absolute path as a traversal attack and so blocked
`/home/me/project/README.md`. Path safety is now expressed as two precise
questions instead of one blunt one:

  1. Does the path hit a deny pattern (`**/.ssh/**`, `**/.env`, ...)?
  2. If a sandbox is configured, does the *resolved* path stay inside it?

Without a sandbox there is nothing to escape from, so `..` is not by itself an
attack -- and legitimate absolute paths are allowed through.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..config import AgentConfig, Config
from ..matching import arguments_match, glob_match, normalize_path, tool_match
from ..models import Action, Finding, Severity, Stage, ToolCall
from ..normalize import strip_invisible
from .base import Guard, collect_strings


class PolicyGuard(Guard):
    stage = Stage.POLICY

    def check(self, call: ToolCall, config: Config) -> Finding | None:
        agent_cfg = resolve_agent(config, call)

        # 1. Filesystem invariants come first: no rule may open a path that the
        #    deny list closes.
        if finding := self._check_paths(call, config, agent_cfg):
            return finding

        # 2. An explicit per-agent deny is the strongest permission signal.
        if agent_cfg:
            for pattern in agent_cfg.deny:
                if tool_match(call.tool, pattern):
                    return self._block(
                        agent_cfg.message
                        or f"Tool '{call.tool}' is denied for agent '{call.agent}'",
                        Severity.HIGH,
                        agent=call.agent, matched=pattern,
                    )

        # 3. Rules, first match wins.
        for rule in config.rules:
            if not tool_match(call.tool, rule.tool):
                continue
            matchers = (rule.match or {}).get("arguments", rule.match or {})
            if not arguments_match(call.arguments, matchers):
                continue

            action = config.action_for(rule.action, Action.BLOCK)
            severity = config.severity_for(rule.severity, Severity.HIGH)
            message = rule.message or f"Matched rule '{rule.name}'"

            if action is Action.ALLOW:
                # Allows the policy stage only. Injection, egress, command and
                # chain guards still run -- a rule cannot switch off safety.
                return self._allow(f"Rule '{rule.name}' permits this call")
            if action is Action.FLAG:
                return self._flag(message, severity, rule=rule.name)
            return self._block(message, severity, rule=rule.name)

        # 4. An allow-list, when present, is exhaustive.
        if agent_cfg and agent_cfg.allow:
            if not any(tool_match(call.tool, p) for p in agent_cfg.allow):
                return self._block(
                    agent_cfg.message
                    or f"Tool '{call.tool}' is not in the allow-list for agent '{call.agent}'",
                    Severity.MEDIUM,
                    agent=call.agent,
                )
            return self._allow(f"Tool '{call.tool}' is allow-listed for '{call.agent}'")

        # 5. Fall through to the configured default.
        if config.action_for(config.default_action, Action.ALLOW) is Action.BLOCK:
            return self._block(
                f"No rule matched '{call.tool}' and defaultAction is block",
                Severity.MEDIUM,
            )
        return None

    # -- filesystem ------------------------------------------------------

    def _check_paths(
        self, call: ToolCall, config: Config, agent_cfg: AgentConfig | None
    ) -> Finding | None:
        fs = config.filesystem
        sandbox = list(agent_cfg.sandbox) if agent_cfg and agent_cfg.sandbox else list(fs.sandbox)

        for raw in extract_paths(call.arguments, fs.fields):
            candidates = _path_candidates(raw)

            for pattern in fs.deny:
                for candidate in candidates:
                    if glob_match(candidate, pattern):
                        return self._block(
                            f"Access to a protected path was blocked: {raw}",
                            Severity.CRITICAL,
                            path=raw, matched=pattern,
                        )

            if sandbox and not _inside_sandbox(raw, sandbox):
                return self._block(
                    f"Path '{raw}' is outside the permitted sandbox",
                    Severity.HIGH,
                    path=raw, sandbox=sandbox,
                )

        return None


def resolve_agent(config: Config, call: ToolCall) -> AgentConfig | None:
    """Tenant-scoped agent config wins over the global one."""
    tenant_roles = config.tenants.get(call.tenant)
    if tenant_roles and call.agent in tenant_roles:
        return tenant_roles[call.agent]
    return config.agents.get(call.agent)


def extract_paths(arguments: dict[str, Any], path_fields: list[str]) -> list[str]:
    """Pull path-like values out of arguments, by key name, at any nesting depth."""
    wanted = {f.lower() for f in path_fields}
    found: list[str] = []

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key).lower() in wanted:
                    for text in collect_strings(value):
                        if text.strip():
                            found.append(text)
                else:
                    walk(value, depth + 1)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item, depth + 1)

    walk(arguments)
    return found


def _path_candidates(raw: str) -> list[str]:
    """The forms of a path a deny pattern should be tested against.

    Checking the resolved form as well as the literal one is what stops
    `../../../home/user/.ssh/id_rsa` from sneaking past `**/.ssh/**`.
    """
    # Strip zero-width padding and shell quoting before matching: `/e<ZWSP>tc`
    # and `.ssh"/"id_rsa` name the same targets a plain matcher would miss.
    raw = strip_invisible(raw).strip().strip("\"'")
    raw = raw.replace('"', "").replace("'", "")
    # A path argument carrying a comment or a second line is not one path.
    raw = raw.split("#")[0].strip() if "#" in raw else raw
    if "\n" in raw:
        raw = max((part.strip() for part in raw.splitlines()), key=len, default=raw)

    candidates = [normalize_path(raw)]
    try:
        expanded = os.path.expanduser(os.path.expandvars(raw))
        candidates.append(normalize_path(expanded))
        candidates.append(normalize_path(os.path.normpath(expanded)))
        candidates.append(normalize_path(os.path.abspath(expanded)))
    except (ValueError, OSError):
        pass
    # De-duplicate while keeping order stable for predictable error messages.
    seen: set[str] = set()
    return [c for c in candidates if c and not (c in seen or seen.add(c))]


def _inside_sandbox(raw: str, sandbox: list[str]) -> bool:
    """True if `raw` resolves to somewhere inside one of the sandbox roots.

    Uses realpath so a symlink pointing out of the sandbox does not count as
    being inside it.
    """
    try:
        expanded = os.path.expanduser(os.path.expandvars(raw))
        target = Path(os.path.realpath(expanded))
    except (ValueError, OSError):
        return False

    for root in sandbox:
        try:
            root_path = Path(os.path.realpath(os.path.expanduser(os.path.expandvars(root))))
        except (ValueError, OSError):
            continue
        if target == root_path:
            return True
        try:
            target.relative_to(root_path)
            return True
        except ValueError:
            continue
    return False
