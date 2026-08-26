"""Chain detection — spot multi-step attacks that look harmless step by step.

`read_file(~/.aws/credentials)` is fine. `http_post(...)` is fine. Doing the
second right after the first is the shape of an exfiltration.

Defaults to `flag` rather than `block`, because a chain is circumstantial: the
tool names that matter differ per stack, and read-then-write is completely
normal for a coding agent. Tune `chains:` for your tools, then switch to block.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any

from ..config import Config
from ..matching import tool_match
from ..models import Finding, Severity, Stage, ToolCall
from .base import Guard

# Each chain: reading/collecting tools -> acting tools that leave the machine.
DEFAULT_CHAINS: list[dict[str, Any]] = [
    {
        "name": "read-then-exfiltrate",
        "after": ["read_file", "read", "get_file*", "view_file", "cat", "open_file",
                  "load_file", "fetch_secret", "get_env*", "list_secrets"],
        "then": ["http_post", "post", "fetch_url", "http_request", "send_request",
                 "curl", "wget", "upload*", "send_email", "send_message", "webhook*"],
        "reason": "Sensitive read followed by an outbound send",
        "severity": "high",
    },
    {
        "name": "recon-then-exfiltrate",
        "after": ["list_directory", "list_files", "glob", "find", "search_files", "tree"],
        "then": ["http_post", "post", "fetch_url", "send_request", "upload*", "webhook*"],
        "reason": "Filesystem reconnaissance followed by an outbound send",
        "severity": "medium",
    },
    {
        "name": "query-then-exfiltrate",
        "after": ["query", "sql*", "execute_sql", "db_query", "database_query", "select"],
        "then": ["http_post", "post", "fetch_url", "send_request", "send_email", "upload*"],
        "reason": "Database query followed by an outbound send",
        "severity": "high",
    },
    {
        "name": "download-then-execute",
        "after": ["fetch_url", "download*", "http_get", "get", "wget", "curl"],
        "then": ["exec", "shell_exec", "run_command", "execute_command", "bash", "sh",
                 "run_script", "python_exec"],
        "reason": "Remote download followed by code execution",
        "severity": "critical",
    },
]


class ChainGuard(Guard):
    stage = Stage.CHAIN

    def __init__(self, max_history: int = 64) -> None:
        self._lock = threading.Lock()
        self._history: dict[str, deque[tuple[str, float]]] = defaultdict(
            lambda: deque(maxlen=max_history)
        )

    def check(self, call: ToolCall, config: Config) -> Finding | None:
        cfg = config.chain
        if not cfg.enabled:
            return None

        chains = cfg.chains or DEFAULT_CHAINS
        key = f"{call.tenant}:{call.agent}"
        now = time.time()
        # A window of 0 means no memory at all, so do not clamp it upward.
        cutoff = now - max(0, cfg.window_seconds)

        with self._lock:
            history = self._history[key]
            while history and history[0][1] <= cutoff:
                history.popleft()
            recent = [tool for tool, _ in history]
            history.append((call.tool, now))

        for chain in chains:
            then = chain.get("then") or []
            if not any(tool_match(call.tool, p) for p in then):
                continue
            after = chain.get("after") or []
            matched = [t for t in recent if any(tool_match(t, p) for p in after)]
            if not matched:
                continue

            severity = config.severity_for(chain.get("severity", "high"), Severity.HIGH)
            reason = chain.get("reason") or chain.get("name", "Suspicious tool sequence")
            return self._decide(
                cfg.action,
                f"Suspicious tool chain: {reason}",
                severity,
                chain=chain.get("name", "unnamed"),
                sequence=[*dict.fromkeys(matched)][-3:] + [call.tool],
            )
        return None

    def reset(self) -> None:
        with self._lock:
            self._history.clear()
