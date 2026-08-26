"""Rate limiting — global, per-agent, and per-agent-per-tool sliding windows."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from ..config import Config
from ..models import Finding, Severity, Stage, ToolCall
from .base import Guard

_UNITS = {"s": 1, "sec": 1, "second": 1, "m": 60, "min": 60, "minute": 60,
          "h": 3600, "hour": 3600, "d": 86400, "day": 86400}


def parse_rate(spec: str) -> tuple[int, int]:
    """Parse '100/min' into (100, 60). Returns (0, 60) if unparseable."""
    try:
        count_str, _, unit = str(spec).strip().partition("/")
        count = int(count_str)
        return count, _UNITS.get(unit.strip().lower().rstrip("s") or "min", 60)
    except (ValueError, AttributeError):
        return 0, 60


class _Window:
    """Sliding window over a deque — O(1) amortised, bounded memory."""

    __slots__ = ("_ticks",)

    def __init__(self) -> None:
        self._ticks: deque[float] = deque()

    def count(self, window_seconds: int, now: float) -> int:
        cutoff = now - window_seconds
        ticks = self._ticks
        while ticks and ticks[0] <= cutoff:
            ticks.popleft()
        return len(ticks)

    def add(self, now: float) -> None:
        self._ticks.append(now)


class RateLimiter(Guard):
    """Enforce call-rate ceilings so a looping agent cannot melt a downstream."""

    stage = Stage.RATE_LIMIT

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._global = _Window()
        self._per_agent: dict[str, _Window] = defaultdict(_Window)

    def check(self, call: ToolCall, config: Config) -> Finding | None:
        if not config.rate_limit.enabled:
            return None

        now = time.time()
        agent_key = f"{call.tenant}:{call.agent}"
        agent_cfg = _agent_config(config, call)

        with self._lock:
            limit = config.rate_limit.max_calls
            window = config.rate_limit.window_seconds
            if limit > 0:
                used = self._global.count(window, now)
                if used >= limit:
                    return self._block(
                        f"Global rate limit reached ({used}/{limit} calls in {window}s)",
                        Severity.MEDIUM, scope="global", used=used, limit=limit,
                    )

            if agent_cfg and agent_cfg.rate_limit:
                a_limit, a_window = parse_rate(agent_cfg.rate_limit)
                if a_limit > 0:
                    used = self._per_agent[agent_key].count(a_window, now)
                    if used >= a_limit:
                        return self._block(
                            f"Rate limit reached for '{call.agent}' "
                            f"({used}/{a_limit} calls in {a_window}s)",
                            Severity.MEDIUM,
                            scope="agent", agent=call.agent, used=used, limit=a_limit,
                        )

            # Only count calls that were not rejected by a limit.
            self._global.add(now)
            self._per_agent[agent_key].add(now)

        return None

    def reset(self) -> None:
        with self._lock:
            self._global = _Window()
            self._per_agent.clear()


def _agent_config(config: Config, call: ToolCall):
    """Tenant-scoped agent config wins over the global one."""
    tenant_roles = config.tenants.get(call.tenant)
    if tenant_roles and call.agent in tenant_roles:
        return tenant_roles[call.agent]
    return config.agents.get(call.agent)
