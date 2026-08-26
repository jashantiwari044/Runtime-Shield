"""The Shield engine — one object, two verbs.

    from shield import Shield

    shield = Shield()

    if shield.check("exec", {"command": cmd}, agent="my-agent").blocked:
        refuse()

    safe_text = shield.scan(tool_output).content

Guards run in a fixed order, cheapest and most decisive first, and the first
blocking finding wins. Every guard is independent: a policy rule that allows a
call cannot switch off injection, egress, command or chain checks.
"""

from __future__ import annotations

import functools
import logging
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .config import Config, load_config
from .guards.base import Guard, OutboundGuard
from .guards.chain import ChainGuard
from .guards.command import CommandGuard
from .guards.egress import EgressGuard
from .guards.injection import InjectionGuard
from .guards.kill_switch import KillSwitch
from .guards.pii import PIIDetector
from .guards.policy import PolicyGuard
from .guards.rate_limit import RateLimiter
from .guards.secrets import SecretScanner
from .guards.trifecta import TrifectaGuard
from .models import Action, Decision, Finding, ScanResult, Severity, Stage, ToolCall
from .provenance import ProvenanceTracker, Trust, classify_tool

log = logging.getLogger("shield")

Listener = Callable[[dict[str, Any]], None]


class ShieldError(RuntimeError):
    """Raised by `Shield.enforce` when a call is blocked."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.reason or "blocked by Runtime Shield")
        self.decision = decision


class Shield:
    """Runtime security for AI agents.

    Args:
        config_path: path to a shield.yaml. Discovered from the working
            directory upwards when omitted.
        config: a ready-made Config, bypassing file loading.
    """

    def __init__(
        self,
        config_path: str | Path | None = None,
        config: Config | None = None,
    ) -> None:
        self.config = config if config is not None else load_config(config_path)
        self.audit = AuditLog(self.config.audit)

        self.provenance = ProvenanceTracker(
            ttl_seconds=self.config.provenance.session_ttl_seconds,
            max_sessions=self.config.provenance.max_sessions,
        )

        self._inbound: list[Guard] = [
            KillSwitch(),
            RateLimiter(),
            PolicyGuard(),
            CommandGuard(),
            InjectionGuard(),
            EgressGuard(),
            ChainGuard(),
            TrifectaGuard(self.provenance),
        ]
        self._outbound: list[OutboundGuard] = [SecretScanner(), PIIDetector()]

        self._lock = threading.Lock()
        self._events: deque[dict[str, Any]] = deque(maxlen=self.config.server.max_events)
        self._counters: Counter[str] = Counter()
        self._listeners: list[Listener] = []
        self._started = time.time()

    # -- core API ---------------------------------------------------------

    def check(
        self,
        tool: str,
        arguments: dict[str, Any] | None = None,
        agent: str = "default",
        tenant: str = "default",
        session: str | None = None,
    ) -> Decision:
        """Decide whether an agent may make this tool call.

        `session` scopes dataflow tracking to one unit of agent work. Pass a
        stable id per task or conversation; it defaults to the agent name.
        """
        call = ToolCall(
            tool=tool,
            arguments=dict(arguments or {}),
            agent=agent,
            tenant=tenant,
            session=session or agent,
        )
        started = time.perf_counter()

        findings: list[Finding] = []
        decision = Decision(action=Action.ALLOW, call_id=call.id)

        for guard in self._inbound:
            try:
                finding = guard.check(call, self.config)
            except Exception as exc:  # a broken guard must not open the gate
                # Loud on purpose: a guard that throws is a guard that is not
                # protecting anything, and the failure is otherwise invisible
                # because the pipeline deliberately keeps going.
                log.error("guard %s raised %s: %s", type(guard).__name__,
                          type(exc).__name__, exc, exc_info=True)
                finding = Finding(
                    stage=getattr(guard, "stage", Stage.POLICY),
                    action=Action.FLAG,
                    reason=f"Guard {type(guard).__name__} errored: {exc}",
                    severity=Severity.MEDIUM,
                    details={"error": type(exc).__name__},
                )

            if finding is None:
                continue
            if finding.action is Action.ALLOW:
                # An explicit policy allow ends the *policy* question only.
                continue

            findings.append(finding)
            if finding.action is Action.BLOCK:
                decision = Decision(
                    action=Action.BLOCK,
                    reason=finding.reason,
                    severity=finding.severity,
                    stage=finding.stage,
                    call_id=call.id,
                )
                break

        if decision.action is not Action.BLOCK and findings:
            # Guards run general-to-specific, so on a severity tie the later
            # finding is the more informative one: "private data is leaving in
            # a session that read untrusted content" beats "read then send".
            worst = max(enumerate(findings), key=lambda p: (p[1].severity.rank, p[0]))[1]
            decision = Decision(
                action=Action.FLAG,
                reason=worst.reason,
                severity=worst.severity,
                stage=worst.stage,
                call_id=call.id,
            )

        # Monitor mode records the verdict but never actually stops anything.
        if decision.action is Action.BLOCK and self.config.monitor_only:
            decision = Decision(
                action=Action.FLAG,
                reason=f"[monitor] would block: {decision.reason}",
                severity=decision.severity,
                stage=decision.stage,
                call_id=call.id,
            )

        decision.findings = findings
        decision.latency_ms = (time.perf_counter() - started) * 1000
        self._publish(self.audit.record(call, decision))
        return decision

    def scan(
        self,
        text: str,
        tool: str = "",
        agent: str = "default",
        tenant: str = "default",
        session: str | None = None,
        trust: str | Trust | None = None,
    ) -> ScanResult:
        """Scan (and redact) text coming back from a tool or a model.

        Passing `tool` also records provenance: the result is classified as
        private, untrusted or neutral, and private data contributes markers the
        trifecta guard watches for on the way out. Pass `trust` to override the
        automatic classification.
        """
        started = time.perf_counter()
        if tool:
            self.observe(text, tool=tool, agent=agent, tenant=tenant,
                         session=session, trust=trust)
        original = text or ""
        current = original
        findings: list[Finding] = []

        for guard in self._outbound:
            try:
                current, guard_findings = guard.scan(current, self.config)
            except Exception as exc:
                findings.append(Finding(
                    stage=getattr(guard, "stage", Stage.SECRETS),
                    action=Action.FLAG,
                    reason=f"Guard {type(guard).__name__} errored: {exc}",
                    severity=Severity.MEDIUM,
                ))
                continue
            findings.extend(guard_findings)

        result = ScanResult(
            content=current,
            original=original,
            findings=findings,
            latency_ms=(time.perf_counter() - started) * 1000,
        )

        if findings:
            worst = max(enumerate(findings), key=lambda p: (p[1].severity.rank, p[0]))[1]
            call = ToolCall(tool=tool or "scan", agent=agent, tenant=tenant,
                            session=session or agent)
            decision = Decision(
                action=worst.action,
                reason=worst.reason,
                severity=worst.severity,
                stage=worst.stage,
                findings=findings,
                latency_ms=result.latency_ms,
                call_id=call.id,
            )
            self._publish(self.audit.record(call, decision, kind="scan"))

        return result

    def observe(
        self,
        text: str,
        tool: str,
        agent: str = "default",
        tenant: str = "default",
        session: str | None = None,
        trust: str | Trust | None = None,
    ) -> None:
        """Record where a piece of data came from, without scanning it.

        `shield.scan(text, tool=...)` calls this for you. Use it directly when
        you want provenance tracked but no redaction — for example on a web
        page the agent fetched, which is untrusted but rarely contains your
        secrets.
        """
        cfg = self.config.provenance
        if not cfg.enabled or not tool:
            return

        if trust is None:
            resolved, _sink = classify_tool(
                tool,
                untrusted=cfg.untrusted_tools or None,
                private=cfg.private_tools or None,
                sinks=cfg.external_sinks or None,
            )
        else:
            try:
                resolved = Trust(str(trust).lower())
            except ValueError:
                resolved = Trust.NEUTRAL

        if resolved is Trust.NEUTRAL:
            return

        self.provenance.record_source(
            tool=tool, text=text or "", trust=resolved,
            session=session or agent, agent=agent, tenant=tenant,
        )

    def sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        """Dataflow state for recent sessions — what each one has touched."""
        return self.provenance.sessions(limit=limit)

    def enforce(
        self,
        tool: str,
        arguments: dict[str, Any] | None = None,
        agent: str = "default",
        tenant: str = "default",
        session: str | None = None,
    ) -> Decision:
        """`check`, but raises ShieldError instead of returning a blocked Decision."""
        decision = self.check(tool, arguments, agent=agent, tenant=tenant, session=session)
        if decision.blocked:
            raise ShieldError(decision)
        return decision

    # -- ergonomics -------------------------------------------------------

    def protect(
        self,
        tool: str | None = None,
        agent: str = "default",
        scan_result: bool = True,
    ) -> Callable:
        """Decorator that guards a tool function on the way in and out.

            @shield.protect()
            def read_file(path: str) -> str:
                return open(path).read()

        Raises ShieldError when the call is blocked; redacts the return value
        when it contains secrets or PII.
        """

        def decorator(func: Callable) -> Callable:
            name = tool or func.__name__

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                arguments = dict(kwargs)
                if args:
                    try:
                        names = func.__code__.co_varnames[: func.__code__.co_argcount]
                        arguments.update(dict(zip(names, args, strict=False)))
                    except AttributeError:
                        arguments["args"] = list(args)
                self.enforce(name, arguments, agent=agent)
                output = func(*args, **kwargs)
                if scan_result and isinstance(output, str):
                    return self.scan(output, tool=name, agent=agent).content
                return output

            return wrapper

        return decorator

    def wrap_tools(self, tools: dict[str, Callable], agent: str = "default") -> dict[str, Callable]:
        """Guard a whole dict of `{name: callable}` tools at once."""
        return {
            name: self.protect(tool=name, agent=agent)(func) for name, func in tools.items()
        }

    # -- operations -------------------------------------------------------

    def reload(self, config_path: str | Path | None = None) -> Config:
        """Re-read configuration without dropping counters or history."""
        self.config = load_config(config_path)
        self.audit = AuditLog(self.config.audit)
        return self.config

    def reset(self) -> None:
        """Clear rate-limit and chain state. Used by tests and /v1/reset."""
        for guard in self._inbound:
            guard.reset()
        self.provenance.reset()
        with self._lock:
            self._events.clear()
            self._counters.clear()

    def on_event(self, listener: Listener) -> Listener:
        """Register a callback fired for every decision (the dashboard uses this)."""
        self._listeners.append(listener)
        return listener

    def events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)[-limit:]

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            counters = dict(self._counters)
            recent = list(self._events)
        total = counters.get("total", 0)
        blocked = counters.get("blocked", 0)
        latencies = sorted(e.get("latency_ms", 0.0) for e in recent) or [0.0]
        return {
            "total": total,
            "allowed": counters.get("allowed", 0),
            "blocked": blocked,
            "flagged": counters.get("flagged", 0),
            "redacted": counters.get("redacted", 0),
            "block_rate": round(blocked / total, 4) if total else 0.0,
            "by_stage": {k[6:]: v for k, v in counters.items() if k.startswith("stage:")},
            "by_agent": {k[6:]: v for k, v in counters.items() if k.startswith("agent:")},
            "by_severity": {k[9:]: v for k, v in counters.items() if k.startswith("severity:")},
            "latency_ms": {
                "p50": round(latencies[len(latencies) // 2], 3),
                "p95": round(latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))], 3),
                "max": round(latencies[-1], 3),
            },
            "uptime_seconds": int(time.time() - self._started),
            "audit_entries": self.audit.entry_count,
            "mode": self.config.mode,
            "sessions": self._session_stats(),
        }

    def _session_stats(self) -> dict[str, int]:
        """Dataflow posture across live sessions.

        Computed here rather than in the HTTP handler so the WebSocket init
        payload, the JSON metrics and the Prometheus scrape all agree.
        """
        active = self.provenance.sessions(limit=500)
        return {
            "active": len(active),
            "trifecta": sum(1 for e in active if e["trifecta"]),
            "tracking_private_data": sum(1 for e in active if e["saw_private"]),
        }

    def _publish(self, entry: dict[str, Any]) -> None:
        action = entry.get("action", "allow")
        with self._lock:
            self._events.append(entry)
            self._counters["total"] += 1
            self._counters[{"block": "blocked", "flag": "flagged",
                            "redact": "redacted"}.get(action, "allowed")] += 1
            if entry.get("stage"):
                self._counters[f"stage:{entry['stage']}"] += 1
            self._counters[f"agent:{entry.get('agent', 'default')}"] += 1
            if action != "allow":
                self._counters[f"severity:{entry.get('severity', 'info')}"] += 1

        for listener in list(self._listeners):
            try:
                listener(entry)
            except Exception:
                # A bad listener must never break the request path.
                log.debug("event listener failed", exc_info=True)
