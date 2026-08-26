"""The lethal-trifecta guard — structural defence against data exfiltration.

Every other guard in this package asks "does this text look malicious?".
This one asks "is private data leaving, in a session that touched untrusted
content?" — a question about dataflow, not about prose.

It fires on three escalating levels of evidence:

  1. **Confirmed leak.** A distinctive marker from private data appears in an
     outbound call, in a session that also read untrusted content. This is the
     lethal trifecta closing with evidence attached. Blocked by default.
  2. **Unattributed egress.** Private data is leaving, but nothing untrusted was
     read — so there is no injection vector. Often legitimate ("email me this
     file"). Flagged.
  3. **Risky posture.** All three legs are present but no marker crossed. The
     shape of a breach without the event. Flagged.

Nothing here depends on how an injection was phrased, which is exactly the
point: paraphrasing the attack does not paraphrase the dataflow.
"""

from __future__ import annotations

from ..config import Config
from ..models import Finding, Severity, Stage, ToolCall
from ..provenance import ProvenanceTracker, Sink, Trust, classify_tool
from .base import Guard, flatten_arguments


class TrifectaGuard(Guard):
    stage = Stage.TRIFECTA

    def __init__(self, tracker: ProvenanceTracker) -> None:
        self.tracker = tracker

    def check(self, call: ToolCall, config: Config) -> Finding | None:
        cfg = config.provenance
        if not cfg.enabled:
            return None

        trust, sink = classify_tool(
            call.tool,
            untrusted=cfg.untrusted_tools or None,
            private=cfg.private_tools or None,
            sinks=cfg.external_sinks or None,
        )

        if sink is not Sink.EXTERNAL:
            # A call to a private or untrusted tool is itself evidence of
            # exposure, even before its result comes back. Recording it here
            # means trifecta posture works for anyone who only wired up
            # `check()` — `scan()` later adds the markers that turn a posture
            # warning into a confirmed leak.
            if trust is not Trust.NEUTRAL:
                self.tracker.record_source(
                    tool=call.tool, text="", trust=trust,
                    session=call.session, agent=call.agent, tenant=call.tenant,
                )
            return None

        ledger = self.tracker.ledger(call.session, call.agent, call.tenant)
        outbound_text = flatten_arguments(call.arguments)
        leaks = ledger.leaked_markers(outbound_text)

        # Record the attempt before deciding, so the session history is honest
        # about what was tried even when the call is refused.
        self.tracker.record_sink(call.tool, call.session, call.agent, call.tenant)

        if leaks:
            sources = sorted({source for _, source in leaks})
            evidence = [_mask(marker) for marker, _ in leaks[:3]]

            if ledger.saw_untrusted:
                return self._decide(
                    cfg.action,
                    f"Lethal trifecta: private data from {', '.join(sources)} is being sent "
                    f"out via '{call.tool}', in a session that read untrusted content from "
                    f"{', '.join(ledger.untrusted_sources)}",
                    Severity.CRITICAL,
                    kind="confirmed_leak",
                    private_sources=sources,
                    untrusted_sources=ledger.untrusted_sources,
                    sink=call.tool,
                    evidence=evidence,
                )

            return self._decide(
                cfg.egress_action,
                f"Private data from {', '.join(sources)} is being sent out via "
                f"'{call.tool}'",
                Severity.HIGH,
                kind="unattributed_egress",
                private_sources=sources,
                sink=call.tool,
                evidence=evidence,
            )

        if ledger.trifecta(sink_available=True):
            return self._decide(
                cfg.trifecta_action,
                f"Lethal trifecta posture: this session read private data "
                f"({', '.join(ledger.private_sources)}), read untrusted content "
                f"({', '.join(ledger.untrusted_sources)}), and is now calling the "
                f"outbound tool '{call.tool}'",
                Severity.HIGH,
                kind="risky_posture",
                private_sources=ledger.private_sources,
                untrusted_sources=ledger.untrusted_sources,
                sink=call.tool,
            )

        return None

    def reset(self) -> None:
        self.tracker.reset()


def _mask(marker: str) -> str:
    """Show enough of a marker to investigate, not enough to leak it further."""
    if len(marker) <= 8:
        return marker[0] + "…" + marker[-1] if len(marker) > 2 else "…"
    return f"{marker[:4]}…{marker[-3:]}"
