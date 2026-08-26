"""Time-travel policy replay — what would this change have done to real traffic?

Editing a security policy is a blind act. You tighten a rule and hope you have
not just broken the agent that ships your invoices; you loosen one and hope you
have not just opened a hole. The feedback arrives days later as an incident or
a complaint.

Replay closes that loop. It takes decisions the shield has already made and
re-evaluates them against a candidate config, then diffs the outcomes:

    $ shield replay --against candidate.yaml
    CHANGED 7 of 1,284
      now blocked (were allowed): 5
      now allowed (were blocked): 2   <- review these before deploying

Requires `audit.capture_arguments: true`, because argument-dependent guards
cannot re-decide on a hash. Without it, replay still runs on tool and agent
identity alone and reports the reduced fidelity rather than pretending.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Config, load_config
from .engine import Shield


@dataclass
class Change:
    """One decision whose outcome differs under the candidate policy."""

    tool: str
    agent: str
    before: str
    after: str
    before_reason: str
    after_reason: str
    before_stage: str | None
    after_stage: str | None
    arguments: dict[str, Any] = field(default_factory=dict)

    @property
    def newly_blocked(self) -> bool:
        return self.after == "block" and self.before != "block"

    @property
    def newly_allowed(self) -> bool:
        return self.before == "block" and self.after != "block"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "agent": self.agent,
            "before": self.before, "after": self.after,
            "before_reason": self.before_reason, "after_reason": self.after_reason,
            "before_stage": self.before_stage, "after_stage": self.after_stage,
            "newly_blocked": self.newly_blocked, "newly_allowed": self.newly_allowed,
        }


@dataclass
class ReplayReport:
    total: int = 0
    unchanged: int = 0
    changes: list[Change] = field(default_factory=list)
    skipped: int = 0
    without_arguments: int = 0

    @property
    def newly_blocked(self) -> list[Change]:
        return [c for c in self.changes if c.newly_blocked]

    @property
    def newly_allowed(self) -> list[Change]:
        return [c for c in self.changes if c.newly_allowed]

    @property
    def full_fidelity(self) -> bool:
        """False when entries lacked arguments, so the diff is approximate."""
        return self.without_arguments == 0

    def summary(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "unchanged": self.unchanged,
            "changed": len(self.changes),
            "newly_blocked": len(self.newly_blocked),
            "newly_allowed": len(self.newly_allowed),
            "skipped": self.skipped,
            "without_arguments": self.without_arguments,
            "full_fidelity": self.full_fidelity,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.summary(), "changes": [c.to_dict() for c in self.changes]}

    def top_changes(self, limit: int = 10) -> list[tuple[str, int]]:
        """The most common (tool, transition) pairs, for a compact report."""
        counter: Counter[str] = Counter(
            f"{c.tool}: {c.before} -> {c.after}" for c in self.changes
        )
        return counter.most_common(limit)


def read_audit(path: str | Path) -> Iterator[dict[str, Any]]:
    """Stream audit entries from a JSONL file, skipping unreadable lines."""
    file = Path(path)
    if not file.exists():
        return
    with file.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def replay(
    audit_path: str | Path,
    candidate: Config | str | Path,
    limit: int | None = None,
) -> ReplayReport:
    """Re-evaluate recorded decisions against a candidate policy.

    Args:
        audit_path: the JSONL audit log to replay.
        candidate: a Config, or a path to the candidate shield.yaml.
        limit: only replay the most recent N entries.
    """
    config = candidate if isinstance(candidate, Config) else load_config(candidate)

    # Replaying must not write a second audit log or trip the kill switch of
    # the machine doing the analysis.
    config.audit.enabled = False
    config.kill_switch.enabled = False
    # Rate limits and chains are stateful over wall-clock time; replaying a
    # day of traffic in a second would fire every one of them spuriously.
    config.rate_limit.enabled = False
    config.chain.enabled = False

    shield = Shield(config=config)
    report = ReplayReport()

    entries = list(read_audit(audit_path))
    if limit:
        entries = entries[-limit:]

    for entry in entries:
        if entry.get("kind") == "scan":
            report.skipped += 1
            continue

        tool = entry.get("tool") or ""
        if not tool:
            report.skipped += 1
            continue

        arguments = entry.get("arguments")
        if arguments is None:
            report.without_arguments += 1
            arguments = {}
        if not isinstance(arguments, dict):
            arguments = {}

        report.total += 1
        before = entry.get("action", "allow")

        decision = shield.check(
            tool,
            arguments,
            agent=entry.get("agent", "default"),
            tenant=entry.get("tenant", "default"),
            session=entry.get("session") or entry.get("agent", "default"),
        )
        after = decision.action.value

        if _same_outcome(before, after):
            report.unchanged += 1
            continue

        report.changes.append(Change(
            tool=tool,
            agent=entry.get("agent", "default"),
            before=before,
            after=after,
            before_reason=entry.get("reason", ""),
            after_reason=decision.reason,
            before_stage=entry.get("stage"),
            after_stage=decision.stage.value if decision.stage else None,
            arguments=arguments,
        ))

    return report


def _same_outcome(before: str, after: str) -> bool:
    """Compare on the decision that matters: blocked or not blocked.

    A call moving from `allow` to `flag` is a change in observability, not in
    what the agent was permitted to do, so it is not reported as a diff.
    """
    return (before == "block") == (after == "block")
