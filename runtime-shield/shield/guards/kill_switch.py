"""Kill switch — one file on disk stops every agent action immediately."""

from __future__ import annotations

from pathlib import Path

from ..config import Config
from ..models import Finding, Severity, Stage, ToolCall
from .base import Guard


class KillSwitch(Guard):
    """Blocks everything while the kill file exists.

    Deliberately a filesystem check, not a config flag: an operator can stop a
    runaway agent with `touch .shield-kill` without a restart or a deploy, and
    it works even if the shield's own API is wedged.
    """

    stage = Stage.KILL_SWITCH

    def check(self, call: ToolCall, config: Config) -> Finding | None:
        if not config.kill_switch.enabled:
            return None
        if Path(config.kill_switch.file).exists():
            return self._block(
                "Kill switch engaged — all agent activity is halted",
                Severity.CRITICAL,
                file=config.kill_switch.file,
            )
        return None
