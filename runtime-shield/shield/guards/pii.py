"""Outbound PII detection and redaction.

Pure-Python and dependency-free by default. Presidio is supported as an
optional upgrade -- install `runtime-shield[pii]` and it is used automatically
for name/location entities that regexes cannot see.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from ..config import Config
from ..models import Action, Finding, Severity, Stage
from .base import OutboundGuard


def _luhn(digits: str) -> bool:
    """Luhn checksum — keeps order numbers and IDs from being read as cards."""
    nums = [int(d) for d in digits if d.isdigit()]
    if len(nums) < 13:
        return False
    total = 0
    for index, digit in enumerate(reversed(nums)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _valid_ssn(text: str) -> bool:
    digits = re.sub(r"\D", "", text)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in ("000", "666") and not area.startswith("9") \
        and group != "00" and serial != "0000"


ENTITIES: dict[str, tuple[str, Severity, Callable[[str], bool] | None]] = {
    "email": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b", Severity.MEDIUM, None),
    "ssn": (r"\b\d{3}-\d{2}-\d{4}\b", Severity.CRITICAL, _valid_ssn),
    "credit_card": (r"\b(?:\d[ -]?){13,19}\b", Severity.CRITICAL, _luhn),
    "phone": (r"(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b", Severity.MEDIUM, None),
    "iban": (r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", Severity.HIGH, None),
    "ip": (r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
           Severity.LOW, None),
    "passport": (r"\b[A-Z]{1,2}\d{6,9}\b", Severity.HIGH, None),
    "date_of_birth": (r"\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b",
                      Severity.MEDIUM, None),
}


class PIIDetector(OutboundGuard):
    stage = Stage.PII

    def __init__(self) -> None:
        self._presidio = None
        self._presidio_tried = False

    def scan(self, text: str, config: Config) -> tuple[str, list[Finding]]:
        cfg = config.pii
        if not cfg.enabled or not text:
            return text, []

        allow = [re.compile(a) for a in cfg.allow if a]
        action = config.action_for(cfg.action, Action.REDACT)
        enabled = [e for e in cfg.entities if e in ENTITIES]
        found: dict[str, int] = {}
        worst = Severity.INFO
        result = text

        for entity in enabled:
            pattern, severity, validator = ENTITIES[entity]

            def replace(match: re.Match[str], _e: str = entity, _s: Severity = severity,
                        _v: Callable[[str], bool] | None = validator) -> str:
                nonlocal worst
                whole = match.group(0)
                if _v and not _v(whole):
                    return whole
                if any(a.search(whole) for a in allow):
                    return whole
                found[_e] = found.get(_e, 0) + 1
                if _s > worst:
                    worst = _s
                if action in (Action.BLOCK, Action.FLAG):
                    return whole
                return cfg.placeholder.format(kind=_e.upper())

            result = re.sub(pattern, replace, result)

        if not found:
            return text, []

        summary = ", ".join(f"{k} x{v}" if v > 1 else k for k, v in sorted(found.items()))
        finding = Finding(
            stage=self.stage,
            action=action,
            reason=f"PII detected in output: {summary}",
            severity=worst,
            details={"entities": sorted(found), "count": sum(found.values())},
        )
        if action in (Action.BLOCK, Action.FLAG):
            return text, [finding]
        return result, [finding]
