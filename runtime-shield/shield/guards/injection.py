"""Prompt-injection detection.

Tuned hard for precision. The previous ruleset blocked the phrase "act as a
reviewer" and every string containing "override", which made the shield
unusable on ordinary traffic -- and an unusable guard gets switched off, which
is worse than a slightly narrower one.

Tiers:
  low     unambiguous attack strings only; safe to block anywhere
  medium  adds strong heuristics (default)
  high    adds fuzzy heuristics; expect false positives, prefer action: flag
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..config import Config
from ..models import Finding, Severity, Stage, ToolCall
from ..normalize import text_variants
from .base import Guard, collect_strings

_Rule = tuple[str, str, Severity]

# --- tier 1: no legitimate text looks like this -------------------------
PATTERNS_LOW: list[_Rule] = [
    (r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|preceding|above|earlier)\s+"
     r"(?:instructions?|prompts?|rules?|directions?|commands?)",
     "Instruction override", Severity.CRITICAL),
    (r"disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system)\s+"
     r"(?:instructions?|prompts?|rules?|messages?)",
     "Instruction override", Severity.CRITICAL),
    (r"<\|im_(?:start|end)\|>|<\|endoftext\|>|<\|system\|>",
     "Chat template injection", Severity.CRITICAL),
    (r"\[/?INST\]|<<\s*/?SYS\s*>>",
     "Llama template injection", Severity.CRITICAL),
    (r"^\s*system\s*:\s*you\s+are\b",
     "System prompt injection", Severity.CRITICAL),
    (r"[\U000E0000-\U000E007F]",
     "Unicode tag smuggling", Severity.CRITICAL),
    (r"(?:reveal|print|output|repeat|show|display|dump)\s+(?:me\s+)?(?:your|the)\s+"
     r"(?:full\s+|complete\s+|initial\s+|original\s+|exact\s+)?(?:system\s+)?"
     r"(?:prompt|instructions?)\b",
     "System prompt extraction", Severity.HIGH),
]

# --- tier 2: strong heuristics ------------------------------------------
PATTERNS_MEDIUM: list[_Rule] = PATTERNS_LOW + [
    (r"forget\s+(?:everything|all)\b|forget\s+(?:your|the)\s+(?:previous|prior|earlier)\b",
     "Memory wipe attempt", Severity.HIGH),
    (r"do\s+not\s+(?:follow|obey|comply\s+with)\s+(?:any\s+)?(?:the\s+)?"
     r"(?:previous|prior|above|earlier|system)\b",
     "Instruction negation", Severity.HIGH),
    (r"\b(?:developer|debug|god|jailbreak|unrestricted|unfiltered)\s+mode\b",
     "Jailbreak mode request", Severity.HIGH),
    (r"\byou\s+are\s+now\s+(?:a\s+|an\s+|in\s+)?(?:DAN|STAN|AIM|evil|unrestricted|unfiltered)\b",
     "Known jailbreak persona", Severity.HIGH),
    (r"\bnew\s+(?:system\s+)?instructions?\s*:",
     "Injected instruction block", Severity.HIGH),
    (r"(?:bypass|disable|turn\s+off|ignore|circumvent|override)\s+(?:all\s+|the\s+|your\s+|any\s+)?"
     r"(?:safety|security|guard\s?rails?|filters?|restrictions?|policies|policy|moderation)",
     "Safety bypass request", Severity.CRITICAL),
    (r"<!--[^>]{0,400}?(?:ignore|instruction|system\s+prompt|you\s+must|do\s+not\s+tell)[^>]{0,400}?-->",
     "Hidden instructions in HTML comment", Severity.HIGH),
    (r"(?:send|post|upload|exfiltrate|transmit|leak)\s+(?:the\s+|all\s+|your\s+)?"
     r"(?:api[\s_-]*keys?|credentials?|secrets?|passwords?|tokens?|env(?:ironment)?\s+variables?)",
     "Credential exfiltration request", Severity.CRITICAL),
    (r"[​‌⁠﻿]{3,}",
     "Zero-width character run", Severity.MEDIUM),
]

# --- tier 3: fuzzy; useful as signal, noisy as a block ------------------
PATTERNS_HIGH: list[_Rule] = PATTERNS_MEDIUM + [
    (r"\bpretend\s+(?:that\s+)?(?:you\s+(?:are|were)|to\s+be)\b",
     "Persona hijack", Severity.MEDIUM),
    (r"\bact\s+as\s+(?:if\s+you\s+(?:are|were)|an?\s+unrestricted)\b",
     "Role impersonation", Severity.MEDIUM),
    (r"\bthis\s+is\s+(?:very\s+)?(?:important|urgent)\s*[:!]",
     "Priority escalation", Severity.LOW),
    (r"[A-Za-z0-9+/]{120,}={0,2}",
     "Long base64 blob", Severity.LOW),
]

TIERS = {"low": PATTERNS_LOW, "medium": PATTERNS_MEDIUM, "high": PATTERNS_HIGH}

_COMPILED: dict[str, list[tuple[re.Pattern[str], str, Severity]]] = {
    tier: [(re.compile(p, re.IGNORECASE | re.MULTILINE), label, sev) for p, label, sev in rules]
    for tier, rules in TIERS.items()
}


class InjectionGuard(Guard):
    stage = Stage.INJECTION

    def check(self, call: ToolCall, config: Config) -> Finding | None:
        cfg = config.injection
        if not cfg.enabled:
            return None

        rules = _COMPILED.get(str(cfg.sensitivity).lower(), _COMPILED["medium"])
        untrusted = {f.lower() for f in cfg.untrusted_fields}

        for text, field_name in _iter_texts(call.arguments):
            if len(text) < 4:
                continue
            # Homoglyphs, zero-width padding and percent-encoding all render as
            # the same sentence to a model, so they must read the same to us.
            for variant in text_variants(text):
                for pattern, label, severity in rules:
                    match = pattern.search(variant)
                    if not match:
                        continue
                    if field_name.lower() in untrusted and severity < Severity.CRITICAL:
                        severity = Severity.CRITICAL
                    return self._decide(
                        cfg.action,
                        f"Prompt injection detected: {label}",
                        severity,
                        pattern=label,
                        field=field_name,
                        matched=match.group(0)[:120],
                    )
        return None


def _iter_texts(arguments: dict, depth: int = 0) -> Iterable[tuple[str, str]]:
    """Yield (text, originating field name) for every string in the arguments."""
    if depth > 8:
        return
    for key, value in arguments.items():
        if isinstance(value, str):
            yield value, str(key)
        elif isinstance(value, dict):
            yield from _iter_texts(value, depth + 1)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, dict):
                    yield from _iter_texts(item, depth + 1)
                else:
                    for text in collect_strings(item):
                        yield text, str(key)
