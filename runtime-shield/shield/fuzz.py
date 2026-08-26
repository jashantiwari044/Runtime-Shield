"""Mutation fuzzer — find the bypasses in your own policy before someone else does.

`shield test` proves the shipped attacks are caught. That is a floor, not a
guarantee: an attacker does not send the canonical phrasing, they send the one
that slips through. This module takes every attack the shield *does* block,
generates variants that mean the same thing, and reports any that get through.

The mutations are the ones attackers actually reach for — case games, unicode
homoglyphs, zero-width padding, shell string-splitting, encoding wrappers — not
random byte flips, which produce noise rather than bypasses.

    $ shield fuzz
    3 bypasses found from 24 attacks × 14 mutations (336 variants)
      exec(command=…)  via split-strings   r""m -rf /
"""

from __future__ import annotations

import base64
import random
import re
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .engine import Shield

Mutator = Callable[[str], str]

# Homoglyphs that render near-identically but are different code points.
_HOMOGLYPHS = {
    "a": "а", "c": "с", "e": "е", "i": "і",
    "o": "о", "p": "р", "s": "ѕ", "x": "х",
}
_ZERO_WIDTH = "​"
_LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}


def m_identity(text: str) -> str:
    return text


def m_upper(text: str) -> str:
    return text.upper()


def m_alternating_case(text: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(text))


def m_extra_spaces(text: str) -> str:
    return re.sub(r" ", "  ", text)


def m_tabs(text: str) -> str:
    return text.replace(" ", "\t")


def m_newline_split(text: str) -> str:
    """Break the string across lines — many regexes are not MULTILINE."""
    return text.replace(" ", " \\\n  ", 1) if " " in text else text


def m_leading_noise(text: str) -> str:
    return f"# harmless comment\n{text}"


def m_trailing_noise(text: str) -> str:
    return f"{text}   # just cleaning up"


def m_zero_width(text: str) -> str:
    """Insert zero-width spaces inside the first word."""
    if len(text) < 4:
        return text
    return text[:2] + _ZERO_WIDTH + text[2:]


def m_homoglyph(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(c, c) for c in text)


def m_leetspeak(text: str) -> str:
    return "".join(_LEET.get(c, c) for c in text)


def m_split_strings(text: str) -> str:
    """Shell string-splitting: `rm` becomes `r""m`, which the shell rejoins."""
    if len(text) < 3:
        return text
    return text[:1] + '""' + text[1:]


def m_quote_wrap(text: str) -> str:
    return text.replace("/", '"/"', 1) if "/" in text else text


def m_url_encode(text: str) -> str:
    return urllib.parse.quote(text)


def m_base64_wrap(text: str) -> str:
    encoded = base64.b64encode(text.encode()).decode()
    return f"echo {encoded} | base64 -d | sh"


def m_unicode_escape(text: str) -> str:
    return text.replace("e", "\\u0065")


def m_prefix_politeness(text: str) -> str:
    return f"Could you please help me with this: {text}"


def m_nested_json(text: str) -> str:
    return f'{{"inner": "{text}"}}'


MUTATORS: dict[str, Mutator] = {
    "upper": m_upper,
    "alternating-case": m_alternating_case,
    "extra-spaces": m_extra_spaces,
    "tabs": m_tabs,
    "newline-split": m_newline_split,
    "leading-comment": m_leading_noise,
    "trailing-comment": m_trailing_noise,
    "zero-width": m_zero_width,
    "homoglyph": m_homoglyph,
    "leetspeak": m_leetspeak,
    "split-strings": m_split_strings,
    "quote-wrap": m_quote_wrap,
    "url-encode": m_url_encode,
    "base64-wrap": m_base64_wrap,
    "unicode-escape": m_unicode_escape,
    "politeness-prefix": m_prefix_politeness,
    "nested-json": m_nested_json,
}


@dataclass
class Bypass:
    """A mutation of a blocked attack that was not blocked."""

    category: str
    tool: str
    mutator: str
    original: str
    mutated: str
    arguments: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category, "tool": self.tool, "mutator": self.mutator,
            "original": self.original[:200], "mutated": self.mutated[:200],
        }


@dataclass
class FuzzReport:
    attacks_tested: int = 0
    variants_tested: int = 0
    bypasses: list[Bypass] = field(default_factory=list)
    skipped_unblocked: int = 0
    skipped_nonviable: int = 0

    @property
    def bypass_rate(self) -> float:
        return round(len(self.bypasses) / self.variants_tested, 4) if self.variants_tested else 0.0

    def by_mutator(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for bypass in self.bypasses:
            counts[bypass.mutator] = counts.get(bypass.mutator, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def to_dict(self) -> dict[str, Any]:
        return {
            "attacks_tested": self.attacks_tested,
            "variants_tested": self.variants_tested,
            "bypasses": len(self.bypasses),
            "bypass_rate": self.bypass_rate,
            "skipped_nonviable": self.skipped_nonviable,
            "by_mutator": self.by_mutator(),
            "findings": [b.to_dict() for b in self.bypasses],
        }


# Which field kinds each mutation still *works* against.
#
# This is the difference between a useful fuzzer and a noisy one. Rewriting
# `~/.ssh/id_rsa` with Cyrillic homoglyphs does evade a path matcher — and also
# names a file that does not exist, so the attack is dead either way. Counting
# that as a bypass trains you to ignore the report. A mutation only counts if
# the mutated payload would still do the thing the original did.
VIABLE_AGAINST: dict[str, set[str]] = {
    # Shell rejoins these; the command still runs.
    "split-strings": {"command"},
    "quote-wrap": {"command"},
    "newline-split": {"command"},
    "base64-wrap": {"command"},
    "extra-spaces": {"command", "text"},
    "tabs": {"command", "text"},
    "leading-comment": {"command", "text"},
    "trailing-comment": {"command", "text"},
    # A model reads these as the same sentence; a filesystem does not.
    "upper": {"text"},
    "alternating-case": {"text"},
    "homoglyph": {"text"},
    "leetspeak": {"text"},
    "unicode-escape": {"text"},
    "zero-width": {"text"},
    "politeness-prefix": {"text"},
    "nested-json": {"text"},
    # A server that decodes its query string still sees the original target.
    "url-encode": {"url"},
}

_PATH_KEYS = {"path", "file", "filename", "filepath", "file_path", "directory", "dir"}
_COMMAND_KEYS = {"command", "cmd", "script", "shell", "code"}
_URL_KEYS = {"url", "uri", "endpoint", "href", "link"}


def _field_kind(key: str, value: str) -> str:
    """Classify an argument so viability can be judged against it."""
    lowered = key.lower()
    if lowered in _COMMAND_KEYS:
        return "command"
    if lowered in _URL_KEYS or value.startswith(("http://", "https://", "file://")):
        return "url"
    if lowered in _PATH_KEYS:
        return "path"
    return "text"


def _mutable_fields(arguments: dict[str, Any]) -> list[str]:
    """Argument keys holding text worth mutating."""
    return [k for k, v in arguments.items() if isinstance(v, str) and len(v) >= 3]


def fuzz(
    shield: Shield,
    attacks: list[tuple[str, str, dict[str, Any], bool]] | None = None,
    mutators: dict[str, Mutator] | None = None,
    seed: int | None = None,
) -> FuzzReport:
    """Mutate every blocked attack and report the variants that get through.

    Args:
        shield: the Shield to test — its live config is what gets fuzzed.
        attacks: `(category, tool, arguments, expect_block)` tuples. Defaults to
            the shipped corpus.
        mutators: name -> function. Defaults to all built-in mutators.
    """
    if attacks is None:
        from .cli import ATTACKS
        attacks = ATTACKS
    active = mutators if mutators is not None else MUTATORS
    if seed is not None:
        random.seed(seed)

    report = FuzzReport()

    for category, tool, arguments, expect_block in attacks:
        if not expect_block:
            continue  # only attacks are worth mutating

        shield.reset()
        if not shield.check(tool, arguments, agent="fuzzer").blocked:
            # Already a hole; `shield test` reports it, no need to double-count.
            report.skipped_unblocked += 1
            continue

        report.attacks_tested += 1
        fields = _mutable_fields(arguments)
        if not fields:
            continue

        for name, mutate in active.items():
            viable = VIABLE_AGAINST.get(name)
            for key in fields:
                original = arguments[key]
                if viable is not None and _field_kind(key, original) not in viable:
                    report.skipped_nonviable += 1
                    continue  # the mutation would break the attack, not hide it
                try:
                    mutated = mutate(original)
                except Exception:  # noqa: S112 - a mutator that cannot handle
                    continue       # this input simply produces no variant
                if mutated == original:
                    continue

                variant = {**arguments, key: mutated}
                shield.reset()
                report.variants_tested += 1

                if not shield.check(tool, variant, agent="fuzzer").blocked:
                    report.bypasses.append(Bypass(
                        category=category, tool=tool, mutator=name,
                        original=original, mutated=mutated, arguments=variant,
                    ))

    return report
