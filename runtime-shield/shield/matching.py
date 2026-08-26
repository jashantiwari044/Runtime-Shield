"""Pattern matching used by the policy guard.

Getting glob semantics right matters more than it looks: the previous
generation of this project converted `**/.ssh/**` into a regex that required a
leading directory, so a relative `.ssh/id_rsa` walked straight past the rule
that existed to stop it. Everything here is covered by tests/test_matching.py.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

__all__ = ["glob_match", "tool_match", "normalize_path", "arguments_match", "value_match"]


def normalize_path(value: str) -> str:
    """Normalize a path for matching: forward slashes, no duplicate separators.

    Deliberately does NOT resolve `..` -- the caller decides whether to resolve
    against a sandbox root. Trailing slashes are dropped so `/tmp/` == `/tmp`.
    """
    text = str(value).strip().replace("\\", "/")
    text = re.sub(r"/{2,}", "/", text)
    if len(text) > 1:
        text = text.rstrip("/")
    return text


@lru_cache(maxsize=2048)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile a glob pattern into a regex with correct `**` semantics."""
    pattern = normalize_path(pattern)
    out: list[str] = []
    i = 0
    n = len(pattern)

    while i < n:
        char = pattern[i]

        if char == "*":
            # Count the run of stars.
            j = i
            while j < n and pattern[j] == "*":
                j += 1
            stars = j - i
            after = pattern[j] if j < n else ""

            if stars >= 2:
                if after == "/":
                    # `**/` matches zero or more leading path segments.
                    out.append("(?:[^/]*/)*")
                    i = j + 1
                    continue
                if j >= n:
                    # Trailing `**` matches anything, including nothing.
                    out.append(".*")
                    i = j
                    continue
                out.append(".*")
                i = j
                continue

            # A single `*` never crosses a path separator.
            out.append("[^/]*")
            i = j
            continue

        if char == "?":
            out.append("[^/]")
            i += 1
            continue

        out.append(re.escape(char))
        i += 1

    regex = "".join(out)
    # `/**` at the end should also match the directory itself.
    regex = regex.replace("/(?:[^/]*/)*", "(?:/(?:[^/]*/)*)?")
    if regex.endswith("/.*"):
        regex = regex[: -len("/.*")] + "(?:/.*)?"
    return re.compile(rf"^{regex}$", re.IGNORECASE)


def glob_match(path: str, pattern: str) -> bool:
    """True if `path` matches a `**`-aware glob `pattern`.

    >>> glob_match(".ssh/id_rsa", "**/.ssh/**")
    True
    >>> glob_match("/home/u/.ssh/id_rsa", "**/.ssh/**")
    True
    >>> glob_match("notes.txt", "**/.ssh/**")
    False
    """
    if not pattern:
        return False
    return bool(_glob_regex(pattern).match(normalize_path(path)))


def tool_match(tool: str, pattern: str) -> bool:
    """Match a tool name against a pattern.

    Supports `*` wildcards, `a|b|c` alternation, and `re:<expr>` for a regex.
    """
    if not pattern:
        return False
    pattern = pattern.strip()

    if pattern == "*":
        return True

    if pattern.startswith("re:"):
        try:
            return bool(re.search(pattern[3:], tool, re.IGNORECASE))
        except re.error:
            return False

    for alternative in pattern.split("|"):
        alternative = alternative.strip()
        if not alternative:
            continue
        if "*" in alternative or "?" in alternative:
            escaped = re.escape(alternative).replace(r"\*", ".*").replace(r"\?", ".")
            if re.match(rf"^{escaped}$", tool, re.IGNORECASE):
                return True
        elif alternative.lower() == tool.lower():
            return True
    return False


def value_match(value: Any, pattern: Any) -> bool:
    """Match a single argument value against a rule pattern."""
    if isinstance(pattern, dict):
        if "regex" in pattern:
            try:
                return bool(re.search(str(pattern["regex"]), str(value), re.IGNORECASE))
            except re.error:
                return False
        if "contains" in pattern:
            return str(pattern["contains"]).lower() in str(value).lower()
        if "equals" in pattern:
            return value == pattern["equals"]
        if "any_of" in pattern:
            return any(value_match(value, p) for p in pattern["any_of"] or [])
        return False

    if isinstance(pattern, list):
        return any(value_match(value, p) for p in pattern)

    if isinstance(pattern, str):
        if isinstance(value, str):
            return glob_match(value, pattern) or pattern.lower() in value.lower()
        return str(value).lower() == pattern.lower()

    return value == pattern


def arguments_match(arguments: dict[str, Any], matchers: dict[str, Any]) -> bool:
    """True only if every matcher matches (missing keys never match)."""
    if not matchers:
        return True
    for key, pattern in matchers.items():
        if key not in arguments:
            return False
        if not value_match(arguments[key], pattern):
            return False
    return True
