"""Text normalisation — see through the disguises before pattern matching.

Attackers do not send canonical strings. They send `r""m -rf /`, which bash
rejoins into `rm -rf /`; or `ignorе all previous instructions` with a Cyrillic
`е`; or a command split across a line continuation. A matcher that only sees
the literal bytes misses all of it.

Every function here is deliberately cheap and lossy in one direction only: it
produces *additional* forms to test, and the original is always tested too, so
normalisation can add detections but never remove one.

The variants implemented here are the ones `shield fuzz` proved were getting
through — this module exists because the fuzzer found the holes.
"""

from __future__ import annotations

import re
import unicodedata
import urllib.parse

__all__ = [
    "strip_invisible", "fold_homoglyphs", "fold_leet", "decode_escapes",
    "normalize_command", "text_variants", "command_variants",
]

# Zero-width and directional characters, plus the Unicode tag block used for
# smuggling instructions that render as nothing at all.
_INVISIBLE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad\U000E0000-\U000E007F]"
)

# Characters that render like Latin letters but are different code points.
_HOMOGLYPHS = str.maketrans({
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ѕ": "s",
    "ј": "j", "ԛ": "q", "ԝ": "w", "ӏ": "l",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "Ѕ": "S", "І": "I",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ϲ": "c",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Fullwidth
    "／": "/", "＂": '"', "＇": "'", "　": " ",
})

_LEET = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "@": "a", "$": "s"})

_PERCENT_ENCODED = re.compile(r"(?:%[0-9a-fA-F]{2}){2,}")
# Literal backslash escapes, as they survive a JSON string that was never
# decoded: "Ignor\\u0065 all previous instructions".
_UNICODE_ESCAPE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{1,3})")

# Shell quoting that a shell collapses to nothing: r""m -> rm, :""() -> :().
# Matches between any two non-space characters, not just word characters,
# because `:""(){ :|:& };:` is still a fork bomb after the shell is done.
_EMPTY_QUOTES = re.compile(r"(?<=\S)(?:\"\"|'')(?=\S)")
# A backslash-newline is a line continuation; the shell joins the lines.
_LINE_CONTINUATION = re.compile(r"\\[\r\n]+\s*")

MAX_NORMALIZE_LENGTH = 100_000


def strip_invisible(text: str) -> str:
    """Remove zero-width, bidi and Unicode-tag characters."""
    return _INVISIBLE.sub("", text)


def fold_homoglyphs(text: str) -> str:
    """Map Cyrillic/Greek/fullwidth lookalikes onto their Latin equivalents."""
    return unicodedata.normalize("NFKC", text).translate(_HOMOGLYPHS)


def fold_leet(text: str) -> str:
    """Fold common leetspeak substitutions back to letters."""
    return text.translate(_LEET)


def decode_escapes(text: str) -> str:
    """Resolve literal \\uXXXX / \\xNN escapes that were never decoded."""
    if not _UNICODE_ESCAPE.search(text):
        return text

    def replace(match: re.Match[str]) -> str:
        try:
            return match.group(0).encode("ascii").decode("unicode_escape")
        except (UnicodeDecodeError, ValueError):
            return match.group(0)

    return _UNICODE_ESCAPE.sub(replace, text)


def _maybe_url_decode(text: str) -> str:
    """Decode percent-encoding, but only when the text is plainly encoded."""
    if not _PERCENT_ENCODED.search(text):
        return text
    try:
        return urllib.parse.unquote_plus(text)
    except (ValueError, UnicodeDecodeError):
        return text


def normalize_command(text: str) -> str:
    """Reduce a shell command to the form the shell will actually execute.

    Joins line continuations, drops shell-collapsing empty quotes, removes
    quotes around path targets, and squeezes whitespace.
    """
    result = strip_invisible(text)
    result = _LINE_CONTINUATION.sub(" ", result)
    result = _EMPTY_QUOTES.sub("", result)
    result = _maybe_url_decode(result)
    # Unquote simple quoted arguments: rm -rf "/" -> rm -rf /
    result = re.sub(r"(?<=\s)([\"'])([^\"'\s]{0,64})\1", r"\2", result)
    result = re.sub(r"[ \t\u00a0]+", " ", result)
    return result.strip()


def _dedupe(forms: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for form in forms:
        if form and form not in seen:
            seen.add(form)
            out.append(form)
    return out


def text_variants(text: str) -> list[str]:
    """Forms of a text to test for prompt injection.

    The original always comes first, so a match on the plain text costs nothing
    extra and the normalised forms are only reached when it does not match.
    """
    if not text or len(text) > MAX_NORMALIZE_LENGTH:
        return [text] if text else []

    stripped = strip_invisible(text)
    folded = fold_homoglyphs(stripped)
    forms = [text, stripped, folded, _maybe_url_decode(folded), decode_escapes(folded)]

    # Leet folding only helps if there are digits to fold, and it is the most
    # false-positive-prone pass, so it goes last and only when relevant.
    if any(c in text for c in "4310573@$"):
        forms.append(fold_leet(folded))

    return _dedupe(forms)


def command_variants(text: str) -> list[str]:
    """Forms of a shell command to test for dangerous operations."""
    if not text or len(text) > MAX_NORMALIZE_LENGTH:
        return [text] if text else []

    normalized = normalize_command(text)
    folded = fold_homoglyphs(normalized)
    return _dedupe([text, normalized, folded])
