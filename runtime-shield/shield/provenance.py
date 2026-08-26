"""Provenance tracking — where did this data come from, and where is it going?

Every shipping guardrail today inspects *content*: it reads a string and asks
"does this look like an attack?". That question is unanswerable in general.
Prompt injection is natural language, and natural language has infinite
paraphrases; a detector tuned tight enough to catch them all blocks ordinary
work, and one tuned loose enough to be usable misses the clever ones.

This module asks a different question, one that *is* answerable:

    Did bytes that came from an untrusted source end up in an outbound call,
    in a session that also touched private data?

That is Simon Willison's "lethal trifecta" — private data access, untrusted
content exposure, and external communication — evaluated at runtime instead of
in a manual architecture review. It is also, in spirit, what DeepMind's CaMeL
does with a custom Python interpreter. The insight here is that you do not need
to own the interpreter: the shield already sees every tool call and every tool
result, and that is exactly the dataflow boundary where taint propagates.

The result does not care how the injection was phrased. It cares that your
private data is leaving the building.
"""

from __future__ import annotations

import base64
import re
import threading
import time
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "Trust", "Sink", "SessionLedger", "ProvenanceTracker",
    "classify_tool", "extract_markers",
]


class Trust(str, Enum):
    """Where a piece of data came from, relative to the trust boundary."""

    UNTRUSTED = "untrusted"  # the open internet, inbound mail, a public issue
    PRIVATE = "private"      # your files, your database, your secrets
    NEUTRAL = "neutral"      # everything else


class Sink(str, Enum):
    """Whether a tool can move data outside the trust boundary."""

    EXTERNAL = "external"    # HTTP POST, email, webhook, PR comment
    LOCAL = "local"          # writes that stay on this machine
    NONE = "none"


# --- default tool classification ---------------------------------------
#
# Tuned for the tool names that agent frameworks actually ship. Override any
# of it under `provenance:` in shield.yaml.

UNTRUSTED_TOOLS = [
    "fetch*", "*fetch_url*", "http_get", "get_url", "browse*", "*web_search*",
    "search_web", "google*", "bing*", "crawl*", "scrape*", "read_url",
    "*read_email*", "get_email*", "read_message*", "get_messages",
    "get_issue*", "read_issue*", "get_comment*", "read_comment*", "list_issues",
    "get_pull_request*", "read_pr*", "*slack_read*", "get_channel*",
    "read_webpage", "load_url", "wikipedia*", "arxiv*", "rss*",
]

PRIVATE_TOOLS = [
    "read_file", "read", "cat", "get_file*", "view_file", "open_file", "load_file",
    "list_directory", "list_files", "glob", "find_files", "grep*",
    "query", "sql*", "execute_sql", "db_query", "database_query", "select*",
    "get_secret*", "read_secret*", "get_env*", "read_env", "list_secrets",
    "get_credential*", "vault*", "kv_get", "describe_*",
]

EXTERNAL_SINKS = [
    "http_post", "post", "http_put", "http_request", "send_request", "request",
    "fetch_post", "curl", "wget", "upload*", "put_object", "s3_*",
    "send_email", "send_mail", "email*", "smtp*",
    "send_message", "post_message", "slack_*", "discord_*", "telegram_*",
    "webhook*", "notify*", "publish*",
    "create_issue", "create_pull_request", "create_pr", "comment*", "post_comment",
    "update_issue", "push*", "git_push", "commit_and_push",
    "tweet*", "post_status", "create_gist", "paste*",
]


def _match_any(name: str, patterns: Iterable[str]) -> bool:
    """Glob match a tool name against a list of patterns."""
    from .matching import tool_match
    return any(tool_match(name, p) for p in patterns)


def classify_tool(
    tool: str,
    untrusted: list[str] | None = None,
    private: list[str] | None = None,
    sinks: list[str] | None = None,
) -> tuple[Trust, Sink]:
    """Classify a tool as a data source and as a data sink.

    A tool can be both: `create_issue` reads nothing but writes outward, while
    `http_request` can fetch untrusted content *and* carry data out.
    """
    trust = Trust.NEUTRAL
    if _match_any(tool, untrusted if untrusted is not None else UNTRUSTED_TOOLS):
        trust = Trust.UNTRUSTED
    elif _match_any(tool, private if private is not None else PRIVATE_TOOLS):
        trust = Trust.PRIVATE

    sink = Sink.EXTERNAL if _match_any(
        tool, sinks if sinks is not None else EXTERNAL_SINKS
    ) else Sink.NONE

    return trust, sink


# --- marker extraction --------------------------------------------------
#
# A "marker" is a distinctive substring of private data. If a marker shows up
# in an outbound call's arguments, that data is leaving. Markers must be rare
# enough that a coincidental match is implausible -- a marker of "the" would
# flag every request ever made.

_HIGH_SIGNAL = [
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"),      # emails
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),  # uuid
    re.compile(r"\b[0-9a-f]{16,}\b", re.I),                                   # hashes, hex ids
    re.compile(r"\b[A-Za-z0-9_-]{20,}\b"),                                    # tokens, keys, ids
    re.compile(r"\b(?:\d[ -]?){13,19}\b"),                                    # card-like digit runs
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                                     # ssn-like
]

# Words that are long but carry no identifying signal.
_COMMON = frozenset("""
information application development configuration environment implementation
documentation authentication authorization infrastructure representation
international organization understanding communication administrator
functionality requirements dependencies capabilities specification
""".split())

MIN_MARKER_LENGTH = 12
MAX_MARKERS_PER_SESSION = 800


def extract_markers(text: str, limit: int = 120) -> set[str]:
    """Pull distinctive, rare-enough substrings out of a piece of private data.

    Returns lowercased markers. Deliberately conservative: a marker that is not
    distinctive produces false accusations of exfiltration, which is the fastest
    way to get a security control switched off.
    """
    if not text:
        return set()

    markers: set[str] = set()
    sample = text[:200_000]

    for pattern in _HIGH_SIGNAL:
        for match in pattern.finditer(sample):
            value = match.group(0).strip()
            if len(value) >= 8:
                markers.add(value.lower())
                if len(markers) >= limit:
                    return markers

    # Long alphanumeric words that are not ordinary English.
    word_pattern = rf"[A-Za-z0-9_./\\-]{{{MIN_MARKER_LENGTH},}}"
    for raw in re.findall(word_pattern, sample):
        # Trailing punctuation is sentence structure, not identity. Without
        # this, "implementation." reads as distinctive while "implementation"
        # is correctly ignored.
        word = raw.strip("./\\-_")
        if len(word) < MIN_MARKER_LENGTH:
            continue
        lowered = word.lower()
        if lowered in _COMMON:
            continue
        # Require internal variety: digits, embedded punctuation, or mixed
        # case. A long lowercase English word identifies nothing.
        has_digit = any(c.isdigit() for c in word)
        has_inner_punct = any(c in "_./\\-" for c in word)
        mixed_case = not word.islower() and not word.isupper()
        if not (has_digit or has_inner_punct or mixed_case):
            continue
        markers.add(lowered)
        if len(markers) >= limit:
            break

    return markers


def _decoded_variants(text: str) -> list[str]:
    """Forms an exfiltration attempt might use to smuggle a marker past us.

    Catches the naive obfuscations -- base64, URL-encoding, hex. Not a complete
    defense against a determined encoder, but it raises the cost meaningfully
    over a plain substring check.
    """
    variants = [text]

    try:
        variants.append(urllib.parse.unquote_plus(text))
    except (ValueError, UnicodeDecodeError):
        pass

    # Decode any long base64-looking runs found in the text.
    for blob in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text)[:20]:
        try:
            padded = blob + "=" * (-len(blob) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", "ignore")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(decoded):
            variants.append(decoded)

    # Decode long hex runs.
    for blob in re.findall(r"\b(?:[0-9a-fA-F]{2}){8,}\b", text)[:20]:
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", "ignore")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(decoded):
            variants.append(decoded)

    return variants


def _looks_like_text(decoded: str) -> bool:
    """Is this decoded blob plausibly human-readable content?

    Deliberately not `str.isprintable()`: that returns False for anything
    containing a newline, so a base64-encoded multi-line config file — the
    exact thing an agent exfiltrates — was being discarded as binary.
    """
    if len(decoded) < 4:
        return False
    readable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
    return readable / len(decoded) >= 0.9


# --- the ledger ---------------------------------------------------------

@dataclass
class Exposure:
    """One recorded contact with data of a given trust level."""

    tool: str
    trust: Trust
    at: float = field(default_factory=time.time)
    preview: str = ""


@dataclass
class SessionLedger:
    """What one agent session has touched, and what it can still reach.

    A "session" is a unit of agent work — one task, one conversation. Taint
    does not leak between sessions, so a long-running agent that handles many
    independent tasks does not accumulate false trifectas forever.
    """

    session: str
    agent: str = "default"
    tenant: str = "default"
    # Every agent that participated, in order of first appearance.
    agents: list[str] = field(default_factory=list)
    started: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    exposures: list[Exposure] = field(default_factory=list)
    markers: dict[str, str] = field(default_factory=dict)   # marker -> source tool
    sinks_used: list[str] = field(default_factory=list)

    @property
    def saw_untrusted(self) -> bool:
        return any(e.trust is Trust.UNTRUSTED for e in self.exposures)

    @property
    def saw_private(self) -> bool:
        return any(e.trust is Trust.PRIVATE for e in self.exposures)

    @property
    def untrusted_sources(self) -> list[str]:
        return sorted({e.tool for e in self.exposures if e.trust is Trust.UNTRUSTED})

    @property
    def private_sources(self) -> list[str]:
        return sorted({e.tool for e in self.exposures if e.trust is Trust.PRIVATE})

    def trifecta(self, sink_available: bool) -> bool:
        """All three legs present: private data, untrusted content, a way out."""
        return self.saw_private and self.saw_untrusted and sink_available

    def leaked_markers(self, text: str, limit: int = 8) -> list[tuple[str, str]]:
        """Markers of private data found in outbound text: [(marker, source)]."""
        if not self.markers or not text:
            return []

        haystacks = [v.lower() for v in _decoded_variants(text)]
        hits: list[tuple[str, str]] = []
        for marker, source in self.markers.items():
            if any(marker in haystack for haystack in haystacks):
                hits.append((marker, source))
                if len(hits) >= limit:
                    break
        return hits

    def to_dict(self) -> dict[str, Any]:
        return {
            "session": self.session,
            "agent": self.agent,
            "agents": self.agents or [self.agent],
            "tenant": self.tenant,
            "age_seconds": round(time.time() - self.started, 1),
            "saw_private": self.saw_private,
            "saw_untrusted": self.saw_untrusted,
            "private_sources": self.private_sources,
            "untrusted_sources": self.untrusted_sources,
            "sinks_used": sorted(set(self.sinks_used)),
            "tracked_markers": len(self.markers),
            "trifecta": self.trifecta(bool(self.sinks_used)),
        }


class ProvenanceTracker:
    """Thread-safe store of per-session ledgers, with TTL eviction."""

    def __init__(self, ttl_seconds: int = 3600, max_sessions: int = 1000) -> None:
        self.ttl = ttl_seconds
        self.max_sessions = max_sessions
        self._sessions: dict[str, SessionLedger] = {}
        self._lock = threading.Lock()

    def _key(self, session: str, agent: str, tenant: str) -> str:
        """Sessions are keyed by tenant and session id, deliberately not by agent.

        A unit of work often spans several agents -- a planner fetches the web
        page, a worker reads the file, a publisher posts the result. Keying on
        the agent would split that one task into three ledgers and lose the
        dataflow between them, which is exactly the dataflow that matters.
        The tenant stays in the key because that is the real isolation boundary.
        """
        return f"{tenant}:{session}"

    def ledger(self, session: str, agent: str = "default", tenant: str = "default") -> SessionLedger:
        key = self._key(session, agent, tenant)
        now = time.time()
        with self._lock:
            entry = self._sessions.get(key)
            if entry is None:
                entry = SessionLedger(session=session, agent=agent, tenant=tenant)
                self._sessions[key] = entry
            entry.last_seen = now
            if agent not in entry.agents:
                entry.agents.append(agent)
            # Evict after inserting, so the cap counts the session we just
            # created rather than leaving room for one more than the limit.
            self._evict(now, protect=key)
            return entry

    def record_source(
        self,
        tool: str,
        text: str,
        trust: Trust,
        session: str,
        agent: str = "default",
        tenant: str = "default",
    ) -> SessionLedger:
        """Record that `tool` returned data of the given trust level."""
        entry = self.ledger(session, agent, tenant)
        with self._lock:
            entry.exposures.append(Exposure(tool=tool, trust=trust, preview=text[:120]))
            if trust is Trust.PRIVATE and len(entry.markers) < MAX_MARKERS_PER_SESSION:
                room = MAX_MARKERS_PER_SESSION - len(entry.markers)
                for marker in list(extract_markers(text))[:room]:
                    entry.markers.setdefault(marker, tool)
        return entry

    def record_sink(
        self, tool: str, session: str, agent: str = "default", tenant: str = "default"
    ) -> SessionLedger:
        entry = self.ledger(session, agent, tenant)
        with self._lock:
            entry.sinks_used.append(tool)
        return entry

    def sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            entries = sorted(self._sessions.values(), key=lambda e: e.last_seen, reverse=True)
            return [e.to_dict() for e in entries[:limit]]

    def reset(self) -> None:
        with self._lock:
            self._sessions.clear()

    def _evict(self, now: float, protect: str | None = None) -> None:
        """Drop expired sessions, then the oldest if still over budget.

        A negative `ttl_seconds` disables expiry; zero means a session is stale
        the moment the next one starts.
        """
        if self.ttl >= 0:
            stale = [
                k for k, v in self._sessions.items()
                if k != protect and now - v.last_seen > self.ttl
            ]
            for key in stale:
                del self._sessions[key]

        overflow = len(self._sessions) - self.max_sessions
        if overflow > 0:
            oldest = sorted(self._sessions.items(), key=lambda kv: kv[1].last_seen)
            for key, _ in oldest:
                if overflow <= 0:
                    break
                if key == protect:
                    continue
                del self._sessions[key]
                overflow -= 1
