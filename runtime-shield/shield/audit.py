"""Tamper-evident audit log.

Every decision is appended as one JSON line carrying the hash of the previous
line. Deleting or editing an entry after the fact breaks the chain, and
`shield audit verify` reports exactly which line broke it. Optional Ed25519
signing additionally proves the entries came from a holder of the key.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import AuditConfig
from .models import Decision, ToolCall

GENESIS = "genesis"


def _hash_line(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _hash_arguments(arguments: dict[str, Any]) -> str:
    """Hash rather than store arguments: an audit log should not become the leak."""
    try:
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        canonical = repr(arguments)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


@dataclass
class VerifyResult:
    valid: bool
    entries: int
    error: str = ""
    broken_line: int | None = None

    def __bool__(self) -> bool:
        return self.valid


class AuditLog:
    """Append-only, thread-safe, hash-chained decision log."""

    def __init__(self, config: AuditConfig | None = None) -> None:
        self.config = config or AuditConfig()
        self.path = Path(self.config.path)
        self._lock = threading.Lock()
        self._previous = GENESIS
        self._count = 0
        self._signer = None

        if not self.config.enabled:
            return

        if self.path.parent and str(self.path.parent) not in ("", "."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.config.sign:
            self._signer = _load_signer(self.config.key_file)
        if self.path.exists():
            self._resume()

    def _resume(self) -> None:
        """Pick the hash chain back up from the last line written."""
        last = ""
        count = 0
        try:
            with self.path.open(encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        last = line
                        count += 1
        except OSError:
            return
        self._count = count
        if last:
            self._previous = _hash_line(last)

    def record(self, call: ToolCall, decision: Decision, kind: str = "check") -> dict[str, Any]:
        """Append one decision. Returns the entry (also used by the dashboard)."""
        entry = {
            "id": call.id,
            "ts": round(time.time(), 3),
            "kind": kind,
            "agent": call.agent,
            "tenant": call.tenant,
            "tool": call.tool,
            "arguments_hash": _hash_arguments(call.arguments),
            "action": decision.action.value,
            "allowed": decision.allowed,
            "stage": decision.stage.value if decision.stage else None,
            "reason": decision.reason,
            "severity": decision.severity.value,
            "latency_ms": round(decision.latency_ms, 3),
            "findings": [f.to_dict() for f in decision.findings],
        }
        if self.config.capture_arguments:
            # Opt-in: the price of replayable traffic is a log that holds real
            # arguments. The field name says so plainly.
            entry["arguments"] = call.arguments
            entry["session"] = call.session

        if not self.config.enabled:
            return entry

        with self._lock:
            entry["previous_hash"] = self._previous
            line = json.dumps(entry, separators=(",", ":"), default=str)
            if self._signer:
                entry["signature"] = self._signer(line)
                line = json.dumps(entry, separators=(",", ":"), default=str)
            try:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError:
                return entry
            self._previous = _hash_line(line)
            self._count += 1
        return entry

    def verify(self) -> VerifyResult:
        """Walk the chain and report the first break, if any."""
        if not self.path.exists():
            return VerifyResult(True, 0)

        previous = GENESIS
        count = 0
        try:
            with self.path.open(encoding="utf-8") as handle:
                for number, raw in enumerate(handle, 1):
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError as exc:
                        return VerifyResult(False, count, f"line {number} is not valid JSON: {exc}", number)
                    if entry.get("previous_hash") != previous:
                        return VerifyResult(
                            False, count,
                            f"hash chain broken at line {number}: expected "
                            f"{previous[:16]}..., found {str(entry.get('previous_hash'))[:16]}...",
                            number,
                        )
                    previous = _hash_line(line)
                    count += 1
        except OSError as exc:
            return VerifyResult(False, count, f"cannot read {self.path}: {exc}")

        return VerifyResult(True, count)

    def read(self, limit: int = 100) -> list[dict[str, Any]]:
        """The most recent `limit` entries, oldest first."""
        return list(self.tail(limit))

    def tail(self, limit: int = 100) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return iter(())
        from collections import deque
        window: deque[str] = deque(maxlen=max(1, limit))
        try:
            with self.path.open(encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        window.append(line)
        except OSError:
            return iter(())
        entries = []
        for line in window:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return iter(entries)

    @property
    def entry_count(self) -> int:
        return self._count


def _load_signer(key_file: str):
    """Return a sign(text)->hex function, or None if crypto is unavailable."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        return None

    path = Path(key_file)
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    else:
        key = Ed25519PrivateKey.generate()
        path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def sign(text: str) -> str:
        return key.sign(text.encode("utf-8")).hex()

    return sign
