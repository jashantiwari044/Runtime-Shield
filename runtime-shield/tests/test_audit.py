"""The audit log must be append-only and tamper-evident."""

from __future__ import annotations

import json

from shield import Shield
from shield.audit import AuditLog
from shield.config import AuditConfig


def test_decisions_are_recorded(audited_shield):
    audited_shield.check("read_file", {"path": "a.txt"})
    audited_shield.check("exec", {"command": "rm -rf /"})
    entries = audited_shield.audit.read(limit=10)
    assert len(entries) == 2
    assert entries[0]["action"] == "allow"
    assert entries[1]["action"] == "block"
    assert entries[1]["stage"] == "command"


def test_arguments_are_hashed_not_stored(audited_shield):
    audited_shield.check("login", {"password": "hunter2-super-secret"})
    raw = audited_shield.audit.path.read_text()
    assert "hunter2" not in raw, "the audit log must not become the leak"
    assert json.loads(raw.strip())["arguments_hash"]


def test_chain_verifies(audited_shield):
    for i in range(20):
        audited_shield.check("read_file", {"path": f"file{i}.txt"})
    result = audited_shield.audit.verify()
    assert result.valid and result.entries == 20


def test_tampering_is_detected(audited_shield):
    """Rewriting a block as an allow must break the chain."""
    audited_shield.check("read_file", {"path": "a.txt"})
    audited_shield.check("exec", {"command": "rm -rf /"})     # blocked
    for i in range(3):
        audited_shield.check("read_file", {"path": f"f{i}.txt"})
    assert audited_shield.audit.verify().valid

    lines = audited_shield.audit.path.read_text().splitlines()
    entry = json.loads(lines[1])
    assert entry["action"] == "block"
    entry["action"] = "allow"                       # cover up the block
    entry["allowed"] = True
    entry["reason"] = ""
    lines[1] = json.dumps(entry, separators=(",", ":"))
    audited_shield.audit.path.write_text("\n".join(lines) + "\n")

    result = audited_shield.audit.verify()
    assert not result.valid, "an edited entry must break the hash chain"
    assert result.broken_line == 3, "the break shows at the following entry"
    assert "hash chain broken" in result.error


def test_deletion_is_detected(audited_shield):
    for i in range(5):
        audited_shield.check("exec", {"command": f"echo {i}"})
    lines = audited_shield.audit.path.read_text().splitlines()
    del lines[2]
    audited_shield.audit.path.write_text("\n".join(lines) + "\n")
    assert not audited_shield.audit.verify().valid


def test_chain_resumes_across_restarts(tmp_path):
    from conftest import make_config
    path = str(tmp_path / "audit.jsonl")

    first = Shield(config=make_config(audit={"enabled": True, "path": path}))
    first.check("read_file", {"path": "a.txt"})

    second = Shield(config=make_config(audit={"enabled": True, "path": path}))
    second.check("read_file", {"path": "b.txt"})

    result = second.audit.verify()
    assert result.valid and result.entries == 2


def test_empty_log_verifies():
    log = AuditLog(AuditConfig(enabled=True, path="/tmp/shield-does-not-exist.jsonl"))
    result = log.verify()
    assert result.valid and result.entries == 0


def test_disabled_audit_writes_nothing(tmp_path):
    from conftest import make_config
    path = tmp_path / "audit.jsonl"
    shield = Shield(config=make_config(audit={"enabled": False, "path": str(path)}))
    shield.check("read_file", {"path": "a.txt"})
    assert not path.exists()


def test_scan_findings_are_audited(audited_shield):
    audited_shield.scan("key AKIAIOSFODNN7EXAMPLE")
    entries = audited_shield.audit.read(limit=5)
    assert entries and entries[-1]["kind"] == "scan"
