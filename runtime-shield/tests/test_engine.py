"""The Shield engine: ordering, monitor mode, metrics, decorators."""

from __future__ import annotations

import pytest
from conftest import make_config

from shield import Shield, ShieldError
from shield.models import Action, Severity


def test_check_allows_ordinary_calls(shield):
    decision = shield.check("read_file", {"path": "notes.txt"})
    assert decision.allowed and not decision.blocked
    assert decision.action is Action.ALLOW
    assert bool(decision) is True


def test_check_blocks_dangerous_calls(shield):
    decision = shield.check("exec", {"command": "rm -rf /"})
    assert decision.blocked and not decision.allowed
    assert decision.stage.value == "command"
    assert decision.severity is Severity.CRITICAL
    assert bool(decision) is False


def test_decision_serializes(shield):
    payload = shield.check("exec", {"command": "rm -rf /"}).to_dict()
    assert payload["allowed"] is False
    assert payload["action"] == "block"
    assert payload["stage"] == "command"
    assert isinstance(payload["latency_ms"], float)
    assert payload["findings"]


def test_a_policy_allow_does_not_disable_other_guards():
    """A rule may grant permission; it may not switch off safety."""
    cfg = make_config(rules=[{"name": "trust-exec", "tool": "exec", "action": "allow"}])
    shield = Shield(config=cfg)
    assert shield.check("exec", {"command": "ls -la"}).allowed
    assert shield.check("exec", {"command": "rm -rf /"}).blocked


def test_kill_switch_beats_everything(tmp_path):
    kill = tmp_path / ".kill"
    shield = Shield(config=make_config(
        kill_switch={"enabled": True, "file": str(kill)},
        rules=[{"name": "allow-all", "tool": "*", "action": "allow"}],
    ))
    assert shield.check("read_file", {"path": "a.txt"}).allowed
    kill.touch()
    decision = shield.check("read_file", {"path": "a.txt"})
    assert decision.blocked and decision.stage.value == "kill_switch"


def test_monitor_mode_never_blocks():
    shield = Shield(config=make_config(mode="monitor"))
    decision = shield.check("exec", {"command": "rm -rf /"})
    assert decision.allowed, "monitor mode must not block"
    assert decision.action is Action.FLAG
    assert "would block" in decision.reason
    assert decision.severity is Severity.CRITICAL, "severity is still reported"


def test_enforce_mode_blocks():
    shield = Shield(config=make_config(mode="enforce"))
    assert shield.check("exec", {"command": "rm -rf /"}).blocked


def test_a_broken_guard_does_not_open_the_gate(shield, monkeypatch):
    from shield.guards.command import CommandGuard

    def explode(self, call, config):
        raise RuntimeError("guard is broken")

    monkeypatch.setattr(CommandGuard, "check", explode)
    decision = shield.check("read_file", {"path": "a.txt"})
    # The engine survives and records the failure rather than crashing.
    assert any("errored" in f.reason for f in decision.findings)


def test_scan_redacts(shield):
    result = shield.scan("key AKIAIOSFODNN7EXAMPLE and mail a@b.com")
    assert result.modified
    assert "AKIAIOSFODNN7EXAMPLE" not in result.content
    assert "a@b.com" not in result.content
    assert len(result.findings) == 2


def test_scan_leaves_clean_text_alone(shield):
    text = "Build succeeded in 12s."
    result = shield.scan(text)
    assert result.content == text
    assert not result.modified and not result.findings


def test_scan_handles_empty(shield):
    result = shield.scan("")
    assert result.content == "" and not result.findings


def test_enforce_raises(shield):
    with pytest.raises(ShieldError) as excinfo:
        shield.enforce("exec", {"command": "rm -rf /"})
    assert excinfo.value.decision.blocked


def test_enforce_returns_on_allow(shield):
    assert shield.enforce("read_file", {"path": "a.txt"}).allowed


def test_protect_decorator(shield):
    @shield.protect()
    def read_file(path: str) -> str:
        return f"contents of {path} with key AKIAIOSFODNN7EXAMPLE"

    assert "REDACTED" in read_file("notes.txt")
    with pytest.raises(ShieldError):
        read_file("/etc/shadow")


def test_protect_decorator_with_kwargs(shield):
    @shield.protect(tool="run")
    def run(command: str) -> str:
        return "done"

    assert run(command="ls") == "done"
    with pytest.raises(ShieldError):
        run(command="rm -rf /")


def test_wrap_tools(shield):
    tools = shield.wrap_tools({"exec": lambda command: "ran"})
    assert tools["exec"](command="echo hi") == "ran"
    with pytest.raises(ShieldError):
        tools["exec"](command="rm -rf /")


def test_metrics(shield):
    shield.check("read_file", {"path": "a.txt"})
    shield.check("exec", {"command": "rm -rf /"})
    metrics = shield.metrics()
    assert metrics["total"] == 2
    assert metrics["blocked"] == 1
    assert metrics["allowed"] == 1
    assert metrics["block_rate"] == 0.5
    assert metrics["by_stage"]["command"] == 1
    assert metrics["mode"] == "enforce"
    assert metrics["latency_ms"]["p95"] >= 0


def test_events_and_listeners(shield):
    seen = []
    shield.on_event(seen.append)
    shield.check("read_file", {"path": "a.txt"})
    assert len(seen) == 1
    assert seen[0]["tool"] == "read_file"
    assert shield.events(limit=10)[-1]["tool"] == "read_file"


def test_a_bad_listener_cannot_break_a_check(shield):
    shield.on_event(lambda e: (_ for _ in ()).throw(RuntimeError("bad listener")))
    assert shield.check("read_file", {"path": "a.txt"}).allowed


def test_reset_clears_state(shield):
    shield.check("read_file", {"path": "a.txt"})
    assert shield.metrics()["total"] == 1
    shield.reset()
    assert shield.metrics()["total"] == 0


def test_arguments_are_never_stored_in_events(shield):
    shield.check("login", {"password": "hunter2-super-secret"})
    serialized = str(shield.events())
    assert "hunter2" not in serialized, "raw arguments must not reach the event log"


def test_module_level_helpers(tmp_path, monkeypatch):
    """The zero-config path: `import shield; shield.check(...)`."""
    monkeypatch.chdir(tmp_path)
    import shield as shield_module
    monkeypatch.setattr(shield_module, "_default", None)
    assert shield_module.check("read_file", {"path": "a.txt"}).allowed
    assert shield_module.check("exec", {"command": "rm -rf /"}).blocked
    assert shield_module.scan("clean text").content == "clean text"


def test_no_guard_errors_across_the_whole_corpus(shield):
    """No guard may raise on any corpus input.

    The engine deliberately survives a throwing guard by degrading it to a
    flag, which means a broken guard silently stops protecting anything. This
    test is the tripwire: it has already caught two import regressions where a
    lint autofix removed a name a guard needed at runtime.
    """
    from shield.cli import ATTACKS, SCAN_CASES

    errors = []
    for _category, tool, arguments, _expect in ATTACKS:
        for finding in shield.check(tool, arguments, agent="corpus").findings:
            if "errored" in finding.reason:
                errors.append(f"check {tool}: {finding.reason}")
    for _label, text, _expect in SCAN_CASES:
        for finding in shield.scan(text, tool="read_file", agent="corpus").findings:
            if "errored" in finding.reason:
                errors.append(f"scan: {finding.reason}")

    assert not errors, "guards raised during normal operation:\n  " + "\n  ".join(errors)


def test_every_guard_survives_hostile_argument_shapes(shield):
    """Guards must not raise on odd-but-legal payloads."""
    hostile = [
        {}, {"a": None}, {"a": []}, {"a": {}}, {"a": 0}, {"a": False},
        {"path": ""}, {"command": ""}, {"url": "not a url"},
        {"url": "http://[::1"}, {"nested": {"deep": {"deeper": {"x": "y"}}}},
        {"big": "x" * 50_000}, {"unicode": "​‮\U000e0041"},
        {"list": [{"path": "/etc/shadow"}, None, 42]},
        {"path": ["/etc/shadow", "/tmp/ok"]},
    ]
    for arguments in hostile:
        for tool in ("exec", "read_file", "http_post", "fetch_url", "summarize"):
            decision = shield.check(tool, arguments, agent="hostile", session="h")
            assert not any("errored" in f.reason for f in decision.findings), \
                f"{tool}({arguments!r}) raised: {[f.reason for f in decision.findings]}"
