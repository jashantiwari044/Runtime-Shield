"""The command line interface."""

from __future__ import annotations

import json

import pytest

from shield.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "runtime-shield" in capsys.readouterr().out


def test_init_writes_a_valid_config(tmp_path, capsys):
    target = tmp_path / "shield.yaml"
    assert main(["init", "-o", str(target)]) == 0
    assert target.exists()

    from shield.config import load_config
    cfg = load_config(target)
    assert cfg.mode == "enforce"
    assert cfg.agents["readonly-bot"].allow


def test_init_refuses_to_clobber(tmp_path):
    target = tmp_path / "shield.yaml"
    target.write_text("mode: monitor\n")
    assert main(["init", "-o", str(target)]) == 1
    assert target.read_text() == "mode: monitor\n"
    assert main(["init", "-o", str(target), "--force"]) == 0


def test_check_exit_codes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["check", "read_file", "--arg", "path=notes.txt"]) == 0
    assert "ALLOWED" in capsys.readouterr().out
    assert main(["check", "exec", "--arg", "command=rm -rf /"]) == 1
    assert "BLOCKED" in capsys.readouterr().out


def test_check_json_output(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    main(["check", "exec", "--arg", "command=rm -rf /", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["allowed"] is False and payload["stage"] == "command"


def test_check_rejects_a_malformed_arg(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["check", "exec", "--arg", "no-equals-sign"]) == 2


def test_scan_redacts_stdin(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "in.txt"
    source.write_text("key AKIAIOSFODNN7EXAMPLE\n")
    assert main(["scan", str(source)]) == 0
    assert "AKIAIOSFODNN7EXAMPLE" not in capsys.readouterr().out


def test_test_command_passes_on_defaults(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["test"]) == 0
    out = capsys.readouterr().out
    assert "checks passed" in out and "✗" not in out


def test_test_command_fails_a_broken_policy(tmp_path, monkeypatch, capsys):
    """Disabling a guard must make `shield test` fail loudly."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "shield.yaml").write_text("command:\n  enabled: false\n")
    assert main(["test"]) == 1
    assert "failed" in capsys.readouterr().out.lower()


def test_test_command_on_the_shipped_starter_config(tmp_path, monkeypatch, capsys):
    """The config `shield init` writes must pass `shield test`."""
    monkeypatch.chdir(tmp_path)
    main(["init"])
    capsys.readouterr()
    assert main(["test"]) == 0


def test_kill_switch_round_trip(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["kill"]) == 0
    assert (tmp_path / ".shield-kill").exists()
    assert main(["check", "read_file", "--arg", "path=a.txt"]) == 1
    assert main(["kill", "--release"]) == 0
    assert not (tmp_path / ".shield-kill").exists()


def test_audit_verify_on_an_empty_log(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["audit", "verify"]) == 0
    assert "intact" in capsys.readouterr().out


def test_audit_tail(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    main(["check", "exec", "--arg", "command=rm -rf /"])
    capsys.readouterr()
    assert main(["audit", "tail", "-n", "5"]) == 0
    assert "BLOCK" in capsys.readouterr().out


def test_bad_config_reports_cleanly(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "shield.yaml").write_text("mode: [unclosed\n")
    assert main(["check", "read_file"]) == 2
    assert "Configuration error" in capsys.readouterr().err


def test_fuzz_command_passes_on_defaults(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["fuzz", "--seed", "1"]) == 0
    assert "No bypasses found" in capsys.readouterr().out


def test_fuzz_command_json(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    main(["fuzz", "--seed", "1", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["bypasses"] == 0 and payload["variants_tested"] > 0


def test_replay_reports_a_loosening_policy(tmp_path, monkeypatch, capsys):
    """The CI gate: a policy that opens a hole must exit non-zero."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "shield.yaml").write_text(
        "audit:\n  enabled: true\n  path: traffic.jsonl\n  captureArguments: true\n")
    main(["check", "exec", "--arg", "command=rm -rf /"])
    main(["check", "read_file", "--arg", "path=src/app.py"])
    capsys.readouterr()

    (tmp_path / "loose.yaml").write_text("command:\n  enabled: false\n")
    assert main(["replay", "--against", "loose.yaml"]) == 1
    assert "Now ALLOWED" in capsys.readouterr().out


def test_replay_accepts_a_tightening_policy(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "shield.yaml").write_text(
        "audit:\n  enabled: true\n  path: traffic.jsonl\n  captureArguments: true\n")
    main(["check", "read_file", "--arg", "path=src/app.py"])
    capsys.readouterr()

    (tmp_path / "tight.yaml").write_text(
        "agents:\n  cli:\n    allow: ['read_file']\n")
    assert main(["replay", "--against", "tight.yaml"]) == 0


def test_replay_without_an_audit_log(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "candidate.yaml").write_text("mode: enforce\n")
    assert main(["replay", "--against", "candidate.yaml"]) == 2
    assert "No audit log" in capsys.readouterr().out


def test_sessions_command_without_a_server(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["sessions", "--server", "http://127.0.0.1:59999"]) == 2
    assert "Cannot reach" in capsys.readouterr().out


@pytest.mark.parametrize("server", [
    "file:///etc/passwd",
    "ftp://internal/x",
    "/etc/passwd",
])
def test_sessions_rejects_non_http_servers(tmp_path, monkeypatch, capsys, server):
    """A security tool must not be talked into opening arbitrary URL schemes."""
    monkeypatch.chdir(tmp_path)
    assert main(["sessions", "--server", server]) == 2
    assert "http(s)" in capsys.readouterr().out
