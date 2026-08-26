"""Config loading, key styles, environment overrides, and error handling."""

from __future__ import annotations

import pytest

from shield.config import Config, ConfigError, find_config, load_config


def test_defaults_are_usable():
    cfg = Config.from_dict({})
    assert cfg.mode == "enforce"
    assert cfg.default_action == "allow", "allow-by-default keeps agents working"
    assert cfg.injection.enabled and cfg.command.enabled and cfg.egress.enabled
    assert cfg.filesystem.sandbox == [], "no sandbox unless asked for"


def test_nested_sections_become_dataclasses():
    cfg = Config.from_dict({"audit": {"enabled": False, "path": "x.jsonl"}})
    assert cfg.audit.enabled is False
    assert cfg.audit.path == "x.jsonl"


def test_camel_case_and_kebab_case_keys():
    cfg = Config.from_dict({
        "defaultAction": "block",
        "rateLimit": {"maxCalls": 5, "windowSeconds": 30},
        "egress": {"blockPrivateIPs": False},
        "kill-switch": {"enabled": False},
    })
    assert cfg.default_action == "block"
    assert cfg.rate_limit.max_calls == 5
    assert cfg.rate_limit.window_seconds == 30
    assert cfg.egress.block_private_ips is False
    assert cfg.kill_switch.enabled is False


def test_unknown_keys_are_ignored_not_fatal():
    cfg = Config.from_dict({"mode": "monitor", "nonsense": {"a": 1}, "audit": {"bogus": 2}})
    assert cfg.mode == "monitor" and cfg.monitor_only


def test_agents_and_rules_are_typed():
    cfg = Config.from_dict({
        "agents": {"bot": {"allow": ["read_file"], "rateLimit": "10/min"}},
        "rules": [{"name": "r1", "tool": "exec", "action": "block"}],
    })
    assert cfg.agents["bot"].allow == ["read_file"]
    assert cfg.agents["bot"].rate_limit == "10/min"
    assert cfg.rules[0].name == "r1"


def test_tenants_are_typed():
    cfg = Config.from_dict({"tenants": {"acme": {"bot": {"deny": ["exec"]}}}})
    assert cfg.tenants["acme"]["bot"].deny == ["exec"]


@pytest.mark.parametrize("mode,expected", [
    ("monitor", True), ("observe", True), ("dry-run", True), ("enforce", False),
])
def test_monitor_only(mode, expected):
    assert Config.from_dict({"mode": mode}).monitor_only is expected


def test_load_from_yaml(tmp_path):
    path = tmp_path / "shield.yaml"
    path.write_text("mode: monitor\ninjection:\n  sensitivity: high\n")
    cfg = load_config(path)
    assert cfg.mode == "monitor"
    assert cfg.injection.sensitivity == "high"


def test_missing_file_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


def test_invalid_yaml_is_reported(tmp_path):
    path = tmp_path / "shield.yaml"
    path.write_text("mode: [unclosed\n")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(path)


def test_non_mapping_yaml_is_reported(tmp_path):
    path = tmp_path / "shield.yaml"
    path.write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(path)


def test_empty_yaml_falls_back_to_defaults(tmp_path):
    path = tmp_path / "shield.yaml"
    path.write_text("")
    assert load_config(path).mode == "enforce"


def test_no_config_anywhere_returns_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert load_config().mode == "enforce"


def test_find_config_walks_upwards(tmp_path, monkeypatch):
    (tmp_path / "shield.yaml").write_text("mode: monitor\n")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    assert find_config() == tmp_path / "shield.yaml"


def test_env_overrides_file(monkeypatch):
    monkeypatch.setenv("SHIELD_MODE", "monitor")
    monkeypatch.setenv("SHIELD_API_KEYS", "key-a, key-b")
    monkeypatch.setenv("SHIELD_PORT", "9999")
    cfg = Config.from_dict({"mode": "enforce"})
    assert cfg.mode == "monitor"
    assert cfg.server.api_keys == ["key-a", "key-b"]
    assert cfg.server.port == 9999


def test_bad_env_port_is_ignored(monkeypatch):
    monkeypatch.setenv("SHIELD_PORT", "not-a-number")
    assert Config.from_dict({}).server.port == 8000


def test_action_and_severity_coercion_is_safe():
    cfg = Config.from_dict({})
    from shield.models import Action, Severity
    assert cfg.action_for("block") is Action.BLOCK
    assert cfg.action_for("nonsense") is Action.BLOCK          # falls back
    assert cfg.action_for("nonsense", Action.ALLOW) is Action.ALLOW
    assert cfg.severity_for("critical") is Severity.CRITICAL
    assert cfg.severity_for("???") is Severity.HIGH
