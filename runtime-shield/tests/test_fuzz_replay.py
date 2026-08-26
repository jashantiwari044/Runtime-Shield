"""The mutation fuzzer and the policy replay engine."""

from __future__ import annotations

import json

import pytest
from conftest import make_config

from shield import Shield
from shield.fuzz import MUTATORS, VIABLE_AGAINST, _field_kind, fuzz
from shield.replay import replay


@pytest.fixture
def shield() -> Shield:
    return Shield(config=make_config())


# --- fuzzer --------------------------------------------------------------

def test_the_shipped_policy_has_no_bypasses(shield):
    """The headline guarantee: no viable mutation of a blocked attack gets through.

    This is the regression test for the fuzz-fix loop. When it fails, someone
    has widened a guard's blind spot — run `shield fuzz` to see which mutation.
    """
    report = fuzz(shield, seed=1)
    assert report.variants_tested > 50, "the corpus stopped producing variants"
    assert not report.bypasses, (
        f"{len(report.bypasses)} bypasses:\n" + "\n".join(
            f"  {b.mutator} on {b.tool}: {b.mutated[:80]!r}" for b in report.bypasses[:10])
    )


def test_fuzzer_finds_a_hole_when_a_guard_is_off():
    """Sanity check: the fuzzer must be capable of failing."""
    shield = Shield(config=make_config(command={"enabled": False}))
    report = fuzz(shield, seed=1)
    # With the command guard off those attacks are not blocked at all, so they
    # are reported as pre-existing holes rather than as bypasses.
    assert report.skipped_unblocked > 0


def test_fuzzer_reports_a_real_bypass_when_normalisation_is_removed(shield, monkeypatch):
    """Disabling command normalisation must resurface `r""m -rf /`."""
    import shield.guards.command as command_module

    monkeypatch.setattr(command_module, "command_variants", lambda text: [text])
    report = fuzz(shield, seed=1)
    assert report.bypasses, "removing normalisation should reopen shell-quoting bypasses"
    assert any(b.mutator in ("split-strings", "quote-wrap") for b in report.bypasses)


@pytest.mark.parametrize("key,value,expected", [
    ("command", "rm -rf /", "command"),
    ("cmd", "ls", "command"),
    ("path", "/etc/shadow", "path"),
    ("url", "http://x/", "url"),
    ("text", "https://x/", "url"),
    ("text", "hello world", "text"),
])
def test_field_kind_classification(key, value, expected):
    assert _field_kind(key, value) == expected


def test_non_viable_mutations_are_not_counted(shield):
    """Homoglyphs against a path change the target, so they are not bypasses."""
    report = fuzz(shield, seed=1)
    assert report.skipped_nonviable > 0
    for bypass in report.bypasses:
        viable = VIABLE_AGAINST.get(bypass.mutator)
        assert viable is None or _field_kind("", bypass.mutated) in viable


def test_every_mutator_is_declared_viable_somewhere():
    """A mutator with no declared viability would silently never run."""
    undeclared = set(MUTATORS) - set(VIABLE_AGAINST)
    assert not undeclared, f"mutators missing a viability declaration: {undeclared}"


def test_mutators_do_not_crash_on_odd_input():
    for name, mutate in MUTATORS.items():
        for text in ("", "a", "\x00\xff", "🎉" * 10, "a" * 5000):
            try:
                mutate(text)
            except Exception as exc:  # noqa: BLE001
                pytest.fail(f"mutator {name} raised on {text[:20]!r}: {exc}")


def test_fuzz_report_serialises(shield):
    payload = fuzz(shield, seed=1).to_dict()
    assert json.dumps(payload)
    assert {"attacks_tested", "variants_tested", "bypasses", "bypass_rate"} <= payload.keys()


# --- replay --------------------------------------------------------------

def _record_traffic(tmp_path, traffic, capture=True):
    path = tmp_path / "traffic.jsonl"
    shield = Shield(config=make_config(
        audit={"enabled": True, "path": str(path), "capture_arguments": capture}))
    for tool, arguments in traffic:
        shield.check(tool, arguments, agent="ci")
    return path


ORDINARY = [
    ("read_file", {"path": "src/app.py"}),
    ("exec", {"command": "pytest -q"}),
    ("exec", {"command": "npm run build"}),
    ("http_get", {"url": "https://api.github.com/x"}),
    ("write_file", {"path": "out.js", "content": "x"}),
]


def test_replay_detects_no_change(tmp_path):
    path = _record_traffic(tmp_path, ORDINARY)
    report = replay(path, make_config())
    assert report.total == len(ORDINARY)
    assert not report.changes
    assert report.full_fidelity


def test_replay_detects_newly_blocked(tmp_path):
    """Tightening to an allow-list should surface what it would break."""
    path = _record_traffic(tmp_path, ORDINARY)
    candidate = make_config(agents={"ci": {"allow": ["read_file", "write_file", "http_get"]}})
    report = replay(path, candidate)
    assert report.newly_blocked
    assert all(c.tool == "exec" for c in report.newly_blocked)
    assert not report.newly_allowed


def test_replay_detects_newly_allowed(tmp_path):
    """The dangerous direction: a change that opens a hole."""
    path = _record_traffic(tmp_path, ORDINARY + [
        ("exec", {"command": "rm -rf /"}),
        ("read_file", {"path": "~/.ssh/id_rsa"}),
    ])
    loose = make_config(command={"enabled": False}, filesystem={"deny": []})
    report = replay(path, loose)
    assert len(report.newly_allowed) == 2
    tools = {c.tool for c in report.newly_allowed}
    assert tools == {"exec", "read_file"}


def test_replay_without_captured_arguments_is_honest(tmp_path):
    path = _record_traffic(tmp_path, ORDINARY, capture=False)
    report = replay(path, make_config())
    assert report.total > 0
    assert not report.full_fidelity
    assert report.without_arguments == report.total


def test_replay_ignores_flag_only_transitions(tmp_path):
    """allow -> flag changes observability, not permission, so it is not a diff."""
    path = _record_traffic(tmp_path, ORDINARY)
    report = replay(path, make_config(chain={"action": "flag"}))
    assert not report.changes


def test_replay_does_not_write_a_second_audit_log(tmp_path):
    path = _record_traffic(tmp_path, ORDINARY)
    before = path.read_text()
    replay(path, make_config())
    assert path.read_text() == before, "replay must never mutate the traffic it reads"


def test_replay_on_a_missing_file_is_empty(tmp_path):
    assert replay(tmp_path / "nope.jsonl", make_config()).total == 0


def test_replay_survives_a_corrupt_line(tmp_path):
    path = _record_traffic(tmp_path, ORDINARY)
    with path.open("a") as handle:
        handle.write("{not json\n\n")
    assert replay(path, make_config()).total == len(ORDINARY)


def test_replay_respects_limit(tmp_path):
    path = _record_traffic(tmp_path, ORDINARY)
    assert replay(path, make_config(), limit=2).total == 2


def test_replay_report_serialises(tmp_path):
    path = _record_traffic(tmp_path, ORDINARY)
    assert json.dumps(replay(path, make_config()).to_dict())
