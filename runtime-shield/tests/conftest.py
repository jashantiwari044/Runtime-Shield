"""Shared fixtures. Every test gets an isolated Shield with audit off."""

from __future__ import annotations

import pytest

from shield import Shield
from shield.config import Config


def make_config(**overrides) -> Config:
    raw = {"audit": {"enabled": False}, "kill_switch": {"file": ".shield-kill-test"}}
    raw.update(overrides)
    return Config.from_dict(raw)


@pytest.fixture
def config() -> Config:
    return make_config()


@pytest.fixture
def shield(config: Config) -> Shield:
    return Shield(config=config)


@pytest.fixture
def audited_shield(tmp_path):
    """A Shield writing a real audit log into a temp directory."""
    cfg = Config.from_dict({
        "audit": {"enabled": True, "path": str(tmp_path / "audit.jsonl")},
        "kill_switch": {"file": str(tmp_path / ".kill")},
    })
    return Shield(config=cfg)
