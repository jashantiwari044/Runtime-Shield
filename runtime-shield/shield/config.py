"""Configuration for Runtime Shield.

Design rule: **the default config must be safe AND usable with zero edits.**

That means allow-by-default with strong deny rules, rather than a whitelist that
breaks every agent that does something the author did not anticipate. Locking
down further is one line: `mode: enforce` plus an `allow:` list per agent.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, fields, is_dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, get_type_hints

from .models import Action, Severity

DEFAULT_CONFIG_NAMES = ("shield.yaml", "shield.yml", ".shield.yaml")


@lru_cache(maxsize=64)
def _hints(cls: type) -> dict[str, Any]:
    """Resolve a dataclass's annotations to real types.

    `from __future__ import annotations` makes every annotation a string, so
    `dataclasses.fields(cls)[i].type` is the text "AuditConfig" rather than the
    class. Without this, nested sections silently stay dicts.
    """
    try:
        return get_type_hints(cls)
    except Exception:
        return {f.name: Any for f in fields(cls)}  # type: ignore[arg-type]


def _to_snake(key: str) -> str:
    """`maxCalls` and `max-calls` both mean `max_calls`."""
    key = str(key).replace("-", " ").replace(" ", "_")
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).lower()


def _coerce(cls: type, value: Any) -> Any:
    """Build a nested dataclass from a plain dict, ignoring unknown keys."""
    if value is None:
        return cls()
    if isinstance(value, cls):
        return value
    if not isinstance(value, dict):
        raise ConfigError(f"expected a mapping for {cls.__name__}, got {type(value).__name__}")

    hints = _hints(cls)
    known = {f.name for f in fields(cls)}  # type: ignore[arg-type]
    kwargs: dict[str, Any] = {}

    for raw_key, raw_val in value.items():
        key = str(raw_key) if str(raw_key) in known else _to_snake(raw_key)
        if key not in known:
            continue  # unknown keys are ignored, never fatal
        target = hints.get(key)
        if isinstance(target, type) and is_dataclass(target):
            kwargs[key] = _coerce(target, raw_val)
        else:
            kwargs[key] = raw_val

    return cls(**kwargs)


class ConfigError(ValueError):
    """Raised when a config file is present but unusable."""


@dataclass
class KillSwitchConfig:
    enabled: bool = True
    file: str = ".shield-kill"


@dataclass
class RateLimitConfig:
    enabled: bool = True
    max_calls: int = 600
    window_seconds: int = 60


@dataclass
class InjectionConfig:
    enabled: bool = True
    # low     -> only unambiguous attack strings (near-zero false positives)
    # medium  -> adds strong heuristics (default)
    # high    -> adds fuzzy heuristics; expect some false positives
    sensitivity: str = "medium"
    action: str = "block"
    # Argument names whose values are known-untrusted (fetched docs, emails...).
    # Everything is scanned by default; this only raises severity.
    untrusted_fields: list[str] = field(default_factory=list)


@dataclass
class CommandConfig:
    """Catches destructive shell commands regardless of which tool runs them."""

    enabled: bool = True
    action: str = "block"
    # Argument keys that carry a shell command.
    fields: list[str] = field(
        default_factory=lambda: ["command", "cmd", "script", "shell", "code", "input"]
    )
    allow: list[str] = field(default_factory=list)


@dataclass
class EgressConfig:
    enabled: bool = True
    block_private_ips: bool = True
    block_cloud_metadata: bool = True
    action: str = "block"
    allow_hosts: list[str] = field(default_factory=list)
    deny_hosts: list[str] = field(default_factory=list)


@dataclass
class ChainConfig:
    """Multi-step attack detection (read secrets -> send them somewhere)."""

    enabled: bool = True
    # Defaults to `flag`: a chain is a signal, not proof. Set to `block` when
    # you have tuned the tool names for your own stack.
    action: str = "flag"
    window_seconds: int = 300
    chains: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ProvenanceConfig:
    """Dataflow tracking — the lethal-trifecta guard.

    Tool classification is glob-matched. Leaving a list empty uses the built-in
    defaults, which cover the tool names the common agent frameworks ship.
    """

    enabled: bool = True
    # A confirmed leak: private data leaving in a session that read untrusted
    # content. High confidence, so this blocks by default.
    action: str = "block"
    # Private data leaving with no untrusted content in the session — no
    # injection vector, often a legitimate "email me this file".
    egress_action: str = "flag"
    # All three legs present but nothing observed crossing.
    trifecta_action: str = "flag"
    session_ttl_seconds: int = 3600
    max_sessions: int = 1000
    untrusted_tools: list[str] = field(default_factory=list)
    private_tools: list[str] = field(default_factory=list)
    external_sinks: list[str] = field(default_factory=list)


@dataclass
class SecretsConfig:
    enabled: bool = True
    action: str = "redact"
    placeholder: str = "[REDACTED:{kind}]"
    allow: list[str] = field(default_factory=list)


@dataclass
class PIIConfig:
    enabled: bool = True
    action: str = "redact"
    entities: list[str] = field(
        default_factory=lambda: ["email", "phone", "ssn", "credit_card", "iban", "ip"]
    )
    placeholder: str = "[REDACTED:{kind}]"
    allow: list[str] = field(default_factory=list)


@dataclass
class FilesystemConfig:
    """Path containment. Empty sandbox == no path restriction (default)."""

    sandbox: list[str] = field(default_factory=list)
    deny: list[str] = field(
        default_factory=lambda: [
            "**/.ssh/**", "**/.aws/**", "**/.gnupg/**", "**/.kube/**",
            "**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/id_rsa*",
            "**/.npmrc", "**/.netrc", "**/.git-credentials",
            "/etc/shadow", "/etc/passwd", "/etc/sudoers",
            "**/credentials.json", "**/service-account*.json",
        ]
    )
    # Argument keys that hold a filesystem path.
    fields: list[str] = field(
        default_factory=lambda: ["path", "file", "filename", "filepath", "file_path", "directory", "dir"]
    )


@dataclass
class AgentConfig:
    """Per-agent (or per-role) permissions."""

    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    rate_limit: str | None = None
    sandbox: list[str] = field(default_factory=list)
    message: str = ""


@dataclass
class RuleConfig:
    name: str = "unnamed"
    tool: str = "*"
    match: dict[str, Any] = field(default_factory=dict)
    action: str = "block"
    message: str = ""
    severity: str = "high"


@dataclass
class AuditConfig:
    enabled: bool = True
    path: str = "shield-audit.jsonl"
    sign: bool = False
    key_file: str = ".shield-audit-key"
    # Arguments are hashed by default so the audit log cannot itself become the
    # leak. Turning this on stores them in the clear, which is what makes
    # `shield replay` able to re-evaluate real traffic against a new policy.
    # Worth it on a staging tier; think hard before enabling it in production.
    capture_arguments: bool = False


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8000
    # Empty == open (fine for localhost). Set keys, or SHIELD_API_KEYS env var,
    # before exposing the server to anything else.
    api_keys: list[str] = field(default_factory=list)
    cors_origins: list[str] = field(default_factory=list)
    dashboard: bool = True
    max_events: int = 2000
    # Upstream for the OpenAI-compatible guarded proxy.
    upstream_base_url: str = ""
    upstream_api_key: str = ""


@dataclass
class Config:
    """Top-level Runtime Shield configuration."""

    # enforce -> blocks are real. monitor -> nothing is ever blocked, everything
    # is recorded. Always roll out with `monitor` first.
    mode: str = "enforce"
    default_action: str = "allow"

    kill_switch: KillSwitchConfig = field(default_factory=KillSwitchConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    injection: InjectionConfig = field(default_factory=InjectionConfig)
    command: CommandConfig = field(default_factory=CommandConfig)
    egress: EgressConfig = field(default_factory=EgressConfig)
    chain: ChainConfig = field(default_factory=ChainConfig)
    provenance: ProvenanceConfig = field(default_factory=ProvenanceConfig)
    secrets: SecretsConfig = field(default_factory=SecretsConfig)
    pii: PIIConfig = field(default_factory=PIIConfig)
    filesystem: FilesystemConfig = field(default_factory=FilesystemConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    server: ServerConfig = field(default_factory=ServerConfig)

    agents: dict[str, AgentConfig] = field(default_factory=dict)
    tenants: dict[str, dict[str, AgentConfig]] = field(default_factory=dict)
    rules: list[RuleConfig] = field(default_factory=list)

    # ---- derived helpers -------------------------------------------------

    @property
    def monitor_only(self) -> bool:
        return self.mode.lower() in ("monitor", "observe", "dry-run", "dry_run")

    def action_for(self, name: str, default: Action = Action.BLOCK) -> Action:
        """Turn a config string like 'block' into an Action, safely."""
        try:
            return Action(str(name).lower())
        except ValueError:
            return default

    def severity_for(self, name: str, default: Severity = Severity.HIGH) -> Severity:
        try:
            return Severity(str(name).lower())
        except ValueError:
            return default

    # ---- construction ----------------------------------------------------

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> Config:
        raw = dict(raw or {})

        agents = {
            str(k): _coerce(AgentConfig, v) for k, v in (raw.pop("agents", None) or {}).items()
        }
        tenants = {
            str(t): {str(r): _coerce(AgentConfig, c) for r, c in (roles or {}).items()}
            for t, roles in (raw.pop("tenants", None) or {}).items()
        }
        rules = [_coerce(RuleConfig, r) for r in (raw.pop("rules", None) or [])]

        cfg = _coerce(cls, raw)
        cfg.agents = agents
        cfg.tenants = tenants
        cfg.rules = rules
        cfg._apply_env()
        return cfg

    def _apply_env(self) -> None:
        """Environment variables win over the file -- 12-factor friendly."""
        if v := os.getenv("SHIELD_MODE"):
            self.mode = v
        if v := os.getenv("SHIELD_API_KEYS"):
            self.server.api_keys = [k.strip() for k in v.split(",") if k.strip()]
        if v := os.getenv("SHIELD_HOST"):
            self.server.host = v
        if v := os.getenv("SHIELD_PORT"):
            try:
                self.server.port = int(v)
            except ValueError:
                pass
        if v := os.getenv("SHIELD_AUDIT_PATH"):
            self.audit.path = v
        if v := os.getenv("SHIELD_UPSTREAM_BASE_URL"):
            self.server.upstream_base_url = v
        if v := os.getenv("SHIELD_UPSTREAM_API_KEY"):
            self.server.upstream_api_key = v


def find_config(start: str | Path | None = None) -> Path | None:
    """Look for shield.yaml in `start` (or cwd), then each parent directory."""
    here = Path(start) if start else Path.cwd()
    if here.is_file():
        return here
    for directory in [here, *here.parents]:
        for name in DEFAULT_CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def load_config(path: str | Path | None = None) -> Config:
    """Load config from a YAML file, or return safe defaults if none exists."""
    resolved = Path(path) if path else find_config()
    if resolved is None:
        return Config.from_dict({})
    if not resolved.is_file():
        raise ConfigError(f"config file not found: {resolved}")

    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - yaml ships with the package
        raise ConfigError("PyYAML is required to read a config file") from exc

    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{resolved} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{resolved} must contain a YAML mapping at the top level")

    return Config.from_dict(raw)
