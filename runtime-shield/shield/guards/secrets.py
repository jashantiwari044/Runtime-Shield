"""Outbound secret detection — stop credentials leaving in a tool result.

Runs on the way *back*: an agent reads a config file, and without this the key
lands in the model's context and then in the transcript, the logs, and any
downstream the model talks to.
"""

from __future__ import annotations

import re

from ..config import Config
from ..models import Action, Finding, Severity, Stage
from .base import OutboundGuard

_Rule = tuple[str, str, Severity]

SECRET_PATTERNS: list[_Rule] = [
    (r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", "aws_access_key", Severity.CRITICAL),
    (r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?", "aws_secret_key", Severity.CRITICAL),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b", "github_token", Severity.CRITICAL),
    (r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b", "github_pat", Severity.CRITICAL),
    (r"\bsk-ant-(?:api|admin)[A-Za-z0-9_-]{20,}\b", "anthropic_api_key", Severity.CRITICAL),
    (r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b", "openai_api_key", Severity.CRITICAL),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "slack_token", Severity.CRITICAL),
    (r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b", "stripe_key", Severity.CRITICAL),
    (r"\bAIza[0-9A-Za-z_-]{35}\b", "google_api_key", Severity.CRITICAL),
    (r"\bya29\.[0-9A-Za-z_-]{20,}\b", "google_oauth_token", Severity.CRITICAL),
    (r"\bnvapi-[A-Za-z0-9_-]{20,}\b", "nvidia_api_key", Severity.CRITICAL),
    (r"\bhf_[A-Za-z0-9]{30,}\b", "huggingface_token", Severity.CRITICAL),
    (r"\bglpat-[A-Za-z0-9_-]{20,}\b", "gitlab_token", Severity.CRITICAL),
    (r"\bdop_v1_[a-f0-9]{64}\b", "digitalocean_token", Severity.CRITICAL),
    (r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b", "sendgrid_key", Severity.CRITICAL),
    (r"\bnpm_[A-Za-z0-9]{36}\b", "npm_token", Severity.CRITICAL),
    (r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY(?:\s+BLOCK)?-----",
     "private_key", Severity.CRITICAL),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "jwt", Severity.HIGH),
    (r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:[^@\s]{3,}@[^\s\"']+",
     "database_url_with_password", Severity.CRITICAL),
    (r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
     r"password|passwd)\s*[:=]\s*[\"']([^\"'\s]{12,})[\"']",
     "hardcoded_credential", Severity.HIGH),
    (r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}",
     "authorization_header", Severity.HIGH),
]

_COMPILED = [(re.compile(p), kind, sev) for p, kind, sev in SECRET_PATTERNS]

# Values that look like secrets but are documentation, not credentials.
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{6,}|\*{6,}|\.{3,}|<[^>]*>|\{\{[^}]*\}\}|\$\{[^}]*\}|"
    r"(?:your|my|example|sample|changeme|placeholder|redacted|dummy|fake|test|insert|"
    r"replace|todo|xxx)[\w-]*)$"
)


class SecretScanner(OutboundGuard):
    stage = Stage.SECRETS

    def scan(self, text: str, config: Config) -> tuple[str, list[Finding]]:
        cfg = config.secrets
        if not cfg.enabled or not text:
            return text, []

        allow = [re.compile(a) for a in cfg.allow if a]
        action = config.action_for(cfg.action, Action.REDACT)
        found: dict[str, int] = {}
        worst = Severity.INFO
        result = text

        for pattern, kind, severity in _COMPILED:
            def replace(match: re.Match[str], _kind: str = kind, _sev: Severity = severity) -> str:
                nonlocal worst
                whole = match.group(0)
                # Prefer the captured group when the pattern matches `key = "value"`.
                secret = match.group(1) if match.groups() and match.group(1) else whole
                if _PLACEHOLDER.match(secret.strip()) or any(a.search(whole) for a in allow):
                    return whole
                found[_kind] = found.get(_kind, 0) + 1
                if _sev > worst:
                    worst = _sev
                if action is Action.BLOCK:
                    return whole
                token = cfg.placeholder.format(kind=_kind.upper())
                return whole.replace(secret, token) if secret != whole else token

            result = pattern.sub(replace, result)

        if not found:
            return text, []

        summary = ", ".join(f"{k} x{v}" if v > 1 else k for k, v in sorted(found.items()))
        finding = Finding(
            stage=self.stage,
            action=action,
            reason=f"Secrets detected in output: {summary}",
            severity=worst,
            details={"kinds": sorted(found), "count": sum(found.values())},
        )
        if action is Action.BLOCK:
            return text, [finding]
        if action is Action.FLAG:
            return text, [finding]
        return result, [finding]
