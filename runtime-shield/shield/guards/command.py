"""Dangerous-command detection.

Exists because permission rules alone kept missing the obvious case: the old
engine allow-listed a tool called `exec` and happily passed
`{"command": "rm -rf /"}` straight through, because its shell rule only listed
the tool names `shell_exec|run_command|execute_command|bash`.

This guard inspects the *command text* rather than the tool name, so it fires
no matter what an integration decided to call its shell tool.
"""

from __future__ import annotations

import re

from ..config import Config
from ..matching import tool_match
from ..models import Finding, Severity, Stage, ToolCall
from ..normalize import command_variants
from .base import Guard, collect_strings

# Tool names that are shell-shaped enough to scan every argument.
SHELL_TOOLS = "*exec*|*shell*|*bash*|*command*|*terminal*|*subprocess*|*run_*|*_run|sh|zsh|cmd|powershell"

_Rule = tuple[str, str, Severity]

# Some keywords ("shutdown", "history") are ordinary English as well as
# commands, so those patterns only fire in a *command position*: the start of
# the string, or just after a separator. Otherwise `echo "shutdown the pool"`
# reads as an attempt to halt the host.
CMD_START = r"(?:\A|[;&|]|\n|\$\(|`)\s*(?:sudo\s+)?"

DANGEROUS: list[_Rule] = [
    # -- destroying the filesystem --------------------------------------
    (r"\brm\s+(?:-[a-zA-Z]*\s+)*-{1,2}[a-zA-Z-]*(?:rf|fr|recursive)[a-zA-Z-]*\s+"
     r"[\"']?(?:/|~/?|\$HOME/?|\.|\*)[\"']?(?:\s|$|\*|#|;|&|\|)",
     "Recursive delete of a root or home directory", Severity.CRITICAL),
    (r"\brm\s+(?:-[a-zA-Z]+\s+)*(?:/etc|/usr|/var|/bin|/sbin|/boot|/lib|/System|/Windows)\b",
     "Delete targeting a system directory", Severity.CRITICAL),
    (r"\bmkfs(?:\.\w+)?\b", "Filesystem format", Severity.CRITICAL),
    (r"\bdd\b[^\n]{0,120}\bof=\s*/dev/(?:sd|nvme|disk|hd|vd)",
     "Raw write to a block device", Severity.CRITICAL),
    (r">\s*/dev/(?:sd|nvme|disk|hd|vd)\w*", "Redirect over a block device", Severity.CRITICAL),
    (r"\bshred\s+(?:-[a-zA-Z]+\s+)*/", "Secure-erase of a filesystem path", Severity.CRITICAL),

    # -- remote code execution ------------------------------------------
    (r"(?:curl|wget|fetch)\b[^|;&\n]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|k|da|c)?sh\b",
     "Piping a downloaded script straight into a shell", Severity.CRITICAL),
    (r"(?:curl|wget)\b[^|;&\n]{0,200}\|\s*(?:sudo\s+)?(?:python|perl|ruby|node)\b",
     "Piping a download into an interpreter", Severity.CRITICAL),
    (r"\bbase64\s+(?:-d|--decode|-D)\b[^\n]{0,120}\|\s*(?:ba)?sh\b",
     "Executing base64-decoded code", Severity.CRITICAL),
    (r"\beval\s*[\"'$(]", "Shell eval of dynamic content", Severity.HIGH),

    # -- reverse shells and exfiltration --------------------------------
    (r"/dev/tcp/\d|\bbash\s+-i\s*>&", "Reverse shell", Severity.CRITICAL),
    (r"\bnc(?:at)?\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*e[a-zA-Z]*\b", "Netcat reverse shell", Severity.CRITICAL),
    (r"(?:curl|wget)\b[^\n]{0,200}(?:--data|--data-binary|-d|-F|-T|--upload-file)[^\n]{0,120}"
     r"(?:/etc/passwd|/etc/shadow|\.ssh|id_rsa|\.env\b|\.aws|credentials)",
     "Uploading credential files to a remote host", Severity.CRITICAL),

    # -- fork bombs and availability ------------------------------------
    (r":\s*\(\s*\)\s*\{\s*:?\s*\|\s*:?\s*&\s*\}\s*;?\s*:", "Fork bomb", Severity.CRITICAL),
    (CMD_START + r"(?:shutdown|reboot|poweroff|halt)\b(?!\s*-?-?h(?:elp)?\b)",
     "Host shutdown or reboot", Severity.HIGH),

    # -- privilege and permission changes -------------------------------
    (r"\bchmod\s+(?:-[a-zA-Z]*R[a-zA-Z]*\s+)?0?777\s+/(?:\s|$|\*)",
     "World-writable permissions on root", Severity.CRITICAL),
    (r"\bchown\s+-[a-zA-Z]*R[a-zA-Z]*\s+[^\s]+\s+/(?:\s|$|\*)",
     "Recursive ownership change on root", Severity.HIGH),
    (r"\b(?:usermod|useradd)\b[^\n]{0,80}\b(?:sudo|wheel|admin|root)\b",
     "Granting administrative group membership", Severity.HIGH),
    (r">>?\s*/etc/(?:sudoers|passwd|shadow)\b", "Writing to a system auth file", Severity.CRITICAL),

    # -- covering tracks -------------------------------------------------
    (CMD_START + r"history\s+-c\b|>\s*~?/?\.?(?:bash|zsh)_history",
     "Clearing shell history", Severity.HIGH),
    (CMD_START + r"crontab\s+-r\b", "Wiping scheduled jobs", Severity.HIGH),
    (r"\b(?:systemctl|service)\s+(?:stop|disable)\s+(?:auditd|rsyslog|syslog|falco)",
     "Disabling audit logging", Severity.CRITICAL),

    # -- worth knowing about, not worth blocking by default -------------
    (r"\bsudo\s+(?!-h|--help)", "Privilege escalation via sudo", Severity.MEDIUM),
    (r"\bgit\s+push\b[^\n]{0,60}(?:--force|-f)\b", "Force push", Severity.LOW),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), label, sev) for p, label, sev in DANGEROUS]

# Only findings at or above this severity are blocked; the rest are flagged.
_BLOCK_FLOOR = Severity.HIGH


class CommandGuard(Guard):
    stage = Stage.COMMAND

    def check(self, call: ToolCall, config: Config) -> Finding | None:
        cfg = config.command
        if not cfg.enabled:
            return None

        for text in self._command_texts(call, cfg.fields):
            if not text or not text.strip():
                continue
            if any(re.search(a, text, re.IGNORECASE) for a in cfg.allow if a):
                continue

            # Test the literal text and every form a shell would reduce it to,
            # so `r""m -rf /` and a line-continuation split are both caught.
            for variant in command_variants(text):
                for pattern, label, severity in _COMPILED:
                    match = pattern.search(variant)
                    if not match:
                        continue
                    if severity < _BLOCK_FLOOR:
                        return self._flag(
                            f"Notable command: {label}", severity,
                            matched=match.group(0)[:120], command=text[:200],
                        )
                    return self._decide(
                        cfg.action, f"Dangerous command blocked: {label}", severity,
                        matched=match.group(0)[:120], command=text[:200],
                    )
        return None

    @staticmethod
    def _command_texts(call: ToolCall, command_fields: list[str]) -> list[str]:
        wanted = {f.lower() for f in command_fields}
        texts: list[str] = []

        for key, value in call.arguments.items():
            if str(key).lower() in wanted:
                texts.extend(collect_strings(value))

        # A shell-shaped tool gets every argument scanned, whatever the key.
        if tool_match(call.tool, SHELL_TOOLS):
            texts.extend(collect_strings(call.arguments))

        return texts
