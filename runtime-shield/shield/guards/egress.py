"""Egress control — stop agents reaching internal networks and cloud metadata.

The classic agent breach: something convinces the model to fetch
`http://169.254.169.254/latest/meta-data/iam/security-credentials/`, and the
instance's IAM credentials end up in the transcript.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from urllib.parse import urlsplit

from ..config import Config
from ..matching import glob_match
from ..models import Finding, Severity, Stage, ToolCall
from ..normalize import decode_escapes, strip_invisible
from .base import Guard, collect_strings

CLOUD_METADATA_HOSTS = {
    "169.254.169.254",          # AWS / Azure / GCP / DigitalOcean
    "169.254.170.2",            # AWS ECS task metadata
    "100.100.100.200",          # Alibaba Cloud
    "192.0.0.192",              # Oracle Cloud
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
}
CLOUD_METADATA_V6 = {"fd00:ec2::254"}

DANGEROUS_SCHEMES = {"file", "gopher", "dict", "ftp", "ldap", "ldaps", "jar", "netdoc", "expect"}

# These are targets to *block*, not addresses to bind.
LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "0.0.0.0", "[::]"}  # noqa: S104

_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://[^\s\"'<>\\)\]}]+", re.IGNORECASE)


class EgressGuard(Guard):
    stage = Stage.EGRESS

    def check(self, call: ToolCall, config: Config) -> Finding | None:
        cfg = config.egress
        if not cfg.enabled:
            return None

        for url in _find_urls(call.arguments):
            try:
                parts = urlsplit(url)
            except ValueError:
                continue

            scheme = (parts.scheme or "").lower()
            try:
                host = (parts.hostname or "").lower().strip("[]")
            except ValueError:
                # Malformed authority (e.g. a bad IPv6 literal) — refuse it.
                return self._decide(cfg.action, f"Malformed URL rejected: {url[:120]}",
                                    Severity.MEDIUM, url=url[:200])

            if scheme in DANGEROUS_SCHEMES:
                return self._decide(
                    cfg.action, f"Blocked dangerous URL scheme '{scheme}://'",
                    Severity.HIGH, url=url[:200], scheme=scheme,
                )

            if not host:
                continue

            if any(glob_match(host, p) for p in cfg.deny_hosts):
                return self._decide(cfg.action, f"Host '{host}' is on the deny list",
                                    Severity.HIGH, url=url[:200], host=host)

            # An allow-list, when set, is exhaustive for http(s).
            if cfg.allow_hosts and scheme in ("http", "https"):
                if not any(glob_match(host, p) for p in cfg.allow_hosts):
                    return self._decide(
                        cfg.action, f"Host '{host}' is not on the egress allow-list",
                        Severity.HIGH, url=url[:200], host=host,
                    )
                continue

            if cfg.block_cloud_metadata and _is_metadata_host(host):
                return self._decide(
                    cfg.action, f"Cloud metadata endpoint blocked: {host}",
                    Severity.CRITICAL, url=url[:200], host=host,
                )

            if cfg.block_private_ips:
                if finding := self._check_private(host, url, cfg.action):
                    return finding

        return None

    def _check_private(self, host: str, url: str, action: str) -> Finding | None:
        if host in LOCAL_NAMES or host.endswith(".localhost") or host.endswith(".internal"):
            return self._decide(action, f"Internal hostname blocked: {host}",
                                Severity.HIGH, url=url[:200], host=host)

        ip = _parse_ip(host)
        if ip is None:
            return None

        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return self._decide(
                action, f"Private or internal address blocked: {ip}",
                Severity.HIGH, url=url[:200], ip=str(ip),
            )
        return None


def _is_metadata_host(host: str) -> bool:
    if host in CLOUD_METADATA_HOSTS or host in CLOUD_METADATA_V6:
        return True
    ip = _parse_ip(host)
    return ip is not None and str(ip) in CLOUD_METADATA_HOSTS | CLOUD_METADATA_V6


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a host as an IP, including decimal/hex/octal obfuscations.

    `http://2130706433/` and `http://0x7f000001/` are both 127.0.0.1.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    try:
        if re.fullmatch(r"0x[0-9a-f]+", host, re.IGNORECASE):
            return ipaddress.ip_address(int(host, 16))
        if re.fullmatch(r"0[0-7]+", host):
            return ipaddress.ip_address(int(host, 8))
        if re.fullmatch(r"\d{1,10}", host):
            value = int(host)
            if 0 <= value <= 0xFFFFFFFF:
                return ipaddress.ip_address(value)
    except (ValueError, ipaddress.AddressValueError):
        pass
    return None


def _find_urls(arguments: dict) -> list[str]:
    """Collect URLs from argument values, including ones embedded in prose.

    Percent-encoded and escaped forms are decoded first: a client that decodes
    `http%3A//169.254.169.254/` before requesting it reaches the metadata
    endpoint just the same, so the guard has to see what the client will see.
    """
    urls: list[str] = []
    seen: set[str] = set()

    for raw in collect_strings(arguments):
        for text in _url_forms(raw):
            if "://" not in text:
                continue
            for url in _URL_RE.findall(text):
                if url not in seen:
                    seen.add(url)
                    urls.append(url)
    return urls


def _url_forms(text: str) -> list[str]:
    """The literal text plus any decoded form that could reveal a URL."""
    forms = [text]
    cleaned = strip_invisible(text)
    if cleaned != text:
        forms.append(cleaned)
    if "%" in cleaned:
        try:
            forms.append(urllib.parse.unquote_plus(cleaned))
        except (ValueError, UnicodeDecodeError):
            pass
    if "\\" in cleaned:
        forms.append(decode_escapes(cleaned))
    return forms
