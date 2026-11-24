"""Deterministic extraction of CTF flags, API keys, tokens, credentials, IDs, names, and numbers."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class IntelRule:
    """Regex extraction rule mapping matched artifacts to a normalized intel category."""

    category: str  # flag | key | credential | identifier | name | number
    label: str
    pattern: re.Pattern[str]
    severity: str  # critical | high | medium | low | info
    cwe_id: str | None = None
    group: int = 0
    redact_when_masked: bool = False


CTF_FLAG_RE = re.compile(
    r"\b(?:HTB|CTF|FLAG|THM|picoCTF|flag|ctf)\{[A-Za-z0-9_!@#$%^&*()\-+=.:/?~]{4,160}\}"
)
JWT_TOKEN_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{2,64}@[A-Za-z0-9.-]{2,120}\.[A-Za-z]{2,16}\b")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
HTML_COMMENT_RE = re.compile(r"<!--([\s\S]{4,500}?)-->")

INTEL_RULES: list[IntelRule] = [
    IntelRule("flag", "CTF / HTB Flag", CTF_FLAG_RE, "critical", "CWE-200", redact_when_masked=True),
    IntelRule("key", "AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high", "CWE-798", redact_when_masked=True),
    IntelRule("key", "Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "high", "CWE-798", redact_when_masked=True),
    IntelRule(
        "key",
        "GitHub Token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        "critical",
        "CWE-798",
        redact_when_masked=True,
    ),
    IntelRule("key", "GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "critical", "CWE-798", redact_when_masked=True),
    IntelRule("key", "Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high", "CWE-798", redact_when_masked=True),
    IntelRule(
        "key",
        "Stripe / OpenAI Secret Key",
        re.compile(r"\b(?:sk_live|rk_live|sk-proj|sk)-[0-9A-Za-z_-]{20,}\b"),
        "critical",
        "CWE-798",
        redact_when_masked=True,
    ),
    IntelRule("key", "Private Key Header", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "critical", "CWE-798", redact_when_masked=True),
    IntelRule("key", "JWT Token", JWT_TOKEN_RE, "medium", "CWE-200", redact_when_masked=True),
    IntelRule(
        "key",
        "Database Connection URI",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s\"'<>]{6,180}"),
        "critical",
        "CWE-798",
        redact_when_masked=True,
    ),
    IntelRule(
        "key",
        "Hardcoded API Key / Token",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|x-api-key|access[_-]?token|auth[_-]?token|client[_-]?secret|bearer[_-]?token|secret[_-]?key)\b\s*[:=]\s*["']([^"'\r\n]{4,160})["']"""
        ),
        "high",
        "CWE-798",
        group=1,
        redact_when_masked=True,
    ),
    IntelRule(
        "credential",
        "Hardcoded Username / Login",
        re.compile(
            r"""(?i)\b(?:username|user_name|admin_user|login_user|db_user)\b\s*[:=]\s*["']([A-Za-z0-9._@-]{2,64})["']"""
        ),
        "medium",
        "CWE-200",
        group=1,
        redact_when_masked=False,
    ),
    IntelRule(
        "credential",
        "Hardcoded Password / Secret",
        re.compile(
            r"""(?i)\b(?:password|passwd|passphrase|db_pass|admin_pass|secret)\b\s*[:=]\s*["']([^"'\r\n]{3,120})["']"""
        ),
        "high",
        "CWE-798",
        group=1,
        redact_when_masked=True,
    ),
    IntelRule(
        "identifier",
        "Named Entity / Client ID",
        re.compile(
            r"""(?i)\b(user_id|account_id|tenant_id|project_id|client_id|org_id|role_id|admin_id|customer_id)\b\s*[:=]\s*["']?([A-Za-z0-9_-]{2,80})["']?"""
        ),
        "info",
        "CWE-200",
        group=0,
        redact_when_masked=False,
    ),
    IntelRule("identifier", "UUID Identifier", UUID_RE, "info", "CWE-200", redact_when_masked=False),
    IntelRule("name", "Email Address", EMAIL_RE, "info", "CWE-200", redact_when_masked=False),
]

NOISY_EMAIL_PREFIXES = ("noreply@", "no-reply@", "example@", "test@", "user@example", "admin@example")
NOISY_EMAIL_DOMAINS = ("example.com", "example.org", "w3.org", "schema.org", "sentry.io", "placeholder.local")


def mask_value(val: str) -> str:
    """Return a shortened preview mask for sensitive tokens/keys."""
    clean = str(val or "")
    if len(clean) <= 8:
        return "*" * max(4, len(clean))
    return f"{clean[:4]}...{clean[-4:]}"


def _extract_ip_numbers(text: str, seen: set[tuple[str, str]], results: list[dict[str, Any]], source_url: str, tool_source: str) -> None:
    for match in IPV4_RE.finditer(text):
        ip_str = match.group(0)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip_obj.is_version if False else False:
            continue
        if ip_str in {"0.0.0.0", "127.0.0.1", "255.255.255.255"}:
            continue
        # Only highlight private/internal IPs or non-version-looking IPs inside text/scripts
        if not (ip_obj.is_private or ip_obj.is_loopback):
            continue
        key = ("Internal / Lab IP", ip_str)
        if key in seen:
            continue
        seen.add(key)
        results.append(
            {
                "category": "number",
                "label": "Internal / Lab IP",
                "value": ip_str,
                "masked_value": ip_str,
                "sensitive": False,
                "severity": "low",
                "cwe_id": "CWE-200",
                "location": source_url,
                "tool_source": tool_source,
            }
        )
        if len(results) >= 60:
            return


def extract_intel_from_text(
    text: str,
    *,
    source_url: str,
    tool_source: str = "intel_extractor",
    include_html_comments: bool = False,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Extract categorized CTF flags, keys, credentials, IDs, names, emails, and internal IPs."""
    if not text:
        return []

    sample = text[:600_000]
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for rule in INTEL_RULES:
        for match in rule.pattern.finditer(sample):
            raw = (match.group(rule.group) if rule.group and match.lastindex and match.lastindex >= rule.group else match.group(0)).strip()
            if not raw or len(raw) > 220:
                continue
            if rule.label == "Email Address":
                low = raw.lower()
                if any(low.startswith(p) for p in NOISY_EMAIL_PREFIXES) or any(low.endswith("@" + d) for d in NOISY_EMAIL_DOMAINS):
                    continue
            if rule.label in ("Hardcoded Password / Secret", "Hardcoded API Key / Token") and raw.lower() in {
                "password",
                "secret",
                "undefined",
                "null",
                "true",
                "false",
                "placeholder",
            }:
                continue
            dedupe_key = (rule.label, raw)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            items.append(
                {
                    "category": rule.category,
                    "label": rule.label,
                    "value": raw,
                    "masked_value": mask_value(raw) if rule.redact_when_masked else raw,
                    "sensitive": rule.redact_when_masked,
                    "severity": rule.severity,
                    "cwe_id": rule.cwe_id,
                    "location": source_url,
                    "tool_source": tool_source,
                }
            )
            if len(items) >= limit:
                return items

    if include_html_comments:
        for match in HTML_COMMENT_RE.finditer(sample):
            comment = re.sub(r"\s+", " ", match.group(1)).strip()
            if len(comment) < 5:
                continue
            interesting_kw = any(
                kw in comment.lower()
                for kw in (
                    "flag",
                    "htb{",
                    "ctf{",
                    "todo",
                    "pass",
                    "user",
                    "admin",
                    "key",
                    "token",
                    "secret",
                    "debug",
                    "api",
                    "dev",
                    "cred",
                    "/",
                )
            )
            if not interesting_kw:
                continue
            dedupe_key = ("HTML Developer Comment", comment[:160])
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            items.append(
                {
                    "category": "name",
                    "label": "HTML Developer Comment",
                    "value": comment[:220],
                    "masked_value": comment[:220],
                    "sensitive": False,
                    "severity": "info",
                    "cwe_id": "CWE-615",
                    "location": source_url,
                    "tool_source": tool_source,
                }
            )
            if len(items) >= limit:
                return items

    _extract_ip_numbers(sample, seen, items, source_url, tool_source)
    return items[:limit]
