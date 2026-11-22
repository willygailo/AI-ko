"""Reversible outbound secret, token, cookie, and credential redactor for remote LLM calls."""
from __future__ import annotations

import re
from dataclasses import dataclass, field


SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")),
    ("BEARER", re.compile(r"(?i)(Authorization\s*:\s*Bearer\s+)([A-Za-z0-9._~+/-]{12,}=*)")),
    ("BASIC", re.compile(r"(?i)(Authorization\s*:\s*Basic\s+)([A-Za-z0-9+/]{8,}={0,2})")),
    ("COOKIE", re.compile(r"(?i)((?:Set-)?Cookie\s*:\s*)([^\r\n]+)")),
    ("APIKEY", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})\b")),
    ("KV_SECRET", re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|secret[_-]?key|password|passwd)\s*[=:]\s*[\"']?)([^\"'\s&,;]{6,})")),
]


@dataclass
class SecretRedactor:
    _forward: dict[str, str] = field(default_factory=dict)
    _reverse: dict[str, str] = field(default_factory=dict)
    _counters: dict[str, int] = field(default_factory=dict)

    def _token_for(self, kind: str, secret_val: str) -> str:
        if secret_val.startswith("__REDACTED_") and secret_val.endswith("__"):
            return secret_val
        if secret_val in self._forward:
            return self._forward[secret_val]
        idx = self._counters.get(kind, 0) + 1
        self._counters[kind] = idx
        placeholder = f"__REDACTED_{kind}_{idx}__"
        self._forward[secret_val] = placeholder
        self._reverse[placeholder] = secret_val
        return placeholder

    def redact(self, text: str) -> str:
        if not text:
            return text
        out = text
        for kind, pattern in SECRET_PATTERNS:
            if pattern.groups == 2:
                out = pattern.sub(
                    lambda m, k=kind: f"{m.group(1)}{self._token_for(k, m.group(2))}",
                    out,
                )
            else:
                out = pattern.sub(
                    lambda m, k=kind: self._token_for(k, m.group(0)),
                    out,
                )
        return out

    def restore(self, text: str) -> str:
        if not text or not self._reverse:
            return text
        out = text
        for placeholder, original in reversed(list(self._reverse.items())):
            out = out.replace(placeholder, original)
        return out
