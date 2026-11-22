"""Nikto bounded web server misconfiguration scanner adapter (Tier 2)."""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredFinding, ToolResult, resolve_binary


class NiktoArgs(BaseModel):
    max_time_seconds: int = Field(default=60, ge=15, le=180)
    timeout_seconds: int = Field(default=120, ge=20, le=240)


class NiktoAdapter(BaseToolAdapter):
    name = "nikto"
    description = "Bounded web server misconfiguration, dangerous file, and header scanner via Nikto."
    tier = 2
    binary_name = "nikto"
    args_schema = NiktoArgs

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, NiktoArgs)
        bin_path = resolve_binary("nikto") or "nikto"
        out_file = work_dir / "nikto.json"
        return [
            bin_path,
            "-h",
            target,
            "-Format",
            "json",
            "-output",
            str(out_file),
            "-maxtime",
            f"{args.max_time_seconds}s",
            "-nointeractive",
            "-nocheck",
            "-Timeout",
            "5",
        ]

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        out_file = work_dir / "nikto.json"
        raw = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""
        findings: list[DiscoveredFinding] = []
        if raw.strip():
            try:
                data = json.loads(raw)
                items = data if isinstance(data, list) else [data]
                for host_obj in items:
                    vulns = host_obj.get("vulnerabilities") or []
                    for v in vulns[:60]:
                        msg = v.get("msg") or "Nikto finding"
                        uri = v.get("url") or ""
                        full_url = target.rstrip("/") + uri if uri.startswith("/") else target
                        findings.append(
                            DiscoveredFinding(
                                title=msg[:120],
                                severity="low",
                                target_url=full_url,
                                cwe_id="CWE-200",
                                owasp_category="A05:2021 - Security Misconfiguration",
                                cvss_score=3.1,
                                description=msg,
                                evidence={"nikto_id": v.get("id"), "osvdb": v.get("OSVDB"), "method": v.get("method"), "url": uri},
                                remediation="Review affected server configuration or exposed path identified by Nikto.",
                                tool_source=self.name,
                            )
                        )
            except json.JSONDecodeError:
                pass
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            findings=findings,
            summary={"findings_count": len(findings)},
        )
