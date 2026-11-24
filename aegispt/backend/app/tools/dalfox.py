"""Dalfox XSS verification adapter (Tier 3 - Mandatory Operator Approval)."""
from __future__ import annotations

import json
import shlex
from pathlib import Path

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import (
    BaseToolAdapter,
    DiscoveredFinding,
    ToolResult,
    resolve_binary,
)


class DalfoxArgs(BaseModel):
    param: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.\[\]-]{0,127}$")
    skip_bav: bool = True
    timeout_seconds: int = Field(default=150, ge=20, le=300)


class DalfoxAdapter(BaseToolAdapter):
    name = "dalfox"
    description = "Approval-gated Cross-Site Scripting (XSS) parameter verification via dalfox."
    tier = 3
    binary_name = "dalfox"
    args_schema = DalfoxArgs

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, DalfoxArgs)
        bin_path = resolve_binary("dalfox") or "dalfox"
        out_file = work_dir / "dalfox.json"
        argv = [
            bin_path,
            "url",
            target,
            "--format",
            "json",
            "--output",
            str(out_file),
            "--silence",
            "--worker",
            str(min(scope.max_concurrency, 5)),
            "--timeout",
            "10",
            "--skip-headless",
        ]
        if args.param:
            argv.extend(["-p", args.param])
        if args.skip_bav:
            argv.append("--skip-bav")
        for k, v in scope.custom_headers.items():
            argv.extend(["-H", f"{k}: {v}"])
        if scope.auth_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in scope.auth_cookies.items())
            argv.extend(["-C", cookie_str])
        return argv

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        out_file = work_dir / "dalfox.json"
        raw = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else stdout
        findings: list[DiscoveredFinding] = []

        items = []
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, list):
                items = loaded
            elif isinstance(loaded, dict):
                items = [loaded]
        except json.JSONDecodeError:
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        for item in items:
            if not isinstance(item, dict):
                continue
            poc = item.get("data") or item.get("poc") or ""
            param = item.get("param")
            if not poc and not item.get("type"):
                continue
            vuln_type = str(item.get("type") or "XSS")
            sev = str(item.get("severity") or "high").lower()
            if sev not in {"critical", "high", "medium", "low", "info"}:
                sev = "high"
            findings.append(
                DiscoveredFinding(
                    title=f"Cross-Site Scripting ({vuln_type}) in '{param or 'input'}'",
                    severity=sev,
                    target_url=target,
                    parameter=param,
                    cwe_id=item.get("cwe") or "CWE-79",
                    owasp_category="A03:2021 - Injection",
                    cvss_score=6.1 if sev == "medium" else 7.4,
                    description=f"Dalfox verified {vuln_type} reflection/execution on parameter '{param}'.",
                    evidence={
                        "type": vuln_type,
                        "inject_type": item.get("inject_type"),
                        "method": item.get("method"),
                        "param": param,
                        "poc": poc,
                    },
                    poc_command=(
                        f"curl -i -s {shlex.quote(str(poc))}"
                        if str(poc).startswith(("http://", "https://"))
                        else None
                    ),
                    remediation="Apply context-aware output encoding and strict Content-Security-Policy (CSP).",
                    tool_source=self.name,
                )
            )
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            findings=findings,
            summary={"xss_findings": len(findings)},
        )
