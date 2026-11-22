"""SQLMap SQL Injection verification adapter (Tier 3 - Mandatory Operator Approval, strictly bounded)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredFinding, ToolResult, resolve_binary


PARAM_BLOCK_RE = re.compile(
    r"Parameter:\s*(?P<param>.+?)\n(?P<body>(?:    .+\n)+)", re.MULTILINE
)


class SqlmapArgs(BaseModel):
    method: Literal["GET", "POST", "PUT", "PATCH"] = "GET"
    data: str | None = None
    param: str | None = None
    level: int = Field(default=1, ge=1, le=2)
    risk: int = Field(default=1, ge=1, le=2)
    technique: str = Field(default="BEUT", pattern=r"^[BEUSTQ]{1,6}$")
    timeout_seconds: int = Field(default=180, ge=30, le=360)


class SqlmapAdapter(BaseToolAdapter):
    name = "sqlmap"
    description = "Approval-gated, strictly bounded SQL injection verification using sqlmap (--batch, level<=2, risk<=2)."
    tier = 3
    binary_name = "sqlmap"
    args_schema = SqlmapArgs

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, SqlmapArgs)
        bin_path = resolve_binary("sqlmap") or "sqlmap"
        out_dir = work_dir / "sqlmap_out"
        out_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            bin_path,
            "-u",
            target,
            "--batch",
            "--disable-coloring",
            "--level",
            str(args.level),
            "--risk",
            str(args.risk),
            "--technique",
            args.technique,
            "--threads",
            str(min(scope.max_concurrency, 3)),
            "--timeout",
            "10",
            "--retries",
            "1",
            "--output-dir",
            str(out_dir),
            "--answers=follow=N,quit=N",
        ]
        if args.method in {"POST", "PUT", "PATCH"} and args.data:
            argv.extend(["--method", args.method, "--data", args.data])
            stripped = args.data.lstrip()
            if (stripped.startswith("{") or stripped.startswith("[")) and not any(
                k.lower() == "content-type" for k in scope.custom_headers
            ):
                argv.extend(["--header", "Content-Type: application/json"])
        if args.param:
            argv.extend(["-p", args.param])
        for k, v in scope.custom_headers.items():
            argv.extend(["--header", f"{k}: {v}"])
        if scope.auth_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in scope.auth_cookies.items())
            argv.extend(["--cookie", cookie_str])
        return argv

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        findings: list[DiscoveredFinding] = []
        for m in PARAM_BLOCK_RE.finditer(stdout):
            param = m.group("param").strip()
            body = m.group("body").strip()
            findings.append(
                DiscoveredFinding(
                    title=f"SQL Injection Verified on Parameter '{param}'",
                    severity="critical",
                    target_url=target,
                    parameter=param,
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 - Injection",
                    cvss_score=9.3,
                    description=f"SQLMap confirmed SQL injection on parameter {param}.",
                    evidence={"parameter": param, "sqlmap_details": body[:1500]},
                    poc_command=f"sqlmap -u '{target}' --batch --level=1 --risk=1 -p '{param}'",
                    remediation="Use parameterized queries / prepared statements for all database access and reject unexpected input types.",
                    tool_source=self.name,
                )
            )
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            findings=findings,
            summary={"injectable_parameters": len(findings)},
        )
