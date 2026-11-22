"""ProjectDiscovery Nuclei template scanner adapter (Tier 2 safe / Tier 3 intrusive)."""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredFinding, ToolResult, resolve_binary


CVSS_BY_SEVERITY = {
    "critical": 9.5,
    "high": 7.8,
    "medium": 5.5,
    "low": 3.1,
    "info": 0.0,
}


class NucleiArgs(BaseModel):
    tags: list[str] = Field(default_factory=list)
    severity: list[str] = Field(default_factory=lambda: ["low", "medium", "high", "critical"])
    include_intrusive: bool = False
    timeout_seconds: int = Field(default=180, ge=20, le=420)


class NucleiAdapter(BaseToolAdapter):
    name = "nuclei"
    description = "YAML-template vulnerability scanner (safe misconfig/exposure templates in Tier 2; intrusive/fuzz templates gated at Tier 3)."
    tier = 2
    binary_name = "nuclei"
    args_schema = NucleiArgs

    def effective_tier(self, args: BaseModel) -> int:
        assert isinstance(args, NucleiArgs)
        intrusive_tags = {"dos", "intrusive", "fuzz", "fuzzing", "sqli", "rce"}
        if args.include_intrusive or any(t.lower() in intrusive_tags for t in args.tags):
            return 3
        return 2

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, NucleiArgs)
        bin_path = resolve_binary("nuclei") or "nuclei"
        argv = [
            bin_path,
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-nc",
            "-rl",
            str(scope.max_rps),
            "-c",
            str(min(scope.max_concurrency * 2, 15)),
            "-severity",
            ",".join(args.severity),
        ]
        if args.tags:
            argv.extend(["-tags", ",".join(args.tags)])
        if not args.include_intrusive:
            argv.extend(["-etags", "dos,intrusive,fuzz,bruteforce"])
        for k, v in scope.custom_headers.items():
            argv.extend(["-H", f"{k}: {v}"])
        if scope.auth_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in scope.auth_cookies.items())
            argv.extend(["-H", f"Cookie: {cookie_str}"])
        return argv

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        findings: list[DiscoveredFinding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info") or {}
            sev = str(info.get("severity") or "info").lower()
            if sev not in CVSS_BY_SEVERITY:
                sev = "info"
            classification = info.get("classification") or {}
            cwe_ids = classification.get("cwe-id") or []
            cwe = cwe_ids[0] if isinstance(cwe_ids, list) and cwe_ids else None
            cvss_score = classification.get("cvss-score") or CVSS_BY_SEVERITY.get(sev)
            matched_at = obj.get("matched-at") or obj.get("host") or target
            template_id = obj.get("template-id") or "nuclei-template"
            name = info.get("name") or template_id

            findings.append(
                DiscoveredFinding(
                    title=f"{name} ({template_id})",
                    severity=sev,
                    target_url=matched_at,
                    cwe_id=cwe,
                    cvss_score=float(cvss_score) if cvss_score is not None else None,
                    cvss_vector=classification.get("cvss-metrics"),
                    description=info.get("description") or f"Detected by Nuclei template `{template_id}`.",
                    evidence={
                        "template_id": template_id,
                        "matcher_name": obj.get("matcher-name"),
                        "extracted_results": obj.get("extracted-results"),
                        "matched_at": matched_at,
                    },
                    poc_command=obj.get("curl-command"),
                    remediation=info.get("remediation") or "Review affected endpoint and apply vendor/framework security hardening.",
                    tool_source=self.name,
                )
            )
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            findings=findings,
            summary={
                "findings_count": len(findings),
                "by_severity": {
                    s: sum(1 for f in findings if f.severity == s)
                    for s in ("critical", "high", "medium", "low", "info")
                    if any(f.severity == s for f in findings)
                },
            },
        )
