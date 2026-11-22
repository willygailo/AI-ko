"""Gitleaks scoped web/JS artifact secret scanner adapter (Tier 1)."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from pydantic import BaseModel, Field

from app.core.redactor import SecretRedactor
from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredFinding, ToolResult, resolve_binary, sanitize_argv
from app.tools.js_miner import _mask_secret
from app.tools.trufflehog_tool import TrufflehogAdapter, TrufflehogArgs


class GitleaksArgs(BaseModel):
    max_bundles: int = Field(default=8, ge=1, le=20)
    timeout_seconds: int = Field(default=90, ge=20, le=240)


class GitleaksAdapter(BaseToolAdapter):
    name = "gitleaks"
    description = "Scans fetched in-scope JS/HTML/config bundles offline with Gitleaks rule patterns."
    tier = 1
    binary_name = "gitleaks"
    args_schema = GitleaksArgs

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, GitleaksArgs)
        bin_path = resolve_binary("gitleaks") or "gitleaks"
        capture_dir = work_dir / "captured"
        capture_dir.mkdir(parents=True, exist_ok=True)
        report_path = work_dir / "gitleaks.json"
        return [
            bin_path,
            "dir",
            str(capture_dir),
            "--no-banner",
            "--no-color",
            "--redact=100",
            "--exit-code",
            "0",
            "-f",
            "json",
            "-r",
            str(report_path),
        ]

    async def execute(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        target: str,
        raw_args: dict,
        scope: ScopePolicy,
    ) -> ToolResult:
        args = self.validate_args(raw_args)
        assert isinstance(args, GitleaksArgs)
        norm_target = self.validate_scope(target, args, scope)
        from app.config import get_settings

        run_dir = get_settings().artifacts_dir / engagement_id / tool_run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        capture_dir = run_dir / "captured"
        capture_dir.mkdir(parents=True, exist_ok=True)

        th_helper = TrufflehogAdapter()
        captured_urls = await th_helper._fetch_in_scope_artifacts(
            engagement_id,
            norm_target,
            TrufflehogArgs(max_bundles=args.max_bundles),
            scope,
            capture_dir,
        )

        argv = sanitize_argv(self.build_argv(norm_target, args, scope, run_dir))
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(run_dir),
            env=self._subprocess_env(),
        )
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=args.timeout_seconds)
        stdout_s = stdout_b.decode("utf-8", errors="replace")
        stderr_s = stderr_b.decode("utf-8", errors="replace")

        log_path = run_dir / f"{self.name}.log"
        redactor = SecretRedactor()
        log_path.write_text(
            f"# ARGV: {' '.join(argv)}\n\n# STDOUT\n{redactor.redact(stdout_s)}\n\n# STDERR\n{redactor.redact(stderr_s)}\n",
            encoding="utf-8",
        )
        parsed = self.parse_output(target=norm_target, args=args, stdout=stdout_s, stderr=stderr_s, work_dir=run_dir)
        parsed.exit_code = proc.returncode or 0
        parsed.raw_log_path = str(log_path)
        parsed.summary["bundles_fetched"] = len(captured_urls)
        return parsed

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        report_file = work_dir / "gitleaks.json"
        findings: list[DiscoveredFinding] = []
        if report_file.is_file():
            try:
                items = json.loads(report_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                items = []
            if isinstance(items, list):
                seen: set[tuple[str, str]] = set()
                for item in items[:50]:
                    rule_id = str(item.get("RuleID") or item.get("Description") or "gitleaks-secret")
                    file_name = Path(str(item.get("File") or "artifact")).name
                    if (rule_id, file_name) in seen:
                        continue
                    seen.add((rule_id, file_name))
                    secret_preview = _mask_secret(str(item.get("Secret") or item.get("Match") or "REDACTED"))
                    findings.append(
                        DiscoveredFinding(
                            title=f"Gitleaks Detected Secret Pattern ({rule_id}) in '{file_name}'",
                            severity="medium",
                            target_url=target,
                            cwe_id="CWE-798",
                            owasp_category="A07:2021 - Identification and Authentication Failures",
                            cvss_score=5.5,
                            description=f"Gitleaks matched rule `{rule_id}` in captured target file `{file_name}`.",
                            evidence={"rule_id": rule_id, "artifact": file_name, "masked_sample": secret_preview},
                            remediation="Remove secrets from client-side code/configs and rotate affected credentials.",
                            tool_source=self.name,
                        )
                    )
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            findings=findings,
            summary={"findings_count": len(findings)},
        )
