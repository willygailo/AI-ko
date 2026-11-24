"""Gitleaks scoped web/JS artifact secret scanner adapter (Tier 1)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import (
    BaseToolAdapter,
    DiscoveredFinding,
    ToolResult,
    resolve_binary,
)
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

    async def pre_execute(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        target: str,
        args: BaseModel,
        scope: ScopePolicy,
        work_dir: Path,
    ) -> dict[str, Any]:
        assert isinstance(args, GitleaksArgs)
        capture_dir = work_dir / "captured"
        capture_dir.mkdir(parents=True, exist_ok=True)
        th_helper = TrufflehogAdapter()
        captured_urls = await th_helper._fetch_in_scope_artifacts(
            engagement_id,
            target,
            TrufflehogArgs(max_bundles=args.max_bundles),
            scope,
            capture_dir,
        )
        return {"bundles_fetched": len(captured_urls)}

    async def post_execute(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        target: str,
        args: BaseModel,
        scope: ScopePolicy,
        work_dir: Path,
        context: dict[str, Any],
        result: ToolResult | None,
    ) -> None:
        if result is not None and "bundles_fetched" in context:
            result.summary["bundles_fetched"] = context["bundles_fetched"]

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        report_file = work_dir / "gitleaks.json"
        findings: list[DiscoveredFinding] = []
        intel_items: list[dict[str, object]] = []
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
                    raw_val = str(item.get("Secret") or item.get("Match") or "REDACTED")
                    secret_preview = _mask_secret(raw_val)
                    intel_items.append(
                        {
                            "category": "key",
                            "label": f"Gitleaks ({rule_id})",
                            "value": raw_val,
                            "masked_value": secret_preview,
                            "sensitive": True,
                            "location": file_name,
                            "tool_source": self.name,
                        }
                    )
                    findings.append(
                        DiscoveredFinding(
                            title=f"Gitleaks Detected Secret Pattern ({rule_id}) in '{file_name}'",
                            severity="medium",
                            target_url=target,
                            cwe_id="CWE-798",
                            owasp_category="A07:2021 - Identification and Authentication Failures",
                            cvss_score=5.5,
                            description=f"Gitleaks matched rule `{rule_id}` in captured target file `{file_name}`.",
                            evidence={
                                "rule_id": rule_id,
                                "artifact": file_name,
                                "masked_sample": secret_preview,
                            },
                            remediation="Remove secrets from client-side code/configs and rotate affected credentials.",
                            tool_source=self.name,
                        )
                    )
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            findings=findings,
            summary={"findings_count": len(findings), "extracted_intel": intel_items},
        )
