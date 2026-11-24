"""TruffleHog scoped web/JS artifact secret scanner adapter (Tier 1)."""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import BaseModel, Field

from app.core.ratelimit import rate_limiters
from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredFinding, ToolResult, resolve_binary
from app.tools.js_miner import SCRIPT_SRC_RE, _mask_secret


class TrufflehogArgs(BaseModel):
    max_bundles: int = Field(default=8, ge=1, le=20)
    verify_secrets: bool = False
    timeout_seconds: int = Field(default=120, ge=20, le=240)


class TrufflehogAdapter(BaseToolAdapter):
    name = "trufflehog"
    description = "Fetches in-scope HTML/JS artifacts and scans them offline with TruffleHog for exposed credentials."
    tier = 1
    binary_name = "trufflehog"
    args_schema = TrufflehogArgs

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, TrufflehogArgs)
        bin_path = resolve_binary("trufflehog") or "trufflehog"
        capture_dir = work_dir / "captured"
        capture_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            bin_path,
            "filesystem",
            str(capture_dir),
            "--json",
            "--no-color",
        ]
        if not args.verify_secrets:
            argv.append("--no-verification")
        return argv

    async def _fetch_in_scope_artifacts(
        self, engagement_id: str, target: str, args: TrufflehogArgs, scope: ScopePolicy, capture_dir: Path
    ) -> list[str]:
        limiter = rate_limiters.get(engagement_id, scope.max_rps)
        is_local = (urlparse(target).hostname or "").lower() in {"127.0.0.1", "localhost", "::1"}
        headers = {"User-Agent": "AegisPT-TruffleHog/0.1", **scope.custom_headers}
        if scope.auth_cookies:
            headers["Cookie"] = scope.build_cookie_header(scope.auth_cookies)

        captured_urls: list[str] = []
        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=15.0, trust_env=not is_local
        ) as client:
            await asyncio.to_thread(scope.validate_target, target, resolve_dns=True)
            await limiter.acquire()
            resp = await client.get(target, headers=headers)
            (capture_dir / "index.html").write_text(resp.text[:500000], encoding="utf-8", errors="replace")
            captured_urls.append(target)

            bundles = []
            for m in SCRIPT_SRC_RE.finditer(resp.text[:200000]):
                cand = urljoin(target, m.group(1))
                if cand not in bundles:
                    bundles.append(cand)
            for idx, bu in enumerate(bundles[: args.max_bundles]):
                try:
                    await asyncio.to_thread(scope.validate_target, bu, resolve_dns=True)
                    await limiter.acquire()
                    rb = await client.get(bu, headers=headers)
                    if rb.status_code == 200:
                        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", urlparse(bu).path.strip("/")) or f"bundle_{idx}.js"
                        (capture_dir / f"{idx}_{safe_name[:80]}").write_text(
                            rb.text[:500000], encoding="utf-8", errors="replace"
                        )
                        captured_urls.append(bu)
                except Exception:
                    continue
        return captured_urls

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
        assert isinstance(args, TrufflehogArgs)
        capture_dir = work_dir / "captured"
        capture_dir.mkdir(parents=True, exist_ok=True)
        captured_urls = await self._fetch_in_scope_artifacts(engagement_id, target, args, scope, capture_dir)
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
        findings: list[DiscoveredFinding] = []
        seen: set[tuple[str, str]] = set()
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            detector = obj.get("DetectorName") or obj.get("DetectorType") or "Secret"
            raw_val = str(obj.get("Raw") or obj.get("RawV2") or "")
            if not raw_val:
                continue
            verified = bool(obj.get("Verified"))
            fs_meta = (((obj.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
            file_ref = Path(str(fs_meta.get("file") or "artifact")).name
            key = (str(detector), file_ref)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                DiscoveredFinding(
                    title=f"TruffleHog Detected {detector} Credential in '{file_ref}'",
                    severity="high" if verified else "medium",
                    target_url=target,
                    cwe_id="CWE-798",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                    cvss_score=7.5 if verified else 5.5,
                    description=f"TruffleHog identified a potential {detector} secret inside captured target artifact `{file_ref}` (verified={verified}).",
                    evidence={
                        "detector": detector,
                        "verified": verified,
                        "artifact": file_ref,
                        "masked_sample": _mask_secret(raw_val),
                    },
                    remediation="Remove hardcoded credentials from client bundles/public files and rotate exposed keys.",
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
