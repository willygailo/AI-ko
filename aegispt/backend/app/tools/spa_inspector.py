"""Playwright Headless SPA XHR/Fetch & LocalStorage/DOM Sink Inspector (Tier 1)."""
from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy, ScopeViolationError
from app.tools.base import (
    BaseToolAdapter,
    DiscoveredEndpoint,
    DiscoveredFinding,
    ToolResult,
)
from app.tools.http_probe import audit_jwt_candidates


class SpaInspectorArgs(BaseModel):
    wait_ms: int = Field(default=2500, ge=500, le=10000)
    timeout_seconds: int = Field(default=60, ge=15, le=120)


class SpaInspectorAdapter(BaseToolAdapter):
    name = "spa_inspector"
    description = "Headless Chromium inspector capturing client-rendered XHR/Fetch API payloads, localStorage tokens, and scope-locked routes."
    tier = 1
    binary_name = None
    args_schema = SpaInspectorArgs

    def _find_chromium(self) -> str | None:
        cache_dir = Path.home() / ".cache" / "ms-playwright"
        if cache_dir.is_dir():
            for match in cache_dir.glob("chromium*/chrome-linux*/chrome"):
                if match.is_file() and os.access(match, os.X_OK):
                    return str(match)
        for cand in ("google-chrome", "chromium", "chromium-browser"):
            p = shutil.which(cand)
            if p:
                return p
        return None

    def is_available(self) -> tuple[bool, str | None]:
        try:
            import playwright.async_api  # noqa: F401
        except Exception:
            return False, None
        exe = self._find_chromium()
        return (exe is not None), exe

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        return ["native:spa_inspector", target]

    async def execute_native(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        target: str,
        args: BaseModel,
        scope: ScopePolicy,
        work_dir: Path,
    ) -> ToolResult:
        assert isinstance(args, SpaInspectorArgs)
        from playwright.async_api import async_playwright

        exe = self._find_chromium()
        if not exe:
            return ToolResult(
                tool_name=self.name,
                exit_code=1,
                duration_ms=0,
                error="No Chromium executable found for spa_inspector.",
            )

        endpoints: list[DiscoveredEndpoint] = []
        findings: list[DiscoveredFinding] = []
        seen_eps: set[tuple[str, str]] = set()
        storage_tokens: list[str] = []

        await asyncio.to_thread(scope.validate_target, target, resolve_dns=True)

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                executable_path=exe,
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                context = await browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=dict(scope.custom_headers),
                )
                page = await context.new_page()

                async def _scope_route(route) -> None:
                    req_url = route.request.url
                    if req_url.startswith(("data:", "blob:", "about:")):
                        await route.continue_()
                        return
                    try:
                        await asyncio.to_thread(scope.validate_target, req_url, resolve_dns=True)
                        await route.continue_()
                    except ScopeViolationError:
                        await route.abort()

                await page.route("**/*", _scope_route)

                def _on_request(req) -> None:
                    if req.resource_type not in {"xhr", "fetch", "document"}:
                        return
                    url_str = req.url
                    p_u = urlparse(url_str)
                    key = (req.method.upper(), url_str)
                    if key in seen_eps or p_u.path.endswith((".js", ".css", ".png", ".svg", ".woff2")):
                        return
                    seen_eps.add(key)
                    b_params: list[str] = []
                    post_data = req.post_data or ""
                    if post_data.strip().startswith("{"):
                        try:
                            import json
                            obj = json.loads(post_data)
                            if isinstance(obj, dict):
                                b_params = list(obj.keys())[:25]
                        except Exception:
                            pass
                    endpoints.append(
                        DiscoveredEndpoint(
                            method=req.method.upper(),
                            url=url_str,
                            path=p_u.path or "/",
                            query_params=list(parse_qs(p_u.query).keys()),
                            body_params=b_params,
                            source=self.name,
                        )
                    )

                page.on("request", _on_request)
                await page.goto(target, wait_until="domcontentloaded", timeout=args.timeout_seconds * 1000)
                await page.wait_for_timeout(args.wait_ms)

                storage_dump: dict[str, Any] = await page.evaluate(
                    """() => ({
                        local: Object.entries(localStorage || {}),
                        session: Object.entries(sessionStorage || {})
                    })"""
                )
                for bucket in ("local", "session"):
                    for k, v in storage_dump.get(bucket) or []:
                        storage_tokens.append(f"{k}={v}")

                findings.extend(audit_jwt_candidates(storage_tokens, target, self.name))
            finally:
                await browser.close()

        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            stdout=f"SPA inspector captured {len(endpoints)} XHR/Fetch routes and {len(findings)} storage/JWT observations.",
            endpoints=endpoints,
            findings=findings,
            summary={"xhr_endpoints": len(endpoints), "findings_count": len(findings)},
        )
