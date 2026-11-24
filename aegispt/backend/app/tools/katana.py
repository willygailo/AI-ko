"""Katana endpoint & JavaScript route crawler adapter (Tier 1)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy, ScopeViolationError
from app.tools.base import (
    BaseToolAdapter,
    DiscoveredEndpoint,
    ToolResult,
    resolve_binary,
)


class KatanaArgs(BaseModel):
    depth: int = Field(default=2, ge=1, le=5)
    js_crawl: bool = True
    timeout_seconds: int = Field(default=150, ge=15, le=360)


class KatanaAdapter(BaseToolAdapter):
    name = "katana"
    description = "Web & JavaScript endpoint crawler using ProjectDiscovery katana."
    tier = 1
    binary_name = "katana"
    args_schema = KatanaArgs

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, KatanaArgs)
        bin_path = resolve_binary("katana") or "katana"
        argv = [
            bin_path,
            "-u",
            target,
            "-d",
            str(args.depth),
            "-jsonl",
            "-silent",
            "-rl",
            str(scope.max_rps),
            "-c",
            str(scope.max_concurrency),
            "-timeout",
            "10",
        ]
        if args.js_crawl:
            argv.append("-jc")
        for k, v in scope.custom_headers.items():
            argv.extend(["-H", f"{k}: {v}"])
        if scope.auth_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in scope.auth_cookies.items())
            argv.extend(["-H", f"Cookie: {cookie_str}"])
        return argv

    def parse_output(
        self,
        *,
        target: str,
        args: BaseModel,
        stdout: str,
        stderr: str,
        work_dir: Path,
        scope: ScopePolicy | None = None,
    ) -> ToolResult:
        endpoints: list[DiscoveredEndpoint] = []
        seen: set[tuple[str, str]] = set()
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            method = "GET"
            url = ""
            status_code = None
            try:
                obj = json.loads(line)
                req = obj.get("request") or {}
                resp = obj.get("response") or {}
                url = (req.get("endpoint") or obj.get("url") or "").strip()
                method = (req.get("method") or "GET").upper()
                status_code = resp.get("status_code")
            except json.JSONDecodeError:
                if line.startswith("http"):
                    url = line
            if not url or (method, url) in seen:
                continue
            if scope is not None:
                try:
                    scope.validate_target(url, resolve_dns=False)
                except ScopeViolationError:
                    continue
            seen.add((method, url))
            p = urlparse(url)
            endpoints.append(
                DiscoveredEndpoint(
                    method=method,
                    url=url,
                    path=p.path or "/",
                    query_params=list(parse_qs(p.query).keys()),
                    status_code=status_code,
                    source=self.name,
                )
            )
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            endpoints=endpoints,
            summary={
                "endpoints_discovered": len(endpoints),
                "sample": [e.url for e in endpoints[:20]],
            },
        )
