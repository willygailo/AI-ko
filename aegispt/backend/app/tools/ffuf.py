"""FFUF bounded content & API path discovery adapter (Tier 2)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy, ScopeViolationError
from app.tools.base import (
    BaseToolAdapter,
    DiscoveredEndpoint,
    ToolResult,
    resolve_binary,
)

BUILTIN_WEB_API_WORDS = [
    "api",
    "api/v1",
    "api/v2",
    "rest",
    "graphql",
    "swagger",
    "swagger-ui.html",
    "openapi.json",
    "api-docs",
    "health",
    "status",
    "metrics",
    "admin",
    "login",
    "auth",
    "register",
    "users",
    "profile",
    "account",
    "search",
    "upload",
    "files",
    "config",
    "debug",
    ".env",
    ".git/HEAD",
    "robots.txt",
    "sitemap.xml",
    "ftp",
    "backup",
]

WORDLIST_CANDIDATES = {
    "api": [
        Path("/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt"),
        Path("/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"),
    ],
    "common": [
        Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
        Path("/usr/share/wordlists/dirb/common.txt"),
    ],
}


class FfufArgs(BaseModel):
    wordlist_profile: Literal["builtin", "api", "common"] = "api"
    method: Literal["GET", "POST", "HEAD"] = "GET"
    max_time_seconds: int = Field(default=60, ge=10, le=120)
    match_codes: str = Field(
        default="200,201,204,301,302,307,401,403,405",
        pattern=r"^(?:all|[1-5][0-9]{2}(?:-[1-5][0-9]{2})?(?:,[1-5][0-9]{2}(?:-[1-5][0-9]{2})?)*)$",
    )
    timeout_seconds: int = Field(default=120, ge=15, le=240)


class FfufAdapter(BaseToolAdapter):
    name = "ffuf"
    description = "Rate-limited web & API endpoint discovery using ffuf with auto-calibration."
    tier = 2
    binary_name = "ffuf"
    args_schema = FfufArgs

    def _resolve_wordlist(self, profile: str, work_dir: Path) -> Path:
        for cand in WORDLIST_CANDIDATES.get(profile, []):
            if cand.is_file():
                return cand
        fallback = work_dir / "builtin_paths.txt"
        fallback.write_text("\n".join(BUILTIN_WEB_API_WORDS) + "\n", encoding="utf-8")
        return fallback

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, FfufArgs)
        bin_path = resolve_binary("ffuf") or "ffuf"
        wl = self._resolve_wordlist(args.wordlist_profile, work_dir)
        out_file = work_dir / "ffuf.json"
        fuzz_url = target if "FUZZ" in target else f"{target.rstrip('/')}/FUZZ"

        argv = [
            bin_path,
            "-u",
            fuzz_url,
            "-w",
            str(wl),
            "-X",
            args.method,
            "-mc",
            args.match_codes,
            "-ac",
            "-s",
            "-noninteractive",
            "-rate",
            str(scope.max_rps),
            "-t",
            str(min(scope.max_concurrency * 2, 15)),
            "-maxtime",
            str(args.max_time_seconds),
            "-of",
            "json",
            "-o",
            str(out_file),
        ]
        for k, v in scope.custom_headers.items():
            argv.extend(["-H", f"{k}: {v}"])
        if scope.auth_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in scope.auth_cookies.items())
            argv.extend(["-b", cookie_str])
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
        out_file = work_dir / "ffuf.json"
        endpoints: list[DiscoveredEndpoint] = []
        if out_file.exists():
            try:
                data = json.loads(out_file.read_text(encoding="utf-8", errors="replace"))
                for item in data.get("results", []):
                    url = item.get("url") or ""
                    if not url:
                        continue
                    if scope is not None:
                        try:
                            scope.validate_target(url, resolve_dns=False)
                        except ScopeViolationError:
                            continue
                    p = urlparse(url)
                    endpoints.append(
                        DiscoveredEndpoint(
                            method=getattr(args, "method", "GET"),
                            url=url,
                            path=p.path or "/",
                            status_code=item.get("status"),
                            content_type=item.get("content-type"),
                            source=self.name,
                        )
                    )
            except json.JSONDecodeError:
                pass
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            endpoints=endpoints,
            summary={
                "discovered_paths": len(endpoints),
                "sample": [{"url": e.url, "status": e.status_code} for e in endpoints[:20]],
            },
        )
