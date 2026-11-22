"""Feroxbuster bounded recursive content discovery adapter (Tier 2)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredEndpoint, ToolResult, resolve_binary
from app.tools.ffuf import BUILTIN_WEB_API_WORDS, WORDLIST_CANDIDATES


class FeroxbusterArgs(BaseModel):
    depth: int = Field(default=2, ge=1, le=4)
    max_time_seconds: int = Field(default=45, ge=10, le=120)
    timeout_seconds: int = Field(default=90, ge=15, le=200)


class FeroxbusterAdapter(BaseToolAdapter):
    name = "feroxbuster"
    description = "Rate-limited recursive web directory & API path discovery via feroxbuster."
    tier = 2
    binary_name = "feroxbuster"
    args_schema = FeroxbusterArgs

    def _resolve_wordlist(self, work_dir: Path) -> Path:
        for cand in WORDLIST_CANDIDATES["api"]:
            if cand.is_file():
                return cand
        wl = work_dir / "ferox_words.txt"
        wl.write_text("\n".join(BUILTIN_WEB_API_WORDS) + "\n", encoding="utf-8")
        return wl

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, FeroxbusterArgs)
        bin_path = resolve_binary("feroxbuster") or "feroxbuster"
        wl = self._resolve_wordlist(work_dir)
        out_file = work_dir / "ferox.json"
        argv = [
            bin_path,
            "-u",
            target,
            "-w",
            str(wl),
            "-d",
            str(args.depth),
            "-t",
            str(min(scope.max_concurrency * 2, 15)),
            "--rate-limit",
            str(scope.max_rps),
            "--time-limit",
            f"{args.max_time_seconds}s",
            "--no-state",
            "--silent",
            "--json",
            "-o",
            str(out_file),
        ]
        for k, v in scope.custom_headers.items():
            argv.extend(["-H", f"{k}:{v}"])
        if scope.auth_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in scope.auth_cookies.items())
            argv.extend(["-b", cookie_str])
        return argv

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        out_file = work_dir / "ferox.json"
        raw = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else stdout
        endpoints: list[DiscoveredEndpoint] = []
        seen: set[str] = set()

        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "response":
                continue
            url = obj.get("url") or ""
            if not url or url in seen:
                continue
            seen.add(url)
            p = urlparse(url)
            endpoints.append(
                DiscoveredEndpoint(
                    method=str(obj.get("method") or "GET").upper(),
                    url=url,
                    path=p.path or "/",
                    status_code=obj.get("status"),
                    source=self.name,
                )
            )
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            endpoints=endpoints,
            summary={"discovered_paths": len(endpoints)},
        )
