"""ProjectDiscovery httpx probe adapter with automatic fallback to native HttpProbeAdapter."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredAsset, ToolResult, resolve_binary
from app.tools.http_probe import HttpProbeAdapter, HttpProbeArgs


class HttpxArgs(BaseModel):
    tech_detect: bool = True
    follow_redirects: bool = True
    timeout_seconds: int = Field(default=90, ge=10, le=300)


def _is_projectdiscovery_httpx(bin_path: str) -> bool:
    try:
        proc = subprocess.run(
            [bin_path, "-version"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        out = (proc.stdout + proc.stderr).lower()
        return "projectdiscovery" in out or "current version" in out
    except Exception:
        return False


class HttpxAdapter(BaseToolAdapter):
    name = "httpx"
    description = "Live HTTP service prober, status/title/tech detector (ProjectDiscovery httpx or native fallback)."
    tier = 1
    binary_name = "httpx"
    args_schema = HttpxArgs

    def is_available(self) -> tuple[bool, str | None]:
        path = resolve_binary("httpx")
        if path and _is_projectdiscovery_httpx(path):
            return True, path
        return True, "native-http_probe-fallback"

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, HttpxArgs)
        bin_path = resolve_binary("httpx") or "httpx"
        argv = [
            bin_path,
            "-u",
            target,
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-rl",
            str(scope.max_rps),
            "-threads",
            str(scope.max_concurrency),
        ]
        if args.tech_detect:
            argv.append("-tech-detect")
        if args.follow_redirects:
            argv.append("-follow-redirects")
        for k, v in scope.custom_headers.items():
            argv.extend(["-H", f"{k}: {v}"])
        return argv

    async def execute(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        target: str,
        raw_args: dict[str, Any],
        scope: ScopePolicy,
    ) -> ToolResult:
        path = resolve_binary("httpx")
        if not (path and _is_projectdiscovery_httpx(path)):
            # Clean fallback to native async HttpProbeAdapter when Python's httpx shadows PD httpx
            fallback = HttpProbeAdapter()
            args = self.validate_args(raw_args)
            res = await fallback.execute(
                engagement_id=engagement_id,
                tool_run_id=tool_run_id,
                target=target,
                raw_args=HttpProbeArgs(
                    mode="passive_audit",
                    follow_redirects=args.follow_redirects,
                    timeout_seconds=min(args.timeout_seconds, 60),
                ).model_dump(),
                scope=scope,
            )
            res.tool_name = self.name
            return res
        return await super().execute(
            engagement_id=engagement_id,
            tool_run_id=tool_run_id,
            target=target,
            raw_args=raw_args,
            scope=scope,
        )

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        assets: list[DiscoveredAsset] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or target
            host = obj.get("host") or (urlparse(url).hostname or target)
            assets.append(
                DiscoveredAsset(
                    asset_type="host",
                    value=host,
                    ip_address=obj.get("host_ip") or (obj.get("a") or [None])[0],
                    status_code=obj.get("status_code"),
                    title=obj.get("title"),
                    technologies=list(obj.get("tech") or []),
                    headers={"webserver": obj.get("webserver")} if obj.get("webserver") else {},
                    discovered_by=self.name,
                )
            )
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            assets=assets,
            summary={"hosts_probed": len(assets)},
        )
