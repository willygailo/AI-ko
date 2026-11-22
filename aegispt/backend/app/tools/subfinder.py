"""Subfinder passive subdomain discovery adapter (Tier 1)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredAsset, ToolResult, resolve_binary


class SubfinderArgs(BaseModel):
    recursive: bool = False
    timeout_seconds: int = Field(default=120, ge=15, le=300)


class SubfinderAdapter(BaseToolAdapter):
    name = "subfinder"
    description = "Passive subdomain enumeration using ProjectDiscovery subfinder."
    tier = 1
    binary_name = "subfinder"
    args_schema = SubfinderArgs

    def _extract_domain(self, target: str) -> str:
        if "://" in target:
            return (urlparse(target).hostname or target).lower()
        return target.split("/", 1)[0].split(":", 1)[0].lower()

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, SubfinderArgs)
        bin_path = resolve_binary("subfinder") or "subfinder"
        domain = self._extract_domain(target)
        argv = [bin_path, "-d", domain, "-json", "-silent", "-t", str(min(scope.max_concurrency * 2, 20))]
        if args.recursive:
            argv.append("-recursive")
        return argv

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        assets: list[DiscoveredAsset] = []
        seen: set[str] = set()
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            host = ""
            source = "subfinder"
            try:
                obj = json.loads(line)
                host = (obj.get("host") or "").strip().lower()
                source = f"subfinder:{obj.get('source', 'passive')}"
            except json.JSONDecodeError:
                host = line.lower()
            if host and host not in seen:
                seen.add(host)
                assets.append(
                    DiscoveredAsset(
                        asset_type="subdomain",
                        value=host,
                        discovered_by=source,
                    )
                )
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            assets=assets,
            summary={"subdomains_found": len(assets), "sample": [a.value for a in assets[:15]]},
        )
