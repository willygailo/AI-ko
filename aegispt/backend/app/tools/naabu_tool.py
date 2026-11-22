"""ProjectDiscovery Naabu fast unprivileged TCP port discovery adapter (Tier 2)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredAsset, ToolResult, resolve_binary


class NaabuArgs(BaseModel):
    top_ports: Literal["100", "1000", "full"] = "100"
    timeout_seconds: int = Field(default=120, ge=15, le=300)


class NaabuAdapter(BaseToolAdapter):
    name = "naabu"
    description = "Fast unprivileged TCP connect port scanner using ProjectDiscovery naabu."
    tier = 2
    binary_name = "naabu"
    args_schema = NaabuArgs

    def _extract_host(self, target: str) -> str:
        if "://" in target:
            return (urlparse(target).hostname or target).lower()
        return target.split("/", 1)[0].split(":", 1)[0].lower()

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, NaabuArgs)
        bin_path = resolve_binary("naabu") or "naabu"
        host = self._extract_host(target)
        return [
            bin_path,
            "-host",
            host,
            "-tp",
            args.top_ports,
            "-s",
            "c",
            "-rate",
            str(max(20, scope.max_rps * 5)),
            "-c",
            str(min(scope.max_concurrency * 2, 25)),
            "-json",
            "-silent",
            "-duc",
        ]

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        ports_by_host: dict[str, list[str]] = {}
        ips_by_host: dict[str, str] = {}
        ports_list: list[dict[str, object]] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = (obj.get("host") or obj.get("ip") or self._extract_host(target)).lower()
            port = obj.get("port")
            ip = obj.get("ip")
            if ip:
                ips_by_host[host] = ip
            if port is not None:
                ports_by_host.setdefault(host, []).append(f"port:{port}/tcp")
                ports_list.append({"host": host, "port": port, "ip": ip})

        assets = [
            DiscoveredAsset(
                asset_type="host",
                value=h,
                ip_address=ips_by_host.get(h),
                technologies=sorted(set(p_tags)),
                discovered_by=self.name,
            )
            for h, p_tags in ports_by_host.items()
        ]
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            assets=assets,
            summary={"open_ports": len(ports_list), "ports": ports_list[:30]},
        )
