"""Wafw00f Web Application Firewall fingerprinting adapter (Tier 1)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredAsset, ToolResult, resolve_binary


class Wafw00fArgs(BaseModel):
    find_all: bool = False
    timeout_seconds: int = Field(default=60, ge=10, le=180)


class Wafw00fAdapter(BaseToolAdapter):
    name = "wafw00f"
    description = "Detects and identifies Web Application Firewalls protecting a target."
    tier = 1
    binary_name = "wafw00f"
    args_schema = Wafw00fArgs

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, Wafw00fArgs)
        bin_path = resolve_binary("wafw00f") or "wafw00f"
        out_file = work_dir / "wafw00f.json"
        argv = [bin_path, "-f", "json", "-o", str(out_file)]
        if args.find_all:
            argv.append("-a")
        argv.append(target)
        return argv

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        out_file = work_dir / "wafw00f.json"
        raw = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""
        assets: list[DiscoveredAsset] = []
        detected_wafs: list[str] = []
        if raw.strip():
            try:
                data = json.loads(raw)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    url = item.get("url") or target
                    host = urlparse(url).hostname or target
                    firewall = item.get("firewall") or "None"
                    if item.get("detected") and firewall and firewall.lower() != "none":
                        detected_wafs.append(firewall)
                    assets.append(
                        DiscoveredAsset(
                            asset_type="host",
                            value=host,
                            waf=firewall if item.get("detected") else "None",
                            discovered_by=self.name,
                        )
                    )
            except json.JSONDecodeError:
                pass
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            assets=assets,
            summary={"detected_wafs": detected_wafs or ["None"]},
        )
