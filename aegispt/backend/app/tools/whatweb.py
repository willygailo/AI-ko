"""WhatWeb technology fingerprinting adapter (Tier 1)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredAsset, ToolResult, resolve_binary


class WhatWebArgs(BaseModel):
    aggression: int = Field(default=1, ge=1, le=3)
    timeout_seconds: int = Field(default=90, ge=10, le=240)


class WhatWebAdapter(BaseToolAdapter):
    name = "whatweb"
    description = "Web technology stack, server, CMS, and framework fingerprinter."
    tier = 1
    binary_name = "whatweb"
    args_schema = WhatWebArgs

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, WhatWebArgs)
        bin_path = resolve_binary("whatweb") or "whatweb"
        out_file = work_dir / "whatweb.json"
        argv = [
            bin_path,
            f"--aggression={args.aggression}",
            f"--log-json={out_file}",
            "--color=never",
            "-q",
        ]
        for k, v in scope.custom_headers.items():
            argv.extend(["-H", f"{k}:{v}"])
        if scope.auth_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in scope.auth_cookies.items())
            argv.extend(["--cookie", cookie_str])
        argv.append(target)
        return argv

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        out_file = work_dir / "whatweb.json"
        raw = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else stdout
        assets: list[DiscoveredAsset] = []
        entries = []
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, list):
                entries = loaded
        except json.JSONDecodeError:
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            t_url = entry.get("target") or target
            host = urlparse(t_url).hostname or target
            plugins = entry.get("plugins") or {}
            techs: list[str] = []
            title = None
            for pname, pval in plugins.items():
                if pname == "Title" and isinstance(pval, dict):
                    vals = pval.get("string") or []
                    if vals:
                        title = str(vals[0])
                    continue
                if pname in {"Country", "IP", "HTTPServer"}:
                    continue
                ver = ""
                if isinstance(pval, dict) and pval.get("version"):
                    vlist = pval["version"]
                    ver = f":{vlist[0]}" if isinstance(vlist, list) and vlist else ""
                techs.append(f"{pname}{ver}")

            assets.append(
                DiscoveredAsset(
                    asset_type="host",
                    value=host,
                    status_code=entry.get("http_status"),
                    title=title,
                    technologies=sorted(set(techs)),
                    discovered_by=self.name,
                )
            )
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            assets=assets,
            summary={
                "fingerprinted": len(assets),
                "technologies": assets[0].technologies if assets else [],
            },
        )
