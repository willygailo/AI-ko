"""Arjun HTTP parameter discovery adapter (Tier 2)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredEndpoint, ToolResult, resolve_binary


class ArjunArgs(BaseModel):
    method: Literal["GET", "POST", "JSON", "XML"] = "GET"
    timeout_seconds: int = Field(default=120, ge=15, le=240)


class ArjunAdapter(BaseToolAdapter):
    name = "arjun"
    description = "Discovers hidden HTTP query, form, and JSON parameters using arjun."
    tier = 2
    binary_name = "arjun"
    args_schema = ArjunArgs

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, ArjunArgs)
        bin_path = resolve_binary("arjun") or "arjun"
        out_file = work_dir / "arjun.json"
        argv = [
            bin_path,
            "-u",
            target,
            "-m",
            args.method,
            "-oJ",
            str(out_file),
            "-t",
            str(min(scope.max_concurrency, 5)),
            "--rate-limit",
            str(scope.max_rps),
            "-q",
        ]
        if scope.custom_headers:
            hdr_str = "\n".join(f"{k}: {v}" for k, v in scope.custom_headers.items())
            argv.extend(["--headers", hdr_str])
        return argv

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        out_file = work_dir / "arjun.json"
        endpoints: list[DiscoveredEndpoint] = []
        param_summary: dict[str, list[str]] = {}
        if out_file.exists():
            try:
                data = json.loads(out_file.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict):
                    for url, info in data.items():
                        params: list[str] = []
                        method = getattr(args, "method", "GET")
                        if isinstance(info, dict):
                            params = [str(p) for p in (info.get("params") or [])]
                            method = str(info.get("method") or method).upper()
                        elif isinstance(info, list):
                            params = [str(p) for p in info]
                        param_summary[url] = params
                        p = urlparse(url)
                        endpoints.append(
                            DiscoveredEndpoint(
                                method="POST" if method == "JSON" else method,
                                url=url,
                                path=p.path or "/",
                                query_params=params if method == "GET" else [],
                                body_params=params if method != "GET" else [],
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
            summary={"parameterized_urls": len(endpoints), "params": param_summary},
        )
