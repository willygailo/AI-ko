"""Central Tool Registry and Environment Doctor."""
from __future__ import annotations

from typing import Any

from app.tools.arjun import ArjunAdapter
from app.tools.base import BaseToolAdapter
from app.tools.dalfox import DalfoxAdapter
from app.tools.ffuf import FfufAdapter
from app.tools.http_probe import HttpProbeAdapter
from app.tools.httpx_tool import HttpxAdapter
from app.tools.katana import KatanaAdapter
from app.tools.nuclei import NucleiAdapter
from app.tools.sqlmap import SqlmapAdapter
from app.tools.subfinder import SubfinderAdapter
from app.tools.wafw00f import Wafw00fAdapter
from app.tools.whatweb import WhatWebAdapter
from app.tools.zaproxy import ZapAdapter


class ToolRegistry:
    def __init__(self) -> None:
        adapters: list[BaseToolAdapter] = [
            HttpProbeAdapter(),
            SubfinderAdapter(),
            HttpxAdapter(),
            KatanaAdapter(),
            WhatWebAdapter(),
            Wafw00fAdapter(),
            FfufAdapter(),
            ArjunAdapter(),
            NucleiAdapter(),
            DalfoxAdapter(),
            SqlmapAdapter(),
            ZapAdapter(),
        ]
        self._tools: dict[str, BaseToolAdapter] = {a.name: a for a in adapters}

    def get(self, name: str) -> BaseToolAdapter:
        if name not in self._tools:
            raise KeyError(f"Unknown tool adapter: {name!r}")
        return self._tools[name]

    def list_tools(self) -> list[BaseToolAdapter]:
        return list(self._tools.values())

    def describe_catalog(self) -> list[dict[str, Any]]:
        catalog = []
        for tool in self._tools.values():
            available, path = tool.is_available()
            catalog.append(
                {
                    "name": tool.name,
                    "tier": tool.tier,
                    "description": tool.description,
                    "available": available,
                    "resolved_path": path,
                    "args_schema": tool.args_schema.model_json_schema(),
                }
            )
        return catalog


tool_registry = ToolRegistry()
