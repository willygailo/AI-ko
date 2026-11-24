"""ParamSpider historical parameterized URL mining adapter (Tier 1)."""
from __future__ import annotations

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


class ParamspiderArgs(BaseModel):
    timeout_seconds: int = Field(default=90, ge=15, le=240)


class ParamspiderAdapter(BaseToolAdapter):
    name = "paramspider"
    description = "Discovers historical parameterized URLs from web archives for allowlisted public domains."
    tier = 1
    binary_name = "paramspider"
    args_schema = ParamspiderArgs

    def _extract_domain(self, target: str) -> str:
        if "://" in target:
            return (urlparse(target).hostname or target).lower()
        return target.split("/", 1)[0].split(":", 1)[0].lower()

    def validate_scope(self, target: str, args: BaseModel, scope: ScopePolicy) -> str:
        dom = self._extract_domain(target)
        scope.validate_target(dom, resolve_dns=False)
        return dom

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        bin_path = resolve_binary("paramspider") or "paramspider"
        dom = self._extract_domain(target)
        return [bin_path, "-d", dom, "-s", "-p", "FUZZ"]

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
        dom = self._extract_domain(target)
        urls: list[str] = []
        res_file = work_dir / "results" / f"{dom}.txt"
        if res_file.is_file():
            urls.extend(res_file.read_text(encoding="utf-8", errors="replace").splitlines())
        urls.extend(stdout.splitlines())

        endpoints: list[DiscoveredEndpoint] = []
        seen: set[str] = set()
        for raw in urls:
            line = raw.strip()
            if not (line.startswith("http://") or line.startswith("https://")):
                continue
            p = urlparse(line)
            if p.hostname and (p.hostname.lower() == dom or p.hostname.lower().endswith("." + dom)):
                if line in seen:
                    continue
                if scope is not None:
                    try:
                        scope.validate_target(line, resolve_dns=False)
                    except ScopeViolationError:
                        continue
                seen.add(line)
                endpoints.append(
                    DiscoveredEndpoint(
                        method="GET",
                        url=line,
                        path=p.path or "/",
                        query_params=list(parse_qs(p.query).keys()),
                        source=self.name,
                    )
                )
                if len(endpoints) >= 200:
                    break
        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            endpoints=endpoints,
            summary={"parameterized_urls": len(endpoints)},
        )
