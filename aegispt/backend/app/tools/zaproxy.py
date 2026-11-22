"""OWASP ZAP REST API adapter (Tier 2 spider/passive alerts, Tier 3 active scan)."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from app.config import get_settings
from app.core.scope import ScopePolicy
from app.tools.base import (
    BaseToolAdapter,
    DiscoveredEndpoint,
    DiscoveredFinding,
    ToolResult,
    resolve_binary,
)


RISK_MAP = {
    "high": ("high", 7.8),
    "medium": ("medium", 5.5),
    "low": ("low", 3.1),
    "informational": ("info", 0.0),
}


class ZapArgs(BaseModel):
    mode: Literal["spider_passive", "active_scan"] = "spider_passive"
    max_duration_seconds: int = Field(default=60, ge=15, le=240)
    timeout_seconds: int = Field(default=150, ge=20, le=360)


class ZapAdapter(BaseToolAdapter):
    name = "zaproxy"
    description = "Interfaces with local OWASP ZAP headless daemon API (spider + passive alerts in Tier 2; active scan gated at Tier 3)."
    tier = 2
    binary_name = None  # Talks to ZAP daemon REST API; also checks binary availability
    args_schema = ZapArgs

    def is_available(self) -> tuple[bool, str | None]:
        path = resolve_binary("zaproxy") or resolve_binary("zap.sh")
        return (path is not None), path

    def effective_tier(self, args: BaseModel) -> int:
        assert isinstance(args, ZapArgs)
        return 3 if args.mode == "active_scan" else 2

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, ZapArgs)
        return ["zaproxy-api", f"--mode={args.mode}", target]

    async def execute_native(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        target: str,
        args: BaseModel,
        scope: ScopePolicy,
        work_dir: Path,
    ) -> ToolResult:
        assert isinstance(args, ZapArgs)
        settings = get_settings()
        base = settings.zap_url.rstrip("/")
        params_auth = {"apikey": settings.zap_api_key} if settings.zap_api_key else {}

        endpoints: list[DiscoveredEndpoint] = []
        findings: list[DiscoveredFinding] = []

        try:
            async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
                ver = await client.get(f"{base}/JSON/core/view/version/", params=params_auth)
                ver.raise_for_status()

                # Start spider
                sp = await client.get(
                    f"{base}/JSON/spider/action/scan/",
                    params={**params_auth, "url": target, "recurse": "true"},
                )
                sp.raise_for_status()
                scan_id = sp.json().get("scan")

                deadline = asyncio.get_event_loop().time() + args.max_duration_seconds
                while asyncio.get_event_loop().time() < deadline:
                    st = await client.get(
                        f"{base}/JSON/spider/view/status/",
                        params={**params_auth, "scanId": scan_id},
                    )
                    if int(st.json().get("status", "100")) >= 100:
                        break
                    await asyncio.sleep(2.0)

                if args.mode == "active_scan":
                    ac = await client.get(
                        f"{base}/JSON/ascan/action/scan/",
                        params={**params_auth, "url": target, "recurse": "true"},
                    )
                    ac.raise_for_status()
                    ac_id = ac.json().get("scan")
                    while asyncio.get_event_loop().time() < deadline:
                        st = await client.get(
                            f"{base}/JSON/ascan/view/status/",
                            params={**params_auth, "scanId": ac_id},
                        )
                        if int(st.json().get("status", "100")) >= 100:
                            break
                        await asyncio.sleep(2.5)

                urls_resp = await client.get(
                    f"{base}/JSON/spider/view/results/",
                    params={**params_auth, "scanId": scan_id},
                )
                for u in urls_resp.json().get("results", [])[:200]:
                    p = urlparse(u)
                    endpoints.append(
                        DiscoveredEndpoint(method="GET", url=u, path=p.path or "/", source=self.name)
                    )

                alerts_resp = await client.get(
                    f"{base}/JSON/alert/view/alerts/",
                    params={**params_auth, "baseurl": target, "start": 0, "count": 100},
                )
                for al in alerts_resp.json().get("alerts", []):
                    risk_key = str(al.get("risk") or "informational").lower()
                    sev, cvss = RISK_MAP.get(risk_key, ("info", 0.0))
                    cwe_id = f"CWE-{al['cweid']}" if al.get("cweid") and str(al["cweid"]) != "-1" else None
                    findings.append(
                        DiscoveredFinding(
                            title=al.get("name") or al.get("alert") or "ZAP Alert",
                            severity=sev,
                            target_url=al.get("url") or target,
                            parameter=al.get("param") or None,
                            cwe_id=cwe_id,
                            cvss_score=cvss,
                            description=al.get("description") or "",
                            evidence={
                                "evidence": al.get("evidence"),
                                "attack": al.get("attack"),
                                "confidence": al.get("confidence"),
                            },
                            remediation=al.get("solution") or "",
                            tool_source=self.name,
                        )
                    )
        except Exception as exc:
            return ToolResult(
                tool_name=self.name,
                exit_code=1,
                duration_ms=0,
                stdout=f"ZAP daemon unreachable at {base}: {exc}",
                error=f"OWASP ZAP daemon not running at {base}. Start with: zaproxy -daemon -port 8080 -config api.disablekey=true",
                summary={"available": False, "error": str(exc)},
            )

        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            stdout=f"ZAP {args.mode} completed: {len(endpoints)} URLs, {len(findings)} alerts.",
            endpoints=endpoints,
            findings=findings,
            summary={"urls": len(endpoints), "alerts": len(findings)},
        )
