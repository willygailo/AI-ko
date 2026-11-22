"""WPScan WordPress security scanner adapter (Tier 2, triggered conditionally on WP targets)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredAsset, DiscoveredFinding, ToolResult, resolve_binary


class WpscanArgs(BaseModel):
    detection_mode: Literal["passive", "mixed", "aggressive"] = "passive"
    enumerate: str = Field(default="vp,vt,u", pattern=r"^[a-zA-Z0-9,_-]+$")
    timeout_seconds: int = Field(default=180, ge=30, le=360)


class WpscanAdapter(BaseToolAdapter):
    name = "wpscan"
    description = "WordPress plugin, theme, user, and misconfiguration scanner (used when WordPress is fingerprinted)."
    tier = 2
    binary_name = "wpscan"
    args_schema = WpscanArgs

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, WpscanArgs)
        bin_path = resolve_binary("wpscan") or "wpscan"
        out_file = work_dir / "wpscan.json"
        throttle_ms = max(100, int(1000 / max(1, scope.max_rps)))
        argv = [
            bin_path,
            "--url",
            target,
            "-f",
            "json",
            "-o",
            str(out_file),
            "--no-banner",
            "--no-update",
            "--random-user-agent",
            "--disable-tls-checks",
            "--detection-mode",
            args.detection_mode,
            "--enumerate",
            args.enumerate,
            "--throttle",
            str(throttle_ms),
            "--request-timeout",
            "15",
        ]
        if scope.auth_cookies:
            argv.extend(["--cookie-string", scope.build_cookie_header(scope.auth_cookies)])
        return argv

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        out_file = work_dir / "wpscan.json"
        raw_text = out_file.read_text(encoding="utf-8", errors="replace") if out_file.is_file() else stdout
        findings: list[DiscoveredFinding] = []
        assets: list[DiscoveredAsset] = []

        try:
            doc = json.loads(raw_text) if raw_text.strip().startswith("{") else {}
        except json.JSONDecodeError:
            doc = {}

        if isinstance(doc, dict) and doc:
            techs: list[str] = ["wordpress"]
            ver = (doc.get("version") or {}).get("number")
            if ver:
                techs.append(f"wordpress:{ver}")
            for pname in list((doc.get("plugins") or {}).keys())[:10]:
                techs.append(f"wp-plugin:{pname}")
            assets.append(
                DiscoveredAsset(
                    asset_type="host",
                    value=target,
                    technologies=techs,
                    discovered_by=self.name,
                )
            )
            for item in (doc.get("interesting_findings") or [])[:25]:
                desc = str(item.get("to_s") or item.get("type") or "WordPress Exposure")
                findings.append(
                    DiscoveredFinding(
                        title=f"WordPress Finding: {desc[:120]}",
                        severity="info",
                        target_url=str(item.get("url") or target),
                        cwe_id="CWE-200",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        description=desc,
                        evidence={"type": item.get("type"), "references": item.get("references")},
                        remediation="Harden WordPress configuration, disable xmlrpc/directory listing if unused, and keep core/plugins updated.",
                        tool_source=self.name,
                    )
                )
            for pname, pdata in (doc.get("plugins") or {}).items():
                for v in (pdata.get("vulnerabilities") or [])[:10]:
                    findings.append(
                        DiscoveredFinding(
                            title=f"Vulnerable WordPress Plugin '{pname}': {v.get('title', 'Known Issue')}",
                            severity="high",
                            target_url=target,
                            cwe_id="CWE-1104",
                            owasp_category="A06:2021 - Vulnerable and Outdated Components",
                            cvss_score=7.5,
                            description=str(v.get("title") or "Known vulnerability in WordPress plugin."),
                            evidence={"plugin": pname, "references": v.get("references")},
                            remediation=f"Update or remove vulnerable WordPress plugin `{pname}`.",
                            tool_source=self.name,
                        )
                    )

        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            assets=assets,
            findings=findings,
            summary={"findings_count": len(findings)},
        )
