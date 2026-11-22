"""ProjectDiscovery dnsx DNS enumeration & SPF/DMARC/CNAME posture adapter (Tier 1)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import (
    BaseToolAdapter,
    DiscoveredAsset,
    DiscoveredFinding,
    ToolResult,
    resolve_binary,
)


class DnsxArgs(BaseModel):
    timeout_seconds: int = Field(default=90, ge=15, le=240)


class DnsxAdapter(BaseToolAdapter):
    name = "dnsx"
    description = "Resolves A/AAAA/CNAME/MX/TXT records and audits SPF/DMARC posture using dnsx."
    tier = 1
    binary_name = "dnsx"
    args_schema = DnsxArgs

    def _extract_host(self, target: str) -> str:
        if "://" in target:
            return (urlparse(target).hostname or target).lower()
        return target.split("/", 1)[0].split(":", 1)[0].lower()

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, DnsxArgs)
        bin_path = resolve_binary("dnsx") or "dnsx"
        host = self._extract_host(target)
        hosts_file = work_dir / "dnsx_hosts.txt"
        hosts_file.write_text(f"{host}\n_dmarc.{host}\n", encoding="utf-8")
        return [
            bin_path,
            "-l",
            str(hosts_file),
            "-a",
            "-aaaa",
            "-cname",
            "-mx",
            "-txt",
            "-re",
            "-json",
            "-silent",
            "-duc",
            "-rl",
            str(max(5, scope.max_rps)),
        ]

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        assets: list[DiscoveredAsset] = []
        findings: list[DiscoveredFinding] = []
        records: list[dict[str, object]] = []
        root_host = self._extract_host(target)
        saw_spf = False
        saw_dmarc = False

        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = (obj.get("host") or "").lower()
            a_recs = obj.get("a") or []
            cnames = obj.get("cname") or []
            txts = obj.get("txt") or []
            records.append({"host": host, "a": a_recs, "cname": cnames, "txt": txts})

            for txt in txts:
                low = str(txt).lower()
                if "v=spf1" in low:
                    saw_spf = True
                if "v=dmarc1" in low:
                    saw_dmarc = True

            if host and not host.startswith("_dmarc."):
                techs = [f"cname:{c}" for c in cnames]
                assets.append(
                    DiscoveredAsset(
                        asset_type="domain",
                        value=host,
                        ip_address=a_recs[0] if a_recs else None,
                        technologies=techs,
                        discovered_by=self.name,
                    )
                )

        if records and "." in root_host and root_host not in {"localhost", "127.0.0.1"}:
            if not saw_spf or not saw_dmarc:
                missing = [x for x, ok in (("SPF", saw_spf), ("DMARC", saw_dmarc)) if not ok]
                findings.append(
                    DiscoveredFinding(
                        title=f"Missing Email Authentication DNS Records ({', '.join(missing)})",
                        severity="info",
                        target_url=target,
                        cwe_id="CWE-290",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        description=f"Domain '{root_host}' lacked {', '.join(missing)} TXT records during DNS audit.",
                        evidence={"domain": root_host, "missing": missing},
                        remediation="Publish restrictive SPF (v=spf1 ...) and DMARC (v=DMARC1; p=quarantine/reject) TXT records if domain handles email.",
                        tool_source=self.name,
                    )
                )

        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            assets=assets,
            findings=findings,
            summary={"dns_records": len(records), "spf": saw_spf, "dmarc": saw_dmarc},
        )
