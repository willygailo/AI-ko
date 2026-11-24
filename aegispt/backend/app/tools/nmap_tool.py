"""Nmap bounded TCP service & port fingerprinting adapter (Tier 2)."""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse
from xml.etree.ElementTree import ParseError as XMLParseError

import defusedxml.ElementTree as ET
from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import BaseToolAdapter, DiscoveredAsset, ToolResult, resolve_binary


class NmapArgs(BaseModel):
    top_ports: int = Field(default=100, ge=10, le=1000)
    service_detection: bool = True
    timeout_seconds: int = Field(default=150, ge=15, le=300)


class NmapAdapter(BaseToolAdapter):
    name = "nmap"
    description = "Bounded unprivileged TCP port & service version scan (-sT -Pn --top-ports) using nmap XML output."
    tier = 2
    binary_name = "nmap"
    args_schema = NmapArgs

    def _extract_host(self, target: str) -> str:
        if "://" in target:
            return (urlparse(target).hostname or target).lower()
        return target.split("/", 1)[0].split(":", 1)[0].lower()

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, NmapArgs)
        bin_path = resolve_binary("nmap") or "nmap"
        host = self._extract_host(target)
        out_xml = work_dir / "nmap.xml"
        argv = [
            bin_path,
            "-sT",
            "-Pn",
            "--open",
            "--top-ports",
            str(args.top_ports),
            "--max-rate",
            str(max(10, scope.max_rps * 3)),
            "-oX",
            str(out_xml),
        ]
        if args.service_detection:
            argv.extend(["-sV", "--version-light"])
        argv.append(host)
        return argv

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        out_xml = work_dir / "nmap.xml"
        raw_xml = out_xml.read_text(encoding="utf-8", errors="replace") if out_xml.exists() else stdout
        assets: list[DiscoveredAsset] = []
        ports_summary: list[dict[str, str]] = []

        if raw_xml.strip().startswith("<"):
            try:
                root = ET.fromstring(raw_xml)
                for host_el in root.findall("host"):
                    addr_el = host_el.find("address")
                    ip_addr = addr_el.attrib.get("addr") if addr_el is not None else None
                    hn_el = host_el.find("hostnames/hostname")
                    hostname = hn_el.attrib.get("name") if hn_el is not None else None
                    value = (hostname or ip_addr or self._extract_host(target)).lower()

                    techs: list[str] = []
                    for port_el in host_el.findall("ports/port"):
                        state_el = port_el.find("state")
                        if state_el is not None and state_el.attrib.get("state") != "open":
                            continue
                        port_id = port_el.attrib.get("portid", "")
                        proto = port_el.attrib.get("protocol", "tcp")
                        svc_el = port_el.find("service")
                        svc_name = svc_el.attrib.get("name", "unknown") if svc_el is not None else "unknown"
                        product = svc_el.attrib.get("product", "") if svc_el is not None else ""
                        version = svc_el.attrib.get("version", "") if svc_el is not None else ""
                        banner = " ".join(x for x in (product, version) if x).strip()
                        label = f"port:{port_id}/{proto}:{svc_name}" + (f" ({banner})" if banner else "")
                        techs.append(label)
                        ports_summary.append({"port": f"{port_id}/{proto}", "service": svc_name, "banner": banner})

                    assets.append(
                        DiscoveredAsset(
                            asset_type="host",
                            value=value,
                            ip_address=ip_addr,
                            technologies=techs,
                            discovered_by=self.name,
                        )
                    )
            except (XMLParseError, Exception):
                pass

        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            assets=assets,
            summary={"open_ports": len(ports_summary), "services": ports_summary[:25]},
        )
