"""SSLScan TLS protocol, cipher, and certificate security auditor (Tier 1)."""
from __future__ import annotations

import defusedxml.ElementTree as ET
from xml.etree.ElementTree import ParseError as XMLParseError
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


WEAK_PROTOCOLS = {"sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "tls 1.0", "tls 1.1"}


class SslscanArgs(BaseModel):
    timeout_seconds: int = Field(default=90, ge=15, le=240)


class SslscanAdapter(BaseToolAdapter):
    name = "sslscan"
    description = "TLS protocol, weak cipher suite, and certificate expiration auditor using sslscan XML output."
    tier = 1
    binary_name = "sslscan"
    args_schema = SslscanArgs

    def _host_port(self, target: str) -> str:
        p = urlparse(target if "://" in target else f"https://{target}")
        host = p.hostname or target
        port = p.port or (443 if p.scheme == "https" else 80)
        return f"{host}:{port}"

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, SslscanArgs)
        bin_path = resolve_binary("sslscan") or "sslscan"
        out_xml = work_dir / "sslscan.xml"
        return [
            bin_path,
            "--no-colour",
            "--timeout=5",
            f"--xml={out_xml}",
            self._host_port(target),
        ]

    def parse_output(
        self, *, target: str, args: BaseModel, stdout: str, stderr: str, work_dir: Path
    ) -> ToolResult:
        out_xml = work_dir / "sslscan.xml"
        raw_xml = out_xml.read_text(encoding="utf-8", errors="replace") if out_xml.exists() else ""
        findings: list[DiscoveredFinding] = []
        assets: list[DiscoveredAsset] = []
        enabled_protos: list[str] = []
        weak_ciphers: list[str] = []

        if raw_xml.strip().startswith("<"):
            try:
                root = ET.fromstring(raw_xml)
                ssltest = root.find("ssltest")
                host = (ssltest.attrib.get("host") if ssltest is not None else None) or (
                    urlparse(target).hostname or target
                )
                for proto in root.findall(".//protocol"):
                    if proto.attrib.get("enabled") == "1":
                        ptype = proto.attrib.get("type", "").upper()
                        pver = proto.attrib.get("version", "")
                        full = f"{ptype}v{pver}" if pver else ptype
                        enabled_protos.append(full)
                        if full.lower() in WEAK_PROTOCOLS:
                            findings.append(
                                DiscoveredFinding(
                                    title=f"Deprecated TLS/SSL Protocol Enabled ({full})",
                                    severity="medium",
                                    target_url=target,
                                    parameter=full,
                                    cwe_id="CWE-326",
                                    owasp_category="A02:2021 - Cryptographic Failures",
                                    cvss_score=5.3,
                                    description=f"Server supports deprecated protocol {full}, exposing connections to downgrade and cryptographic weaknesses.",
                                    evidence={"host": host, "protocol": full},
                                    poc_command=f"sslscan --no-colour '{self._host_port(target)}'",
                                    remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1; enforce TLS 1.2 and TLS 1.3 only.",
                                    tool_source=self.name,
                                )
                            )

                for cipher in root.findall(".//cipher"):
                    status = cipher.attrib.get("status", "")
                    bits = int(cipher.attrib.get("bits", "256") or "256")
                    cname = cipher.attrib.get("cipher", "")
                    if status in {"accepted", "preferred"} and (
                        bits < 128 or "RC4" in cname.upper() or "DES" in cname.upper() or "NULL" in cname.upper()
                    ):
                        weak_ciphers.append(f"{cname} ({bits}b)")

                if weak_ciphers:
                    findings.append(
                        DiscoveredFinding(
                            title="Weak TLS Cipher Suites Supported",
                            severity="medium",
                            target_url=target,
                            cwe_id="CWE-327",
                            owasp_category="A02:2021 - Cryptographic Failures",
                            cvss_score=5.3,
                            description=f"Server accepted weak cipher suites: {', '.join(weak_ciphers[:8])}.",
                            evidence={"weak_ciphers": weak_ciphers},
                            poc_command=f"sslscan --no-colour '{self._host_port(target)}'",
                            remediation="Configure strong AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) and disable RC4, 3DES, NULL, and export ciphers.",
                            tool_source=self.name,
                        )
                    )

                for cert in root.findall(".//certificate"):
                    expired = cert.findtext("expired", "").lower() == "true"
                    self_signed = cert.findtext("self-signed", "").lower() == "true"
                    if expired:
                        findings.append(
                            DiscoveredFinding(
                                title="Expired TLS Certificate",
                                severity="medium",
                                target_url=target,
                                cwe_id="CWE-295",
                                owasp_category="A02:2021 - Cryptographic Failures",
                                cvss_score=5.3,
                                description="The presented X.509 certificate is expired.",
                                evidence={"subject": cert.findtext("subject", ""), "not_after": cert.findtext("not-valid-after", "")},
                                remediation="Renew and deploy a valid TLS certificate.",
                                tool_source=self.name,
                            )
                        )
                    elif self_signed:
                        findings.append(
                            DiscoveredFinding(
                                title="Self-Signed TLS Certificate",
                                severity="low",
                                target_url=target,
                                cwe_id="CWE-295",
                                owasp_category="A02:2021 - Cryptographic Failures",
                                cvss_score=3.1,
                                description="The endpoint presents a self-signed certificate not trusted by standard CAs.",
                                evidence={"subject": cert.findtext("subject", "")},
                                remediation="Use a certificate issued by a trusted Certificate Authority for production endpoints.",
                                tool_source=self.name,
                            )
                        )

                assets.append(
                    DiscoveredAsset(
                        asset_type="host",
                        value=host.lower(),
                        technologies=[f"TLS:{p}" for p in enabled_protos],
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
            findings=findings,
            summary={
                "enabled_protocols": enabled_protos,
                "weak_ciphers": len(weak_ciphers),
                "findings_count": len(findings),
            },
        )
