"""Native async HTTP/API Probe & Passive Security Analyzer (headers, TLS, CORS, cookies, OpenAPI/GraphQL)."""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from pydantic import BaseModel, Field

from app.core.scope import ScopePolicy
from app.tools.base import (
    BaseToolAdapter,
    DiscoveredAsset,
    DiscoveredEndpoint,
    DiscoveredFinding,
    ToolResult,
)


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]
API_SCHEMA_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/graphql",
    "/robots.txt",
    "/.well-known/security.txt",
]


JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
SENSITIVE_JWT_CLAIMS = {"password", "passwd", "secret", "ssn", "private_key", "credit_card", "pin"}


def _decode_jwt_part(part: str) -> dict[str, Any] | None:
    try:
        padded = part + "=" * (-len(part) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        obj = json.loads(raw.decode("utf-8", errors="replace"))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def audit_jwt_candidates(tokens: list[str], target_url: str, tool_source: str) -> list[DiscoveredFinding]:
    """Passively inspect JWT headers/claims for alg=none, missing exp, and sensitive claim keys."""
    findings: list[DiscoveredFinding] = []
    seen_issues: set[str] = set()

    for raw_tok in tokens:
        for m in JWT_RE.finditer(raw_tok or ""):
            parts = m.group(0).split(".")
            if len(parts) != 3:
                continue
            header = _decode_jwt_part(parts[0])
            payload = _decode_jwt_part(parts[1])
            if not header or not payload:
                continue

            alg = str(header.get("alg") or "").lower()
            if alg == "none" and "alg_none" not in seen_issues:
                seen_issues.add("alg_none")
                findings.append(
                    DiscoveredFinding(
                        title="Insecure JWT Algorithm ('alg: none')",
                        severity="high",
                        target_url=target_url,
                        cwe_id="CWE-347",
                        owasp_category="API2:2023 - Broken Authentication",
                        cvss_score=7.5,
                        description="Observed a JSON Web Token specifying alg='none', indicating unsigned token usage.",
                        evidence={"header": header, "claim_keys": sorted(payload.keys())},
                        remediation="Enforce strict asymmetric/HMAC JWT signature verification and reject 'none' or unexpected algorithms.",
                        tool_source=tool_source,
                    )
                )

            if "exp" not in payload and "missing_exp" not in seen_issues:
                seen_issues.add("missing_exp")
                findings.append(
                    DiscoveredFinding(
                        title="JWT Missing Expiration Claim ('exp')",
                        severity="low",
                        target_url=target_url,
                        cwe_id="CWE-613",
                        owasp_category="API2:2023 - Broken Authentication",
                        cvss_score=3.5,
                        description="Observed a JWT without an 'exp' expiration claim, allowing indefinite token replay if leaked.",
                        evidence={"header_alg": header.get("alg"), "claim_keys": sorted(payload.keys())},
                        remediation="Include short-lived 'exp' timestamps on all issued JWTs and enforce expiration server-side.",
                        tool_source=tool_source,
                    )
                )

            sensitive_keys = sorted(k for k in payload.keys() if k.lower() in SENSITIVE_JWT_CLAIMS)
            if sensitive_keys and "sensitive_claims" not in seen_issues:
                seen_issues.add("sensitive_claims")
                findings.append(
                    DiscoveredFinding(
                        title="Sensitive Claim Names Inside JWT Payload",
                        severity="medium",
                        target_url=target_url,
                        cwe_id="CWE-200",
                        owasp_category="API2:2023 - Broken Authentication",
                        cvss_score=5.3,
                        description=f"JWT payload contains sensitive fields ({', '.join(sensitive_keys)}), which are readable via base64 decoding.",
                        evidence={"sensitive_claim_keys": sensitive_keys},
                        remediation="Store only opaque identifiers/scopes in JWT payloads; never place passwords or secrets in JWT claims.",
                        tool_source=tool_source,
                    )
                )

    return findings


class HttpProbeArgs(BaseModel):
    mode: Literal["passive_audit", "api_discovery", "replay_request"] = "passive_audit"
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    follow_redirects: bool = True
    check_cors: bool = True
    discover_api_schemas: bool = True
    timeout_seconds: int = Field(default=30, ge=5, le=120)


class HttpProbeAdapter(BaseToolAdapter):
    name = "http_probe"
    description = (
        "Native async HTTP/API analyzer: inspects status, tech headers, missing security headers, "
        "CORS policy, cookie security flags, robots.txt, and OpenAPI/Swagger/GraphQL endpoints; "
        "supports approval-gated custom request replay."
    )
    tier = 1
    binary_name = None
    args_schema = HttpProbeArgs

    def effective_tier(self, args: BaseModel) -> int:
        assert isinstance(args, HttpProbeArgs)
        if args.mode == "replay_request" or args.method in {"POST", "PUT", "PATCH", "DELETE"}:
            return 3
        return 1

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, HttpProbeArgs)
        return ["native:http_probe", f"--mode={args.mode}", f"--method={args.method}", target]

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
        assert isinstance(args, HttpProbeArgs)
        merged_headers = {
            "User-Agent": "AegisPT-SecurityProbe/0.1",
            **scope.custom_headers,
            **args.headers,
        }
        cookies = dict(scope.auth_cookies)
        assets: list[DiscoveredAsset] = []
        endpoints: list[DiscoveredEndpoint] = []
        findings: list[DiscoveredFinding] = []
        transcript: list[str] = []

        is_local = (urlparse(target).hostname or "").lower() in {"127.0.0.1", "localhost", "::1"}
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=args.follow_redirects,
            timeout=float(args.timeout_seconds),
            cookies=cookies,
            trust_env=not is_local,
        ) as client:
            resp = await client.request(
                args.method,
                target,
                headers=merged_headers,
                content=args.body,
            )
            final_url = str(resp.url)
            scope.validate_target(final_url, resolve_dns=False)

            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            title_match = TITLE_RE.search(resp.text[:32768])
            title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else None

            techs: list[str] = []
            for h in ("server", "x-powered-by", "x-generator", "via"):
                if h in resp_headers:
                    techs.append(f"{h}:{resp_headers[h]}")

            parsed = urlparse(final_url)
            host = parsed.hostname or target
            assets.append(
                DiscoveredAsset(
                    asset_type="host",
                    value=host,
                    status_code=resp.status_code,
                    title=title,
                    technologies=techs,
                    headers={
                        k: resp_headers[k]
                        for k in ("server", "x-powered-by", "content-type")
                        if k in resp_headers
                    },
                    discovered_by=self.name,
                )
            )
            q_params = list(parse_qs(parsed.query).keys())
            endpoints.append(
                DiscoveredEndpoint(
                    method=args.method,
                    url=final_url,
                    path=parsed.path or "/",
                    query_params=q_params,
                    status_code=resp.status_code,
                    content_type=resp_headers.get("content-type"),
                    source=self.name,
                )
            )

            transcript.append(
                json.dumps(
                    {
                        "request": {"method": args.method, "url": target},
                        "response": {
                            "final_url": final_url,
                            "status_code": resp.status_code,
                            "headers": dict(resp.headers),
                            "body_preview": resp.text[:1500],
                        },
                    },
                    indent=2,
                )
            )

            # Passive security checks
            if args.mode in ("passive_audit", "api_discovery"):
                missing = [
                    h
                    for h in SECURITY_HEADERS
                    if h not in resp_headers
                    and (h != "strict-transport-security" or parsed.scheme == "https")
                ]
                if missing:
                    findings.append(
                        DiscoveredFinding(
                            title="Missing HTTP Security Headers",
                            severity="low",
                            target_url=final_url,
                            cwe_id="CWE-693",
                            owasp_category="A05:2021 - Security Misconfiguration",
                            cvss_score=3.1,
                            description=(
                                f"Target response omitted recommended defensive headers: {', '.join(missing)}."
                            ),
                            evidence={
                                "url": final_url,
                                "status_code": resp.status_code,
                                "missing_headers": missing,
                            },
                            poc_command=f"curl -i -s '{final_url}' | head -n 30",
                            remediation="Configure HSTS (on HTTPS), Content-Security-Policy, X-Frame-Options, X-Content-Type-Options: nosniff, and Referrer-Policy.",
                            tool_source=self.name,
                        )
                    )

                # Cookie flags check
                set_cookies = resp.headers.get_list("set-cookie")
                for ck in set_cookies:
                    ck_lower = ck.lower()
                    ck_name = ck.split("=", 1)[0].strip()
                    weaknesses = []
                    if "httponly" not in ck_lower:
                        weaknesses.append("HttpOnly")
                    if parsed.scheme == "https" and "secure" not in ck_lower:
                        weaknesses.append("Secure")
                    if "samesite" not in ck_lower:
                        weaknesses.append("SameSite")
                    if weaknesses:
                        findings.append(
                            DiscoveredFinding(
                                title=f"Cookie '{ck_name}' Missing Security Attributes",
                                severity="low",
                                target_url=final_url,
                                parameter=ck_name,
                                cwe_id="CWE-614",
                                owasp_category="A05:2021 - Security Misconfiguration",
                                cvss_score=3.5,
                                description=f"Set-Cookie header for '{ck_name}' lacks: {', '.join(weaknesses)}.",
                                evidence={"set_cookie": ck, "missing_flags": weaknesses},
                                poc_command=f"curl -I -s '{final_url}' | grep -i set-cookie",
                                remediation="Set HttpOnly, Secure (over HTTPS), and SameSite=Lax/Strict attributes on sensitive cookies.",
                                tool_source=self.name,
                            )
                        )

                # Passive JWT audit across headers/cookies
                jwt_sources = (
                    list(merged_headers.values())
                    + list(cookies.values())
                    + resp.headers.get_list("set-cookie")
                    + [resp.headers.get("authorization", "")]
                )
                findings.extend(audit_jwt_candidates(jwt_sources, final_url, self.name))

                # CORS check with benign Origin header
                if args.check_cors:
                    cors_resp = await client.get(
                        final_url,
                        headers={**merged_headers, "Origin": "https://aegispt-cors-check.invalid"},
                    )
                    acao = cors_resp.headers.get("access-control-allow-origin", "")
                    acac = cors_resp.headers.get("access-control-allow-credentials", "").lower()
                    if acao == "https://aegispt-cors-check.invalid" or (acao == "*" and acac == "true"):
                        sev = "high" if acac == "true" else "medium"
                        findings.append(
                            DiscoveredFinding(
                                title="Permissive Cross-Origin Resource Sharing (CORS) Policy",
                                severity=sev,
                                target_url=final_url,
                                cwe_id="CWE-942",
                                owasp_category="A05:2021 - Security Misconfiguration",
                                cvss_score=7.5 if sev == "high" else 5.3,
                                description=(
                                    f"Server responded with Access-Control-Allow-Origin: {acao!r} "
                                    f"and Access-Control-Allow-Credentials: {acac!r}."
                                ),
                                evidence={
                                    "origin_sent": "https://aegispt-cors-check.invalid",
                                    "access_control_allow_origin": acao,
                                    "access_control_allow_credentials": acac,
                                },
                                poc_command=f"curl -I -H 'Origin: https://aegispt-cors-check.invalid' '{final_url}'",
                                remediation="Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins and avoid combining wildcard/reflected origins with Allow-Credentials: true.",
                                tool_source=self.name,
                            )
                        )

            # Well-known API/Schema discovery
            if args.discover_api_schemas and args.mode in ("passive_audit", "api_discovery"):
                base_origin = f"{parsed.scheme}://{parsed.netloc}"
                for path in API_SCHEMA_PATHS:
                    candidate = urljoin(base_origin, path)
                    try:
                        scope.validate_target(candidate, resolve_dns=False)
                        r = await client.get(candidate, headers=merged_headers)
                    except Exception:
                        continue
                    if r.status_code in (200, 401, 403):
                        ct = r.headers.get("content-type", "")
                        if r.status_code == 200 and path.endswith(".json") and "json" in ct.lower():
                            try:
                                doc = r.json()
                            except Exception:
                                doc = None
                            if isinstance(doc, dict) and ("paths" in doc or "openapi" in doc or "swagger" in doc):
                                paths_dict = doc.get("paths") or {}
                                for api_path, methods_map in list(paths_dict.items())[:150]:
                                    if isinstance(methods_map, dict):
                                        for m in methods_map.keys():
                                            if m.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                                                ep_url = urljoin(base_origin, api_path)
                                                endpoints.append(
                                                    DiscoveredEndpoint(
                                                        method=m.upper(),
                                                        url=ep_url,
                                                        path=api_path,
                                                        status_code=200,
                                                        content_type="application/json",
                                                        source="openapi_spec",
                                                    )
                                                )
                                findings.append(
                                    DiscoveredFinding(
                                        title="Exposed OpenAPI / Swagger Specification",
                                        severity="info",
                                        target_url=candidate,
                                        cwe_id="CWE-200",
                                        owasp_category="API9:2023 - Improper Inventory Management",
                                        description=f"Public OpenAPI specification discovered at {candidate} exposing {len(paths_dict)} API path definitions.",
                                        evidence={"url": candidate, "path_count": len(paths_dict)},
                                        poc_command=f"curl -s '{candidate}' | head -n 40",
                                        remediation="Verify whether unauthenticated API documentation exposure is intentional in production environments.",
                                        tool_source=self.name,
                                    )
                                )
                        elif path == "/graphql" and r.status_code in (200, 400):
                            endpoints.append(
                                DiscoveredEndpoint(
                                    method="POST",
                                    url=candidate,
                                    path="/graphql",
                                    content_type=ct,
                                    source=self.name,
                                )
                            )
                            # Safe non-mutating GraphQL introspection probe
                            try:
                                gql_r = await client.post(
                                    candidate,
                                    headers={**merged_headers, "Content-Type": "application/json"},
                                    json={"query": "{__schema{queryType{name}}}"},
                                )
                                if gql_r.status_code == 200 and "__schema" in gql_r.text:
                                    findings.append(
                                        DiscoveredFinding(
                                            title="Unauthenticated GraphQL Introspection Enabled",
                                            severity="medium",
                                            target_url=candidate,
                                            cwe_id="CWE-200",
                                            owasp_category="API8:2023 - Security Misconfiguration",
                                            cvss_score=5.3,
                                            description="GraphQL endpoint responds to __schema introspection queries without authentication, exposing full API types and mutations.",
                                            evidence={"url": candidate, "response_preview": gql_r.text[:400]},
                                            poc_command=f"curl -s -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{queryType{{name}}}}}}\"}}' '{candidate}'",
                                            remediation="Disable GraphQL introspection in production environments and require authentication on schema queries.",
                                            tool_source=self.name,
                                        )
                                    )
                            except Exception:
                                pass
                        elif r.status_code == 200 and path == "/robots.txt":
                            for line in r.text.splitlines():
                                line = line.strip()
                                if line.lower().startswith(("disallow:", "allow:")):
                                    p = line.split(":", 1)[1].strip()
                                    if p.startswith("/") and "*" not in p:
                                        endpoints.append(
                                            DiscoveredEndpoint(
                                                method="GET",
                                                url=urljoin(base_origin, p),
                                                path=p,
                                                source="robots_txt",
                                            )
                                        )

        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            stdout="\n".join(transcript),
            assets=assets,
            endpoints=endpoints,
            findings=findings,
            summary={
                "status_code": resp.status_code,
                "final_url": str(resp.url),
                "title": title,
                "technologies": techs,
                "endpoints_discovered": len(endpoints),
                "findings_count": len(findings),
            },
        )
