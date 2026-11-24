"""Native async HTTP/API Probe & Multi-Skill Security Verifier."""
from __future__ import annotations

import asyncio
import base64
import difflib
import hashlib
import hmac
import json
import re
import shlex
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx
from pydantic import BaseModel, Field

from app.core.ratelimit import TokenBucketRateLimiter, rate_limiters
from app.core.scope import ScopePolicy, ScopeViolationError
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
OPENAPI_SPEC_PATHS = {
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
}
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/graphql/console"]
WEAK_JWT_PLACEHOLDERS = (
    "secret",
    "password",
    "123456",
    "changeme",
    "jwt_secret",
    "supersecret",
    "dev",
    "test",
    "your-256-bit-secret",
)

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


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _redact_set_cookie(raw_header: str) -> str:
    """Redact the cookie value in a Set-Cookie header while preserving name and attributes."""
    parts = raw_header.split(";")
    if not parts:
        return "<REDACTED>"
    first = parts[0]
    if "=" in first:
        name, _ = first.split("=", 1)
        parts[0] = f"{name.strip()}=<REDACTED>"
    else:
        parts[0] = "<REDACTED>"
    return ";".join(parts)


def _headers_with_cookies(headers: dict[str, str], cookies: dict[str, str] | None) -> dict[str, str]:
    out = dict(headers)
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items() if k)
        if cookie_str:
            existing = out.get("Cookie") or out.get("cookie")
            out["Cookie"] = f"{existing}; {cookie_str}" if existing else cookie_str
    return out


def audit_jwt_candidates(tokens: list[str], target_url: str, tool_source: str) -> list[DiscoveredFinding]:
    """Passively inspect JWT headers/claims for alg=none, missing exp, weak placeholder HMAC, and sensitive claims."""
    findings: list[DiscoveredFinding] = []
    seen_issues: set[str] = set()

    for raw_tok in tokens:
        for m in JWT_RE.finditer(raw_tok or ""):
            tok_str = m.group(0)
            parts = tok_str.split(".")
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

            if alg == "hs256" and "weak_hmac" not in seen_issues:
                signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
                for secret_cand in WEAK_JWT_PLACEHOLDERS:
                    expected_sig = _b64url(hmac.new(secret_cand.encode("utf-8"), signing_input, hashlib.sha256).digest())
                    if hmac.compare_digest(expected_sig, parts[2]):
                        seen_issues.add("weak_hmac")
                        findings.append(
                            DiscoveredFinding(
                                title="JWT Uses Known Default/Weak HMAC Signing Secret",
                                severity="critical",
                                target_url=target_url,
                                cwe_id="CWE-798",
                                owasp_category="API2:2023 - Broken Authentication",
                                cvss_score=9.1,
                                description="Observed HS256 JWT validates against a known trivial placeholder secret key.",
                                evidence={"alg": header.get("alg"), "placeholder_hint": f"{secret_cand[:2]}***"},
                                remediation="Rotate the JWT signing key immediately to a high-entropy CSPRNG secret (>=256 bits).",
                                tool_source=tool_source,
                            )
                        )
                        break

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
    mode: Literal[
        "passive_audit",
        "api_discovery",
        "replay_request",
        "differential_bola",
        "ssti_probe",
        "open_redirect_probe",
        "graphql_deep_audit",
        "oauth_audit",
        "jwt_active_probe",
        "bfla_verb_tamper",
        "race_burst_probe",
        "hpp_and_content_switch",
    ] = "passive_audit"
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    secondary_headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    param: str | None = None
    token: str | None = None
    burst_count: int = Field(default=6, ge=2, le=15)
    follow_redirects: bool = True
    check_cors: bool = True
    discover_api_schemas: bool = True
    timeout_seconds: int = Field(default=30, ge=5, le=120)


class HttpProbeAdapter(BaseToolAdapter):
    name = "http_probe"
    description = (
        "Native async HTTP/API analyzer & skill verifier: headers, CORS, cookies, JWT, OpenAPI, "
        "GraphQL deep audit, OAuth hygiene, multi-role BOLA/IDOR, verb BFLA, TOCTOU concurrency burst, "
        "HPP/content-type checks, benign SSTI, and open-redirect checks."
    )
    tier = 1
    binary_name = None
    args_schema = HttpProbeArgs

    def effective_tier(self, args: BaseModel) -> int:
        assert isinstance(args, HttpProbeArgs)
        if args.mode in {"graphql_deep_audit", "oauth_audit"}:
            return 2
        if (
            args.mode
            in {
                "replay_request",
                "differential_bola",
                "ssti_probe",
                "open_redirect_probe",
                "jwt_active_probe",
                "bfla_verb_tamper",
                "race_burst_probe",
                "hpp_and_content_switch",
            }
            or args.method in {"POST", "PUT", "PATCH", "DELETE"}
        ):
            return 3
        return 1

    async def _safe_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        scope: ScopePolicy,
        limiter: TokenBucketRateLimiter,
        headers: dict[str, str],
        content: str | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = True,
        max_hops: int = 5,
    ) -> httpx.Response:
        current_url = url
        current_method = method
        current_body = content
        req_headers = _headers_with_cookies(headers, cookies)
        resp: httpx.Response | None = None
        for _ in range(max_hops + 1):
            await asyncio.to_thread(scope.validate_target, current_url, resolve_dns=True)
            await limiter.acquire()
            resp = await client.request(
                current_method,
                current_url,
                headers=req_headers,
                content=current_body,
            )
            if not follow_redirects or resp.status_code not in {301, 302, 303, 307, 308}:
                return resp
            loc = resp.headers.get("location")
            if not loc:
                return resp
            next_url = urljoin(current_url, loc)
            await asyncio.to_thread(scope.validate_target, next_url, resolve_dns=True)
            current_url = next_url
            if resp.status_code == 303:
                current_method = "GET"
                current_body = None
        assert resp is not None
        return resp

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
            "User-Agent": "AegisPT-SecurityProbe/0.2",
            **scope.custom_headers,
            **args.headers,
        }
        cookies = dict(scope.auth_cookies)
        assets: list[DiscoveredAsset] = []
        endpoints: list[DiscoveredEndpoint] = []
        findings: list[DiscoveredFinding] = []
        transcript: list[str] = []

        limiter = rate_limiters.get(engagement_id, scope.max_rps)
        is_local = (urlparse(target).hostname or "").lower() in {"127.0.0.1", "localhost", "::1"}
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=float(args.timeout_seconds),
            trust_env=not is_local,
        ) as client:
            resp = await self._safe_request(
                client,
                args.method,
                target,
                scope=scope,
                limiter=limiter,
                headers=merged_headers,
                content=args.body,
                cookies=cookies,
                follow_redirects=args.follow_redirects,
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
                        "request": {"method": args.method, "url": target, "mode": args.mode},
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
                            description=f"Target response omitted recommended defensive headers: {', '.join(missing)}.",
                            evidence={"url": final_url, "status_code": resp.status_code, "missing_headers": missing},
                            poc_command=f"curl -i -s {shlex.quote(final_url)}",
                            remediation="Configure HSTS (on HTTPS), Content-Security-Policy, X-Frame-Options, X-Content-Type-Options: nosniff, and Referrer-Policy.",
                            tool_source=self.name,
                        )
                    )

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
                                evidence={"set_cookie": _redact_set_cookie(ck), "missing_flags": weaknesses},
                                poc_command=f"curl -I -s {shlex.quote(final_url)}",
                                remediation="Set HttpOnly, Secure (over HTTPS), and SameSite=Lax/Strict attributes on sensitive cookies.",
                                tool_source=self.name,
                            )
                        )

                jwt_sources = (
                    list(merged_headers.values())
                    + list(cookies.values())
                    + resp.headers.get_list("set-cookie")
                    + [resp.headers.get("authorization", "")]
                )
                findings.extend(audit_jwt_candidates(jwt_sources, final_url, self.name))

                # Multi-Origin CORS matrix check
                if args.check_cors:
                    probe_origins = [
                        "https://aegispt-cors-check.invalid",
                        "null",
                        f"https://{host}.aegispt-cors-check.invalid",
                    ]
                    for origin_cand in probe_origins:
                        cors_resp = await self._safe_request(
                            client,
                            "GET",
                            final_url,
                            scope=scope,
                            limiter=limiter,
                            headers={**merged_headers, "Origin": origin_cand},
                            cookies=cookies,
                            follow_redirects=False,
                        )
                        acao = cors_resp.headers.get("access-control-allow-origin", "")
                        acac = cors_resp.headers.get("access-control-allow-credentials", "").lower()
                        if acao == origin_cand or (acao == "*" and acac == "true"):
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
                                        f"and Access-Control-Allow-Credentials: {acac!r} for Origin {origin_cand!r}."
                                    ),
                                    evidence={
                                        "origin_sent": origin_cand,
                                        "access_control_allow_origin": acao,
                                        "access_control_allow_credentials": acac,
                                    },
                                    poc_command=f"curl -I -H {shlex.quote(f'Origin: {origin_cand}')} {shlex.quote(final_url)}",
                                    remediation="Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins and never trust 'null' or wildcard origins with credentials.",
                                    tool_source=self.name,
                                )
                            )
                            break

            # Well-known API/Schema discovery
            if args.discover_api_schemas and args.mode in ("passive_audit", "api_discovery"):
                base_origin = f"{parsed.scheme}://{parsed.netloc}"
                for path in API_SCHEMA_PATHS:
                    candidate = urljoin(base_origin, path)
                    try:
                        r = await self._safe_request(
                            client,
                            "GET",
                            candidate,
                            scope=scope,
                            limiter=limiter,
                            headers=merged_headers,
                            cookies=cookies,
                            follow_redirects=False,
                        )
                    except Exception:
                        continue
                    ct = r.headers.get("content-type", "")
                    if path == "/graphql" and r.status_code in (200, 400):
                        endpoints.append(
                            DiscoveredEndpoint(
                                method="POST",
                                url=candidate,
                                path="/graphql",
                                content_type=ct,
                                source=self.name,
                            )
                        )
                        try:
                            introspection_body = '{"query":"{__schema{queryType{name}}}"}'
                            gql_r = await self._safe_request(
                                client,
                                "POST",
                                candidate,
                                scope=scope,
                                limiter=limiter,
                                headers={**merged_headers, "Content-Type": "application/json"},
                                content=introspection_body,
                                cookies=cookies,
                                follow_redirects=False,
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
                                        poc_command=(
                                            f"curl -s -X POST -H 'Content-Type: application/json' "
                                            f"-d {shlex.quote(introspection_body)} {shlex.quote(candidate)}"
                                        ),
                                        remediation="Disable GraphQL introspection in production environments and require authentication on schema queries.",
                                        tool_source=self.name,
                                    )
                                )
                        except Exception:
                            pass
                    elif r.status_code in (200, 401, 403):
                        if (
                            r.status_code == 200
                            and path in OPENAPI_SPEC_PATHS
                            and ("json" in ct.lower() or r.text.lstrip().startswith("{"))
                        ):
                            try:
                                doc = r.json()
                            except Exception:
                                doc = None
                            if isinstance(doc, dict) and ("paths" in doc or "openapi" in doc or "swagger" in doc):
                                paths_dict = doc.get("paths") or {}
                                for api_path, methods_map in list(paths_dict.items())[:150]:
                                    if isinstance(methods_map, dict):
                                        for m, op_obj in methods_map.items():
                                            if m.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                                                ep_url = urljoin(base_origin, api_path)
                                                try:
                                                    scope.validate_target(ep_url, resolve_dns=False)
                                                except ScopeViolationError:
                                                    continue
                                                b_params: list[str] = []
                                                if isinstance(op_obj, dict):
                                                    req_b = (((op_obj.get("requestBody") or {}).get("content") or {}).get("application/json") or {}).get("schema") or {}
                                                    if isinstance(req_b.get("properties"), dict):
                                                        b_params = list(req_b["properties"].keys())[:20]
                                                endpoints.append(
                                                    DiscoveredEndpoint(
                                                        method=m.upper(),
                                                        url=ep_url,
                                                        path=api_path,
                                                        body_params=b_params,
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
                                        poc_command=f"curl -s {shlex.quote(candidate)}",
                                        remediation="Verify whether unauthenticated API documentation exposure is intentional in production environments.",
                                        tool_source=self.name,
                                    )
                                )
                        elif r.status_code == 200 and path == "/robots.txt":
                            for line in r.text.splitlines():
                                line = line.strip()
                                if line.lower().startswith(("disallow:", "allow:")):
                                    p = line.split(":", 1)[1].strip()
                                    if p.startswith("/") and "*" not in p:
                                        rob_url = urljoin(base_origin, p)
                                        try:
                                            scope.validate_target(rob_url, resolve_dns=False)
                                        except ScopeViolationError:
                                            continue
                                        endpoints.append(
                                            DiscoveredEndpoint(
                                                method="GET",
                                                url=rob_url,
                                                path=p,
                                                source="robots_txt",
                                            )
                                        )

            # Tier-2/3 Deep Skill Modes
            if args.mode == "graphql_deep_audit":
                base_origin = f"{parsed.scheme}://{parsed.netloc}"
                probe_paths = list(dict.fromkeys(([parsed.path] if "graphql" in (parsed.path or "").lower() else []) + GRAPHQL_PATHS))
                for gpath in probe_paths:
                    gurl = urljoin(base_origin, gpath)
                    try:
                        r_type = await self._safe_request(
                            client,
                            "POST",
                            gurl,
                            scope=scope,
                            limiter=limiter,
                            headers={**merged_headers, "Content-Type": "application/json"},
                            content=json.dumps({"query": "{__typename}"}),
                            cookies=cookies,
                            follow_redirects=False,
                        )
                    except Exception:
                        continue
                    if r_type.status_code not in (200, 400):
                        continue
                    if "__typename" not in r_type.text and "data" not in r_type.text and "errors" not in r_type.text:
                        continue

                    endpoints.append(
                        DiscoveredEndpoint(method="POST", url=gurl, path=gpath, content_type="application/json", source="graphql_audit")
                    )

                    # 1. Full schema dump (query + mutation names)
                    full_q = '{"query":"{__schema{queryType{fields{name}} mutationType{fields{name}}}}"}'
                    r_schema = await self._safe_request(
                        client, "POST", gurl, scope=scope, limiter=limiter,
                        headers={**merged_headers, "Content-Type": "application/json"},
                        content=full_q, cookies=cookies, follow_redirects=False,
                    )
                    if r_schema.status_code == 200 and "__schema" in r_schema.text:
                        try:
                            s_obj = r_schema.json().get("data", {}).get("__schema", {})
                            for op_group in ("queryType", "mutationType"):
                                for fld in ((s_obj.get(op_group) or {}).get("fields") or [])[:40]:
                                    op_name = fld.get("name")
                                    if op_name:
                                        endpoints.append(
                                            DiscoveredEndpoint(
                                                method="POST",
                                                url=f"{gurl}#{op_name}",
                                                path=f"{gpath}#{op_name}",
                                                content_type="application/graphql",
                                                source="graphql_schema",
                                            )
                                        )
                        except Exception:
                            pass
                        findings.append(
                            DiscoveredFinding(
                                title="Unauthenticated GraphQL Introspection Enabled",
                                severity="medium",
                                target_url=gurl,
                                cwe_id="CWE-200",
                                owasp_category="API8:2023 - Security Misconfiguration",
                                cvss_score=5.3,
                                description="GraphQL endpoint exposes full __schema metadata including Query and Mutation fields.",
                                evidence={"url": gurl, "schema_preview": r_schema.text[:500]},
                                poc_command=f"curl -s -X POST -H 'Content-Type: application/json' -d {shlex.quote(full_q)} {shlex.quote(gurl)}",
                                remediation="Disable GraphQL introspection in production environments.",
                                tool_source=self.name,
                            )
                        )
                    else:
                        # 2. Field suggestion oracle check when introspection is disabled
                        oracle_q = '{"query":"{aegisNonExistentField}"}'
                        r_ora = await self._safe_request(
                            client, "POST", gurl, scope=scope, limiter=limiter,
                            headers={**merged_headers, "Content-Type": "application/json"},
                            content=oracle_q, cookies=cookies, follow_redirects=False,
                        )
                        if "did you mean" in r_ora.text.lower():
                            findings.append(
                                DiscoveredFinding(
                                    title="GraphQL Field Suggestion Oracle Leakage",
                                    severity="low",
                                    target_url=gurl,
                                    cwe_id="CWE-209",
                                    owasp_category="API8:2023 - Security Misconfiguration",
                                    cvss_score=3.7,
                                    description="GraphQL returns 'Did you mean' schema field hints on invalid queries even if full introspection is disabled.",
                                    evidence={"response_preview": r_ora.text[:400]},
                                    poc_command=f"curl -s -X POST -H 'Content-Type: application/json' -d {shlex.quote(oracle_q)} {shlex.quote(gurl)}",
                                    remediation="Disable verbose field-suggestion error hints in production GraphQL validation.",
                                    tool_source=self.name,
                                )
                            )

                    # 3. Query array batching check
                    batch_q = json.dumps([{"query": "{__typename}"}, {"query": "{__typename}"}])
                    r_batch = await self._safe_request(
                        client, "POST", gurl, scope=scope, limiter=limiter,
                        headers={**merged_headers, "Content-Type": "application/json"},
                        content=batch_q, cookies=cookies, follow_redirects=False,
                    )
                    if r_batch.status_code == 200 and r_batch.text.lstrip().startswith("["):
                        findings.append(
                            DiscoveredFinding(
                                title="GraphQL Array Query Batching Enabled",
                                severity="low",
                                target_url=gurl,
                                cwe_id="CWE-770",
                                owasp_category="API4:2023 - Unrestricted Resource Consumption",
                                cvss_score=3.8,
                                description="GraphQL accepts batched JSON operation arrays in a single HTTP request, which can amplify brute-force or resource exhaustion unless depth/cost limits are enforced.",
                                evidence={"batch_response_preview": r_batch.text[:300]},
                                poc_command=f"curl -s -X POST -H 'Content-Type: application/json' -d {shlex.quote(batch_q)} {shlex.quote(gurl)}",
                                remediation="Disable query batching or enforce strict per-operation complexity/rate quotas.",
                                tool_source=self.name,
                            )
                        )
                    break

            elif args.mode == "oauth_audit":
                base_origin = f"{parsed.scheme}://{parsed.netloc}"
                for wk in ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"):
                    wurl = urljoin(base_origin, wk)
                    try:
                        rw = await self._safe_request(
                            client, "GET", wurl, scope=scope, limiter=limiter,
                            headers=merged_headers, cookies=cookies, follow_redirects=False,
                        )
                    except Exception:
                        continue
                    if rw.status_code == 200:
                        try:
                            oidc = rw.json()
                        except Exception:
                            oidc = None
                        if isinstance(oidc, dict):
                            resp_types = oidc.get("response_types_supported") or []
                            pkce_methods = oidc.get("code_challenge_methods_supported") or []
                            if any("token" in str(rt).lower() and "id_token" not in str(rt).lower() for rt in resp_types):
                                findings.append(
                                    DiscoveredFinding(
                                        title="OAuth Implicit Grant ('token') Advertised in Discovery Metadata",
                                        severity="medium",
                                        target_url=wurl,
                                        cwe_id="CWE-287",
                                        owasp_category="API2:2023 - Broken Authentication",
                                        cvss_score=5.3,
                                        description="OAuth discovery metadata advertises deprecated implicit token response_types.",
                                        evidence={"response_types_supported": resp_types},
                                        poc_command=f"curl -s {shlex.quote(wurl)}",
                                        remediation="Migrate clients to Authorization Code + PKCE (S256) and disable implicit response types.",
                                        tool_source=self.name,
                                    )
                                )
                            if not pkce_methods or "S256" not in [str(m).upper() for m in pkce_methods]:
                                findings.append(
                                    DiscoveredFinding(
                                        title="OIDC Discovery Missing PKCE S256 Support",
                                        severity="low",
                                        target_url=wurl,
                                        cwe_id="CWE-345",
                                        owasp_category="API2:2023 - Broken Authentication",
                                        cvss_score=3.7,
                                        description="OIDC discovery does not advertise S256 PKCE code_challenge_methods_supported.",
                                        evidence={"code_challenge_methods_supported": pkce_methods},
                                        poc_command=f"curl -s {shlex.quote(wurl)}",
                                        remediation="Require PKCE with S256 for public and confidential OAuth 2.0/2.1 clients.",
                                        tool_source=self.name,
                                    )
                                )
                # Check redirect_uri strictness on target if it looks like an authorize URL
                oauth_blob = f"{target} {final_url}".lower()
                if "authorize" in oauth_blob or "redirect_uri" in oauth_blob:
                    p_url = urlparse(target)
                    q_map = parse_qs(p_url.query, keep_blank_values=True)
                    q_map["redirect_uri"] = ["https://aegispt-oauth-check.invalid/callback"]
                    q_map.pop("state", None)
                    test_auth = urlunparse(p_url._replace(query=urlencode(q_map, doseq=True)))
                    ra = await self._safe_request(
                        client, "GET", test_auth, scope=scope, limiter=limiter,
                        headers=merged_headers, cookies=cookies, follow_redirects=False,
                    )
                    loc = ra.headers.get("location", "")
                    if "aegispt-oauth-check.invalid" in loc:
                        findings.append(
                            DiscoveredFinding(
                                title="Permissive OAuth redirect_uri Reflection / Bypass",
                                severity="high",
                                target_url=target,
                                parameter="redirect_uri",
                                cwe_id="CWE-601",
                                owasp_category="API2:2023 - Broken Authentication",
                                cvss_score=7.4,
                                description="OAuth authorization endpoint redirected to an unallowlisted redirect_uri without strict exact matching.",
                                evidence={"location": loc, "status_code": ra.status_code},
                                poc_command=f"curl -I -s {shlex.quote(test_auth)}",
                                remediation="Enforce exact string matching against pre-registered redirect_uri values and require unguessable state parameters.",
                                tool_source=self.name,
                            )
                        )

            elif args.mode == "differential_bola":
                if scope.has_secondary_auth:
                    sec_headers = {"User-Agent": "AegisPT-SecurityProbe/0.2", **scope.secondary_headers, **args.secondary_headers}
                    sec_cookies = dict(scope.secondary_cookies)
                    auth_label = "Secondary-role/account"
                else:
                    sec_headers = {"User-Agent": "AegisPT-SecurityProbe/0.2", **args.secondary_headers}
                    sec_cookies = {}
                    auth_label = "Unauthenticated/secondary"

                unauth_resp = await self._safe_request(
                    client,
                    args.method,
                    target,
                    scope=scope,
                    limiter=limiter,
                    headers=sec_headers,
                    content=args.body,
                    cookies=sec_cookies,
                    follow_redirects=False,
                )
                ratio = difflib.SequenceMatcher(
                    None, resp.text[:4000], unauth_resp.text[:4000]
                ).ratio()
                if (
                    resp.status_code in range(200, 300)
                    and unauth_resp.status_code in range(200, 300)
                    and len(unauth_resp.text.strip()) >= 20
                    and ratio >= 0.85
                ):
                    findings.append(
                        DiscoveredFinding(
                            title="Potential Missing Authorization / BOLA on Endpoint",
                            severity="high",
                            target_url=final_url,
                            cwe_id="CWE-862",
                            owasp_category="API1:2023 - Broken Object Level Authorization",
                            cvss_score=7.5,
                            description=(
                                f"{auth_label} request returned HTTP {unauth_resp.status_code} "
                                f"with {round(ratio * 100, 1)}% body similarity to primary authenticated request ({resp.status_code})."
                            ),
                            evidence={
                                "auth_status": resp.status_code,
                                "secondary_status": unauth_resp.status_code,
                                "similarity": round(ratio, 3),
                                "secondary_mode": "multi_role" if scope.has_secondary_auth else "unauth",
                                "response_preview": unauth_resp.text[:400],
                            },
                            poc_command=f"curl -i -s {shlex.quote(target)}",
                            remediation="Enforce server-side session authentication and object-level ownership checks on every API route.",
                            tool_source=self.name,
                        )
                    )

            elif args.mode == "jwt_active_probe":
                raw_tok = args.token
                token_cookie_key: str | None = None
                if not raw_tok:
                    for hv in merged_headers.values():
                        m = JWT_RE.search(str(hv))
                        if m:
                            raw_tok = m.group(0)
                            break
                if not raw_tok:
                    for ck_k, ck_v in cookies.items():
                        m = JWT_RE.search(str(ck_v))
                        if m:
                            raw_tok = m.group(0)
                            token_cookie_key = ck_k
                            break
                if raw_tok and len(raw_tok.split(".")) == 3:
                    findings.extend(audit_jwt_candidates([raw_tok], final_url, self.name))
                    _, p_b64, _ = raw_tok.split(".")
                    none_hdr = _b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
                    for label, forged in [
                        ("alg:none", f"{none_hdr}.{p_b64}."),
                        ("stripped-signature", f"{raw_tok.split('.')[0]}.{p_b64}."),
                    ]:
                        if token_cookie_key:
                            test_hdrs = dict(merged_headers)
                            test_cookies = {**cookies, token_cookie_key: forged}
                            poc_hdr = f"Cookie: {token_cookie_key}={none_hdr}.<payload>."
                        else:
                            test_hdrs = {k: v for k, v in merged_headers.items() if k.lower() != "authorization"}
                            test_hdrs["Authorization"] = f"Bearer {forged}"
                            test_cookies = cookies
                            poc_hdr = f"Authorization: Bearer {none_hdr}.<payload>."
                        rj = await self._safe_request(
                            client, args.method, target, scope=scope, limiter=limiter,
                            headers=test_hdrs, content=args.body, cookies=test_cookies, follow_redirects=False,
                        )
                        sim = difflib.SequenceMatcher(None, resp.text[:2000], rj.text[:2000]).ratio()
                        if resp.status_code in range(200, 300) and rj.status_code in range(200, 300) and sim >= 0.85:
                            findings.append(
                                DiscoveredFinding(
                                    title=f"JWT Signature Verification Bypass Accepted ({label})",
                                    severity="critical",
                                    target_url=final_url,
                                    cwe_id="CWE-347",
                                    owasp_category="API2:2023 - Broken Authentication",
                                    cvss_score=9.4,
                                    description=f"Endpoint accepted modified JWT ({label}) returning HTTP {rj.status_code} matching primary response ({round(sim * 100, 1)}%).",
                                    evidence={
                                        "variant": label,
                                        "source": f"cookie:{token_cookie_key}" if token_cookie_key else "header",
                                        "status_code": rj.status_code,
                                        "similarity": round(sim, 3),
                                    },
                                    poc_command=f"curl -i -s -H {shlex.quote(poc_hdr)} {shlex.quote(target)}",
                                    remediation="Validate JWT signatures using an explicit server-configured algorithm allowlist and reject empty signatures or alg=none.",
                                    tool_source=self.name,
                                )
                            )
                            break

            elif args.mode == "bfla_verb_tamper":
                # Test whether alternate HTTP methods bypass authorization controls (OPTIONS excluded: CORS/preflight)
                verbs = ["GET", "POST", "PUT", "PATCH", "DELETE"]
                sec_hdrs = {"User-Agent": "AegisPT-SecurityProbe/0.2", **(scope.secondary_headers or {})}
                sec_ck = dict(scope.secondary_cookies) if scope.has_secondary_auth else {}
                allowed_verbs: list[str] = []
                for verb in verbs:
                    rv = await self._safe_request(
                        client, verb, target, scope=scope, limiter=limiter,
                        headers=sec_hdrs, cookies=sec_ck, follow_redirects=False,
                    )
                    if rv.status_code in range(200, 300) and len(rv.text.strip()) > 0:
                        allowed_verbs.append(f"{verb}:{rv.status_code}")
                if resp.status_code in {401, 403} and allowed_verbs:
                    first_verb = allowed_verbs[0].split(":")[0]
                    findings.append(
                        DiscoveredFinding(
                            title="Inconsistent HTTP Method Authorization (Verb Tampering / BFLA)",
                            severity="high",
                            target_url=final_url,
                            cwe_id="CWE-285",
                            owasp_category="API5:2023 - Broken Function Level Authorization",
                            cvss_score=7.2,
                            description=f"Endpoint rejected {args.method} ({resp.status_code}) but succeeded on alternate verb(s): {', '.join(allowed_verbs)}.",
                            evidence={"baseline_status": resp.status_code, "accepted_verbs": allowed_verbs},
                            poc_command=f"curl -i -X {shlex.quote(first_verb)} {shlex.quote(target)}",
                            remediation="Apply role/authorization middleware uniformly across all HTTP methods at the router level.",
                            tool_source=self.name,
                        )
                    )

            elif args.mode == "race_burst_probe":
                gate = asyncio.Event()

                async def _burst_call() -> tuple[int, int]:
                    await gate.wait()
                    r_b = await self._safe_request(
                        client, args.method, target, scope=scope, limiter=limiter,
                        headers=merged_headers, content=args.body, cookies=cookies, follow_redirects=False,
                    )
                    return r_b.status_code, len(r_b.text)

                tasks = [asyncio.create_task(_burst_call()) for _ in range(args.burst_count)]
                await asyncio.sleep(0.02)
                gate.set()
                outcomes = await asyncio.gather(*tasks, return_exceptions=True)
                codes = [o[0] for o in outcomes if isinstance(o, tuple)]
                ok_2xx = sum(1 for c in codes if 200 <= c < 300)
                if args.method in {"POST", "PUT", "PATCH", "DELETE"} and ok_2xx > 1 and any(
                    k in final_url.lower() for k in ("coupon", "redeem", "transfer", "withdraw", "vote", "apply", "checkout", "verify")
                ):
                    burst_targets = " ".join(shlex.quote(target) for _ in range(int(args.burst_count)))
                    findings.append(
                        DiscoveredFinding(
                            title="Potential Concurrency / Idempotency Race Condition (TOCTOU)",
                            severity="medium",
                            target_url=final_url,
                            cwe_id="CWE-362",
                            owasp_category="API4:2023 - Unrestricted Resource Consumption",
                            cvss_score=5.9,
                            description=(
                                f"Sent {args.burst_count} synchronized concurrent {args.method} requests; "
                                f"{ok_2xx}/{len(codes)} returned HTTP 2xx concurrently without conflict/lock rejection."
                            ),
                            evidence={"burst_count": args.burst_count, "status_codes": codes, "success_count": ok_2xx},
                            poc_command=(
                                f"curl --parallel --parallel-max {int(args.burst_count)} -s -o /dev/null "
                                f"-w '%{{http_code}}\\n' -X {shlex.quote(args.method)} {burst_targets}"
                            ),
                            remediation="Wrap state transitions in serializable database transactions or idempotency keys.",
                            tool_source=self.name,
                        )
                    )

            elif args.mode == "hpp_and_content_switch":
                p_url = urlparse(target)
                q_map = parse_qs(p_url.query, keep_blank_values=True)
                if q_map:
                    first_k = next(iter(q_map.keys()))
                    hpp_query = f"{p_url.query}&{first_k}=aegis_hpp_second"
                    hpp_url = urlunparse(p_url._replace(query=hpp_query))
                    rh = await self._safe_request(
                        client, "GET", hpp_url, scope=scope, limiter=limiter,
                        headers=merged_headers, cookies=cookies, follow_redirects=False,
                    )
                    if "aegis_hpp_second" in rh.text and rh.status_code == 200:
                        findings.append(
                            DiscoveredFinding(
                                title=f"HTTP Parameter Pollution Last-Value Precedence on '{first_k}'",
                                severity="info",
                                target_url=final_url,
                                parameter=first_k,
                                cwe_id="CWE-235",
                                owasp_category="A03:2021 - Injection",
                                description=f"Duplicate parameter '{first_k}' influenced response body via second occurrence.",
                                evidence={"probe_url": hpp_url, "status_code": rh.status_code},
                                poc_command=f"curl -s {shlex.quote(hpp_url)}",
                                remediation="Reject duplicate query parameter occurrences or validate canonicalized parameter cardinality.",
                                tool_source=self.name,
                            )
                        )
                elif args.method in {"POST", "PUT", "PATCH"} and args.body and args.body.strip().startswith("{"):
                    try:
                        obj = json.loads(args.body)
                    except Exception:
                        obj = None
                    if isinstance(obj, dict):
                        form_headers = {**merged_headers, "Content-Type": "application/x-www-form-urlencoded"}
                        rf = await self._safe_request(
                            client, args.method, target, scope=scope, limiter=limiter,
                            headers=form_headers, content=urlencode(obj), cookies=cookies, follow_redirects=False,
                        )
                        if rf.status_code in range(200, 300):
                            findings.append(
                                DiscoveredFinding(
                                    title="Endpoint Accepts Content-Type Switching (JSON to Form-Urlencoded)",
                                    severity="low",
                                    target_url=final_url,
                                    cwe_id="CWE-436",
                                    owasp_category="A05:2021 - Security Misconfiguration",
                                    cvss_score=3.7,
                                    description="Endpoint accepted application/x-www-form-urlencoded where JSON schema was expected (potential CSRF/validation bypass risk).",
                                    evidence={"status_code": rf.status_code},
                                    poc_command=f"curl -i -X {shlex.quote(args.method)} -H 'Content-Type: application/x-www-form-urlencoded' {shlex.quote(target)}",
                                    remediation="Enforce strict Content-Type validation (reject non-application/json payloads with HTTP 415).",
                                    tool_source=self.name,
                                )
                            )

            elif args.mode == "ssti_probe":
                p_url = urlparse(target)
                q_map = parse_qs(p_url.query, keep_blank_values=True)
                target_params = [args.param] if args.param else list(q_map.keys())[:3]
                baseline_has_eval = "1850" in resp.text
                for pname in target_params:
                    if not pname or baseline_has_eval:
                        continue
                    for family, payload in (
                        ("Jinja2/Twig", "{{37*50}}"),
                        ("SpEL/EL/FreeMarker", "${37*50}"),
                        ("ERB", "<%= 37*50 %>"),
                    ):
                        mut_q = {k: list(v) for k, v in q_map.items()}
                        mut_q[pname] = [payload]
                        test_url = urlunparse(p_url._replace(query=urlencode(mut_q, doseq=True)))
                        r_ssti = await self._safe_request(
                            client, "GET", test_url, scope=scope, limiter=limiter,
                            headers=merged_headers, cookies=cookies, follow_redirects=False,
                        )
                        if "1850" in r_ssti.text and payload not in r_ssti.text:
                            findings.append(
                                DiscoveredFinding(
                                    title=f"Server-Side Template Injection ({family}) on '{pname}'",
                                    severity="critical",
                                    target_url=final_url,
                                    parameter=pname,
                                    cwe_id="CWE-1336",
                                    owasp_category="A03:2021 - Injection",
                                    cvss_score=9.4,
                                    description=f"Benign mathematical expression `{payload}` ({family}) evaluated to `1850` in server response.",
                                    evidence={"parameter": pname, "family": family, "payload": payload, "probe_url": test_url},
                                    poc_command=f"curl -s {shlex.quote(test_url)}",
                                    remediation="Avoid passing untrusted input into template compilation; use logic-less templates or strict context escaping.",
                                    tool_source=self.name,
                                )
                            )
                            break

            elif args.mode == "open_redirect_probe":
                p_url = urlparse(target)
                q_map = parse_qs(p_url.query, keep_blank_values=True)
                candidates = (
                    [args.param]
                    if args.param
                    else [k for k in q_map.keys() if k.lower() in {"next", "url", "redirect", "return", "dest", "to", "callback"}]
                )
                probe_dest = "https://aegispt-redirect-check.invalid/probe"
                for pname in candidates[:3]:
                    if not pname:
                        continue
                    mut_q = {k: list(v) for k, v in q_map.items()}
                    mut_q[pname] = [probe_dest]
                    test_url = urlunparse(p_url._replace(query=urlencode(mut_q, doseq=True)))
                    r_redir = await self._safe_request(
                        client, "GET", test_url, scope=scope, limiter=limiter,
                        headers=merged_headers, cookies=cookies, follow_redirects=False,
                    )
                    loc = r_redir.headers.get("location", "")
                    if r_redir.status_code in {301, 302, 303, 307, 308} and "aegispt-redirect-check.invalid" in loc:
                        findings.append(
                            DiscoveredFinding(
                                title=f"Open Redirect on Parameter '{pname}'",
                                severity="medium",
                                target_url=final_url,
                                parameter=pname,
                                cwe_id="CWE-601",
                                owasp_category="A01:2021 - Broken Access Control",
                                cvss_score=5.4,
                                description=f"Endpoint redirected Location header to external domain via parameter '{pname}'.",
                                evidence={"parameter": pname, "location": loc, "status_code": r_redir.status_code},
                                poc_command=f"curl -I -s {shlex.quote(test_url)}",
                                remediation="Validate redirect destinations against a strict server-side allowlist of relative paths or trusted domains.",
                                tool_source=self.name,
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
                "mode": args.mode,
                "status_code": resp.status_code,
                "final_url": str(resp.url),
                "title": title,
                "technologies": techs,
                "endpoints_discovered": len(endpoints),
                "findings_count": len(findings),
            },
        )
