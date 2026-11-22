"""Native JS Bundle, Source Map & DOM Sink Miner (Tier 1)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import BaseModel, Field

from app.core.ratelimit import rate_limiters
from app.core.scope import ScopePolicy
from app.tools.base import (
    BaseToolAdapter,
    DiscoveredEndpoint,
    DiscoveredFinding,
    ToolResult,
)


SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")
API_PATH_RE = re.compile(r"""["'`](\/(?:api|rest|v[1-9]|graphql|oauth|auth|admin|users)[A-Za-z0-9_./:-]{1,100})["'`]""")
JSON_KEYS_RE = re.compile(r"JSON\.stringify\s*\(\s*\{([A-Za-z0-9_,\s:\"'$-]{1,240})\}")
DOM_SINK_RE = re.compile(r"(dangerouslySetInnerHTML|\.innerHTML\s*=|eval\(|addEventListener\s*\(\s*['\"]message['\"])")
JS_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
    ("GitHub Token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b")),
    ("Stripe/OpenAI Secret Key", re.compile(r"\b(sk_(?:live|test)_[0-9A-Za-z]{16,}|sk-[A-Za-z0-9_-]{24,})\b")),
    ("Private Key Header", re.compile(r"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)")),
    ("Hardcoded JWT", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,})\b")),
]


def _mask_secret(val: str) -> str:
    if len(val) <= 10:
        return val[:2] + "***"
    return val[:6] + "..." + val[-4:]


def _extract_body_keys(js_text: str) -> list[str]:
    keys: set[str] = set()
    for m in JSON_KEYS_RE.finditer(js_text[:300000]):
        chunk = m.group(1)
        for token in re.findall(r"""(?:^|,)\s*["']?([A-Za-z_][A-Za-z0-9_]{1,30})["']?\s*:""", chunk):
            if token not in {"method", "headers", "body"}:
                keys.add(token)
            if len(keys) >= 25:
                return sorted(keys)
    return sorted(keys)


def analyze_js_text(js_text: str, source_url: str) -> tuple[list[DiscoveredEndpoint], list[DiscoveredFinding]]:
    """Extract hidden API paths, JSON body keys, DOM sink indicators, and masked secrets from JS."""
    endpoints: list[DiscoveredEndpoint] = []
    findings: list[DiscoveredFinding] = []
    parsed = urlparse(source_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    inferred_body_keys = _extract_body_keys(js_text)
    seen_paths: set[str] = set()
    for m in API_PATH_RE.finditer(js_text):
        p = m.group(1)
        if p not in seen_paths and not p.endswith((".png", ".jpg", ".css", ".svg")):
            seen_paths.add(p)
            endpoints.append(
                DiscoveredEndpoint(
                    method="GET",
                    url=urljoin(origin, p),
                    path=p,
                    body_params=inferred_body_keys[:10] if any(t in p for t in ("/login", "/auth", "/register", "/users", "/cart", "/order", "/graphql")) else [],
                    source="js_miner",
                )
            )
            if len(seen_paths) >= 100:
                break

    seen_kinds: set[str] = set()
    for kind, pat in JS_SECRET_PATTERNS:
        m = pat.search(js_text)
        if m and kind not in seen_kinds:
            seen_kinds.add(kind)
            findings.append(
                DiscoveredFinding(
                    title=f"Potential {kind} Exposed in Client JavaScript",
                    severity="high" if "Private Key" in kind or "Secret" in kind else "medium",
                    target_url=source_url,
                    cwe_id="CWE-798",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                    cvss_score=7.5 if "Private Key" in kind else 5.8,
                    description=f"JavaScript bundle `{source_url}` contains a pattern matching {kind}.",
                    evidence={"secret_type": kind, "masked_sample": _mask_secret(m.group(1))},
                    remediation="Remove hardcoded credentials and private keys from client-side bundles and rotate any exposed tokens.",
                    tool_source="js_miner",
                )
            )

    dom_sinks = sorted({m.group(1).strip() for m in DOM_SINK_RE.finditer(js_text[:300000])})
    if dom_sinks:
        findings.append(
            DiscoveredFinding(
                title="Client-Side DOM Injection Sink Indicators Detected",
                severity="info",
                target_url=source_url,
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                description=f"JavaScript bundle `{source_url}` uses dynamic DOM/message sinks ({', '.join(dom_sinks[:5])}) that warrant manual XSS review.",
                evidence={"sinks": dom_sinks[:10]},
                remediation="Sanitize untrusted input before assigning innerHTML/dangerouslySetInnerHTML and validate event.origin in postMessage handlers.",
                tool_source="js_miner",
            )
        )
    return endpoints, findings


class JsMinerArgs(BaseModel):
    max_bundles: int = Field(default=10, ge=1, le=30)
    timeout_seconds: int = Field(default=60, ge=10, le=180)


class JsMinerAdapter(BaseToolAdapter):
    name = "js_miner"
    description = "Fetches in-scope HTML/JS bundles & source maps to mine hidden API routes, body params, DOM sinks, and secrets."
    tier = 1
    binary_name = None
    args_schema = JsMinerArgs

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, JsMinerArgs)
        return ["native:js_miner", f"--max-bundles={args.max_bundles}", target]

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
        assert isinstance(args, JsMinerArgs)
        limiter = rate_limiters.get(engagement_id, scope.max_rps)
        is_local = (urlparse(target).hostname or "").lower() in {"127.0.0.1", "localhost", "::1"}
        headers = {"User-Agent": "AegisPT-JSMiner/0.2", **scope.custom_headers}
        if scope.auth_cookies:
            headers["Cookie"] = scope.build_cookie_header(scope.auth_cookies)
        endpoints: list[DiscoveredEndpoint] = []
        findings: list[DiscoveredFinding] = []
        scanned_bundles: list[str] = []

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=float(args.timeout_seconds),
            trust_env=not is_local,
        ) as client:
            bundle_urls: list[str] = []
            if target.lower().split("?")[0].endswith(".js"):
                bundle_urls.append(target)
            else:
                await limiter.acquire()
                resp = await client.get(target, headers=headers)
                for m in SCRIPT_SRC_RE.finditer(resp.text[:200000]):
                    cand = urljoin(target, m.group(1))
                    if cand not in bundle_urls:
                        bundle_urls.append(cand)
                eps, fnds = analyze_js_text(resp.text[:200000], target)
                endpoints.extend(eps)
                findings.extend(fnds)

            for bu in bundle_urls[: args.max_bundles]:
                try:
                    scope.validate_target(bu, resolve_dns=False)
                    await limiter.acquire()
                    r = await client.get(bu, headers=headers)
                    if r.status_code == 200:
                        scanned_bundles.append(bu)
                        eps, fnds = analyze_js_text(r.text[:500000], bu)
                        endpoints.extend(eps)
                        findings.extend(fnds)

                        # Check for exposed sourceMap reference
                        sm_match = SOURCE_MAP_RE.search(r.text[-4096:])
                        if sm_match:
                            map_ref = sm_match.group(1).strip()
                            if not map_ref.startswith("data:"):
                                map_url = urljoin(bu, map_ref)
                                try:
                                    scope.validate_target(map_url, resolve_dns=False)
                                    await limiter.acquire()
                                    rm = await client.get(map_url, headers=headers)
                                    if rm.status_code == 200 and '"sources"' in rm.text[:2000]:
                                        m_obj = json.loads(rm.text[:1000000])
                                        sources = (m_obj.get("sources") or [])[:25]
                                        findings.append(
                                            DiscoveredFinding(
                                                title="Exposed JavaScript Source Map File (.js.map)",
                                                severity="low",
                                                target_url=map_url,
                                                cwe_id="CWE-540",
                                                owasp_category="A05:2021 - Security Misconfiguration",
                                                cvss_score=3.5,
                                                description=f"Public source map `{map_url}` exposes unminified original frontend module paths ({len(m_obj.get('sources') or [])} source files).",
                                                evidence={"map_url": map_url, "sample_sources": sources},
                                                poc_command=f"curl -s '{map_url}' | head -c 500",
                                                remediation="Restrict or remove .js.map files from public production web servers.",
                                                tool_source=self.name,
                                            )
                                        )
                                except Exception:
                                    pass
                except Exception:
                    continue

        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            stdout=f"Scanned {len(scanned_bundles)} JS bundles; extracted {len(endpoints)} routes and {len(findings)} potential exposures/leads.",
            endpoints=endpoints,
            findings=findings,
            summary={
                "bundles_scanned": len(scanned_bundles),
                "routes_extracted": len(endpoints),
                "findings_count": len(findings),
            },
        )
