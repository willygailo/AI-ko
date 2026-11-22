"""Native JS Bundle Route & Secret Miner (Tier 1)."""
from __future__ import annotations

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
API_PATH_RE = re.compile(r"""["'`](\/(?:api|rest|v[1-9]|graphql|auth|admin|users)[A-Za-z0-9_./:-]{1,100})["'`]""")
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


def analyze_js_text(js_text: str, source_url: str) -> tuple[list[DiscoveredEndpoint], list[DiscoveredFinding]]:
    """Extract hidden API paths and masked secret exposures from JavaScript source."""
    endpoints: list[DiscoveredEndpoint] = []
    findings: list[DiscoveredFinding] = []
    parsed = urlparse(source_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

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
    return endpoints, findings


class JsMinerArgs(BaseModel):
    max_bundles: int = Field(default=10, ge=1, le=30)
    timeout_seconds: int = Field(default=60, ge=10, le=180)


class JsMinerAdapter(BaseToolAdapter):
    name = "js_miner"
    description = "Fetches in-scope HTML/JS bundles to mine hidden API routes, GraphQL paths, and exposed secrets."
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
        headers = {"User-Agent": "AegisPT-JSMiner/0.1", **scope.custom_headers}
        endpoints: list[DiscoveredEndpoint] = []
        findings: list[DiscoveredFinding] = []
        scanned_bundles: list[str] = []

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=float(args.timeout_seconds),
            cookies=dict(scope.auth_cookies),
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
                except Exception:
                    continue

        return ToolResult(
            tool_name=self.name,
            exit_code=0,
            duration_ms=0,
            stdout=f"Scanned {len(scanned_bundles)} JS bundles; extracted {len(endpoints)} routes and {len(findings)} potential secret exposures.",
            endpoints=endpoints,
            findings=findings,
            summary={
                "bundles_scanned": len(scanned_bundles),
                "routes_extracted": len(endpoints),
                "secrets_detected": len(findings),
            },
        )
