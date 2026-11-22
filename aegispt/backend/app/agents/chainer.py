"""Cross-Finding Attack-Chain Synthesizer."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, AttackChain, Endpoint, Finding


def _title_has(f: Finding, *needles: str) -> bool:
    blob = f"{f.title} {f.cwe_id or ''} {f.owasp_category or ''}".lower()
    return any(n in blob for n in needles)


async def synthesize_attack_chains(
    session: AsyncSession, engagement_id: str
) -> list[AttackChain]:
    """Identify and persist multi-step attack chains linking correlated findings & surface nodes."""
    findings = (
        await session.execute(
            select(Finding).where(
                Finding.engagement_id == engagement_id,
                Finding.status != "false_positive",
            )
        )
    ).scalars().all()
    endpoints = (
        await session.execute(select(Endpoint).where(Endpoint.engagement_id == engagement_id))
    ).scalars().all()
    assets = (
        await session.execute(select(Asset).where(Asset.engagement_id == engagement_id))
    ).scalars().all()

    if not findings:
        return []

    candidate_specs: list[dict[str, Any]] = []

    cors_findings = [f for f in findings if _title_has(f, "cors", "cwe-942")]
    cookie_findings = [f for f in findings if _title_has(f, "cookie", "httponly", "samesite", "cwe-614")]
    if cors_findings and cookie_findings:
        candidate_specs.append(
            {
                "title": "Cross-Origin Session & API Data Exposure Chain",
                "severity": "high",
                "target_url": cors_findings[0].target_url,
                "finding_ids": [cors_findings[0].id, cookie_findings[0].id],
                "steps": [
                    f"1. Permissive CORS policy on {cors_findings[0].target_url} reflects arbitrary Origins with credentials.",
                    f"2. Weak cookie attributes on '{cookie_findings[0].parameter or 'session'}' widen browser session exposure.",
                    "3. Combined risk: untrusted origins can issue credentialed cross-site reads against authenticated API routes.",
                ],
                "risk_summary": "Chained CORS + cookie configuration weakness enables cross-origin authenticated data access.",
            }
        )

    secret_findings = [f for f in findings if _title_has(f, "secret", "api key", "hardcoded jwt", "token", "cwe-798", "jwt")]
    bola_findings = [f for f in findings if _title_has(f, "bola", "idor", "missing authorization", "bfla", "cwe-862", "cwe-639")]
    if secret_findings and bola_findings:
        candidate_specs.append(
            {
                "title": "Credential/Token Exposure + Broken Object Authorization Chain",
                "severity": "critical",
                "target_url": bola_findings[0].target_url,
                "finding_ids": [secret_findings[0].id, bola_findings[0].id],
                "steps": [
                    f"1. Client bundle / token hygiene weakness discovered ({secret_findings[0].title}).",
                    f"2. Authorization boundary flaw confirmed at {bola_findings[0].target_url}.",
                    "3. Combined risk: leaked/weak tokens allow unauthorized cross-object API operations.",
                ],
                "risk_summary": "Chained token/credential weakness paired with weak server-side object authorization.",
            }
        )

    gql_findings = [f for f in findings if _title_has(f, "graphql", "introspection", "field suggestion")]
    mut_gql = [ep for ep in endpoints if "graphql" in (ep.url or "").lower()]
    if gql_findings and (bola_findings or any(_title_has(f, "sql", "xss", "ssti") for f in findings) or mut_gql):
        linked = [gql_findings[0].id]
        if bola_findings:
            linked.append(bola_findings[0].id)
        candidate_specs.append(
            {
                "title": "GraphQL Schema Disclosure to Privileged Query/Mutation Surface Chain",
                "severity": "high",
                "target_url": gql_findings[0].target_url,
                "finding_ids": linked,
                "steps": [
                    f"1. {gql_findings[0].title} exposes internal GraphQL types, arguments, and mutations.",
                    "2. Discovered schema operations map directly into tested API endpoints.",
                    "3. Combined risk: full operation enumeration accelerates authorization and resolver-injection checks.",
                ],
                "risk_summary": "Schema exposure lowers discovery friction for GraphQL resolver authorization flaws.",
            }
        )

    redir_findings = [f for f in findings if _title_has(f, "open redirect", "cwe-601")]
    oauth_eps = [ep for ep in endpoints if any(k in (ep.url or "").lower() for k in ("oauth", "authorize", "callback"))]
    if redir_findings and oauth_eps:
        candidate_specs.append(
            {
                "title": "Open Redirect Chained with OAuth Callback Surface",
                "severity": "high",
                "target_url": redir_findings[0].target_url,
                "finding_ids": [redir_findings[0].id],
                "steps": [
                    f"1. Unvalidated redirect confirmed at {redir_findings[0].target_url} (param={redir_findings[0].parameter}).",
                    f"2. OAuth/authentication endpoint observed at {oauth_eps[0].url}.",
                    "3. Combined risk: weak redirect_uri prefix matching can bounce tokens/codes through the same-origin open redirect.",
                ],
                "risk_summary": "Open redirect on an auth-bearing origin weakens OAuth redirect_uri trust boundaries.",
            }
        )

    port_assets = [a for a in assets if any(str(t).startswith("port:") for t in (a.technologies or []))]
    inj_or_ssrf = [f for f in findings if _title_has(f, "ssrf", "sql injection", "ssti", "command")]
    if port_assets and inj_or_ssrf:
        candidate_specs.append(
            {
                "title": "High-Severity Injection/SSRF Paired with Exposed Internal/Host Services",
                "severity": "critical",
                "target_url": inj_or_ssrf[0].target_url,
                "finding_ids": [inj_or_ssrf[0].id],
                "steps": [
                    f"1. Verified {inj_or_ssrf[0].title} on {inj_or_ssrf[0].target_url}.",
                    f"2. Host port scan enumerated active services on {port_assets[0].value} ({', '.join((port_assets[0].technologies or [])[:4])}).",
                    "3. Combined risk: server-side execution/fetch bugs increase blast radius across co-hosted services.",
                ],
                "risk_summary": "Critical server-side flaw combined with adjacent exposed TCP services.",
            }
        )

    existing_chains = (
        await session.execute(select(AttackChain).where(AttackChain.engagement_id == engagement_id))
    ).scalars().all()
    existing_titles = {c.title for c in existing_chains}
    created: list[AttackChain] = []
    for spec in candidate_specs:
        if spec["title"] in existing_titles:
            continue
        chain = AttackChain(
            engagement_id=engagement_id,
            title=spec["title"],
            severity=spec["severity"],
            risk_summary=spec["risk_summary"],
            target_url=spec["target_url"],
            steps=spec["steps"],
            finding_ids=spec["finding_ids"],
        )
        session.add(chain)
        created.append(chain)
        existing_titles.add(spec["title"])
    return created
