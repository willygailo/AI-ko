"""Shared async SQLite persistence helper with cross-tool finding correlation."""
from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, Endpoint, Finding
from app.tools.base import ToolResult, fingerprint_finding


def _norm_target_key(url: str) -> str:
    p = urlparse(url or "")
    if p.scheme and p.netloc:
        return f"{p.scheme.lower()}://{p.netloc.lower()}{(p.path or '/').rstrip('/') or '/'}"
    return (url or "").strip().lower().rstrip("/")


async def persist_tool_result(
    session: AsyncSession,
    engagement_id: str,
    result: ToolResult,
) -> int:
    """Upsert discovered assets, endpoints, and deduplicated/correlated findings into SQLite.

    Returns the number of newly inserted findings.
    """
    new_findings = 0

    for a in result.assets:
        existing = (
            await session.execute(
                select(Asset).where(
                    Asset.engagement_id == engagement_id,
                    Asset.asset_type == a.asset_type,
                    Asset.value == a.value,
                )
            )
        ).scalar_one_or_none()
        if existing:
            if a.status_code is not None:
                existing.status_code = a.status_code
            if a.title:
                existing.title = a.title
            if a.waf:
                existing.waf = a.waf
            if a.ip_address:
                existing.ip_address = a.ip_address
            existing.technologies = sorted(
                set(existing.technologies or []) | set(a.technologies or [])
            )
            if a.headers:
                existing.headers = {**(existing.headers or {}), **a.headers}
        else:
            session.add(
                Asset(
                    engagement_id=engagement_id,
                    asset_type=a.asset_type,
                    value=a.value,
                    ip_address=a.ip_address,
                    status_code=a.status_code,
                    title=a.title,
                    waf=a.waf,
                    technologies=a.technologies,
                    headers=a.headers,
                    discovered_by=a.discovered_by,
                )
            )

    for ep in result.endpoints:
        existing_ep = (
            await session.execute(
                select(Endpoint).where(
                    Endpoint.engagement_id == engagement_id,
                    Endpoint.method == ep.method,
                    Endpoint.url == ep.url,
                )
            )
        ).scalar_one_or_none()
        if existing_ep:
            existing_ep.query_params = sorted(
                set(existing_ep.query_params or []) | set(ep.query_params or [])
            )
            existing_ep.body_params = sorted(
                set(existing_ep.body_params or []) | set(ep.body_params or [])
            )
            if ep.status_code is not None:
                existing_ep.status_code = ep.status_code
            if ep.content_type and not existing_ep.content_type:
                existing_ep.content_type = ep.content_type
        else:
            session.add(
                Endpoint(
                    engagement_id=engagement_id,
                    method=ep.method,
                    url=ep.url,
                    path=ep.path,
                    query_params=ep.query_params,
                    body_params=ep.body_params,
                    status_code=ep.status_code,
                    content_type=ep.content_type,
                    source=ep.source,
                )
            )

    existing_eng_findings = (
        await session.execute(
            select(Finding).where(Finding.engagement_id == engagement_id)
        )
    ).scalars().all()

    for f in result.findings:
        fp = fingerprint_finding(f.tool_source, f.title, f.target_url, f.parameter)
        existing_f = next((ef for ef in existing_eng_findings if ef.fingerprint == fp), None)
        if existing_f:
            continue

        # Cross-tool correlation: same CWE + normalized URL path + parameter
        correlated = None
        if f.cwe_id:
            t_key = _norm_target_key(f.target_url)
            p_key = (f.parameter or "").strip().lower()
            for ef in existing_eng_findings:
                if (
                    ef.cwe_id == f.cwe_id
                    and _norm_target_key(ef.target_url) == t_key
                    and (ef.parameter or "").strip().lower() == p_key
                ):
                    correlated = ef
                    break

        if correlated is not None:
            corr_list = sorted(set(correlated.corroborated_by or [correlated.tool_source]) | {f.tool_source})
            correlated.corroborated_by = corr_list
            if f.evidence:
                correlated.evidence = {
                    **(correlated.evidence or {}),
                    f"corroborated_{f.tool_source}": f.evidence,
                }
            continue

        row = Finding(
            engagement_id=engagement_id,
            title=f.title,
            severity=f.severity,
            status="open",
            cvss_score=f.cvss_score,
            cvss_vector=f.cvss_vector,
            cwe_id=f.cwe_id,
            owasp_category=f.owasp_category,
            target_url=f.target_url,
            parameter=f.parameter,
            description=f.description,
            evidence=f.evidence,
            poc_command=f.poc_command,
            remediation=f.remediation,
            tool_source=f.tool_source,
            corroborated_by=[f.tool_source],
            fingerprint=fp,
        )
        session.add(row)
        existing_eng_findings.append(row)
        new_findings += 1

    return new_findings
