"""Risk-weighted Attack-Surface Graph serializer for token-efficient reflective LLM reasoning."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Asset,
    AttackChain,
    Endpoint,
    Engagement,
    Finding,
    Hypothesis,
    ScopePolicyModel,
    SkillOutcomeStat,
    ToolRun,
)
from app.knowledge.store import knowledge_store

HIGH_VALUE_TOKENS = (
    "/admin",
    "/api",
    "/rest",
    "/graphql",
    "/oauth",
    "/auth",
    "/login",
    "/upload",
    "/webhook",
    "/checkout",
    "/coupon",
    "/redeem",
    "/transfer",
    "/withdraw",
    "/users",
    "/orders",
    "/export",
    "/import",
)


def score_endpoint_risk(ep: Endpoint, tested_urls: set[str]) -> int:
    score = 0
    url_l = (ep.url or "").lower()
    path_l = (ep.path or "").lower()
    for tok in HIGH_VALUE_TOKENS:
        if tok in path_l or tok in url_l:
            score += 4
    if ep.method and ep.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 5
    score += min(len(ep.query_params or []) * 3 + len(ep.body_params or []) * 3, 12)
    if ep.status_code in {200, 201, 401, 403, 500}:
        score += 2
    if ep.url not in tested_urls:
        score += 3
    if path_l.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2", ".ico")):
        score -= 10
    return score


async def build_graph_context(session: AsyncSession, engagement_id: str) -> dict[str, Any]:
    eng = await session.get(Engagement, engagement_id)
    scope_row = (
        await session.execute(
            select(ScopePolicyModel).where(ScopePolicyModel.engagement_id == engagement_id)
        )
    ).scalar_one_or_none()
    has_secondary_auth = bool(
        scope_row and (scope_row.secondary_headers or scope_row.secondary_cookies)
    )

    assets = (
        await session.execute(
            select(Asset).where(Asset.engagement_id == engagement_id).limit(60)
        )
    ).scalars().all()
    all_endpoints = (
        await session.execute(
            select(Endpoint).where(Endpoint.engagement_id == engagement_id).limit(400)
        )
    ).scalars().all()
    runs = (
        await session.execute(
            select(ToolRun)
            .where(ToolRun.engagement_id == engagement_id)
            .order_by(ToolRun.created_at.desc())
            .limit(40)
        )
    ).scalars().all()
    findings = (
        await session.execute(
            select(Finding).where(Finding.engagement_id == engagement_id).limit(60)
        )
    ).scalars().all()
    hypotheses = (
        await session.execute(
            select(Hypothesis)
            .where(Hypothesis.engagement_id == engagement_id)
            .order_by(Hypothesis.updated_at.desc())
            .limit(35)
        )
    ).scalars().all()
    chains = (
        await session.execute(
            select(AttackChain).where(AttackChain.engagement_id == engagement_id).limit(20)
        )
    ).scalars().all()

    tested_urls = {r.target for r in runs if r.status in {"completed", "failed"}}
    ranked_endpoints = sorted(
        all_endpoints,
        key=lambda ep: (-score_endpoint_risk(ep, tested_urls), ep.url),
    )[:60]

    graph_payload: dict[str, Any] = {
        "assets": [
            {
                "type": a.asset_type,
                "value": a.value,
                "status_code": a.status_code,
                "title": a.title,
                "waf": a.waf,
                "technologies": (a.technologies or [])[:12],
            }
            for a in assets[:40]
        ],
        "endpoints": [
            {
                "method": e.method,
                "url": e.url,
                "path": e.path,
                "status_code": e.status_code,
                "query_params": e.query_params,
                "body_params": e.body_params,
                "source": e.source,
                "risk_score": score_endpoint_risk(e, tested_urls),
            }
            for e in ranked_endpoints
        ],
        "total_endpoints_discovered": len(all_endpoints),
        "recent_runs": [
            {
                "tool": r.tool_name,
                "target": r.target,
                "args": r.args or {},
                "status": r.status,
                "summary": r.summary,
                "error": r.error_message,
            }
            for r in runs[:25]
        ],
        "findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "cwe_id": f.cwe_id,
                "target_url": f.target_url,
                "parameter": f.parameter,
                "status": f.status,
                "corroborated_by": f.corroborated_by or [],
            }
            for f in findings
        ],
        "hypotheses": [
            {
                "title": h.title,
                "target_url": h.target_url,
                "parameter": h.parameter,
                "cwe_id": h.cwe_id,
                "status": h.status,
                "evidence_note": h.evidence_note,
            }
            for h in hypotheses
        ],
        "attack_chains": [
            {"title": c.title, "severity": c.severity, "steps": c.steps}
            for c in chains
        ],
        "waf_detected": next((a.waf for a in assets if a.waf), None),
        "has_secondary_auth": has_secondary_auth,
        "operator_hints": list((eng.operator_hints or [])[-5:]) if eng else [],
    }

    matched_skills = knowledge_store.match_skills_for_graph(
        graph_payload,
        eng.objective if eng else "",
        has_secondary_auth=has_secondary_auth,
        limit=6,
    )
    graph_payload["active_skills"] = [
        {
            "id": s["id"],
            "title": s["title"],
            "wstg_id": s["wstg_id"],
            "recommended_tools": s["recommended_tools"],
            "checklist": s["checklist"][:4],
        }
        for s in matched_skills
    ]

    # Pull top historical skill success signals
    stats_rows = (
        await session.execute(
            select(SkillOutcomeStat)
            .where(SkillOutcomeStat.findings_count > 0)
            .order_by(SkillOutcomeStat.findings_count.desc())
            .limit(8)
        )
    ).scalars().all()
    if stats_rows:
        graph_payload["historical_skill_stats"] = [
            {
                "skill_id": st.skill_id,
                "tech": st.tech_signature,
                "waf": st.waf_name,
                "findings": st.findings_count,
                "runs": st.runs_count,
            }
            for st in stats_rows
        ]

    return graph_payload
