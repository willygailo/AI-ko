"""Compact Attack-Surface Graph serializer for token-efficient reflective LLM reasoning."""
from __future__ import annotations

from typing import Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, Endpoint, Finding, Hypothesis, ToolRun


async def build_graph_context(session: AsyncSession, engagement_id: str) -> dict[str, Any]:
    assets = (
        await session.execute(
            select(Asset).where(Asset.engagement_id == engagement_id).limit(40)
        )
    ).scalars().all()
    endpoints = (
        await session.execute(
            select(Endpoint).where(Endpoint.engagement_id == engagement_id).limit(60)
        )
    ).scalars().all()
    runs = (
        await session.execute(
            select(ToolRun)
            .where(ToolRun.engagement_id == engagement_id)
            .order_by(ToolRun.created_at.desc())
            .limit(25)
        )
    ).scalars().all()
    findings = (
        await session.execute(
            select(Finding).where(Finding.engagement_id == engagement_id).limit(40)
        )
    ).scalars().all()
    hypotheses = (
        await session.execute(
            select(Hypothesis)
            .where(Hypothesis.engagement_id == engagement_id)
            .order_by(Hypothesis.updated_at.desc())
            .limit(30)
        )
    ).scalars().all()

    return {
        "assets": [
            {
                "type": a.asset_type,
                "value": a.value,
                "status_code": a.status_code,
                "title": a.title,
                "waf": a.waf,
                "technologies": (a.technologies or [])[:12],
            }
            for a in assets
        ],
        "endpoints": [
            {
                "method": e.method,
                "url": e.url,
                "status_code": e.status_code,
                "query_params": e.query_params,
                "body_params": e.body_params,
                "source": e.source,
            }
            for e in endpoints
        ],
        "recent_runs": [
            {
                "tool": r.tool_name,
                "target": r.target,
                "status": r.status,
                "summary": r.summary,
                "error": r.error_message,
            }
            for r in runs
        ],
        "findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "target_url": f.target_url,
                "parameter": f.parameter,
                "status": f.status,
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
            }
            for h in hypotheses
        ],
    }
