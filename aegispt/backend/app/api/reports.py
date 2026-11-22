"""Report export routes (Markdown, HTML, SARIF 2.1.0, JSON)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.reporter import (
    render_html_report,
    render_markdown_report,
    render_poc_script,
    render_sarif_report,
)
from app.core.auth import require_api_token
from app.db.database import get_db
from app.db.models import Asset, AttackChain, Endpoint, Engagement, Finding, ToolRun

router = APIRouter(
    prefix="/api/v1/engagements",
    tags=["reports"],
    dependencies=[Depends(require_api_token)],
)


@router.get("/{engagement_id}/report")
async def export_report(
    engagement_id: str,
    format: str = Query(default="markdown", pattern="^(markdown|md|html|sarif|json|poc_sh)$"),
    db: AsyncSession = Depends(get_db),
):
    eng = await db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found.")
    assets = (await db.execute(select(Asset).where(Asset.engagement_id == engagement_id))).scalars().all()
    endpoints = (await db.execute(select(Endpoint).where(Endpoint.engagement_id == engagement_id))).scalars().all()
    findings = (await db.execute(select(Finding).where(Finding.engagement_id == engagement_id))).scalars().all()
    runs = (await db.execute(select(ToolRun).where(ToolRun.engagement_id == engagement_id))).scalars().all()
    chains = (await db.execute(select(AttackChain).where(AttackChain.engagement_id == engagement_id))).scalars().all()

    fmt = format.lower()
    if fmt in ("markdown", "md"):
        return PlainTextResponse(
            content=render_markdown_report(eng, assets, endpoints, findings, runs, chains),
            media_type="text/markdown; charset=utf-8",
        )
    if fmt == "html":
        return HTMLResponse(
            content=render_html_report(eng, assets, endpoints, findings, runs, chains),
        )
    if fmt == "sarif":
        return JSONResponse(content=render_sarif_report(eng, findings))
    if fmt == "poc_sh":
        return PlainTextResponse(
            content=render_poc_script(eng, findings),
            media_type="text/x-shellscript; charset=utf-8",
        )

    return JSONResponse(
        content={
            "engagement": {"id": eng.id, "name": eng.name, "status": eng.status},
            "assets_count": len(assets),
            "endpoints_count": len(endpoints),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "status": f.status,
                    "cvss_score": f.cvss_score,
                    "cwe_id": f.cwe_id,
                    "target_url": f.target_url,
                    "parameter": f.parameter,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in findings
            ],
        }
    )
