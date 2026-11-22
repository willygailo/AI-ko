"""Findings triage & status management routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import FindingUpdateInput
from app.core.auth import require_api_token
from app.db.database import get_db
from app.db.models import Finding

router = APIRouter(
    prefix="/api/v1",
    tags=["findings"],
    dependencies=[Depends(require_api_token)],
)


@router.get("/engagements/{engagement_id}/findings")
async def list_findings(
    engagement_id: str,
    severity: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    stmt = select(Finding).where(Finding.engagement_id == engagement_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status:
        stmt = stmt.where(Finding.status == status)
    rows = (await db.execute(stmt.order_by(Finding.created_at.desc()))).scalars().all()
    return {
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "cvss_score": f.cvss_score,
                "cwe_id": f.cwe_id,
                "owasp_category": f.owasp_category,
                "target_url": f.target_url,
                "parameter": f.parameter,
                "description": f.description,
                "evidence": f.evidence,
                "poc_command": f.poc_command,
                "remediation": f.remediation,
                "tool_source": f.tool_source,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in rows
        ]
    }


@router.patch("/findings/{finding_id}")
async def update_finding(
    finding_id: str,
    body: FindingUpdateInput,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    if body.status is not None:
        finding.status = body.status
    if body.severity is not None:
        finding.severity = body.severity
    await db.commit()
    await db.refresh(finding)
    return {
        "id": finding.id,
        "status": finding.status,
        "severity": finding.severity,
    }
