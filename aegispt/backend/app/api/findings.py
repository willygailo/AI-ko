"""Findings triage & status management routes."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    FindingCreateInput,
    FindingUpdateInput,
    HypothesisUpdateInput,
)
from app.core.auth import require_api_token
from app.core.scope import ScopePolicy, ScopeViolationError
from app.db.database import get_db
from app.db.models import Engagement, Finding, Hypothesis, ScopePolicyModel
from app.tools.base import fingerprint_finding
from app.tools.http_probe import HttpProbeAdapter

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
                "corroborated_by": f.corroborated_by or [f.tool_source],
                "verified_at": f.verified_at.isoformat() if getattr(f, "verified_at", None) else None,
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


@router.post("/findings/{finding_id}/reverify")
async def reverify_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    if finding.tool_source != "http_probe":
        return {
            "id": finding.id,
            "finding_id": finding.id,
            "status": finding.status,
            "still_present": None,
            "manual_reverify_required": True,
            "verified_at": finding.verified_at.isoformat() if getattr(finding, "verified_at", None) else None,
            "message": (
                f"Automated reverification is not supported for '{finding.tool_source}' findings. "
                f"Re-run '{finding.tool_source}' or verify manually to avoid false remediation."
            ),
        }

    scope_row = (
        await db.execute(
            select(ScopePolicyModel).where(ScopePolicyModel.engagement_id == finding.engagement_id)
        )
    ).scalar_one_or_none()
    if not scope_row:
        raise HTTPException(status_code=400, detail="Scope policy not found.")
    scope = ScopePolicy.from_orm(scope_row)

    adapter = HttpProbeAdapter()
    mode = "passive_audit"
    tl = finding.title.lower()
    if "graphql" in tl:
        mode = "graphql_deep_audit"
    elif "oauth" in tl:
        mode = "oauth_audit"
    elif "redirect" in tl:
        mode = "open_redirect_probe"
    elif "bola" in tl or "authorization" in tl:
        mode = "differential_bola"
    elif "verb tampering" in tl or "bfla" in tl:
        mode = "bfla_verb_tamper"
    elif "race" in tl or "concurrency" in tl:
        mode = "race_burst_probe"
    elif "ssti" in tl or "template injection" in tl:
        mode = "ssti_probe"
    elif "jwt" in tl and ("bypass" in tl or "weak" in tl or "alg" in tl):
        mode = "jwt_active_probe"
    elif "hpp" in tl or "content-type" in tl:
        mode = "hpp_and_content_switch"

    try:
        norm_url = await scope.validate_target_async(finding.target_url)
    except ScopeViolationError as exc:
        raise HTTPException(status_code=403, detail=f"Scope blocked reverification: {exc}")

    res = await adapter.execute(
        engagement_id=finding.engagement_id,
        tool_run_id=f"reverify-{finding.id}",
        target=norm_url,
        raw_args={"mode": mode, "param": finding.parameter},
        scope=scope,
    )
    still_present = any(
        (finding.cwe_id and nf.cwe_id == finding.cwe_id)
        or nf.title.lower().split("(")[0].strip() == finding.title.lower().split("(")[0].strip()
        for nf in res.findings
    )
    finding.verified_at = datetime.now(timezone.utc)
    finding.status = "confirmed" if still_present else "remediated"
    await db.commit()
    return {
        "id": finding.id,
        "finding_id": finding.id,
        "status": finding.status,
        "still_present": still_present,
        "manual_reverify_required": False,
        "verified_at": finding.verified_at.isoformat(),
        "message": (
            "Finding is still reproducible."
            if still_present
            else "Finding was not reproduced and has been marked remediated."
        ),
    }


@router.post("/engagements/{engagement_id}/findings", status_code=201)
async def create_manual_finding(
    engagement_id: str,
    body: FindingCreateInput,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    eng = await db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found.")
    fp = fingerprint_finding("repeater", body.title, body.target_url, body.parameter)
    finding = Finding(
        engagement_id=engagement_id,
        title=body.title,
        severity=body.severity,
        status="confirmed",
        cvss_score=body.cvss_score,
        cwe_id=body.cwe_id,
        owasp_category=body.owasp_category,
        target_url=body.target_url,
        parameter=body.parameter,
        description=body.description,
        evidence=body.evidence,
        poc_command=body.poc_command,
        remediation=body.remediation,
        tool_source="repeater",
        fingerprint=fp,
    )
    db.add(finding)
    await db.commit()
    await db.refresh(finding)
    return {"id": finding.id, "title": finding.title, "severity": finding.severity}


@router.patch("/hypotheses/{hypothesis_id}")
async def update_hypothesis(
    hypothesis_id: str,
    body: HypothesisUpdateInput,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    hyp = await db.get(Hypothesis, hypothesis_id)
    if not hyp:
        raise HTTPException(status_code=404, detail="Hypothesis not found.")
    hyp.status = body.status
    if body.evidence_note is not None:
        hyp.evidence_note = body.evidence_note
    await db.commit()
    await db.refresh(hyp)
    return {"id": hyp.id, "status": hyp.status, "evidence_note": hyp.evidence_note}
