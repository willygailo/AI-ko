"""Engagement lifecycle, attack-surface inspection, and manual tool run routes."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import time

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.orchestrator import orchestrator_manager
from app.api.schemas import EngagementCreate, ManualToolRunInput, RepeaterRequestInput
from app.config import get_settings
from app.core.auth import require_api_token
from app.core.events import event_bus
from app.core.policy import approval_coordinator
from app.core.ratelimit import rate_limiters
from app.core.scope import ScopePolicy, ScopeViolationError
from app.core.vault import encrypt_dict
from app.db.database import get_db
from app.db.models import (
    AgentEvent,
    ApprovalRequest,
    Asset,
    Endpoint,
    Engagement,
    Finding,
    Hypothesis,
    ScanSnapshot,
    ScopePolicyModel,
    ToolRun,
)
from app.db.persistence import persist_tool_result
from app.db.snapshots import capture_snapshot, compute_snapshot_diff
from app.tools.http_probe import HttpProbeAdapter
from app.tools.registry import tool_registry

router = APIRouter(
    prefix="/api/v1/engagements",
    tags=["engagements"],
    dependencies=[Depends(require_api_token)],
)


def _serialize_engagement(e: Engagement, scope: ScopePolicyModel | None = None) -> dict[str, object]:
    out: dict[str, object] = {
        "id": e.id,
        "name": e.name,
        "description": e.description,
        "objective": e.objective,
        "status": e.status,
        "autonomy_mode": e.autonomy_mode,
        "tier2_auto": e.tier2_auto,
        "max_steps": e.max_steps,
        "current_step": e.current_step,
        "llm_profile_id": e.llm_profile_id,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "updated_at": e.updated_at.isoformat() if e.updated_at else None,
    }
    if scope is not None:
        out["scope"] = {
            "allowed_domains": scope.allowed_domains,
            "allowed_urls": scope.allowed_urls,
            "allowed_cidrs": scope.allowed_cidrs,
            "excluded_hosts": scope.excluded_hosts,
            "excluded_paths": scope.excluded_paths,
            "max_rps": scope.max_rps,
            "max_concurrency": scope.max_concurrency,
            "custom_headers": {k: "***" for k in (scope.custom_headers or {}).keys()},
            "custom_header_keys": sorted((scope.custom_headers or {}).keys()),
            "auth_cookies_keys": sorted((scope.auth_cookies or {}).keys()),
            "allow_private_ips": scope.allow_private_ips,
        }
    return out


@router.get("")
async def list_engagements(db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    rows = (
        await db.execute(select(Engagement).order_by(Engagement.created_at.desc()))
    ).scalars().all()
    items = []
    for e in rows:
        scope = (
            await db.execute(
                select(ScopePolicyModel).where(ScopePolicyModel.engagement_id == e.id)
            )
        ).scalar_one_or_none()
        items.append(_serialize_engagement(e, scope))
    return {"engagements": items}


@router.post("", status_code=201)
async def create_engagement(body: EngagementCreate, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    # Validate scope policy immediately on creation
    try:
        ScopePolicy(
            allowed_domains=body.scope.allowed_domains,
            allowed_urls=body.scope.allowed_urls,
            allowed_cidrs=body.scope.allowed_cidrs,
            excluded_hosts=body.scope.excluded_hosts,
            excluded_paths=body.scope.excluded_paths,
            max_rps=body.scope.max_rps,
            max_concurrency=body.scope.max_concurrency,
            custom_headers=body.scope.custom_headers,
            auth_cookies=body.scope.auth_cookies,
            allow_private_ips=body.scope.allow_private_ips,
        )
    except ScopeViolationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not (body.scope.allowed_domains or body.scope.allowed_urls or body.scope.allowed_cidrs):
        raise HTTPException(
            status_code=400,
            detail="Scope must include at least one allowlisted domain, URL, or CIDR.",
        )

    eng = Engagement(
        name=body.name,
        description=body.description,
        objective=body.objective,
        autonomy_mode=body.autonomy_mode,
        tier2_auto=body.tier2_auto,
        max_steps=body.max_steps,
        llm_profile_id=body.llm_profile_id,
    )
    db.add(eng)
    await db.flush()

    scope = ScopePolicyModel(
        engagement_id=eng.id,
        allowed_domains=body.scope.allowed_domains,
        allowed_urls=body.scope.allowed_urls,
        allowed_cidrs=body.scope.allowed_cidrs,
        excluded_hosts=body.scope.excluded_hosts,
        excluded_paths=body.scope.excluded_paths,
        max_rps=body.scope.max_rps,
        max_concurrency=body.scope.max_concurrency,
        custom_headers=encrypt_dict(body.scope.custom_headers),
        auth_cookies=encrypt_dict(body.scope.auth_cookies),
        allow_private_ips=body.scope.allow_private_ips,
    )
    db.add(scope)
    await db.commit()
    await db.refresh(eng)
    await db.refresh(scope)
    return _serialize_engagement(eng, scope)


@router.get("/{engagement_id}")
async def get_engagement(engagement_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    eng = await db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found.")

    scope = (
        await db.execute(select(ScopePolicyModel).where(ScopePolicyModel.engagement_id == engagement_id))
    ).scalar_one_or_none()
    assets = (
        await db.execute(select(Asset).where(Asset.engagement_id == engagement_id))
    ).scalars().all()
    endpoints = (
        await db.execute(select(Endpoint).where(Endpoint.engagement_id == engagement_id).limit(300))
    ).scalars().all()
    runs = (
        await db.execute(
            select(ToolRun)
            .where(ToolRun.engagement_id == engagement_id)
            .order_by(ToolRun.created_at.desc())
            .limit(100)
        )
    ).scalars().all()
    approvals = (
        await db.execute(
            select(ApprovalRequest)
            .where(ApprovalRequest.engagement_id == engagement_id)
            .order_by(ApprovalRequest.created_at.desc())
        )
    ).scalars().all()
    findings = (
        await db.execute(
            select(Finding)
            .where(Finding.engagement_id == engagement_id)
            .order_by(Finding.created_at.desc())
        )
    ).scalars().all()
    events = (
        await db.execute(
            select(AgentEvent)
            .where(AgentEvent.engagement_id == engagement_id)
            .order_by(AgentEvent.id.desc())
            .limit(100)
        )
    ).scalars().all()
    hypotheses = (
        await db.execute(
            select(Hypothesis)
            .where(Hypothesis.engagement_id == engagement_id)
            .order_by(Hypothesis.updated_at.desc())
        )
    ).scalars().all()
    snapshots = (
        await db.execute(
            select(ScanSnapshot)
            .where(ScanSnapshot.engagement_id == engagement_id)
            .order_by(ScanSnapshot.created_at.asc())
        )
    ).scalars().all()

    return {
        **_serialize_engagement(eng, scope),
        "assets": [
            {
                "id": a.id,
                "asset_type": a.asset_type,
                "value": a.value,
                "ip_address": a.ip_address,
                "status_code": a.status_code,
                "title": a.title,
                "waf": a.waf,
                "technologies": a.technologies,
                "discovered_by": a.discovered_by,
            }
            for a in assets
        ],
        "endpoints": [
            {
                "id": ep.id,
                "method": ep.method,
                "url": ep.url,
                "path": ep.path,
                "query_params": ep.query_params,
                "body_params": ep.body_params,
                "status_code": ep.status_code,
                "source": ep.source,
            }
            for ep in endpoints
        ],
        "tool_runs": [
            {
                "id": r.id,
                "tool_name": r.tool_name,
                "tier": r.tier,
                "target": r.target,
                "args": r.args,
                "argv": r.argv,
                "status": r.status,
                "exit_code": r.exit_code,
                "duration_ms": r.duration_ms,
                "summary": r.summary,
                "error_message": r.error_message,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in runs
        ],
        "approvals": [
            {
                "id": ap.id,
                "tool_run_id": ap.tool_run_id,
                "tool_name": ap.tool_name,
                "tier": ap.tier,
                "target": ap.target,
                "proposed_args": ap.proposed_args,
                "argv_preview": ap.argv_preview,
                "rationale": ap.rationale,
                "risk_summary": ap.risk_summary,
                "status": ap.status,
                "modified_args": ap.modified_args,
                "operator_note": ap.operator_note,
                "created_at": ap.created_at.isoformat() if ap.created_at else None,
            }
            for ap in approvals
        ],
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
            for f in findings
        ],
        "events": [
            {
                "id": ev.id,
                "event_type": ev.event_type,
                "agent_name": ev.agent_name,
                "message": ev.message,
                "payload": ev.payload,
                "created_at": ev.created_at.isoformat() if ev.created_at else None,
            }
            for ev in reversed(events)
        ],
        "hypotheses": [
            {
                "id": h.id,
                "title": h.title,
                "target_url": h.target_url,
                "parameter": h.parameter,
                "cwe_id": h.cwe_id,
                "confidence": h.confidence,
                "status": h.status,
                "rationale": h.rationale,
                "evidence_note": h.evidence_note,
                "updated_at": h.updated_at.isoformat() if h.updated_at else None,
            }
            for h in hypotheses
        ],
        "snapshots": [
            {
                "id": s.id,
                "label": s.label,
                "assets_count": s.assets_count,
                "endpoints_count": s.endpoints_count,
                "findings_count": s.findings_count,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in snapshots
        ],
    }


@router.delete("/{engagement_id}")
async def delete_engagement(engagement_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    eng = await db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found.")
    await orchestrator_manager.stop(engagement_id)
    await db.delete(eng)
    await db.commit()
    return {"deleted": engagement_id}


@router.post("/{engagement_id}/start")
async def start_engagement(engagement_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    eng = await db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found.")
    await orchestrator_manager.start(engagement_id)
    return {"engagement_id": engagement_id, "status": "running"}


@router.post("/{engagement_id}/pause")
async def pause_engagement(engagement_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    eng = await db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found.")
    await orchestrator_manager.pause(engagement_id)
    return {"engagement_id": engagement_id, "status": "paused"}


@router.post("/{engagement_id}/resume")
async def resume_engagement(engagement_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    eng = await db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found.")
    await orchestrator_manager.resume(engagement_id)
    return {"engagement_id": engagement_id, "status": "running"}


@router.post("/{engagement_id}/stop")
async def stop_engagement(engagement_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    eng = await db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found.")
    await orchestrator_manager.stop(engagement_id)
    return {"engagement_id": engagement_id, "status": "stopped"}


@router.post("/{engagement_id}/run-tool")
async def run_tool_manually(
    engagement_id: str,
    body: ManualToolRunInput,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    eng = await db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found.")
    scope_row = (
        await db.execute(select(ScopePolicyModel).where(ScopePolicyModel.engagement_id == engagement_id))
    ).scalar_one_or_none()
    if not scope_row:
        raise HTTPException(status_code=400, detail="Scope policy not found.")
    scope = ScopePolicy.from_orm(scope_row)

    try:
        adapter = tool_registry.get(body.tool_name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {body.tool_name}")

    try:
        validated_args = adapter.validate_args(body.args)
        norm_target = adapter.validate_scope(body.target, validated_args, scope)
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Policy/Scope blocked execution: {exc}")

    tier = adapter.effective_tier(validated_args)
    run = ToolRun(
        engagement_id=engagement_id,
        tool_name=adapter.name,
        tier=tier,
        target=norm_target,
        args=validated_args.model_dump(),
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    result = await adapter.execute(
        engagement_id=engagement_id,
        tool_run_id=run.id,
        target=norm_target,
        raw_args=validated_args.model_dump(),
        scope=scope,
    )

    run.status = "completed" if result.exit_code == 0 or result.findings or result.assets or result.endpoints else "failed"
    run.exit_code = result.exit_code
    run.duration_ms = result.duration_ms
    run.raw_log_path = result.raw_log_path
    run.summary = result.summary
    run.error_message = result.error
    run.completed_at = datetime.now(timezone.utc)

    new_findings = await persist_tool_result(db, engagement_id, result)

    await db.commit()
    await event_bus.publish(
        engagement_id=engagement_id,
        event_type="manual_tool_completed",
        agent_name="operator",
        message=f"Manual `{adapter.name}` finished ({result.duration_ms}ms, +{len(result.endpoints)} endpoints, +{new_findings} findings).",
        payload={"tool_run_id": run.id, "summary": result.summary},
    )
    return {
        "tool_run_id": run.id,
        "status": run.status,
        "duration_ms": result.duration_ms,
        "summary": result.summary,
    }


@router.get("/{engagement_id}/runs/{run_id}/log")
async def get_run_log(
    engagement_id: str,
    run_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    run = await db.get(ToolRun, run_id)
    if not run or run.engagement_id != engagement_id:
        raise HTTPException(status_code=404, detail="Tool run not found.")
    if not run.raw_log_path:
        return {"log": ""}
    p = Path(run.raw_log_path)
    if not p.is_file():
        return {"log": ""}
    return {"log": p.read_text(encoding="utf-8", errors="replace")[:200000]}


@router.get("/{engagement_id}/hypotheses")
async def list_hypotheses(engagement_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    rows = (
        await db.execute(
            select(Hypothesis)
            .where(Hypothesis.engagement_id == engagement_id)
            .order_by(Hypothesis.updated_at.desc())
        )
    ).scalars().all()
    return {
        "hypotheses": [
            {
                "id": h.id,
                "title": h.title,
                "target_url": h.target_url,
                "parameter": h.parameter,
                "cwe_id": h.cwe_id,
                "confidence": h.confidence,
                "status": h.status,
                "rationale": h.rationale,
                "evidence_note": h.evidence_note,
                "updated_at": h.updated_at.isoformat() if h.updated_at else None,
            }
            for h in rows
        ]
    }


@router.post("/{engagement_id}/snapshots", status_code=201)
async def create_snapshot(
    engagement_id: str,
    label: str = Query(default="manual-snapshot"),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    eng = await db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found.")
    snap = await capture_snapshot(db, engagement_id, label=label)
    await db.commit()
    return {
        "id": snap.id,
        "label": snap.label,
        "assets_count": snap.assets_count,
        "endpoints_count": snap.endpoints_count,
        "findings_count": snap.findings_count,
    }


@router.get("/{engagement_id}/diff")
async def get_scan_diff(
    engagement_id: str,
    base: str | None = None,
    target: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    snaps = (
        await db.execute(
            select(ScanSnapshot)
            .where(ScanSnapshot.engagement_id == engagement_id)
            .order_by(ScanSnapshot.created_at.asc())
        )
    ).scalars().all()
    if len(snaps) < 2:
        return {"has_diff": False, "snapshots_count": len(snaps)}
    base_snap = next((s for s in snaps if s.id == base), snaps[0]) if base else snaps[0]
    tgt_snap = next((s for s in snaps if s.id == target), snaps[-1]) if target else snaps[-1]
    return {"has_diff": True, "snapshots_count": len(snaps), **compute_snapshot_diff(base_snap, tgt_snap)}


@router.post("/{engagement_id}/repeater")
async def run_repeater(
    engagement_id: str,
    body: RepeaterRequestInput,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    eng = await db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found.")
    scope_row = (
        await db.execute(select(ScopePolicyModel).where(ScopePolicyModel.engagement_id == engagement_id))
    ).scalar_one_or_none()
    if not scope_row:
        raise HTTPException(status_code=400, detail="Scope policy not found.")
    scope = ScopePolicy.from_orm(scope_row)

    try:
        norm_url = scope.validate_target(body.url)
    except ScopeViolationError as exc:
        raise HTTPException(status_code=403, detail=f"Scope blocked repeater target: {exc}")

    merged_headers: dict[str, str] = {"User-Agent": "AegisPT-Repeater/0.1"}
    if body.use_engagement_auth:
        merged_headers.update(scope.custom_headers)
    merged_headers.update(body.headers)
    cookies = dict(scope.auth_cookies) if body.use_engagement_auth else {}

    limiter = rate_limiters.get(engagement_id, scope.max_rps)
    is_local = (urlparse(norm_url).hostname or "").lower() in {"127.0.0.1", "localhost", "::1"}
    adapter = HttpProbeAdapter()
    start = time.monotonic()

    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=float(body.timeout_seconds),
            trust_env=not is_local,
        ) as client:
            resp = await adapter._safe_request(
                client,
                body.method,
                norm_url,
                scope=scope,
                limiter=limiter,
                headers=merged_headers,
                content=body.body,
                cookies=cookies,
                follow_redirects=body.follow_redirects,
            )
    except ScopeViolationError as exc:
        raise HTTPException(status_code=403, detail=f"Scope blocked redirect target: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Repeater request failed: {exc}")

    elapsed_ms = int((time.monotonic() - start) * 1000)
    curl_parts = [f"curl -i -s -X {body.method}"]
    for hk, hv in body.headers.items():
        curl_parts.append(f"-H '{hk}: {hv}'")
    if body.body:
        curl_parts.append(f"--data '{body.body[:500]}'")
    curl_parts.append(f"'{norm_url}'")

    return {
        "status_code": resp.status_code,
        "final_url": str(resp.url),
        "duration_ms": elapsed_ms,
        "headers": dict(resp.headers),
        "body": resp.text[:50000],
        "curl_command": " ".join(curl_parts),
    }
