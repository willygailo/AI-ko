"""Tier 2/3 Approval Queue REST routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ApprovalDecisionInput
from app.core.auth import require_api_token
from app.core.policy import approval_coordinator
from app.core.scope import ScopePolicy, ScopeViolationError
from app.db.database import get_db
from app.db.models import ApprovalRequest, ScopePolicyModel
from app.tools.registry import tool_registry

router = APIRouter(
    prefix="/api/v1",
    tags=["approvals"],
    dependencies=[Depends(require_api_token)],
)


@router.get("/engagements/{engagement_id}/approvals")
async def list_approvals(
    engagement_id: str,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    stmt = select(ApprovalRequest).where(ApprovalRequest.engagement_id == engagement_id)
    if status:
        stmt = stmt.where(ApprovalRequest.status == status)
    rows = (await db.execute(stmt.order_by(ApprovalRequest.created_at.desc()))).scalars().all()
    return {
        "approvals": [
            {
                "id": a.id,
                "tool_run_id": a.tool_run_id,
                "tool_name": a.tool_name,
                "tier": a.tier,
                "target": a.target,
                "proposed_args": a.proposed_args,
                "argv_preview": a.argv_preview,
                "rationale": a.rationale,
                "risk_summary": a.risk_summary,
                "status": a.status,
                "modified_args": a.modified_args,
                "operator_note": a.operator_note,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "decided_at": a.decided_at.isoformat() if a.decided_at else None,
            }
            for a in rows
        ]
    }


@router.post("/approvals/{approval_id}/decide")
async def decide_approval(
    approval_id: str,
    body: ApprovalDecisionInput,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    existing = await db.get(ApprovalRequest, approval_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Approval request not found.")
    if existing.status != "pending":
        raise HTTPException(status_code=409, detail=f"Approval already resolved ({existing.status}).")

    validated_modified_args = body.modified_args
    if body.decision == "modified":
        if body.modified_args is None:
            raise HTTPException(
                status_code=400,
                detail="modified_args must be provided when decision is 'modified'.",
            )
        try:
            adapter = tool_registry.get(existing.tool_name)
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Unknown tool: {existing.tool_name}")

        scope_row = (
            await db.execute(
                select(ScopePolicyModel).where(
                    ScopePolicyModel.engagement_id == existing.engagement_id
                )
            )
        ).scalar_one_or_none()
        if not scope_row:
            raise HTTPException(status_code=400, detail="Scope policy not found for engagement.")
        scope = ScopePolicy.from_orm(scope_row)

        try:
            parsed_args = adapter.validate_args(body.modified_args)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid modified_args: {exc}")

        try:
            adapter.validate_scope(existing.target, parsed_args, scope)
        except ScopeViolationError as exc:
            raise HTTPException(status_code=403, detail=f"Scope blocked modified_args: {exc}")

        validated_modified_args = parsed_args.model_dump()

    updated = await approval_coordinator.resolve(
        approval_id=approval_id,
        decision=body.decision,
        modified_args=validated_modified_args,
        operator_note=body.operator_note,
    )
    return {
        "id": approval_id,
        "status": updated.status if updated else body.decision,
    }
