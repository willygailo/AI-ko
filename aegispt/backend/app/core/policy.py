"""3-Tier Autonomy Policy Engine and interactive Human-in-the-Loop Approval Coordinator."""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from app.config import get_settings
from app.core.events import event_bus
from app.db.database import session_scope
from app.db.models import ApprovalRequest, Engagement, ToolRun


@dataclass
class ApprovalDecision:
    status: str  # approved | modified | rejected | expired
    args: dict[str, Any]
    operator_note: str | None = None


class ApprovalCoordinator:
    """Manages pending Tier 2/3 operator approvals with async wait/notify."""

    def __init__(self) -> None:
        self._waiters: dict[str, asyncio.Event] = {}
        self._decisions: dict[str, ApprovalDecision] = {}

    @staticmethod
    def requires_approval(
        autonomy_mode: str, tier: int, tier2_auto: bool = True
    ) -> bool:
        if autonomy_mode == "copilot":
            return True
        if autonomy_mode == "lab_autopilot":
            return False
        # Default: tiered autonomy
        if tier <= 1:
            return False
        if tier == 2:
            return not tier2_auto
        return True  # Tier 3 ALWAYS requires explicit operator approval

    async def request_and_wait(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        tool_name: str,
        tier: int,
        target: str,
        proposed_args: dict[str, Any],
        argv_preview: list[str],
        rationale: str,
        risk_summary: str,
        timeout_seconds: int | None = None,
    ) -> ApprovalDecision:
        timeout = timeout_seconds or get_settings().approval_timeout_seconds
        approval_id = uuid.uuid4().hex[:16]
        waiter = asyncio.Event()
        # Register waiter BEFORE committing to DB to eliminate the fast-resolve hang race.
        self._waiters[approval_id] = waiter

        try:
            async with session_scope() as session:
                req = ApprovalRequest(
                    id=approval_id,
                    engagement_id=engagement_id,
                    tool_run_id=tool_run_id,
                    tool_name=tool_name,
                    tier=tier,
                    target=target,
                    proposed_args=proposed_args,
                    argv_preview=argv_preview,
                    rationale=rationale,
                    risk_summary=risk_summary,
                    status="pending",
                )
                session.add(req)

                run = await session.get(ToolRun, tool_run_id)
                if run:
                    run.status = "awaiting_approval"

                eng = await session.get(Engagement, engagement_id)
                if eng and eng.status == "running":
                    eng.status = "awaiting_approval"

                await session.flush()

            await event_bus.publish(
                engagement_id=engagement_id,
                event_type="approval_required",
                agent_name="policy",
                message=f"Approval required for Tier {tier} tool `{tool_name}` against {target}",
                payload={
                    "approval_id": approval_id,
                    "tool_run_id": tool_run_id,
                    "tool_name": tool_name,
                    "tier": tier,
                    "target": target,
                    "proposed_args": proposed_args,
                    "argv_preview": argv_preview,
                    "rationale": rationale,
                    "risk_summary": risk_summary,
                },
            )

            await asyncio.wait_for(waiter.wait(), timeout=timeout)
            decision = self._decisions.pop(approval_id, None)
            if decision is None:
                # Fallback: read from DB
                async with session_scope() as session:
                    req = await session.get(ApprovalRequest, approval_id)
                    if req:
                        decision = ApprovalDecision(
                            status=req.status,
                            args=req.modified_args or req.proposed_args,
                            operator_note=req.operator_note,
                        )
                    else:
                        decision = ApprovalDecision(status="rejected", args=proposed_args)
            return decision
        except asyncio.TimeoutError:
            await self.resolve(
                approval_id=approval_id,
                decision="expired",
                operator_note="Approval request timed out.",
            )
            return ApprovalDecision(
                status="expired",
                args=proposed_args,
                operator_note="Approval request timed out.",
            )
        finally:
            self._waiters.pop(approval_id, None)
            self._decisions.pop(approval_id, None)

    async def resolve(
        self,
        *,
        approval_id: str,
        decision: str,  # approved | modified | rejected | expired
        modified_args: dict[str, Any] | None = None,
        operator_note: str | None = None,
        restore_running: bool = True,
    ) -> ApprovalRequest | None:
        now = datetime.now(timezone.utc)
        async with session_scope() as session:
            req = await session.get(ApprovalRequest, approval_id)
            if not req or req.status != "pending":
                return req

            req.status = decision
            req.operator_note = operator_note
            req.decided_at = now
            if decision == "modified" and modified_args is not None:
                req.modified_args = modified_args

            effective_args = (
                modified_args if (decision == "modified" and modified_args is not None) else req.proposed_args
            )

            run = await session.get(ToolRun, req.tool_run_id)
            if run:
                if decision in ("approved", "modified"):
                    run.status = "queued"
                    run.args = effective_args
                else:
                    run.status = "rejected"
                    run.error_message = operator_note or f"Action {decision} by operator."

            eng = await session.get(Engagement, req.engagement_id)
            if restore_running and eng and eng.status == "awaiting_approval":
                # Check if any other pending approvals exist
                others = (
                    await session.execute(
                        select(ApprovalRequest).where(
                            ApprovalRequest.engagement_id == req.engagement_id,
                            ApprovalRequest.status == "pending",
                            ApprovalRequest.id != approval_id,
                        )
                    )
                ).scalars().all()
                if not others:
                    eng.status = "running"

            engagement_id = req.engagement_id
            tool_name = req.tool_name

        self._decisions[approval_id] = ApprovalDecision(
            status=decision,
            args=effective_args,
            operator_note=operator_note,
        )
        waiter = self._waiters.get(approval_id)
        if waiter:
            waiter.set()

        await event_bus.publish(
            engagement_id=engagement_id,
            event_type="approval_resolved",
            agent_name="policy",
            message=f"Operator {decision} `{tool_name}` ({approval_id})",
            payload={
                "approval_id": approval_id,
                "decision": decision,
                "operator_note": operator_note,
            },
        )
        return req

    async def cancel_engagement_approvals(self, engagement_id: str) -> None:
        async with session_scope() as session:
            pending = (
                await session.execute(
                    select(ApprovalRequest).where(
                        ApprovalRequest.engagement_id == engagement_id,
                        ApprovalRequest.status == "pending",
                    )
                )
            ).scalars().all()
            ids = [p.id for p in pending]
        for aid in ids:
            await self.resolve(
                approval_id=aid,
                decision="rejected",
                operator_note="Engagement stopped by operator.",
                restore_running=False,
            )


approval_coordinator = ApprovalCoordinator()
