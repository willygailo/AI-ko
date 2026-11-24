"""Tiered Autonomy Policy & Human-in-the-Loop Approval Coordinator tests."""
from __future__ import annotations

import asyncio
from pathlib import Path

from app.config import get_settings
from app.core.policy import ApprovalCoordinator
from app.db.database import close_db, init_db, session_scope
from app.db.models import ApprovalRequest, Engagement, ToolRun
from app.tools.http_probe import HttpProbeAdapter, HttpProbeArgs
from app.tools.nuclei import NucleiAdapter, NucleiArgs


def test_requires_approval_matrix():
    assert ApprovalCoordinator.requires_approval("tiered", tier=1, tier2_auto=True) is False
    assert ApprovalCoordinator.requires_approval("tiered", tier=2, tier2_auto=True) is False
    assert ApprovalCoordinator.requires_approval("tiered", tier=2, tier2_auto=False) is True
    assert ApprovalCoordinator.requires_approval("tiered", tier=3, tier2_auto=True) is True

    assert ApprovalCoordinator.requires_approval("copilot", tier=1) is True
    assert ApprovalCoordinator.requires_approval("lab_autopilot", tier=3) is False


def test_effective_tier_splits_safe_vs_intrusive_modes():
    nuclei = NucleiAdapter()
    assert nuclei.effective_tier(NucleiArgs(tags=["misconfig"], include_intrusive=False)) == 2
    assert nuclei.effective_tier(NucleiArgs(tags=["misconfig"], include_intrusive=True)) == 3
    assert nuclei.effective_tier(NucleiArgs(tags=["fuzz"], include_intrusive=False)) == 3

    probe = HttpProbeAdapter()
    assert probe.effective_tier(HttpProbeArgs(mode="passive_audit", method="GET")) == 1
    assert probe.effective_tier(HttpProbeArgs(mode="replay_request", method="POST")) == 3


def test_approval_coordinator_pause_and_resume_flow(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    get_settings.cache_clear()

    async def _scenario():
        await init_db(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
        coord = ApprovalCoordinator()

        async with session_scope() as session:
            eng = Engagement(id="eng1", name="Test", status="running")
            session.add(eng)
            await session.flush()
            run = ToolRun(
                id="run1",
                engagement_id="eng1",
                tool_name="sqlmap",
                tier=3,
                target="http://127.0.0.1:3000/rest/products/search?q=a",
            )
            session.add(run)

        wait_task = asyncio.create_task(
            coord.request_and_wait(
                engagement_id="eng1",
                tool_run_id="run1",
                tool_name="sqlmap",
                tier=3,
                target="http://127.0.0.1:3000/rest/products/search?q=a",
                proposed_args={"param": "q", "level": 1, "risk": 1},
                argv_preview=["sqlmap", "-u", "http://127.0.0.1:3000/rest/products/search?q=a"],
                rationale="Verify potential SQLi",
                risk_summary="Tier 3 active test",
            )
        )

        # Wait until ApprovalRequest is persisted
        approval_id = None
        for _ in range(30):
            await asyncio.sleep(0.05)
            async with session_scope() as session:
                from sqlalchemy import select

                row = (
                    await session.execute(
                        select(ApprovalRequest).where(ApprovalRequest.engagement_id == "eng1")
                    )
                ).scalar_one_or_none()
                if row:
                    approval_id = row.id
                    break
        assert approval_id is not None

        await coord.resolve(
            approval_id=approval_id,
            decision="modified",
            modified_args={"param": "q", "level": 2, "risk": 1},
            operator_note="Approved with level 2",
        )
        decision = await wait_task
        assert decision.status == "modified"
        assert decision.args["level"] == 2
        await close_db()

    asyncio.run(_scenario())
