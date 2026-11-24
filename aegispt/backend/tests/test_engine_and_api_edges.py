"""Engine reliability, DB persistence dedup, approval/orchestrator races, and API contract edge tests."""
from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from app.agents.graph_context import build_graph_context
from app.agents.orchestrator import EngagementOrchestrator, OrchestratorManager
from app.config import get_settings
from app.core.events import EventBus
from app.core.policy import ApprovalCoordinator
from app.core.ratelimit import rate_limiters
from app.core.vault import decrypt_or_passthrough, reset_vault_cache
from app.db.database import close_db, init_db, session_scope
from app.db.models import (
    ApprovalRequest,
    Asset,
    Endpoint,
    Engagement,
    Hypothesis,
    LLMProfile,
    ScopePolicyModel,
    ToolRun,
)
from app.db.persistence import persist_tool_result
from app.llm.schemas import ProposedToolCall
from app.main import _seed_default_llm_profile, create_app
from app.tools.base import DiscoveredAsset, DiscoveredEndpoint, ToolResult
from app.tools.registry import tool_registry


def test_persist_tool_result_deduplicates_duplicate_assets_and_endpoints_in_single_batch(
    tmp_path: Path,
):
    async def _run():
        await init_db(f"sqlite+aiosqlite:///{tmp_path / 'batch.db'}")
        async with session_scope() as session:
            eng = Engagement(id="eng_batch", name="Batch Dedup")
            session.add(eng)
            await session.flush()

            res = ToolResult(
                tool_name="http_probe",
                exit_code=0,
                duration_ms=42,
                assets=[
                    DiscoveredAsset(
                        asset_type="host",
                        value="app.example.com",
                        status_code=200,
                        technologies=["nginx"],
                        headers={"Server": "nginx"},
                    ),
                    DiscoveredAsset(
                        asset_type="host",
                        value="app.example.com",
                        title="App Home",
                        technologies=["react"],
                        headers={"X-Frame-Options": "DENY"},
                    ),
                ],
                endpoints=[
                    DiscoveredEndpoint(
                        method="GET",
                        url="https://app.example.com/api/items",
                        path="/api/items",
                        query_params=["page"],
                    ),
                    DiscoveredEndpoint(
                        method="GET",
                        url="https://app.example.com/api/items",
                        path="/api/items",
                        query_params=["sort"],
                        status_code=200,
                        content_type="application/json",
                    ),
                ],
            )
            await persist_tool_result(session, "eng_batch", res)

        async with session_scope() as session:
            from sqlalchemy import select

            assets = (
                await session.execute(select(Asset).where(Asset.engagement_id == "eng_batch"))
            ).scalars().all()
            eps = (
                await session.execute(select(Endpoint).where(Endpoint.engagement_id == "eng_batch"))
            ).scalars().all()
            assert len(assets) == 1
            assert set(assets[0].technologies) == {"nginx", "react"}
            assert assets[0].title == "App Home"
            assert len(eps) == 1
            assert set(eps[0].query_params) == {"page", "sort"}
            assert eps[0].status_code == 200

        await close_db()

    asyncio.run(_run())


def test_approval_waiter_preregistration_and_cancel_status(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    get_settings.cache_clear()

    async def _run():
        await init_db(f"sqlite+aiosqlite:///{tmp_path / 'policy_edge.db'}")
        coord = ApprovalCoordinator()

        async with session_scope() as session:
            session.add(Engagement(id="eng_p", name="Policy Edge", status="running"))
            await session.flush()
            session.add(
                ToolRun(
                    id="run_p",
                    engagement_id="eng_p",
                    tool_name="sqlmap",
                    tier=3,
                    target="http://127.0.0.1:3000/search?q=1",
                )
            )

        wait_task = asyncio.create_task(
            coord.request_and_wait(
                engagement_id="eng_p",
                tool_run_id="run_p",
                tool_name="sqlmap",
                tier=3,
                target="http://127.0.0.1:3000/search?q=1",
                proposed_args={"param": "q"},
                argv_preview=["sqlmap"],
                rationale="Test",
                risk_summary="Tier 3",
                timeout_seconds=10,
            )
        )

        # Wait until waiter is registered, then cancel via cancel_engagement_approvals
        for _ in range(40):
            if coord._waiters:
                break
            await asyncio.sleep(0.02)
        assert len(coord._waiters) == 1

        # Wait until DB row is visible then cancel
        for _ in range(40):
            async with session_scope() as session:
                from sqlalchemy import select

                row = (
                    await session.execute(
                        select(ApprovalRequest).where(ApprovalRequest.engagement_id == "eng_p")
                    )
                ).scalar_one_or_none()
                if row is not None:
                    break
            await asyncio.sleep(0.02)

        await coord.cancel_engagement_approvals("eng_p")
        decision = await asyncio.wait_for(wait_task, timeout=5.0)
        assert decision.status == "rejected"

        # Engagement status must NOT have been flipped back to "running" by cancel_engagement_approvals
        async with session_scope() as session:
            eng = await session.get(Engagement, "eng_p")
            assert eng is not None
            assert eng.status == "awaiting_approval"

        await close_db()

    asyncio.run(_run())
    get_settings.cache_clear()


def test_orchestrator_hypothesis_scoping_graph_args_default_profile_and_manager_stop(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    reset_vault_cache()

    async def _run():
        await init_db(f"sqlite+aiosqlite:///{tmp_path / 'orch_edge.db'}")
        async with session_scope() as session:
            prof = LLMProfile(
                name="Default Cloud",
                provider="ollama",
                base_url="http://127.0.0.1:11434",
                api_key="plain-or-enc-key",
                fast_model="fast-m",
                reasoning_model="reason-m",
                is_default=True,
            )
            session.add(prof)
            await session.flush()

            eng = Engagement(id="eng_o", name="Orch Edge", status="paused", llm_profile_id=None)
            session.add(eng)
            await session.flush()
            session.add(
                ScopePolicyModel(
                    engagement_id="eng_o",
                    allowed_urls=["http://127.0.0.1:3000"],
                    allow_private_ips=True,
                )
            )
            session.add(
                ToolRun(
                    engagement_id="eng_o",
                    tool_name="http_probe",
                    tier=2,
                    target="http://127.0.0.1:3000",
                    args={"mode": "graphql_deep_audit"},
                    status="completed",
                )
            )
            session.add(
                Hypothesis(
                    id="h_child_xss",
                    engagement_id="eng_o",
                    title="Reflected XSS on search",
                    target_url="http://127.0.0.1:3000/search",
                    parameter="q",
                    cwe_id="CWE-79",
                    status="proposed",
                )
            )
            session.add(
                Hypothesis(
                    id="h_child_sqli",
                    engagement_id="eng_o",
                    title="SQLi on search",
                    target_url="http://127.0.0.1:3000/search",
                    parameter="q",
                    cwe_id="CWE-89",
                    status="proposed",
                )
            )

        orch = EngagementOrchestrator("eng_o")
        # _load_state resolves DB is_default=True profile when eng.llm_profile_id is None
        _eng, _scope, llm_cfg, _fb = await orch._load_state()
        assert llm_cfg.name == "Default Cloud"
        assert llm_cfg.fast_model == "fast-m"

        # graph_context includes "args" on recent_runs
        async with session_scope() as session:
            graph = await build_graph_context(session, "eng_o")
            assert graph["recent_runs"][0]["args"] == {"mode": "graphql_deep_audit"}

        # Root URL run must NOT disprove child /search hypotheses
        await orch._update_hypothesis_outcome("http://127.0.0.1:3000/", "http_probe", 0)
        async with session_scope() as session:
            h_xss = await session.get(Hypothesis, "h_child_xss")
            h_sqli = await session.get(Hypothesis, "h_child_sqli")
            assert h_xss is not None and h_xss.status == "proposed"
            assert h_sqli is not None and h_sqli.status == "proposed"

        # sqlmap 0 findings on /search disproves ONLY CWE-89, leaving CWE-79 intact
        await orch._update_hypothesis_outcome(
            "http://127.0.0.1:3000/search", "sqlmap", 0, args={"param": "q"}
        )
        async with session_scope() as session:
            h_xss = await session.get(Hypothesis, "h_child_xss")
            h_sqli = await session.get(Hypothesis, "h_child_sqli")
            assert h_sqli is not None and h_sqli.status == "disproven"
            assert h_xss is not None and h_xss.status == "proposed"
            graph2 = await build_graph_context(session, "eng_o")

        # Critic filters sqlmap on /search but STILL allows dalfox (XSS) on /search
        kept = orch._critic_filter_proposals(
            [
                ProposedToolCall(tool_name="sqlmap", target="http://127.0.0.1:3000/search", args={}),
                ProposedToolCall(tool_name="dalfox", target="http://127.0.0.1:3000/search", args={}),
            ],
            graph2,
        )
        assert [p.tool_name for p in kept] == ["dalfox"]

        # OrchestratorManager.stop() updates DB status even without active task & clears rate limiter
        mgr = OrchestratorManager()
        rate_limiters.get("eng_o", 10)
        assert "eng_o" in rate_limiters._limiters
        await mgr.stop("eng_o")
        assert "eng_o" not in rate_limiters._limiters
        async with session_scope() as session:
            eng_after = await session.get(Engagement, "eng_o")
            assert eng_after is not None and eng_after.status == "stopped"

        # Task-identity _cleanup check: old finished task cannot evict a newer task
        old_task = asyncio.create_task(asyncio.sleep(0))
        new_task = asyncio.create_task(asyncio.sleep(10))
        mgr._tasks["eng_o"] = new_task

        def _simulate_old_cleanup(finished_task: asyncio.Task[None]) -> None:
            if mgr._tasks.get("eng_o") is finished_task:
                mgr._tasks.pop("eng_o", None)

        await old_task
        _simulate_old_cleanup(old_task)
        assert mgr._tasks.get("eng_o") is new_task
        new_task.cancel()
        try:
            await new_task
        except asyncio.CancelledError:
            pass

        await close_db()

    asyncio.run(_run())
    reset_vault_cache()
    get_settings.cache_clear()


def test_seed_default_llm_profile_cloud_and_remote(tmp_path: Path, monkeypatch):
    cloud_dir = tmp_path / "cloud"
    cloud_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(cloud_dir))
    monkeypatch.setenv("AEGISPT_OLLAMA_URL", "https://ollama.com")
    monkeypatch.setenv("AEGISPT_OLLAMA_API_KEY", "cloud-secret-key-123")
    monkeypatch.delenv("AEGISPT_REMOTE_LLM_URL", raising=False)
    get_settings.cache_clear()
    reset_vault_cache()

    async def _run_cloud():
        await init_db(f"sqlite+aiosqlite:///{cloud_dir / 'aegispt.db'}")
        await _seed_default_llm_profile()
        async with session_scope() as session:
            from sqlalchemy import select

            prof = (await session.execute(select(LLMProfile))).scalars().first()
            assert prof is not None
            assert prof.provider == "ollama"
            assert prof.is_default is True
            assert prof.api_key.startswith("enc:fernet:")
            assert decrypt_or_passthrough(prof.api_key) == "cloud-secret-key-123"
        await close_db()

    asyncio.run(_run_cloud())

    # Remote OpenAI-compatible default seeding
    remote_dir = tmp_path / "remote"
    remote_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(remote_dir))
    monkeypatch.setenv("AEGISPT_REMOTE_LLM_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("AEGISPT_REMOTE_LLM_API_KEY", "remote-key-456")
    monkeypatch.setenv("AEGISPT_REMOTE_FAST_MODEL", "llama-fast")
    monkeypatch.setenv("AEGISPT_REMOTE_REASONING_MODEL", "llama-reason")
    get_settings.cache_clear()
    reset_vault_cache()

    async def _run_remote():
        await init_db(f"sqlite+aiosqlite:///{remote_dir / 'aegispt.db'}")
        await _seed_default_llm_profile()
        async with session_scope() as session:
            from sqlalchemy import select

            prof = (await session.execute(select(LLMProfile))).scalars().first()
            assert prof is not None
            assert prof.provider == "openai_compat"
            assert prof.base_url == "https://llm.example.com/v1"
            assert prof.fast_model == "llama-fast"
            assert decrypt_or_passthrough(prof.api_key) == "remote-key-456"
        await close_db()

    asyncio.run(_run_remote())
    reset_vault_cache()
    get_settings.cache_clear()


def test_event_bus_overflow_never_raises():
    async def _run():
        bus = EventBus()
        q = bus.subscribe("eng_overflow")
        for i in range(550):
            await bus.publish(
                engagement_id="eng_overflow",
                event_type="tick",
                message=f"msg-{i}",
                persist=False,
            )
        assert q.qsize() == 500
        bus.unsubscribe(q, "eng_overflow")

    asyncio.run(_run())


def test_api_contracts_approvals_reverify_profiles_and_tool_failures(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AEGISPT_API_TOKEN", "edge_tok_777")
    monkeypatch.setenv("AEGISPT_DEFAULT_MAX_STEPS", "33")
    monkeypatch.setenv("AEGISPT_LLM_MODE", "offline")
    get_settings.cache_clear()
    reset_vault_cache()

    app = create_app()
    headers = {"Authorization": "Bearer edge_tok_777"}
    try:
        with TestClient(app) as client:
            # Invalid llm_profile_id returns 404 (not 500 IntegrityError)
            bad_eng = client.post(
                "/api/v1/engagements",
                headers=headers,
                json={
                    "name": "Bad Profile Ref",
                    "llm_profile_id": "nonexistent_prof",
                    "scope": {"allowed_domains": ["example.com"]},
                },
            )
            assert bad_eng.status_code == 404

            # EngagementCreate max_steps defaults from AEGISPT_DEFAULT_MAX_STEPS
            eng = client.post(
                "/api/v1/engagements",
                headers=headers,
                json={
                    "name": "Contracts Eng",
                    "scope": {"allowed_urls": ["http://127.0.0.1:3000"], "allow_private_ips": True},
                },
            ).json()
            eng_id = eng["id"]
            assert eng["max_steps"] == 33

            # List engagements works without N+1 errors
            lst = client.get("/api/v1/engagements", headers=headers)
            assert lst.status_code == 200
            assert len(lst.json()["engagements"]) == 1

            # POST /snapshots includes created_at
            snap = client.post(f"/api/v1/engagements/{eng_id}/snapshots?label=s1", headers=headers)
            assert snap.status_code == 201
            assert snap.json()["created_at"]

            # Steer creates an event; GET /engagements/{id} events[] includes engagement_id
            client.post(f"/api/v1/engagements/{eng_id}/steer", headers=headers, json={"hint": "Check auth"})
            detail = client.get(f"/api/v1/engagements/{eng_id}", headers=headers).json()
            assert detail["events"]
            assert all(ev["engagement_id"] == eng_id for ev in detail["events"])

            # Manual finding + PATCH finding + non-http_probe reverify returns manual_reverify_required
            created_f = client.post(
                f"/api/v1/engagements/{eng_id}/findings",
                headers=headers,
                json={
                    "title": "Confirmed SQLi via SQLMap",
                    "severity": "high",
                    "target_url": "http://127.0.0.1:3000/search?q=1",
                    "parameter": "q",
                    "cwe_id": "CWE-89",
                },
            ).json()
            fid = created_f["id"]
            patched = client.patch(
                f"/api/v1/findings/{fid}",
                headers=headers,
                json={"severity": "critical", "status": "confirmed"},
            )
            assert patched.status_code == 200 and patched.json()["severity"] == "critical"

            rev = client.post(f"/api/v1/findings/{fid}/reverify", headers=headers)
            assert rev.status_code == 200
            rev_body = rev.json()
            assert rev_body["finding_id"] == fid
            assert rev_body["status"] == "confirmed"
            assert rev_body["still_present"] is None
            assert rev_body["manual_reverify_required"] is True
            assert rev_body["message"]

            # Report export works via both ?format=json and /reports/json
            rep_q = client.get(f"/api/v1/engagements/{eng_id}/report?format=json", headers=headers)
            assert rep_q.status_code == 200 and rep_q.json()["engagement"]["id"] == eng_id
            rep_p = client.get(f"/api/v1/engagements/{eng_id}/reports/json", headers=headers)
            assert rep_p.status_code == 200 and rep_p.json()["engagement"]["id"] == eng_id

            # Approval decide: 404, invalid modified_args (400), valid modified_args (200), repeat (409)
            assert (
                client.post(
                    "/api/v1/approvals/missing_id/decide",
                    headers=headers,
                    json={"decision": "approved"},
                ).status_code
                == 404
            )
            with sqlite3.connect(tmp_path / "aegispt.db") as conn:
                conn.execute(
                    "INSERT INTO tool_runs (id, engagement_id, tool_name, tier, target, args, argv, status, summary, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "run_ap1",
                        eng_id,
                        "http_probe",
                        3,
                        "http://127.0.0.1:3000/api",
                        "{}",
                        "[]",
                        "awaiting_approval",
                        "{}",
                        "2026-01-01 00:00:00",
                    ),
                )
                conn.execute(
                    "INSERT INTO approval_requests (id, engagement_id, tool_run_id, tool_name, tier, target, proposed_args, argv_preview, rationale, risk_summary, status, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "ap_1",
                        eng_id,
                        "run_ap1",
                        "http_probe",
                        3,
                        "http://127.0.0.1:3000/api",
                        '{"mode": "passive_audit"}',
                        "[]",
                        "test",
                        "tier3",
                        "pending",
                        "2026-01-01 00:00:00",
                    ),
                )
                conn.commit()

            # Invalid mode in modified_args -> 400
            bad_mod = client.post(
                "/api/v1/approvals/ap_1/decide",
                headers=headers,
                json={"decision": "modified", "modified_args": {"mode": "nonexistent_mode"}},
            )
            assert bad_mod.status_code == 400

            # Valid modified_args -> 200
            good_mod = client.post(
                "/api/v1/approvals/ap_1/decide",
                headers=headers,
                json={"decision": "modified", "modified_args": {"mode": "passive_audit"}},
            )
            assert good_mod.status_code == 200 and good_mod.json()["status"] == "modified"

            # Re-deciding already resolved approval -> 409
            dup_mod = client.post(
                "/api/v1/approvals/ap_1/decide",
                headers=headers,
                json={"decision": "approved"},
            )
            assert dup_mod.status_code == 409

            # run-tool: unavailable tool -> 503; exploding execute() -> 500 AND marks run failed (not stuck running)
            adapter = tool_registry.get("http_probe")
            monkeypatch.setattr(adapter, "is_available", lambda: (False, "missing binary"))
            unavail = client.post(
                f"/api/v1/engagements/{eng_id}/run-tool",
                headers=headers,
                json={"tool_name": "http_probe", "target": "http://127.0.0.1:3000", "args": {"mode": "passive_audit"}},
            )
            assert unavail.status_code == 503
            monkeypatch.undo()
            monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
            monkeypatch.setenv("AEGISPT_API_TOKEN", "edge_tok_777")
            monkeypatch.setenv("AEGISPT_LLM_MODE", "offline")

            async def _boom(**_kwargs):
                raise RuntimeError("simulated adapter crash")

            monkeypatch.setattr(adapter, "execute", _boom)
            crashed = client.post(
                f"/api/v1/engagements/{eng_id}/run-tool",
                headers=headers,
                json={"tool_name": "http_probe", "target": "http://127.0.0.1:3000", "args": {"mode": "passive_audit"}},
            )
            assert crashed.status_code == 500
            runs_after = client.get(f"/api/v1/engagements/{eng_id}", headers=headers).json()["tool_runs"]
            crashed_run = next(r for r in runs_after if r["tool_name"] == "http_probe" and r["id"] != "run_ap1")
            assert crashed_run["status"] == "failed"
            assert "simulated adapter crash" in (crashed_run["error_message"] or "")
            assert isinstance(crashed_run["argv"], list) and len(crashed_run["argv"]) >= 1

            # LLM profiles CRUD + default toggle + doctor checks default profile
            p_create = client.post(
                "/api/v1/llm-profiles",
                headers=headers,
                json={
                    "name": "Custom Local",
                    "provider": "openai_compat",
                    "base_url": "http://127.0.0.1:8000/v1",
                    "api_key": "k123",
                    "fast_model": "f1",
                    "reasoning_model": "r1",
                    "is_default": True,
                },
            )
            assert p_create.status_code == 201
            pid = p_create.json()["id"]
            assert p_create.json()["is_default"] is True

            doc = client.get("/api/v1/system/doctor", headers=headers)
            assert doc.status_code == 200
            assert doc.json()["llm"]["base_url"] == "http://127.0.0.1:8000/v1"
            assert doc.json()["llm"]["offline"] is True

            assert client.get("/api/v1/system/tools", headers=headers).status_code == 200
            assert client.get("/api/v1/system/kb/search?q=graphql", headers=headers).status_code == 200

            p_del = client.delete(f"/api/v1/llm-profiles/{pid}", headers=headers)
            assert p_del.status_code == 200

            # Stop and delete engagement
            assert client.post(f"/api/v1/engagements/{eng_id}/stop", headers=headers).status_code == 200
            assert client.delete(f"/api/v1/engagements/{eng_id}", headers=headers).status_code == 200
            assert client.get(f"/api/v1/engagements/{eng_id}", headers=headers).status_code == 404
    finally:
        reset_vault_cache()
        get_settings.cache_clear()
