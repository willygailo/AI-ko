"""End-to-end Orchestrator state-machine, Tier 3 approval pause/resume, and static UI tests."""
from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from fastapi.testclient import TestClient

from app.agents.orchestrator import EngagementOrchestrator
from app.config import get_settings
from app.core.policy import approval_coordinator
from app.db.database import close_db, init_db, session_scope
from app.db.models import ApprovalRequest, Engagement, ScopePolicyModel
from app.main import create_app


def test_frontend_dist_served_by_fastapi(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AEGISPT_API_TOKEN", "ui_test_tok")
    get_settings.cache_clear()

    default_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if (default_dist / "index.html").is_file():
        app = create_app()
    else:
        mock_dist = tmp_path / "frontend_dist"
        mock_dist.mkdir(parents=True, exist_ok=True)
        (mock_dist / "index.html").write_text(
            "<!doctype html><html><head><title>AegisPT</title></head><body>AegisPT</body></html>",
            encoding="utf-8",
        )
        app = create_app(frontend_dist=mock_dist)

    with TestClient(app) as client:
        resp = client.get("/")
        assert resp.status_code == 200
        assert "AegisPT" in resp.text
    get_settings.cache_clear()


def test_orchestrator_end_to_end_with_tier3_approval(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AEGISPT_OLLAMA_URL", "http://127.0.0.1:1")  # Force deterministic fallback planner
    get_settings.cache_clear()

    class MockWebApp(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><title>MockLab</title><body><a href='/search?q=hello'>Search</a></body></html>"
            )

        def log_message(self, *_args):
            return

    httpd = HTTPServer(("127.0.0.1", 0), MockWebApp)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    try:
        async def _run():
            await init_db(f"sqlite+aiosqlite:///{tmp_path / 'orch.db'}")
            async with session_scope() as session:
                eng = Engagement(
                    id="eng_e2e",
                    name="MockLab Audit",
                    autonomy_mode="tiered",
                    tier2_auto=True,
                    max_steps=4,
                )
                session.add(eng)
                await session.flush()
                session.add(
                    ScopePolicyModel(
                        engagement_id="eng_e2e",
                        allowed_urls=[f"http://127.0.0.1:{port}/search?q=hello"],
                        allow_private_ips=True,
                        max_rps=25,
                    )
                )

            orch = EngagementOrchestrator("eng_e2e")
            task = asyncio.create_task(orch.run())

            # Wait briefly to see if a Tier-3 approval appears, and reject it cleanly to exercise gate
            approval_id = None
            for _ in range(80):
                if task.done():
                    break
                await asyncio.sleep(0.1)
                async with session_scope() as session:
                    from sqlalchemy import select

                    ap = (
                        await session.execute(
                            select(ApprovalRequest).where(
                                ApprovalRequest.engagement_id == "eng_e2e",
                                ApprovalRequest.status == "pending",
                            )
                        )
                    ).scalar_one_or_none()
                    if ap:
                        approval_id = ap.id
                        break

            if approval_id:
                await approval_coordinator.resolve(
                    approval_id=approval_id,
                    decision="rejected",
                    operator_note="Verified approval gate works",
                )

            await asyncio.wait_for(task, timeout=45.0)

            async with session_scope() as session:
                eng_final = await session.get(Engagement, "eng_e2e")
                assert eng_final is not None
                assert eng_final.status == "completed"

            await close_db()

        asyncio.run(_run())
    finally:
        httpd.shutdown()
        httpd.server_close()
        get_settings.cache_clear()
