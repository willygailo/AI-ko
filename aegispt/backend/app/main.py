"""FastAPI entrypoint for AegisPT Private AI Pentesting Platform."""
from __future__ import annotations

from contextlib import asynccontextmanager
import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, update

from app.agents.orchestrator import orchestrator_manager
from app.api import approvals, engagements, findings, models_api, oob, reports, system, ws
from app.config import get_settings
from app.core.vault import encrypt_str
from app.db.database import close_db, init_db, session_scope
from app.db.models import ApprovalRequest, Engagement, LLMProfile, ToolRun
from app.knowledge.store import knowledge_store
from app.llm.router import llm_router


async def _recover_interrupted_runs() -> None:
    """Cleanly transition orphaned running/awaiting states left by a prior process exit."""
    async with session_scope() as session:
        await session.execute(
            update(Engagement)
            .where(Engagement.status.in_(["running", "awaiting_approval"]))
            .values(status="paused")
        )
        await session.execute(
            update(ToolRun)
            .where(ToolRun.status.in_(["running", "awaiting_approval"]))
            .values(status="failed", error_message="Interrupted by server restart.")
        )
        await session.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.status == "pending")
            .values(status="expired", operator_note="Expired due to server restart.")
        )


async def _seed_default_llm_profile() -> None:
    settings = get_settings()
    async with session_scope() as session:
        existing = (await session.execute(select(LLMProfile))).scalars().first()
        if existing:
            return
        if settings.remote_llm_url:
            session.add(
                LLMProfile(
                    name="Remote LLM (Default)",
                    provider="openai_compat",
                    base_url=settings.remote_llm_url.rstrip("/"),
                    api_key=encrypt_str(settings.remote_llm_api_key),
                    fast_model=settings.remote_fast_model or settings.ollama_fast_model,
                    reasoning_model=settings.remote_reasoning_model or settings.ollama_reasoning_model,
                    redact_outbound=settings.redact_outbound,
                    is_default=True,
                )
            )
            return
        is_cloud = bool(settings.ollama_api_key) or "ollama.com" in settings.ollama_url.lower()
        session.add(
            LLMProfile(
                name="Ollama Cloud (Default)" if is_cloud else "Local Ollama (Default)",
                provider="ollama",
                base_url=settings.ollama_url.rstrip("/"),
                api_key=encrypt_str(settings.ollama_api_key),
                fast_model=settings.ollama_fast_model,
                reasoning_model=settings.ollama_reasoning_model,
                redact_outbound=settings.redact_outbound,
                is_default=True,
            )
        )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()
    token = settings.get_or_create_api_token()
    await init_db()
    await _recover_interrupted_runs()
    await knowledge_store.ensure_indexed_async()
    settings.enforce_storage_permissions()
    await _seed_default_llm_profile()
    print(f"[AegisPT] Listening on http://{settings.host}:{settings.port}")
    if os.environ.get("AEGISPT_PRINT_TOKEN") == "1":
        print(f"[AegisPT] Local API Token: {token}")
    else:
        print("[AegisPT] Local API token ready (run `./aegispt token` to display it).")
    try:
        yield
    finally:
        await orchestrator_manager.stop_all()
        await llm_router.aclose()
        await close_db()


def create_app(frontend_dist: Path | None = None) -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AegisPT Private AI Pentesting Platform",
        version="0.1.0",
        lifespan=lifespan,
    )

    cors_origins = list(
        dict.fromkeys(
            [
                "http://127.0.0.1:5173",
                "http://localhost:5173",
                f"http://127.0.0.1:{settings.port}",
                f"http://localhost:{settings.port}",
            ]
        )
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key"],
    )

    app.include_router(system.router)
    app.include_router(models_api.router)
    app.include_router(engagements.router)
    app.include_router(approvals.router)
    app.include_router(findings.router)
    app.include_router(reports.router)
    app.include_router(oob.router)
    app.include_router(ws.router)

    dist_dir = frontend_dist if frontend_dist is not None else Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if dist_dir.is_dir():
        app.mount("/", StaticFiles(directory=str(dist_dir), html=True), name="frontend")

    return app


app = create_app()


def run_server() -> None:
    settings = get_settings()
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run_server()
