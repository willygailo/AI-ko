"""FastAPI entrypoint for AegisPT Private AI Pentesting Platform."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, update

from app.api import approvals, engagements, findings, models_api, reports, system, ws
from app.config import get_settings
from app.db.database import close_db, init_db, session_scope
from app.db.models import ApprovalRequest, Engagement, LLMProfile, ToolRun
from app.knowledge.store import knowledge_store


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
        session.add(
            LLMProfile(
                name="Local Ollama (Default)",
                provider="ollama",
                base_url=settings.ollama_url,
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
    knowledge_store.ensure_indexed()
    await _seed_default_llm_profile()
    print(f"[AegisPT] Listening on http://{settings.host}:{settings.port}")
    print(f"[AegisPT] Local API Token: {token}")
    try:
        yield
    finally:
        await close_db()


def create_app() -> FastAPI:
    app = FastAPI(
        title="AegisPT Private AI Pentesting Platform",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "http://127.0.0.1:8443",
            "http://localhost:8443",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(system.router)
    app.include_router(models_api.router)
    app.include_router(engagements.router)
    app.include_router(approvals.router)
    app.include_router(findings.router)
    app.include_router(reports.router)
    app.include_router(ws.router)

    frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")

    return app


app = create_app()


def run_server() -> None:
    settings = get_settings()
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run_server()
