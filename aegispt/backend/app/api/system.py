"""System health, tool doctor, WebSocket ticket, and OWASP knowledge base routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_api_token, ws_ticket_store
from app.core.vault import decrypt_or_passthrough
from app.db.database import get_db
from app.db.models import LLMProfile
from app.knowledge.store import knowledge_store
from app.llm.router import LLMProfileConfig, default_profile_from_settings, llm_router
from app.tools.registry import tool_registry

router = APIRouter(prefix="/api/v1/system", tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "aegispt", "version": "0.1.0"}


@router.post("/ws-ticket", dependencies=[Depends(require_api_token)])
async def create_ws_ticket() -> dict[str, object]:
    """Issue a short-lived, single-use ticket for browser WebSocket authentication."""
    ticket, expires_in = ws_ticket_store.issue()
    return {"ticket": ticket, "expires_in": expires_in}


@router.get("/tools", dependencies=[Depends(require_api_token)])
async def list_tools() -> dict[str, object]:
    return {"tools": tool_registry.describe_catalog()}


@router.get("/doctor", dependencies=[Depends(require_api_token)])
async def doctor(db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    await knowledge_store.ensure_indexed_async()
    tools = tool_registry.describe_catalog()

    default_row = (
        await db.execute(
            select(LLMProfile).where(LLMProfile.is_default.is_(True)).limit(1)
        )
    ).scalar_one_or_none()
    if default_row is not None:
        llm_cfg = LLMProfileConfig(
            name=default_row.name,
            provider=default_row.provider,  # type: ignore[arg-type]
            base_url=default_row.base_url,
            api_key=decrypt_or_passthrough(default_row.api_key),
            fast_model=default_row.fast_model,
            reasoning_model=default_row.reasoning_model,
            redact_outbound=default_row.redact_outbound,
        )
    else:
        llm_cfg = default_profile_from_settings()

    llm_status = await llm_router.list_models(llm_cfg)
    kb_count = len(await knowledge_store.search_async("", limit=100))
    available_count = sum(1 for t in tools if t["available"])
    return {
        "status": "ready",
        "tools_available": available_count,
        "tools_total": len(tools),
        "tools": tools,
        "llm": llm_status,
        "knowledge_playbooks": kb_count,
    }


@router.get("/kb/search", dependencies=[Depends(require_api_token)])
async def search_kb(q: str = Query(default=""), limit: int = Query(default=5, ge=1, le=20)) -> dict[str, object]:
    return {"results": await knowledge_store.search_async(q, limit=limit)}
