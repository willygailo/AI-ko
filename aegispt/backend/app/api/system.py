"""System health, tool doctor, and OWASP knowledge base routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.core.auth import require_api_token
from app.knowledge.store import knowledge_store
from app.llm.router import default_profile_from_settings, llm_router
from app.tools.registry import tool_registry

router = APIRouter(prefix="/api/v1/system", tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "aegispt", "version": "0.1.0"}


@router.get("/tools", dependencies=[Depends(require_api_token)])
async def list_tools() -> dict[str, object]:
    return {"tools": tool_registry.describe_catalog()}


@router.get("/doctor", dependencies=[Depends(require_api_token)])
async def doctor() -> dict[str, object]:
    knowledge_store.ensure_indexed()
    tools = tool_registry.describe_catalog()
    llm_status = await llm_router.list_models(default_profile_from_settings())
    kb_count = len(knowledge_store.search("", limit=20))
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
    return {"results": knowledge_store.search(q, limit=limit)}
