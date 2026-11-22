"""LLM Provider Profile management and live model discovery routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import LLMDiscoverInput, LLMProfileCreate
from app.core.auth import require_api_token
from app.db.database import get_db
from app.db.models import LLMProfile
from app.llm.router import LLMProfileConfig, llm_router

router = APIRouter(
    prefix="/api/v1/llm-profiles",
    tags=["llm"],
    dependencies=[Depends(require_api_token)],
)


def _serialize_profile(p: LLMProfile) -> dict[str, object]:
    return {
        "id": p.id,
        "name": p.name,
        "provider": p.provider,
        "base_url": p.base_url,
        "has_api_key": bool(p.api_key),
        "fast_model": p.fast_model,
        "reasoning_model": p.reasoning_model,
        "redact_outbound": p.redact_outbound,
        "is_default": p.is_default,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


@router.get("")
async def list_profiles(db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    rows = (await db.execute(select(LLMProfile).order_by(LLMProfile.created_at.asc()))).scalars().all()
    return {"profiles": [_serialize_profile(r) for r in rows]}


@router.post("", status_code=201)
async def create_profile(body: LLMProfileCreate, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    existing = (
        await db.execute(select(LLMProfile).where(LLMProfile.name == body.name))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail=f"LLM profile '{body.name}' already exists.")
    if body.is_default:
        await db.execute(update(LLMProfile).values(is_default=False))
    prof = LLMProfile(
        name=body.name,
        provider=body.provider,
        base_url=body.base_url.rstrip("/"),
        api_key=body.api_key,
        fast_model=body.fast_model,
        reasoning_model=body.reasoning_model,
        redact_outbound=body.redact_outbound,
        is_default=body.is_default,
    )
    db.add(prof)
    await db.commit()
    await db.refresh(prof)
    return _serialize_profile(prof)


@router.delete("/{profile_id}")
async def delete_profile(profile_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    prof = await db.get(LLMProfile, profile_id)
    if not prof:
        raise HTTPException(status_code=404, detail="LLM profile not found.")
    await db.delete(prof)
    await db.commit()
    return {"deleted": profile_id}


@router.post("/discover")
async def discover_models(body: LLMDiscoverInput) -> dict[str, object]:
    cfg = LLMProfileConfig(
        name="probe",
        provider=body.provider,
        base_url=body.base_url.rstrip("/"),
        api_key=body.api_key,
        fast_model="",
        reasoning_model="",
    )
    return await llm_router.list_models(cfg)
