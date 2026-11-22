"""Scoped Local Lab Out-of-Band (OOB) HTTP Callback Catcher."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_api_token
from app.core.events import event_bus
from app.db.database import get_db
from app.db.models import Engagement, OOBEvent

router = APIRouter(tags=["oob"])


@router.api_route(
    "/oob/{engagement_id}/{token}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def capture_oob_callback(
    engagement_id: str,
    token: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Record inbound local lab callback hits used for non-destructive SSRF/XXE verification."""
    eng = await db.get(Engagement, engagement_id)
    if not eng:
        return JSONResponse(status_code=404, content={"status": "unknown_engagement"})

    raw_body = (await request.body())[:2048].decode("utf-8", errors="replace")
    safe_headers = {
        k: ("***" if k.lower() in {"authorization", "cookie"} else v[:200])
        for k, v in request.headers.items()
    }
    src_ip = request.client.host if request.client else ""
    ev = OOBEvent(
        engagement_id=engagement_id,
        token=token[:64],
        method=request.method,
        path=str(request.url.path)[:512],
        source_ip=src_ip,
        headers=safe_headers,
        body_preview=raw_body,
    )
    db.add(ev)
    await db.commit()

    await event_bus.publish(
        engagement_id=engagement_id,
        event_type="oob_callback_received",
        agent_name="oob",
        message=f"Captured local OOB `{request.method}` callback for token `{token}` from `{src_ip}`.",
        payload={"token": token, "method": request.method, "source_ip": src_ip},
    )
    return JSONResponse(status_code=200, content={"status": "recorded", "token": token})


@router.get(
    "/api/v1/engagements/{engagement_id}/oob",
    dependencies=[Depends(require_api_token)],
)
async def list_oob_events(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    rows = (
        await db.execute(
            select(OOBEvent)
            .where(OOBEvent.engagement_id == engagement_id)
            .order_by(OOBEvent.created_at.desc())
            .limit(100)
        )
    ).scalars().all()
    return {
        "oob_events": [
            {
                "id": r.id,
                "token": r.token,
                "method": r.method,
                "path": r.path,
                "source_ip": r.source_ip,
                "headers": r.headers,
                "body_preview": r.body_preview,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    }
