"""Scoped Local Lab Out-of-Band (OOB) HTTP Callback Catcher."""
from __future__ import annotations

from collections import deque
import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_api_token
from app.core.events import event_bus
from app.db.database import get_db
from app.db.models import Engagement, OOBEvent

router = APIRouter(tags=["oob"])

OOB_MAX_BODY_BYTES = 2048
OOB_MAX_EVENTS_PER_ENGAGEMENT = 200
OOB_RATE_WINDOW_SECONDS = 10.0
OOB_RATE_MAX_HITS_PER_WINDOW = 40
ACTIVE_OOB_STATUSES = {"running", "awaiting_approval"}

_oob_hit_windows: dict[str, deque[float]] = {}


def reset_oob_rate_limits() -> None:
    """Clear in-memory OOB rate-limit state (useful in tests)."""
    _oob_hit_windows.clear()


def _check_oob_rate_limit(engagement_id: str) -> bool:
    now = time.monotonic()
    window = _oob_hit_windows.setdefault(engagement_id, deque())
    cutoff = now - OOB_RATE_WINDOW_SECONDS
    while window and window[0] < cutoff:
        window.popleft()
    if len(window) >= OOB_RATE_MAX_HITS_PER_WINDOW:
        return False
    window.append(now)
    return True


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

    if eng.status not in ACTIVE_OOB_STATUSES:
        return JSONResponse(
            status_code=409,
            content={"status": "engagement_inactive", "engagement_status": eng.status},
        )

    if not _check_oob_rate_limit(engagement_id):
        return JSONResponse(status_code=429, content={"status": "rate_limited"})

    existing_count = (
        await db.execute(
            select(func.count()).select_from(OOBEvent).where(OOBEvent.engagement_id == engagement_id)
        )
    ).scalar_one()
    if existing_count >= OOB_MAX_EVENTS_PER_ENGAGEMENT:
        return JSONResponse(status_code=429, content={"status": "oob_cap_reached"})

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        if not chunk:
            continue
        remaining = OOB_MAX_BODY_BYTES - total
        if remaining <= 0:
            break
        piece = chunk[:remaining]
        chunks.append(piece)
        total += len(piece)
        if total >= OOB_MAX_BODY_BYTES:
            break
    raw_body = b"".join(chunks).decode("utf-8", errors="replace")

    safe_headers = {
        k[:80]: ("***" if k.lower() in {"authorization", "cookie", "x-api-key"} else v[:200])
        for k, v in list(request.headers.items())[:32]
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
