"""Real-time authenticated WebSocket stream for agent reasoning, logs, and approvals."""
from __future__ import annotations

import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.core.auth import authenticate_websocket
from app.core.events import event_bus
from app.db.database import session_scope
from app.db.models import AgentEvent

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/engagements/{engagement_id}")
async def engagement_ws(websocket: WebSocket, engagement_id: str) -> None:
    if not await authenticate_websocket(websocket):
        await websocket.close(code=4401)
        return

    await websocket.accept()
    queue = event_bus.subscribe(engagement_id)
    try:
        # Replay recent persisted events on initial connect
        async with session_scope() as session:
            recent = (
                await session.execute(
                    select(AgentEvent)
                    .where(AgentEvent.engagement_id == engagement_id)
                    .order_by(AgentEvent.id.desc())
                    .limit(40)
                )
            ).scalars().all()
        for ev in reversed(recent):
            await websocket.send_json(
                {
                    "id": ev.id,
                    "engagement_id": ev.engagement_id,
                    "event_type": ev.event_type,
                    "agent_name": ev.agent_name,
                    "message": ev.message,
                    "payload": ev.payload,
                    "created_at": ev.created_at.isoformat() if ev.created_at else None,
                }
            )

        async def _receiver() -> None:
            while True:
                msg = await websocket.receive_text()
                if msg == "ping":
                    await websocket.send_json({"event_type": "pong"})

        recv_task = asyncio.create_task(_receiver())
        try:
            while True:
                send_wait = asyncio.create_task(queue.get())
                done, _ = await asyncio.wait(
                    {send_wait, recv_task}, return_when=asyncio.FIRST_COMPLETED
                )
                if recv_task in done:
                    send_wait.cancel()
                    recv_task.result()
                    break
                payload = send_wait.result()
                await websocket.send_json(payload)
        finally:
            recv_task.cancel()
    except WebSocketDisconnect:
        pass
    finally:
        event_bus.unsubscribe(queue, engagement_id)
