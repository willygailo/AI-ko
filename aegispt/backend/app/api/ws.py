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
@router.websocket("/api/v1/engagements/{engagement_id}/ws")
async def engagement_ws(websocket: WebSocket, engagement_id: str) -> None:
    if not await authenticate_websocket(websocket):
        await websocket.close(code=4401)
        return

    await websocket.accept()
    queue = event_bus.subscribe(engagement_id)
    seen_ids: set[int] = set()
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
            if ev.id is not None:
                seen_ids.add(ev.id)
            await websocket.send_json(
                {
                    "id": ev.id,
                    "engagement_id": ev.engagement_id,
                    "event_type": ev.event_type,
                    "agent_name": ev.agent_name,
                    "message": ev.message,
                    "payload": ev.payload,
                    "created_at": ev.created_at.isoformat() if ev.created_at else None,
                    "replayed": True,
                }
            )

        async def _receiver() -> None:
            while True:
                msg = await websocket.receive_text()
                if msg == "ping":
                    await websocket.send_json({"event_type": "pong"})

        recv_task: asyncio.Task[None] = asyncio.create_task(_receiver())
        send_task: asyncio.Task[dict[str, object]] = asyncio.create_task(queue.get())
        try:
            while True:
                done, _ = await asyncio.wait(
                    {send_task, recv_task}, return_when=asyncio.FIRST_COMPLETED
                )
                if recv_task in done:
                    recv_task.result()
                    break
                payload = send_task.result()
                send_task = asyncio.create_task(queue.get())
                ev_id = payload.get("id")
                if isinstance(ev_id, int):
                    if ev_id in seen_ids:
                        continue
                    seen_ids.add(ev_id)
                await websocket.send_json({**payload, "replayed": False})
        finally:
            pending_tasks = [t for t in (recv_task, send_task) if not t.done()]
            for t in pending_tasks:
                t.cancel()
            if pending_tasks:
                await asyncio.gather(*pending_tasks, return_exceptions=True)
    except WebSocketDisconnect:
        pass
    finally:
        event_bus.unsubscribe(queue, engagement_id)
