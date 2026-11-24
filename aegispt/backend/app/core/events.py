"""Async real-time EventBus powering WebSockets and persistent audit logging."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from app.db.database import session_scope
from app.db.models import AgentEvent


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._global_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def subscribe(self, engagement_id: str | None = None) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        if engagement_id is None:
            self._global_subscribers.add(q)
        else:
            self._subscribers[engagement_id].add(q)
        return q

    def unsubscribe(
        self, queue: asyncio.Queue[dict[str, Any]], engagement_id: str | None = None
    ) -> None:
        if engagement_id is None:
            self._global_subscribers.discard(queue)
        else:
            self._subscribers[engagement_id].discard(queue)
            if not self._subscribers[engagement_id]:
                self._subscribers.pop(engagement_id, None)

    async def publish(
        self,
        engagement_id: str,
        event_type: str,
        message: str = "",
        payload: dict[str, Any] | None = None,
        agent_name: str = "orchestrator",
        persist: bool = True,
    ) -> dict[str, Any]:
        payload = payload or {}
        now = datetime.now(timezone.utc)
        event_id: int | None = None

        if persist:
            async with session_scope() as session:
                ev = AgentEvent(
                    engagement_id=engagement_id,
                    event_type=event_type,
                    agent_name=agent_name,
                    message=message,
                    payload=payload,
                    created_at=now,
                )
                session.add(ev)
                await session.flush()
                event_id = ev.id

        wire = {
            "id": event_id,
            "engagement_id": engagement_id,
            "event_type": event_type,
            "agent_name": agent_name,
            "message": message,
            "payload": payload,
            "created_at": now.isoformat(),
        }

        targets = list(self._subscribers.get(engagement_id, ())) + list(
            self._global_subscribers
        )
        for q in targets:
            for _ in range(3):
                try:
                    q.put_nowait(wire)
                    break
                except asyncio.QueueFull:
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass

        return wire


event_bus = EventBus()
