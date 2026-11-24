"""Local bearer token / API key authentication for REST and WebSocket endpoints."""
from __future__ import annotations

import secrets
import time

from fastapi import Header, HTTPException, WebSocket, status

from app.config import get_settings

WS_TICKET_TTL_SECONDS = 30
WS_TICKET_MAX_ENTRIES = 256


class WsTicketStore:
    """In-memory TTL-bounded, single-use WebSocket ticket store."""

    def __init__(
        self,
        *,
        default_ttl: int = WS_TICKET_TTL_SECONDS,
        max_entries: int = WS_TICKET_MAX_ENTRIES,
    ) -> None:
        self._default_ttl = default_ttl
        self._max_entries = max_entries
        self._tickets: dict[str, float] = {}

    def _prune(self, now: float) -> None:
        expired = [tok for tok, exp in self._tickets.items() if exp <= now]
        for tok in expired:
            self._tickets.pop(tok, None)

    def issue(self, ttl_seconds: int | None = None) -> tuple[str, int]:
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        now = time.monotonic()
        self._prune(now)
        while len(self._tickets) >= self._max_entries:
            oldest_key = next(iter(self._tickets))
            self._tickets.pop(oldest_key, None)
        ticket = secrets.token_urlsafe(32)
        self._tickets[ticket] = now + float(ttl)
        return ticket, ttl

    def consume(self, ticket: str | None) -> bool:
        if not ticket:
            return False
        now = time.monotonic()
        self._prune(now)
        exp = self._tickets.pop(ticket.strip(), None)
        return exp is not None and exp > now

    def clear(self) -> None:
        self._tickets.clear()


ws_ticket_store = WsTicketStore()


def _verify_token_value(provided: str | None) -> bool:
    if not provided:
        return False
    expected = get_settings().get_or_create_api_token()
    return secrets.compare_digest(provided.strip(), expected)


async def require_api_token(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> str:
    candidate: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        candidate = authorization[7:].strip()
    elif x_api_key:
        candidate = x_api_key.strip()

    if not _verify_token_value(candidate):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing AegisPT API token.",
        )
    assert candidate is not None
    return candidate


async def authenticate_websocket(websocket: WebSocket) -> bool:
    auth = websocket.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        if _verify_token_value(auth[7:].strip()):
            return True
    api_key = websocket.headers.get("x-api-key")
    if api_key and _verify_token_value(api_key):
        return True
    ticket = websocket.query_params.get("ticket")
    if ticket and ws_ticket_store.consume(ticket):
        return True
    return False
