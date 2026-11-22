"""Local bearer token / API key authentication for REST and WebSocket endpoints."""
from __future__ import annotations

import secrets
from fastapi import Depends, Header, HTTPException, Query, WebSocket, status

from app.config import get_settings


def _verify_token_value(provided: str | None) -> bool:
    if not provided:
        return False
    expected = get_settings().get_or_create_api_token()
    return secrets.compare_digest(provided.strip(), expected)


async def require_api_token(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    token: str | None = Query(default=None),
) -> str:
    candidate: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        candidate = authorization[7:].strip()
    elif x_api_key:
        candidate = x_api_key.strip()
    elif token:
        candidate = token.strip()

    if not _verify_token_value(candidate):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing AegisPT API token.",
        )
    assert candidate is not None
    return candidate


async def authenticate_websocket(websocket: WebSocket) -> bool:
    token = websocket.query_params.get("token")
    if not token:
        auth = websocket.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
    if not token:
        token = websocket.headers.get("x-api-key")
    return _verify_token_value(token)
