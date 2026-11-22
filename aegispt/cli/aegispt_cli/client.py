"""REST & WebSocket client helper for AegisPT CLI."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx


def resolve_server_url() -> str:
    return os.environ.get("AEGISPT_SERVER_URL", "http://127.0.0.1:8443").rstrip("/")


def resolve_api_token() -> str:
    env_tok = os.environ.get("AEGISPT_API_TOKEN", "").strip()
    if env_tok:
        return env_tok
    candidates = [
        Path.cwd() / "data" / ".api_token",
        Path(__file__).resolve().parents[2] / "data" / ".api_token",
    ]
    for c in candidates:
        if c.is_file():
            tok = c.read_text(encoding="utf-8").strip()
            if tok:
                return tok
    return ""


class AegisClient:
    def __init__(self, base_url: str | None = None, token: str | None = None) -> None:
        self.base_url = (base_url or resolve_server_url()).rstrip("/")
        self.token = token if token is not None else resolve_api_token()

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def ws_url(self, engagement_id: str) -> str:
        ws_base = self.base_url.replace("https://", "wss://").replace("http://", "ws://")
        return f"{ws_base}/ws/engagements/{engagement_id}?token={self.token}"

    def get(self, path: str, **params: Any) -> httpx.Response:
        with httpx.Client(
            base_url=self.base_url, headers=self.headers, timeout=30.0, trust_env=False
        ) as client:
            resp = client.get(path, params=params or None)
            resp.raise_for_status()
            return resp

    def post(self, path: str, json_body: dict[str, Any] | None = None) -> httpx.Response:
        with httpx.Client(
            base_url=self.base_url, headers=self.headers, timeout=60.0, trust_env=False
        ) as client:
            resp = client.post(path, json=json_body)
            resp.raise_for_status()
            return resp

    def patch(self, path: str, json_body: dict[str, Any]) -> httpx.Response:
        with httpx.Client(
            base_url=self.base_url, headers=self.headers, timeout=30.0, trust_env=False
        ) as client:
            resp = client.patch(path, json=json_body)
            resp.raise_for_status()
            return resp
