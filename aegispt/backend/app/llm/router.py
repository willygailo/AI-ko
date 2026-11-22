"""Provider-agnostic async LLM Router (Ollama + OpenAI-compatible vLLM/llama.cpp/APIs)."""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

from app.config import get_settings
from app.core.redactor import SecretRedactor
from app.llm.schemas import parse_json_object


@dataclass
class LLMProfileConfig:
    name: str
    provider: Literal["ollama", "openai_compat"]
    base_url: str
    fast_model: str
    reasoning_model: str
    api_key: str = ""
    redact_outbound: bool = True

    @property
    def is_local_endpoint(self) -> bool:
        host = (urlparse(self.base_url).hostname or "").lower()
        return host in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


@dataclass
class LLMCompletionResult:
    content: str
    model: str
    provider: str
    redacted_applied: bool = False
    usage: dict[str, Any] | None = None


def default_profile_from_settings() -> LLMProfileConfig:
    settings = get_settings()
    if settings.remote_llm_url:
        return LLMProfileConfig(
            name="remote-default",
            provider="openai_compat",
            base_url=settings.remote_llm_url.rstrip("/"),
            api_key=settings.remote_llm_api_key,
            fast_model=settings.remote_fast_model or settings.ollama_fast_model,
            reasoning_model=settings.remote_reasoning_model or settings.ollama_reasoning_model,
            redact_outbound=settings.redact_outbound,
        )
    return LLMProfileConfig(
        name="local-ollama",
        provider="ollama",
        base_url=settings.ollama_url.rstrip("/"),
        api_key=settings.ollama_api_key,
        fast_model=settings.ollama_fast_model,
        reasoning_model=settings.ollama_reasoning_model,
        redact_outbound=settings.redact_outbound,
    )


class LLMRouter:
    """Routes chat and structured-JSON requests across local Ollama and remote OpenAI-compatible servers."""

    def __init__(self, timeout: float = 90.0) -> None:
        self.timeout = timeout

    async def complete(
        self,
        *,
        profile: LLMProfileConfig | None = None,
        fallback_profiles: list[LLMProfileConfig] | None = None,
        tier: Literal["fast", "reasoning"] = "reasoning",
        messages: list[dict[str, str]],
        json_mode: bool = False,
        temperature: float = 0.2,
        max_tokens: int = 1600,
        max_retries: int = 2,
    ) -> LLMCompletionResult:
        candidates = [profile or default_profile_from_settings(), *(fallback_profiles or [])]
        last_exc: Exception | None = None

        for cfg in candidates:
            model = cfg.fast_model if tier == "fast" else cfg.reasoning_model
            redactor: SecretRedactor | None = None
            prepared_messages = messages
            redacted_applied = False
            if cfg.redact_outbound and not cfg.is_local_endpoint:
                redactor = SecretRedactor()
                prepared_messages = [
                    {
                        "role": m["role"],
                        "content": redactor.redact(m.get("content", "")),
                    }
                    for m in messages
                ]
                redacted_applied = True

            for attempt in range(max_retries + 1):
                try:
                    if cfg.provider == "ollama":
                        res = await self._call_ollama(
                            cfg=cfg,
                            model=model,
                            messages=prepared_messages,
                            json_mode=json_mode,
                            temperature=temperature,
                            max_tokens=max_tokens,
                        )
                    elif cfg.provider == "openai_compat":
                        res = await self._call_openai_compat(
                            cfg=cfg,
                            model=model,
                            messages=prepared_messages,
                            json_mode=json_mode,
                            temperature=temperature,
                            max_tokens=max_tokens,
                        )
                    else:
                        raise ValueError(f"Unsupported LLM provider: {cfg.provider}")

                    if redactor is not None:
                        res.content = redactor.restore(res.content)
                    res.redacted_applied = redacted_applied
                    return res
                except Exception as exc:
                    last_exc = exc
                    is_transient = isinstance(exc, (httpx.TimeoutException, httpx.ConnectError)) or (
                        isinstance(exc, httpx.HTTPStatusError)
                        and exc.response.status_code in {429, 500, 502, 503, 504}
                    )
                    if is_transient and attempt < max_retries:
                        await asyncio.sleep(0.4 * (2**attempt))
                        continue
                    break

        assert last_exc is not None
        raise last_exc

    async def complete_json(
        self,
        *,
        profile: LLMProfileConfig | None = None,
        fallback_profiles: list[LLMProfileConfig] | None = None,
        tier: Literal["fast", "reasoning"] = "reasoning",
        messages: list[dict[str, str]],
        temperature: float = 0.15,
        max_tokens: int = 1600,
    ) -> dict[str, Any]:
        res = await self.complete(
            profile=profile,
            fallback_profiles=fallback_profiles,
            tier=tier,
            messages=messages,
            json_mode=True,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return parse_json_object(res.content)

    def _ollama_url(self, base_url: str, endpoint: str) -> str:
        base = base_url.rstrip("/")
        if base.endswith("/api"):
            return f"{base}/{endpoint.lstrip('/')}"
        return f"{base}/api/{endpoint.lstrip('/')}"

    async def _call_ollama(
        self,
        *,
        cfg: LLMProfileConfig,
        model: str,
        messages: list[dict[str, str]],
        json_mode: bool,
        temperature: float,
        max_tokens: int,
    ) -> LLMCompletionResult:
        url = self._ollama_url(cfg.base_url, "chat")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if cfg.api_key:
            headers["Authorization"] = f"Bearer {cfg.api_key}"
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if json_mode:
            body["format"] = "json"

        async with httpx.AsyncClient(
            timeout=self.timeout, trust_env=not cfg.is_local_endpoint
        ) as client:
            resp = await client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        msg = data.get("message") or {}
        content = msg.get("content", "")
        return LLMCompletionResult(
            content=content,
            model=data.get("model", model),
            provider="ollama",
            usage={
                "prompt_eval_count": data.get("prompt_eval_count"),
                "eval_count": data.get("eval_count"),
            },
        )

    async def _call_openai_compat(
        self,
        *,
        cfg: LLMProfileConfig,
        model: str,
        messages: list[dict[str, str]],
        json_mode: bool,
        temperature: float,
        max_tokens: int,
    ) -> LLMCompletionResult:
        base = cfg.base_url.rstrip("/")
        url = f"{base}/chat/completions" if base.endswith("/v1") else f"{base}/v1/chat/completions"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if cfg.api_key:
            headers["Authorization"] = f"Bearer {cfg.api_key}"

        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        async with httpx.AsyncClient(
            timeout=self.timeout, trust_env=not cfg.is_local_endpoint
        ) as client:
            resp = await client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        choices = data.get("choices") or []
        content = ""
        if choices:
            content = (choices[0].get("message") or {}).get("content") or ""
        return LLMCompletionResult(
            content=content,
            model=data.get("model", model),
            provider="openai_compat",
            usage=data.get("usage"),
        )

    async def list_models(self, profile: LLMProfileConfig | None = None) -> dict[str, Any]:
        cfg = profile or default_profile_from_settings()
        try:
            async with httpx.AsyncClient(
                timeout=8.0, trust_env=not cfg.is_local_endpoint
            ) as client:
                if cfg.provider == "ollama":
                    headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
                    resp = await client.get(self._ollama_url(cfg.base_url, "tags"), headers=headers)
                    resp.raise_for_status()
                    data = resp.json()
                    models = [m.get("name") for m in data.get("models", []) if m.get("name")]
                    return {"reachable": True, "provider": "ollama", "base_url": cfg.base_url, "models": models}
                else:
                    base = cfg.base_url.rstrip("/")
                    url = f"{base}/models" if base.endswith("/v1") else f"{base}/v1/models"
                    headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
                    resp = await client.get(url, headers=headers)
                    resp.raise_for_status()
                    data = resp.json()
                    models = [m.get("id") for m in data.get("data", []) if m.get("id")]
                    return {"reachable": True, "provider": "openai_compat", "base_url": cfg.base_url, "models": models}
        except Exception as exc:
            return {
                "reachable": False,
                "provider": cfg.provider,
                "base_url": cfg.base_url,
                "models": [],
                "error": str(exc),
            }


llm_router = LLMRouter()
