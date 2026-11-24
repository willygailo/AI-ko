"""Provider-agnostic async LLM Router (Ollama + OpenAI-compatible vLLM/llama.cpp/APIs)."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

from app.config import get_settings
from app.core.redactor import SecretRedactor
from app.core.scope import BLOCKED_METADATA_HOSTS, BLOCKED_METADATA_IPS, UNSAFE_CONTROL_RE
from app.llm.schemas import parse_json_object

EXTRA_BLOCKED_LLM_HOSTS = BLOCKED_METADATA_HOSTS | {
    "metadata.azure.com",
    "metadata.aws.internal",
}


def _is_blocked_llm_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip_obj in BLOCKED_METADATA_IPS or ip_obj.is_link_local or ip_obj.is_multicast:
        return True
    mapped = getattr(ip_obj, "ipv4_mapped", None)
    if mapped is not None and (mapped in BLOCKED_METADATA_IPS or mapped.is_link_local):
        return True
    return False


def validate_llm_base_url(base_url: str, *, resolve_dns: bool = True) -> str:
    """Validate an LLM provider base URL against SSRF to cloud metadata / link-local hosts."""
    if not base_url or not isinstance(base_url, str):
        raise ValueError("LLM base_url is required.")
    raw = base_url.strip()
    if UNSAFE_CONTROL_RE.search(raw):
        raise ValueError("LLM base_url contains disallowed control characters.")

    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"LLM base_url must use http or https scheme (got {scheme!r}).")

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("LLM base_url must include a valid hostname.")
    if host in EXTRA_BLOCKED_LLM_HOSTS:
        raise ValueError(f"LLM base_url host {host!r} is a blocked metadata hostname.")

    try:
        ip_obj = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if _is_blocked_llm_ip(ip_obj):
            raise ValueError(f"LLM base_url IP {ip_obj} is a blocked metadata/link-local address.")
        return raw.rstrip("/")

    if resolve_dns:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            resolved_ips = {info[4][0] for info in infos}
        except socket.gaierror:
            resolved_ips = set()
        for ip_str in resolved_ips:
            try:
                resolved_ip = ipaddress.ip_address(ip_str.strip("[]"))
            except ValueError:
                continue
            if _is_blocked_llm_ip(resolved_ip):
                raise ValueError(
                    f"LLM base_url host {host!r} resolves to blocked metadata/link-local address {resolved_ip}."
                )

    return raw.rstrip("/")


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
        self._local_client: httpx.AsyncClient | None = None
        self._remote_client: httpx.AsyncClient | None = None
        self._client_loop: asyncio.AbstractEventLoop | None = None

    def _get_client(self, *, is_local: bool) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._client_loop is not loop:
            # Event loop changed (e.g. across asyncio.run calls in tests); recreate pooled clients.
            self._local_client = None
            self._remote_client = None
            self._client_loop = loop
        if is_local:
            if self._local_client is None or self._local_client.is_closed:
                self._local_client = httpx.AsyncClient(timeout=self.timeout, trust_env=False)
            return self._local_client
        if self._remote_client is None or self._remote_client.is_closed:
            self._remote_client = httpx.AsyncClient(timeout=self.timeout, trust_env=True)
        return self._remote_client

    async def aclose(self) -> None:
        for attr in ("_local_client", "_remote_client"):
            client = getattr(self, attr)
            if client is not None and not client.is_closed:
                try:
                    await client.aclose()
                except Exception:
                    pass
            setattr(self, attr, None)
        self._client_loop = None

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
        if get_settings().llm_mode.strip().lower() == "offline":
            raise RuntimeError("Outbound LLM calls are disabled (AEGISPT_LLM_MODE=offline).")

        candidates = [profile or default_profile_from_settings(), *(fallback_profiles or [])]
        last_exc: Exception | None = None

        for cfg in candidates:
            validate_llm_base_url(cfg.base_url, resolve_dns=False)
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

        client = self._get_client(is_local=cfg.is_local_endpoint)
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

        client = self._get_client(is_local=cfg.is_local_endpoint)
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
        if get_settings().llm_mode.strip().lower() == "offline":
            return {
                "reachable": False,
                "offline": True,
                "provider": cfg.provider,
                "base_url": cfg.base_url,
                "models": [],
                "error": "Outbound LLM calls are disabled (AEGISPT_LLM_MODE=offline).",
            }
        try:
            await asyncio.to_thread(validate_llm_base_url, cfg.base_url, resolve_dns=True)
            client = self._get_client(is_local=cfg.is_local_endpoint)
            if cfg.provider == "ollama":
                headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
                resp = await client.get(
                    self._ollama_url(cfg.base_url, "tags"), headers=headers, timeout=8.0
                )
                resp.raise_for_status()
                data = resp.json()
                models = [m.get("name") for m in data.get("models", []) if m.get("name")]
                return {"reachable": True, "provider": "ollama", "base_url": cfg.base_url, "models": models}
            else:
                base = cfg.base_url.rstrip("/")
                url = f"{base}/models" if base.endswith("/v1") else f"{base}/v1/models"
                headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
                resp = await client.get(url, headers=headers, timeout=8.0)
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
