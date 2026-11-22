"""Centralized Pydantic settings for AegisPT."""
from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGISPT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8443)
    api_token: str = Field(default="")

    data_dir: Path = Field(default=Path("./data"))

    # Default Local Ollama
    ollama_url: str = Field(default="http://127.0.0.1:11434")
    ollama_fast_model: str = Field(default="qwen2.5:3b")
    ollama_reasoning_model: str = Field(default="qwen2.5-coder:7b")

    # Optional Remote OpenAI-Compatible Server (vLLM, llama.cpp, API proxy)
    remote_llm_url: str = Field(default="")
    remote_llm_api_key: str = Field(default="")
    remote_fast_model: str = Field(default="")
    remote_reasoning_model: str = Field(default="")
    redact_outbound: bool = Field(default=True)

    # OWASP ZAP Daemon
    zap_url: str = Field(default="http://127.0.0.1:8080")
    zap_api_key: str = Field(default="")

    # Execution Bounds
    default_tool_timeout: int = Field(default=180)
    max_output_bytes: int = Field(default=2 * 1024 * 1024)
    default_max_steps: int = Field(default=25)
    approval_timeout_seconds: int = Field(default=3600)

    @property
    def resolved_data_dir(self) -> Path:
        p = self.data_dir.expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def db_path(self) -> Path:
        return self.resolved_data_dir / "aegispt.db"

    @property
    def kb_db_path(self) -> Path:
        return self.resolved_data_dir / "knowledge.db"

    @property
    def artifacts_dir(self) -> Path:
        p = self.resolved_data_dir / "artifacts"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def get_or_create_api_token(self) -> str:
        if self.api_token:
            return self.api_token
        token_file = self.resolved_data_dir / ".api_token"
        if token_file.exists():
            tok = token_file.read_text(encoding="utf-8").strip()
            if tok:
                return tok
        tok = f"aegis_{secrets.token_urlsafe(32)}"
        token_file.write_text(tok + "\n", encoding="utf-8")
        try:
            os.chmod(token_file, 0o600)
        except OSError:
            pass
        return tok


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
