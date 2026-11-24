"""Centralized Pydantic settings for AegisPT."""
from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path
from pydantic import Field, PrivateAttr
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_data_dir() -> Path:
    """Resolve default data directory consistently across editable and installed packages."""
    project_root = Path(__file__).resolve().parents[2]
    if (project_root / "pyproject.toml").is_file():
        return project_root / "data"
    return Path.home() / ".local" / "share" / "aegispt"


def _chmod_best_effort(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


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

    # LLM operating mode: "auto" (use configured provider) or "offline" (disable outbound LLM calls)
    llm_mode: str = Field(default="auto")

    # Default Local or Cloud Ollama
    ollama_url: str = Field(default="http://127.0.0.1:11434")
    ollama_api_key: str = Field(default="")
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

    _cached_api_token: str | None = PrivateAttr(default=None)

    @property
    def resolved_data_dir(self) -> Path:
        if not self.data_dir.is_absolute() and self.data_dir == Path("./data") and "AEGISPT_DATA_DIR" not in os.environ:
            p = _default_data_dir().expanduser().resolve()
        else:
            p = self.data_dir.expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
        _chmod_best_effort(p, 0o700)
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
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
        _chmod_best_effort(p, 0o700)
        return p

    def enforce_storage_permissions(self) -> None:
        """Enforce 0700 on data_dir and 0600 on local SQLite DB and secret files."""
        data_dir = self.resolved_data_dir
        _chmod_best_effort(data_dir, 0o700)
        for name in (
            ".api_token",
            ".master.key",
            "aegispt.db",
            "aegispt.db-wal",
            "aegispt.db-shm",
            "knowledge.db",
            "knowledge.db-wal",
            "knowledge.db-shm",
        ):
            target = data_dir / name
            if target.is_file():
                _chmod_best_effort(target, 0o600)

    def get_or_create_api_token(self) -> str:
        if self.api_token:
            return self.api_token
        if self._cached_api_token:
            return self._cached_api_token

        token_file = self.resolved_data_dir / ".api_token"
        if token_file.is_file():
            tok = token_file.read_text(encoding="utf-8").strip()
            if tok:
                _chmod_best_effort(token_file, 0o600)
                self._cached_api_token = tok
                return tok

        tok = f"aegis_{secrets.token_urlsafe(32)}"
        try:
            fd = os.open(str(token_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(tok + "\n")
        except FileExistsError:
            existing = token_file.read_text(encoding="utf-8").strip()
            if existing:
                tok = existing
            else:
                fd = os.open(str(token_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(tok + "\n")

        _chmod_best_effort(token_file, 0o600)
        self._cached_api_token = tok
        return tok


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
