"""REST & WebSocket client helper for AegisPT CLI."""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx


class AegisAPIError(Exception):
    """Structured error raised when communicating with the AegisPT API."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        detail: str | None = None,
        is_connection_error: bool = False,
        hint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.detail = detail
        self.is_connection_error = is_connection_error
        self.hint = hint


def _find_repo_root() -> Path | None:
    """Return the editable repo root if running from a source checkout, else None."""
    try:
        candidate = Path(__file__).resolve().parents[2]
    except IndexError:
        return None
    if (candidate / "pyproject.toml").is_file() or (
        (candidate / "backend").is_dir() and (candidate / "cli").is_dir()
    ):
        return candidate
    return None


def _xdg_config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME", "").strip()
    return (Path(base).expanduser() if base else Path.home() / ".config") / "aegispt"


def _xdg_data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME", "").strip()
    return (Path(base).expanduser() if base else Path.home() / ".local" / "share") / "aegispt"


def _parse_dotenv(path: Path) -> dict[str, str]:
    """Parse key=value pairs from a .env file safely."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        key, raw_val = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        val = raw_val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in {'"', "'"}:
            quote = val[0]
            val = val[1:-1]
            if quote == '"':
                val = val.replace('\\"', '"').replace("\\\\", "\\")
        elif " #" in val:
            val = val.split(" #", 1)[0].rstrip()
        values[key] = val
    return values


def _dotenv_candidates() -> list[Path]:
    """Return candidate .env paths ordered from lowest to highest precedence."""
    candidates: list[Path] = [_xdg_config_dir() / ".env"]
    repo_root = _find_repo_root()
    if repo_root is not None:
        candidates.append(repo_root / ".env")
    candidates.append(Path.cwd() / ".env")

    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved not in seen:
            seen.add(resolved)
            deduped.append(path)
    return deduped


def _load_env_config() -> tuple[dict[str, str], dict[str, Path]]:
    """Load merged AEGISPT_* settings from .env files and os.environ."""
    merged: dict[str, str] = {}
    sources: dict[str, Path] = {}
    for env_file in _dotenv_candidates():
        parsed = _parse_dotenv(env_file)
        for k, v in parsed.items():
            merged[k] = v
            sources[k] = env_file.parent

    for k, v in os.environ.items():
        if k.startswith("AEGISPT_"):
            merged[k] = v
            sources.pop(k, None)
    return merged, sources


def default_env_path() -> tuple[Path, Path | None]:
    """Choose a writable default .env path and optional .env.example template."""
    repo_root = _find_repo_root()
    if repo_root is not None and os.access(repo_root, os.W_OK):
        template = repo_root / ".env.example"
        return repo_root / ".env", template if template.is_file() else None

    cwd = Path.cwd()
    if (cwd / ".env").exists() or (cwd / ".env.example").exists():
        template = cwd / ".env.example"
        return cwd / ".env", template if template.is_file() else None

    return _xdg_config_dir() / ".env", None


def resolve_server_url() -> str:
    """Resolve the AegisPT server base URL from env, .env, or defaults."""
    env_map, _ = _load_env_config()

    explicit_url = env_map.get("AEGISPT_SERVER_URL", "").strip()
    if explicit_url:
        return explicit_url.rstrip("/")

    host = env_map.get("AEGISPT_HOST", "").strip()
    port_raw = env_map.get("AEGISPT_PORT", "").strip()

    if not host or not port_raw:
        try:
            from app.config import get_settings

            settings = get_settings()
            if not host:
                host = settings.host
            if not port_raw:
                port_raw = str(settings.port)
        except Exception:
            host = host or "127.0.0.1"
            port_raw = port_raw or "8443"

    if host in {"0.0.0.0", ""}:
        host = "127.0.0.1"
    elif host == "::":
        host = "[::1]"
    elif ":" in host and not host.startswith("["):
        host = f"[{host}]"

    return f"http://{host}:{port_raw}".rstrip("/")


def resolve_api_token() -> str:
    """Resolve the API bearer token from env, .env, or data_dir/.api_token."""
    env_map, sources = _load_env_config()

    tok = env_map.get("AEGISPT_API_TOKEN", "").strip()
    if tok:
        return tok

    candidates: list[Path] = []
    data_dir_val = env_map.get("AEGISPT_DATA_DIR", "").strip()
    if data_dir_val:
        raw_path = Path(data_dir_val).expanduser()
        if not raw_path.is_absolute() and "AEGISPT_DATA_DIR" in sources:
            candidates.append((sources["AEGISPT_DATA_DIR"] / raw_path) / ".api_token")
        candidates.append(raw_path / ".api_token")

    candidates.append(Path.cwd() / "data" / ".api_token")
    repo_root = _find_repo_root()
    if repo_root is not None:
        candidates.append(repo_root / "data" / ".api_token")
    candidates.append(_xdg_data_dir() / ".api_token")

    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        if resolved in seen:
            continue
        seen.add(resolved)
        if candidate.is_file():
            try:
                file_tok = candidate.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if file_tok:
                return file_tok
    return ""


def _is_loopback_url(url: str) -> bool:
    """Return True when the URL points to a loopback address."""
    host = (urlparse(url).hostname or "").strip().lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _extract_error_detail(resp: httpx.Response) -> str:
    """Extract a readable error detail from FastAPI JSON or plain text responses."""
    try:
        body = resp.json()
    except Exception:
        text = (resp.text or "").strip()
        return text[:300] if text else (resp.reason_phrase or "Request failed")

    if isinstance(body, dict) and "detail" in body:
        detail = body["detail"]
        if isinstance(detail, str):
            return detail
        if isinstance(detail, list):
            parts: list[str] = []
            for item in detail:
                if isinstance(item, dict):
                    loc = ".".join(str(x) for x in item.get("loc") or [])
                    msg = str(item.get("msg") or "")
                    parts.append(f"{loc}: {msg}" if loc else msg)
                else:
                    parts.append(str(item))
            return "; ".join(p for p in parts if p) or str(detail)
        return str(detail)
    return (resp.text or "").strip()[:300] or resp.reason_phrase or "Request failed"


class AegisClient:
    """Pooled HTTP and WebSocket helper for the AegisPT API."""

    def __init__(self, base_url: str | None = None, token: str | None = None) -> None:
        self.base_url = (base_url or resolve_server_url()).rstrip("/")
        self.token = token if token is not None else resolve_api_token()
        self._client: httpx.Client | None = None

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    @property
    def ws_headers(self) -> dict[str, str]:
        return dict(self.headers)

    @property
    def trust_env(self) -> bool:
        return not _is_loopback_url(self.base_url)

    def _get_client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers=self.headers,
                timeout=30.0,
                trust_env=self.trust_env,
            )
        return self._client

    def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            self._client.close()
        self._client = None

    def __enter__(self) -> AegisClient:
        self._get_client()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def ws_url(self, engagement_id: str) -> str:
        """Return WebSocket URL without embedding bearer tokens in query strings."""
        parsed = urlparse(self.base_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        ws_base = urlunparse(parsed._replace(scheme=ws_scheme, query="", fragment="")).rstrip("/")
        return f"{ws_base}/ws/engagements/{engagement_id}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        client = self._get_client()
        kwargs: dict[str, Any] = {}
        if params:
            kwargs["params"] = params
        if json_body is not None:
            kwargs["json"] = json_body
        if timeout is not None:
            kwargs["timeout"] = timeout

        try:
            resp = client.request(method, path, **kwargs)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.NetworkError) as exc:
            raise AegisAPIError(
                f"Could not connect to AegisPT server at {self.base_url}: {exc}",
                is_connection_error=True,
                hint="Start the server with `./aegispt serve` or set AEGISPT_SERVER_URL.",
            ) from exc
        except httpx.TimeoutException as exc:
            raise AegisAPIError(
                f"Request to {self.base_url}{path} timed out.",
                is_connection_error=True,
                hint="Check whether the AegisPT server is healthy or busy.",
            ) from exc
        except httpx.HTTPError as exc:
            raise AegisAPIError(
                f"HTTP transport error communicating with {self.base_url}: {exc}",
                is_connection_error=True,
            ) from exc

        if resp.is_error:
            detail = _extract_error_detail(resp)
            hint: str | None = None
            if resp.status_code == 401:
                hint = "Verify AEGISPT_API_TOKEN or run `./aegispt token` to inspect the active token."
            elif resp.status_code == 403:
                hint = "Target or action was rejected by ScopePolicy or authorization rules."
            raise AegisAPIError(
                f"HTTP {resp.status_code}: {detail}",
                status_code=resp.status_code,
                detail=detail,
                is_connection_error=False,
                hint=hint,
            )
        return resp

    def get(self, path: str, **params: Any) -> httpx.Response:
        clean_params = {k: v for k, v in params.items() if v is not None}
        return self._request("GET", path, params=clean_params or None)

    def post(
        self,
        path: str,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        return self._request(
            "POST",
            path,
            params=clean_params or None,
            json_body=json_body,
            timeout=60.0,
        )

    def patch(self, path: str, json_body: dict[str, Any]) -> httpx.Response:
        return self._request("PATCH", path, json_body=json_body)

    def delete(self, path: str) -> httpx.Response:
        return self._request("DELETE", path)
