"""Comprehensive unit tests for AegisPT CLI client, commands, WS loop, packaging, and lab."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import tomllib
from typing import Any

import httpx
import pytest
from setuptools import PackageFinder
from typer.testing import CliRunner
import yaml

from aegispt_cli import client as cli_client
from aegispt_cli import main as cli_main
from aegispt_cli.client import AegisAPIError, AegisClient
from aegispt_cli.main import _parse_kv, _stream_and_approve, app

runner = CliRunner()
AEGISPT_ROOT = Path(__file__).resolve().parents[2]


class FakeResponse:
    def __init__(self, data: Any = None, text: str = "", status_code: int = 200) -> None:
        self._data = data
        self.text = text if text else (json.dumps(data) if data is not None else "")
        self.status_code = status_code

    def json(self) -> Any:
        return self._data


class FakeClient:
    """In-memory programmable stub for AegisClient."""

    def __init__(self, responses: dict[tuple[str, str], Any] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.closed = False
        self.base_url = "http://127.0.0.1:8443"
        self.token = "tok_test_123"

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    @property
    def ws_headers(self) -> dict[str, str]:
        return dict(self.headers)

    def ws_url(self, engagement_id: str) -> str:
        return f"ws://127.0.0.1:8443/ws/engagements/{engagement_id}"

    def close(self) -> None:
        self.closed = True

    def _dispatch(self, method: str, path: str, meta: dict[str, Any]) -> FakeResponse:
        self.calls.append((method, path, meta))
        handler = self.responses.get((method, path))
        if isinstance(handler, Exception):
            raise handler
        if callable(handler):
            res = handler(meta)
            if isinstance(res, Exception):
                raise res
            if isinstance(res, FakeResponse):
                return res
            return FakeResponse(res)
        if isinstance(handler, FakeResponse):
            return handler
        return FakeResponse(handler if handler is not None else {})

    def get(self, path: str, **params: Any) -> FakeResponse:
        return self._dispatch("GET", path, {"params": params})

    def post(
        self,
        path: str,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> FakeResponse:
        return self._dispatch("POST", path, {"json": json_body, "params": params})

    def patch(self, path: str, json_body: dict[str, Any]) -> FakeResponse:
        return self._dispatch("PATCH", path, {"json": json_body})

    def delete(self, path: str) -> FakeResponse:
        return self._dispatch("DELETE", path, {})


# ---------------------------------------------------------------------------
# Client config, URL/token resolution, pooling & error parsing tests
# ---------------------------------------------------------------------------


def test_resolve_server_url_from_dotenv_and_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for var in ("AEGISPT_SERVER_URL", "AEGISPT_HOST", "AEGISPT_PORT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli_client, "_find_repo_root", lambda: None)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg_cfg"))
    monkeypatch.chdir(tmp_path)

    (tmp_path / ".env").write_text("AEGISPT_HOST=0.0.0.0\nAEGISPT_PORT=9555\n", encoding="utf-8")
    assert cli_client.resolve_server_url() == "http://127.0.0.1:9555"

    monkeypatch.setenv("AEGISPT_SERVER_URL", "https://scanner.internal:8443/")
    assert cli_client.resolve_server_url() == "https://scanner.internal:8443"


def test_resolve_api_token_from_dotenv_data_dir_and_non_editable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for var in ("AEGISPT_API_TOKEN", "AEGISPT_DATA_DIR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli_client, "_find_repo_root", lambda: None)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg_cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg_data"))
    monkeypatch.chdir(tmp_path)

    # 1. XDG fallback when non-editable and no CWD .env/data
    xdg_tok = tmp_path / "xdg_data" / "aegispt" / ".api_token"
    xdg_tok.parent.mkdir(parents=True, exist_ok=True)
    xdg_tok.write_text("tok_from_xdg\n", encoding="utf-8")
    assert cli_client.resolve_api_token() == "tok_from_xdg"

    # 2. Custom AEGISPT_DATA_DIR from .env
    custom_data = tmp_path / "custom_data"
    custom_data.mkdir()
    (custom_data / ".api_token").write_text("tok_from_custom_dir\n", encoding="utf-8")
    (tmp_path / ".env").write_text("AEGISPT_DATA_DIR=./custom_data\n", encoding="utf-8")
    assert cli_client.resolve_api_token() == "tok_from_custom_dir"

    # 3. Direct AEGISPT_API_TOKEN in .env
    (tmp_path / ".env").write_text('AEGISPT_API_TOKEN="tok_from_dotenv"\n', encoding="utf-8")
    assert cli_client.resolve_api_token() == "tok_from_dotenv"

    # 4. Process env takes top precedence
    monkeypatch.setenv("AEGISPT_API_TOKEN", "tok_from_env")
    assert cli_client.resolve_api_token() == "tok_from_env"


def test_default_env_path_non_editable_uses_xdg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli_client, "_find_repo_root", lambda: None)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.chdir(tmp_path)
    env_p, tmpl_p = cli_client.default_env_path()
    assert env_p == tmp_path / "xdg" / "aegispt" / ".env"
    assert tmpl_p is None


def test_client_ws_url_headers_trust_env_and_error_parsing() -> None:
    local_client = AegisClient(base_url="http://127.0.0.1:8443", token="secret-tok")
    assert local_client.ws_url("eng-1") == "ws://127.0.0.1:8443/ws/engagements/eng-1"
    assert "token=" not in local_client.ws_url("eng-1")
    assert local_client.headers == {"Authorization": "Bearer secret-tok"}
    assert local_client.ws_headers == {"Authorization": "Bearer secret-tok"}
    assert local_client.trust_env is False

    remote_client = AegisClient(base_url="https://api.example.org/base", token="secret-tok")
    assert remote_client.ws_url("eng-2") == "wss://api.example.org/base/ws/engagements/eng-2"
    assert remote_client.trust_env is True

    # Test pooled client + FastAPI JSON detail parsing + 401 hint + connection error
    calls: list[str] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/ok":
            return httpx.Response(200, json={"ok": True})
        if request.url.path == "/unauth":
            return httpx.Response(401, json={"detail": "Invalid bearer token"})
        if request.url.path == "/valerr":
            return httpx.Response(
                422, json={"detail": [{"loc": ["body", "name"], "msg": "field required"}]}
            )
        raise httpx.ConnectError("connection refused", request=request)

    with AegisClient(base_url="http://127.0.0.1:8443", token="tok") as c:
        c._client = httpx.Client(
            base_url=c.base_url,
            headers=c.headers,
            transport=httpx.MockTransport(transport_handler),
        )
        first_pool = c._client
        assert c.get("/ok").json() == {"ok": True}
        assert c._client is first_pool  # pooled reuse

        with pytest.raises(AegisAPIError) as exc_401:
            c.get("/unauth")
        assert exc_401.value.status_code == 401
        assert exc_401.value.is_connection_error is False
        assert "Invalid bearer token" in exc_401.value.message
        assert exc_401.value.hint and "AEGISPT_API_TOKEN" in exc_401.value.hint

        with pytest.raises(AegisAPIError) as exc_422:
            c.post("/valerr", json_body={})
        assert exc_422.value.status_code == 422
        assert "body.name: field required" in exc_422.value.message

        with pytest.raises(AegisAPIError) as exc_conn:
            c.get("/down")
        assert exc_conn.value.is_connection_error is True
        assert exc_conn.value.hint and "serve" in exc_conn.value.hint


# ---------------------------------------------------------------------------
# _parse_kv, serve, token, and doctor tests
# ---------------------------------------------------------------------------


def test_parse_kv_strict_validation() -> None:
    assert _parse_kv(["Authorization: Bearer abc", "X-Test: 1:2"], ":") == {
        "Authorization": "Bearer abc",
        "X-Test": "1:2",
    }
    assert _parse_kv(["session=xyz=1"], "=") == {"session": "xyz=1"}

    with pytest.raises(Exception, match="expected"):
        _parse_kv(["MalformedHeader"], ":", label="--auth-header")
    with pytest.raises(Exception, match="cannot be empty"):
        _parse_kv([" : value"], ":", label="--auth-header")


def test_serve_honors_settings_without_clobbering_env(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: dict[str, Any] = {}

    class DummySettings:
        host = "127.0.0.1"
        port = 9443

    monkeypatch.delenv("AEGISPT_HOST", raising=False)
    monkeypatch.delenv("AEGISPT_PORT", raising=False)
    monkeypatch.setattr("app.config.get_settings", lambda: DummySettings())
    monkeypatch.setattr(
        "uvicorn.run",
        lambda app_path, host, port, reload: recorded.update(
            {"app": app_path, "host": host, "port": port, "reload": reload}
        ),
    )

    res = runner.invoke(app, ["serve"])
    assert res.exit_code == 0, res.output
    assert recorded == {"app": "app.main:app", "host": "127.0.0.1", "port": 9443, "reload": False}
    assert "AEGISPT_PORT" not in cli_main.os.environ

    res_override = runner.invoke(app, ["serve", "--host", "127.0.0.2", "--port", "9001"])
    assert res_override.exit_code == 0, res_override.output
    assert recorded["host"] == "127.0.0.2"
    assert recorded["port"] == 9001


def test_serve_clears_settings_cache_on_host_port_override(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import get_settings

    monkeypatch.delenv("AEGISPT_HOST", raising=False)
    monkeypatch.delenv("AEGISPT_PORT", raising=False)
    get_settings.cache_clear()

    # Prime cache with default host/port before invoking `serve --host ... --port ...`
    initial = get_settings()
    assert initial.port != 9123

    observed: dict[str, Any] = {}

    def _fake_uvicorn_run(app_path: str, host: str, port: int, reload: bool) -> None:
        refreshed = get_settings()
        observed.update(
            {
                "app": app_path,
                "host": host,
                "port": port,
                "reload": reload,
                "settings_host": refreshed.host,
                "settings_port": refreshed.port,
            }
        )

    monkeypatch.setattr("uvicorn.run", _fake_uvicorn_run)
    try:
        res = runner.invoke(app, ["serve", "--host", "0.0.0.0", "--port", "9123"])
        assert res.exit_code == 0, res.output
        assert observed == {
            "app": "app.main:app",
            "host": "0.0.0.0",
            "port": 9123,
            "reload": False,
            "settings_host": "0.0.0.0",
            "settings_port": 9123,
        }
    finally:
        monkeypatch.delenv("AEGISPT_HOST", raising=False)
        monkeypatch.delenv("AEGISPT_PORT", raising=False)
        get_settings.cache_clear()


def test_token_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "resolve_api_token", lambda: "aegis_demo_token_xyz")
    res = runner.invoke(app, ["token"])
    assert res.exit_code == 0, res.output
    assert "aegis_demo_token_xyz" in res.output


def test_doctor_online_offline_fallback_and_no_swallow_on_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    doctor_payload = {
        "tools_available": 1,
        "tools_total": 1,
        "tools": [{"name": "http_probe", "tier": 1, "available": True, "resolved_path": "builtin"}],
        "llm": {"provider": "ollama", "base_url": "http://127.0.0.1:11434", "reachable": True, "models": ["qwen2.5:3b"]},
        "knowledge_playbooks": 10,
    }

    # Online JSON
    fake_ok = FakeClient({("GET", "/api/v1/system/doctor"): doctor_payload})
    monkeypatch.setattr(cli_main, "AegisClient", lambda: fake_ok)
    res_json = runner.invoke(app, ["doctor", "--json"])
    assert res_json.exit_code == 0, res_json.output
    assert json.loads(res_json.output)["tools_available"] == 1
    assert fake_ok.closed is True

    # 401 MUST NOT fall back to offline mode
    fake_401 = FakeClient(
        {
            ("GET", "/api/v1/system/doctor"): AegisAPIError(
                "HTTP 401: Unauthorized",
                status_code=401,
                detail="Unauthorized",
                is_connection_error=False,
            )
        }
    )
    monkeypatch.setattr(cli_main, "AegisClient", lambda: fake_401)
    res_401 = runner.invoke(app, ["doctor"])
    assert res_401.exit_code == 1
    assert "401" in res_401.output

    # Connection error DOES fall back to offline diagnostics
    fake_down = FakeClient(
        {
            ("GET", "/api/v1/system/doctor"): AegisAPIError(
                "Could not connect", is_connection_error=True
            )
        }
    )
    monkeypatch.setattr(cli_main, "AegisClient", lambda: fake_down)
    async def _fake_list_models(_cfg: Any) -> dict[str, Any]:
        return {"provider": "ollama", "base_url": "http://127.0.0.1:11434", "reachable": False, "error": "offline"}

    monkeypatch.setattr("app.llm.router.llm_router.list_models", _fake_list_models)
    res_offline = runner.invoke(app, ["doctor"])
    assert res_offline.exit_code == 0, res_offline.output
    assert "offline diagnostics" in res_offline.output.lower()


# ---------------------------------------------------------------------------
# Engagement, lifecycle, tool runs, approvals, snapshots, findings, llm-profiles
# ---------------------------------------------------------------------------


def test_engagement_commands_and_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeClient(
        {
            ("GET", "/api/v1/engagements"): {
                "engagements": [
                    {
                        "id": "eng-1",
                        "name": "Lab [bold]Target[/bold]",
                        "autonomy_mode": "tiered",
                        "status": "idle",
                        "scope": {"allowed_urls": ["http://127.0.0.1:3000"]},
                    }
                ]
            },
            ("POST", "/api/v1/engagements"): {
                "id": "eng-2",
                "name": "New Lab",
                "autonomy_mode": "copilot",
                "max_steps": 12,
            },
            ("DELETE", "/api/v1/engagements/eng-1"): {"deleted": "eng-1"},
        }
    )
    monkeypatch.setattr(cli_main, "AegisClient", lambda: fake)

    res_list = runner.invoke(app, ["engagement", "list"])
    assert res_list.exit_code == 0, res_list.output
    assert "eng-1" in res_list.output

    res_create = runner.invoke(
        app,
        [
            "engagement",
            "create",
            "-n",
            "New Lab",
            "-u",
            "http://127.0.0.1:3000",
            "--allowed-cidr",
            "127.0.0.1/32",
            "--exclude-host",
            "admin.local",
            "-H",
            "Authorization: Bearer tok",
            "-C",
            "sid=abc",
            "--mode",
            "copilot",
            "--max-steps",
            "12",
            "--no-tier2-auto",
            "--llm-profile-id",
            "prof-1",
            "--max-concurrency",
            "3",
            "--allow-private-ips",
        ],
    )
    assert res_create.exit_code == 0, res_create.output
    post_call = [c for c in fake.calls if c[0] == "POST"][0]
    body = post_call[2]["json"]
    assert body["autonomy_mode"] == "copilot"
    assert body["max_steps"] == 12
    assert body["tier2_auto"] is False
    assert body["llm_profile_id"] == "prof-1"
    assert body["scope"]["allowed_cidrs"] == ["127.0.0.1/32"]
    assert body["scope"]["excluded_hosts"] == ["admin.local"]
    assert body["scope"]["max_concurrency"] == 3
    assert body["scope"]["custom_headers"] == {"Authorization": "Bearer tok"}
    assert body["scope"]["auth_cookies"] == {"sid": "abc"}

    # Invalid mode and malformed header fail cleanly
    res_bad_mode = runner.invoke(
        app, ["engagement", "create", "-n", "Bad", "-u", "http://x", "--mode", "turbo"]
    )
    assert res_bad_mode.exit_code != 0

    res_bad_hdr = runner.invoke(
        app, ["engagement", "create", "-n", "Bad", "-u", "http://x", "-H", "NoColonHere"]
    )
    assert res_bad_hdr.exit_code != 0

    # Delete supports latest + confirmation abort / --yes
    res_abort = runner.invoke(app, ["engagement", "delete", "latest"], input="n\n")
    assert res_abort.exit_code != 0
    res_del = runner.invoke(app, ["engagement", "delete", "latest", "--yes"])
    assert res_del.exit_code == 0, res_del.output
    assert any(c[0] == "DELETE" and c[1] == "/api/v1/engagements/eng-1" for c in fake.calls)


def test_operator_parity_commands(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = FakeClient(
        {
            ("GET", "/api/v1/engagements"): {
                "engagements": [{"id": "eng-1", "name": "Demo"}]
            },
            ("POST", "/api/v1/engagements/eng-1/pause"): {"engagement_id": "eng-1", "status": "paused"},
            ("POST", "/api/v1/engagements/eng-1/resume"): {"engagement_id": "eng-1", "status": "running"},
            ("POST", "/api/v1/engagements/eng-1/stop"): {"engagement_id": "eng-1", "status": "stopped"},
            ("POST", "/api/v1/engagements/eng-1/run-tool"): {
                "tool_run_id": "run-9",
                "status": "completed",
                "duration_ms": 145,
                "summary": "Found [red]1[/red] header issue",
            },
            ("GET", "/api/v1/engagements/eng-1/approvals"): {
                "approvals": [
                    {
                        "id": "apr-1",
                        "tool_name": "sqlmap",
                        "tier": 3,
                        "status": "pending",
                        "target": "http://127.0.0.1:3000/api",
                        "risk_summary": "Active SQLi probe",
                    }
                ]
            },
            ("POST", "/api/v1/approvals/apr-1/decide"): {"id": "apr-1", "status": "approved"},
            ("GET", "/api/v1/engagements/eng-1"): {
                "id": "eng-1",
                "tool_runs": [
                    {
                        "id": "run-9",
                        "tool_name": "http_probe",
                        "tier": 1,
                        "status": "completed",
                        "duration_ms": 50,
                        "target": "http://127.0.0.1:3000",
                    }
                ],
                "snapshots": [
                    {
                        "id": "snap-1",
                        "label": "initial",
                        "assets_count": 1,
                        "endpoints_count": 5,
                        "findings_count": 2,
                        "created_at": "2026-01-01T00:00:00Z",
                    }
                ],
                "attack_chains": [
                    {
                        "id": "ch-1",
                        "title": "JWT + BOLA [critical]",
                        "severity": "critical",
                        "target_url": "http://127.0.0.1:3000",
                        "risk_summary": "Full account takeover",
                        "steps": ["1. Forge token", "2. Access /api/users/2"],
                    }
                ],
                "checklist_items": [
                    {"skill_title": "Auth", "status": "tested", "item_text": "Check JWT alg:none"}
                ],
            },
            ("GET", "/api/v1/engagements/eng-1/runs/run-9/log"): {
                "log": "raw output with [bold red]untrusted[/bold red] markup"
            },
            ("POST", "/api/v1/engagements/eng-1/snapshots"): {
                "id": "snap-2",
                "label": "pre-fix",
                "assets_count": 1,
                "endpoints_count": 6,
                "findings_count": 2,
            },
            ("GET", "/api/v1/engagements/eng-1/findings"): {
                "findings": [
                    {
                        "id": "f-1",
                        "severity": "high",
                        "title": "SQL Injection [CWE-89]",
                        "target_url": "http://127.0.0.1:3000/search?q=1",
                        "parameter": "q",
                        "tool_source": "sqlmap",
                        "status": "open",
                    }
                ]
            },
            ("PATCH", "/api/v1/findings/f-1"): {
                "id": "f-1",
                "status": "confirmed",
                "severity": "critical",
            },
            ("POST", "/api/v1/findings/f-1/reverify"): {
                "finding_id": "f-1",
                "status": "open",
                "still_present": None,
                "manual_reverify_required": True,
                "message": "sqlmap findings require manual operator reverification.",
            },
            ("GET", "/api/v1/llm-profiles"): {
                "profiles": [
                    {
                        "id": "prof-1",
                        "name": "Local Ollama",
                        "provider": "ollama",
                        "base_url": "http://127.0.0.1:11434",
                        "fast_model": "qwen2.5:1.5b",
                        "reasoning_model": "qwen2.5:3b",
                        "is_default": True,
                    }
                ]
            },
            ("POST", "/api/v1/llm-profiles"): {
                "id": "prof-2",
                "name": "Cloud",
                "provider": "ollama",
                "base_url": "https://ollama.com",
                "is_default": False,
            },
            ("DELETE", "/api/v1/llm-profiles/prof-2"): {"deleted": "prof-2"},
            ("POST", "/api/v1/llm-profiles/discover"): {
                "reachable": True,
                "models": ["qwen2.5:3b"],
            },
            ("GET", "/api/v1/engagements/eng-1/hypotheses"): {
                "hypotheses": [
                    {
                        "status": "confirmed",
                        "confidence": "high",
                        "cwe_id": "CWE-89",
                        "title": "SQLi in search",
                        "target_url": "http://127.0.0.1:3000/search",
                    }
                ]
            },
            ("GET", "/api/v1/engagements/eng-1/diff"): {
                "has_diff": True,
                "baseline": {"label": "initial"},
                "current": {"label": "pre-fix"},
                "new_assets": [],
                "new_endpoints": ["GET /api/new"],
                "new_findings": [],
                "resolved_findings": [],
                "new_open_ports": [],
            },
            ("POST", "/api/v1/engagements/eng-1/repeater"): {
                "status_code": 200,
                "duration_ms": 12,
                "final_url": "http://127.0.0.1:3000/api",
                "headers": {"content-type": "application/json"},
                "body": ("A" * 2500) + "\n[not-markup]",
                "curl_command": "curl -i -s -X GET 'http://127.0.0.1:3000/api'",
            },
            ("POST", "/api/v1/engagements/eng-1/steer"): {
                "operator_hints": ["Focus on /api/v2/admin"]
            },
            ("POST", "/api/v1/engagements/eng-1/chains/synthesize"): {"synthesized": 1},
            ("GET", "/api/v1/engagements/eng-1/report"): FakeResponse(
                text='{"report":"[raw-not-rich]","line":"' + ("x" * 120) + '"}'
            ),
        }
    )
    monkeypatch.setattr(cli_main, "AegisClient", lambda: fake)

    assert runner.invoke(app, ["pause"]).exit_code == 0
    assert runner.invoke(app, ["resume"]).exit_code == 0
    assert runner.invoke(app, ["stop"]).exit_code == 0

    res_tool = runner.invoke(
        app,
        ["run-tool", "http_probe", "http://127.0.0.1:3000", "--args", '{"mode":"passive_audit"}'],
    )
    assert res_tool.exit_code == 0, res_tool.output
    assert "run-9" in res_tool.output

    assert runner.invoke(app, ["run-tool", "http_probe", "http://127.0.0.1:3000", "--args", "not-json"]).exit_code != 0
    assert runner.invoke(app, ["run-tool", "http_probe", "http://127.0.0.1:3000", "--args", "[1,2]"]).exit_code != 0

    assert runner.invoke(app, ["runs"]).exit_code == 0
    res_log = runner.invoke(app, ["runs", "eng-1", "--log", "run-9"])
    assert res_log.exit_code == 0, res_log.output
    assert "[bold red]untrusted[/bold red]" in res_log.output

    assert runner.invoke(app, ["approvals"]).exit_code == 0
    assert runner.invoke(app, ["approvals", "list", "--status", "pending"]).exit_code == 0
    assert runner.invoke(app, ["approvals", "decide", "apr-1", "-d", "approved"]).exit_code == 0
    assert runner.invoke(app, ["approvals", "decide", "apr-1", "-d", "modified"]).exit_code != 0

    assert runner.invoke(app, ["snapshots"]).exit_code == 0
    res_snap = runner.invoke(app, ["snapshots", "create", "--label", "pre-fix"])
    assert res_snap.exit_code == 0, res_snap.output
    snap_call = [c for c in fake.calls if c[1].endswith("/snapshots")][0]
    assert snap_call[2]["params"] == {"label": "pre-fix"}

    assert runner.invoke(app, ["findings"]).exit_code == 0
    assert runner.invoke(app, ["findings", "eng-1"]).exit_code == 0
    assert runner.invoke(app, ["findings", "list", "--severity", "high"]).exit_code == 0
    res_triage = runner.invoke(
        app, ["findings", "triage", "f-1", "--status", "confirmed", "--severity", "critical"]
    )
    assert res_triage.exit_code == 0, res_triage.output
    res_reverify = runner.invoke(app, ["findings", "reverify", "f-1"])
    assert res_reverify.exit_code == 0, res_reverify.output
    assert "Manual reverification required" in res_reverify.output

    assert runner.invoke(app, ["llm-profiles"]).exit_code == 0
    res_lp_create = runner.invoke(
        app,
        [
            "llm-profiles",
            "create",
            "-n",
            "Cloud",
            "-p",
            "ollama",
            "--url",
            "https://ollama.com",
            "--fast-model",
            "qwen3-next:80b",
            "--reasoning-model",
            "qwen3-coder:480b",
            "--api-key-stdin",
        ],
        input="stdin-key\n",
    )
    assert res_lp_create.exit_code == 0, res_lp_create.output
    assert runner.invoke(app, ["llm-profiles", "delete", "prof-2", "--yes"]).exit_code == 0
    assert runner.invoke(app, ["llm-profiles", "discover"]).exit_code == 0

    assert runner.invoke(app, ["hypotheses"]).exit_code == 0
    assert runner.invoke(app, ["diff", "--base", "snap-1", "--target", "snap-2"]).exit_code == 0
    assert runner.invoke(app, ["steer", "Focus on /api/v2/admin"]).exit_code == 0
    assert runner.invoke(app, ["chains"]).exit_code == 0
    assert runner.invoke(app, ["checklist"]).exit_code == 0

    # Repeat: headers, flags, truncation notice, curl_command, and --full-body
    res_rep = runner.invoke(
        app,
        [
            "repeat",
            "eng-1",
            "http://127.0.0.1:3000/api",
            "-H",
            "X-Role: user",
            "--follow-redirects",
            "--no-auth",
        ],
    )
    assert res_rep.exit_code == 0, res_rep.output
    assert "truncated" in res_rep.output
    assert "curl -i -s -X GET" in res_rep.output
    assert "content-type: application/json" in res_rep.output

    res_rep_full = runner.invoke(
        app, ["repeat", "eng-1", "http://127.0.0.1:3000/api", "--full-body"]
    )
    assert res_rep_full.exit_code == 0, res_rep_full.output
    assert "[not-markup]" in res_rep_full.output

    # Report raw stdout (exact, unwrapped JSON; status diagnostic goes to stderr)
    res_rep_stdout = runner.invoke(app, ["report", "latest", "--format", "json"])
    assert res_rep_stdout.exit_code == 0, res_rep_stdout.output
    parsed_stdout = json.loads(res_rep_stdout.stdout)
    assert parsed_stdout["report"] == "[raw-not-rich]"
    assert len(parsed_stdout["line"]) == 120

    # Report --out creates missing parent directories
    nested_out = tmp_path / "reports" / "nested" / "out.json"
    res_rep_file = runner.invoke(
        app, ["report", "eng-1", "--format", "json", "--out", str(nested_out)]
    )
    assert res_rep_file.exit_code == 0, res_rep_file.output
    assert nested_out.is_file()
    assert json.loads(nested_out.read_text(encoding="utf-8"))["report"] == "[raw-not-rich]"


def test_clean_api_error_exit_code_no_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeClient(
        {
            ("GET", "/api/v1/engagements"): AegisAPIError(
                "HTTP 500: Internal failure",
                status_code=500,
                detail="Internal failure",
                is_connection_error=False,
            )
        }
    )
    monkeypatch.setattr(cli_main, "AegisClient", lambda: fake)
    res = runner.invoke(app, ["engagement", "list"])
    assert res.exit_code == 1
    assert "Internal failure" in res.output
    assert "Traceback" not in res.output


# ---------------------------------------------------------------------------
# WebSocket _stream_and_approve tests (replay, auth headers, JSON retry, 409)
# ---------------------------------------------------------------------------


def test_ws_stream_ignores_replayed_events_validates_json_and_handles_409(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frames = [
        # Replayed terminal & approval frames must be ignored (neither break nor prompt)
        json.dumps(
            {
                "event_type": "approval_required",
                "agent_name": "orchestrator",
                "message": "Old approval",
                "replayed": True,
                "payload": {"approval_id": "apr-old", "tool_name": "sqlmap", "tier": 3},
            }
        ),
        json.dumps(
            {
                "event_type": "engagement_finished",
                "agent_name": "orchestrator",
                "message": "Previous run finished",
                "replayed": True,
            }
        ),
        # Untrusted Rich markup in tool output must not crash
        json.dumps(
            {
                "event_type": "tool_output",
                "agent_name": "ffuf",
                "message": "Found [/invalid] [bold]path",
                "replayed": False,
            }
        ),
        # Live approval 1: operator edits with bad JSON -> non-dict JSON -> valid JSON dict
        json.dumps(
            {
                "event_type": "approval_required",
                "agent_name": "orchestrator",
                "message": "Approve http_probe",
                "replayed": False,
                "payload": {
                    "approval_id": "apr-live-1",
                    "tool_name": "http_probe",
                    "tier": 3,
                    "target": "http://127.0.0.1:3000",
                    "proposed_args": {"mode": "ssti_probe"},
                    "argv_preview": ["http_probe", "[evil]"],
                },
            }
        ),
        # Live approval 2: backend returns HTTP 409 (already resolved in Web UI)
        json.dumps(
            {
                "event_type": "approval_required",
                "agent_name": "orchestrator",
                "message": "Approve sqlmap",
                "replayed": False,
                "payload": {
                    "approval_id": "apr-live-2",
                    "tool_name": "sqlmap",
                    "tier": 3,
                    "target": "http://127.0.0.1:3000",
                    "proposed_args": {},
                },
            }
        ),
        # Live terminal event stops the loop cleanly
        json.dumps(
            {
                "event_type": "engagement_finished",
                "agent_name": "orchestrator",
                "message": "Done",
                "replayed": False,
            }
        ),
    ]

    connect_capture: dict[str, Any] = {}

    class FakeWS:
        def __init__(self) -> None:
            self._idx = 0

        async def __aenter__(self) -> FakeWS:
            return self

        async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
            return None

        async def recv(self) -> str:
            if self._idx >= len(frames):
                raise asyncio.CancelledError
            item = frames[self._idx]
            self._idx += 1
            return item

    def fake_ws_connect(uri: str, **kwargs: Any) -> FakeWS:
        connect_capture["uri"] = uri
        connect_capture["kwargs"] = kwargs
        return FakeWS()

    prompt_answers = iter(
        [
            "e",  # live approval 1 -> edit
            "{bad-json",  # invalid JSON -> retry
            "[1, 2, 3]",  # not a JSON object -> retry
            '{"mode": "passive_audit"}',  # valid dict -> submitted
            "a",  # live approval 2 -> approve -> 409 handled gracefully
        ]
    )
    monkeypatch.setattr(cli_main.websockets, "connect", fake_ws_connect)
    monkeypatch.setattr(cli_main.Prompt, "ask", lambda *a, **kw: next(prompt_answers))

    fake = FakeClient(
        {
            ("POST", "/api/v1/approvals/apr-live-1/decide"): {"id": "apr-live-1", "status": "modified"},
            ("POST", "/api/v1/approvals/apr-live-2/decide"): AegisAPIError(
                "HTTP 409: Approval already resolved",
                status_code=409,
                detail="Approval already resolved",
                is_connection_error=False,
            ),
        }
    )

    asyncio.run(_stream_and_approve(fake, "eng-42"))

    assert connect_capture["uri"] == "ws://127.0.0.1:8443/ws/engagements/eng-42"
    assert "token=" not in connect_capture["uri"]
    hdrs = connect_capture["kwargs"].get("additional_headers") or connect_capture["kwargs"].get(
        "extra_headers"
    )
    assert hdrs == {"Authorization": "Bearer tok_test_123"}

    posted_paths = [c[1] for c in fake.calls if c[0] == "POST"]
    assert "/api/v1/approvals/apr-old/decide" not in posted_paths
    assert posted_paths == [
        "/api/v1/approvals/apr-live-1/decide",
        "/api/v1/approvals/apr-live-2/decide",
    ]
    mod_call = fake.calls[0][2]["json"]
    assert mod_call == {"decision": "modified", "modified_args": {"mode": "passive_audit"}}


def test_run_calls_start_while_attach_does_not(monkeypatch: pytest.MonkeyPatch) -> None:
    streamed: list[str] = []

    async def _fake_stream(_client: Any, eng_id: str) -> None:
        streamed.append(eng_id)

    fake = FakeClient(
        {
            ("GET", "/api/v1/engagements"): {"engagements": [{"id": "eng-7", "name": "Live"}]},
            ("POST", "/api/v1/engagements/eng-7/start"): {"engagement_id": "eng-7", "status": "running"},
        }
    )
    monkeypatch.setattr(cli_main, "AegisClient", lambda: fake)
    monkeypatch.setattr(cli_main, "_stream_and_approve", _fake_stream)

    res_attach = runner.invoke(app, ["attach", "latest"])
    assert res_attach.exit_code == 0, res_attach.output
    assert streamed == ["eng-7"]
    assert not any(c[1].endswith("/start") for c in fake.calls)

    res_run = runner.invoke(app, ["run", "latest"])
    assert res_run.exit_code == 0, res_run.output
    assert streamed == ["eng-7", "eng-7"]
    assert any(c[0] == "POST" and c[1] == "/api/v1/engagements/eng-7/start" for c in fake.calls)


# ---------------------------------------------------------------------------
# Packaging metadata & Docker lab hardening tests
# ---------------------------------------------------------------------------


def test_pyproject_packaging_metadata_and_package_data() -> None:
    pyproject_path = AEGISPT_ROOT / "pyproject.toml"
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))

    deps = data["project"]["dependencies"]
    dep_names = {d.split(">=")[0].split("[")[0].strip().lower() for d in deps}
    assert "cryptography" in dep_names
    assert "defusedxml" in dep_names
    assert "jinja2" not in dep_names

    opt = data["project"]["optional-dependencies"]
    assert any(d.lower().startswith("playwright") for d in opt["spa"])
    assert any(d.lower().startswith("ruff") for d in opt["dev"])
    assert any(d.lower().startswith("pytest") for d in opt["dev"])

    find_cfg = data["tool"]["setuptools"]["packages"]["find"]
    assert find_cfg["where"] == ["backend", "cli"]
    assert "tests" in find_cfg["exclude"]
    assert "tests.*" in find_cfg["exclude"]

    # Verify setuptools package discovery excludes top-level tests
    discovered: list[str] = []
    for where_dir in find_cfg["where"]:
        discovered.extend(
            PackageFinder.find(where=str(AEGISPT_ROOT / where_dir), exclude=find_cfg["exclude"])
        )
    assert "app" in discovered
    assert "aegispt_cli" in discovered
    assert not any(pkg == "tests" or pkg.startswith("tests.") for pkg in discovered)

    pkg_data = data["tool"]["setuptools"]["package-data"]
    assert pkg_data["app.knowledge"] == ["playbooks.json", "skills/*.md"]

    kb_dir = AEGISPT_ROOT / "backend" / "app" / "knowledge"
    assert (kb_dir / "playbooks.json").is_file()
    assert len(list((kb_dir / "skills").glob("*.md"))) >= 1


def test_docker_compose_lab_hardening() -> None:
    compose_path = AEGISPT_ROOT / "lab" / "docker-compose.lab.yml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    svc = compose["services"]["juice-shop"]

    assert svc["image"] == "bkimminich/juice-shop:${JUICE_SHOP_TAG:-v17.3.0}"
    assert "ALL" in svc["cap_drop"]
    assert "no-new-privileges:true" in svc["security_opt"]
    assert svc["mem_limit"] == "1g"
    assert svc["pids_limit"] == 256
    assert svc["restart"] == "no"
    assert "healthcheck" in svc
    assert svc["logging"]["driver"] == "json-file"
    assert any("${JUICE_SHOP_PORT:-3000}:3000" in p for p in svc["ports"])
