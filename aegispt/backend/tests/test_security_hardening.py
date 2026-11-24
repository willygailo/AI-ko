"""Security hardening regression tests: ScopePolicy, Auth/WS tickets, SSRF, OOB, Redactor, Permissions."""
from __future__ import annotations

import asyncio
import os
import shlex
import sqlite3
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.api import oob as oob_module
from app.config import get_settings
from app.core.auth import ws_ticket_store
from app.core.redactor import SecretRedactor
from app.core.scope import ScopePolicy, ScopeViolationError
from app.core.vault import encrypt_str, reset_vault_cache
from app.llm.router import LLMProfileConfig, LLMRouter, validate_llm_base_url
from app.main import create_app


def test_scope_policy_effective_ports_unquote_excluded_and_cookies():
    # Effective port enforcement: omitting port (80) cannot bypass explicit :3000 allowlist
    lab = ScopePolicy(allowed_urls=["http://127.0.0.1:3000"], allow_private_ips=True)
    assert lab.validate_target("http://127.0.0.1:3000/rest/products", resolve_dns=False)
    assert lab.validate_target("127.0.0.1:3000", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        lab.validate_target("http://127.0.0.1/admin", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        lab.validate_target("127.0.0.1/admin", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        lab.validate_target("127.0.0.1", resolve_dns=False)

    # Default HTTPS port 443 cannot be bypassed by :8443 or http://
    https_only = ScopePolicy(allowed_urls=["https://example.com"])
    assert https_only.validate_target("https://example.com:443/api", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        https_only.validate_target("https://example.com:8443/api", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        https_only.validate_target("http://example.com/api", resolve_dns=False)

    # URL-encoded traversal & schemeless path exclusions
    path_scoped = ScopePolicy(
        allowed_urls=["https://example.com/api"],
        excluded_paths=["/api/logout", "/admin"],
    )
    with pytest.raises(ScopeViolationError):
        path_scoped.validate_target("https://example.com/api/%2e%2e/admin", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        path_scoped.validate_target("https://example.com/api/v1/%2e%2e%2flogout", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        path_scoped.validate_target("https://example.com/api/%252e%252e/admin", resolve_dns=False)

    dom_scoped = ScopePolicy(
        allowed_domains=["example.com"],
        excluded_paths=["/logout"],
    )
    with pytest.raises(ScopeViolationError):
        dom_scoped.validate_target("example.com/logout", resolve_dns=False)

    # Cookie CRLF / control-char injection
    with pytest.raises(ScopeViolationError):
        ScopePolicy(
            allowed_domains=["example.com"],
            auth_cookies={"sid": "abc\r\nX-Injected: 1"},
        )
    with pytest.raises(ScopeViolationError):
        ScopePolicy(
            allowed_domains=["example.com"],
            secondary_cookies={"bad\nkey": "val"},
        )


def test_scope_policy_validate_target_async():
    policy = ScopePolicy(allowed_domains=["rebind.example.com"], allow_private_ips=False)

    async def _run():
        assert (
            await policy.validate_target_async(
                "https://rebind.example.com/ok",
                resolve_dns=True,
                dns_resolver=lambda _h: ["93.184.216.34"],
            )
            == "https://rebind.example.com/ok"
        )
        with pytest.raises(ScopeViolationError):
            await policy.validate_target_async(
                "https://rebind.example.com/meta",
                resolve_dns=True,
                dns_resolver=lambda _h: ["169.254.169.254"],
            )

    asyncio.run(_run())


def test_secret_redactor_json_pem_api_key_and_set_cookie():
    r = SecretRedactor()
    pem_begin = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
    pem_end = "-----" + "END RSA PRIVATE KEY" + "-----"
    pem_block = f"{pem_begin}\nMIIEowIBAAKCAQEAtestkeydata1234567890\n{pem_end}"
    sample = (
        '{"Authorization": "Bearer superSecretBearerToken9999", '
        '"X-API-Key": "my-secret-x-api-key-val", '
        '"Set-Cookie": "sid=secret_session_cookie_123; HttpOnly; Path=/", '
        '"token": "aegis_abcdefghijklmnopqrstuvwxyz123456"} '
        + pem_block
    )
    redacted = r.redact(sample)
    assert "superSecretBearerToken9999" not in redacted
    assert "my-secret-x-api-key-val" not in redacted
    assert "secret_session_cookie_123" not in redacted
    assert "aegis_abcdefghijklmnopqrstuvwxyz123456" not in redacted
    assert "MIIEowIBAAKCAQEAtestkeydata1234567890" not in redacted
    assert r.restore(redacted) == sample


def test_llm_ssrf_validation_and_offline_mode(monkeypatch):
    # Valid local and remote HTTP(S) URLs
    assert validate_llm_base_url("http://127.0.0.1:11434/", resolve_dns=False) == "http://127.0.0.1:11434"
    assert validate_llm_base_url("https://api.example.com/v1/", resolve_dns=False) == "https://api.example.com/v1"

    # Blocked schemes and cloud metadata / link-local hosts
    for bad_url in (
        "file:///etc/passwd",
        "ftp://127.0.0.1:21",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.170.2/v2/credentials",
        "http://169.254.1.2:8080",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://[fd00:ec2::254]/latest",
        "http://[::ffff:169.254.169.254]/",
        "http://100.100.100.200/latest",
    ):
        with pytest.raises(ValueError):
            validate_llm_base_url(bad_url, resolve_dns=False)

    # Offline mode blocks outbound calls cleanly
    monkeypatch.setenv("AEGISPT_LLM_MODE", "offline")
    get_settings.cache_clear()
    try:
        async def _check_offline():
            router = LLMRouter(timeout=2.0)
            cfg = LLMProfileConfig(
                name="local",
                provider="ollama",
                base_url="http://127.0.0.1:11434",
                fast_model="m1",
                reasoning_model="m2",
            )
            with pytest.raises(RuntimeError, match="offline"):
                await router.complete(
                    profile=cfg,
                    messages=[{"role": "user", "content": "hi"}],
                )
            models = await router.list_models(cfg)
            assert models["reachable"] is False
            assert models.get("offline") is True
            await router.aclose()

        asyncio.run(_check_offline())
    finally:
        get_settings.cache_clear()


def test_storage_permissions_and_atomic_secret_creation(tmp_path: Path, monkeypatch):
    data_dir = tmp_path / "secure_data"
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(data_dir))
    monkeypatch.delenv("AEGISPT_API_TOKEN", raising=False)
    get_settings.cache_clear()
    reset_vault_cache()

    try:
        settings = get_settings()
        tok1 = settings.get_or_create_api_token()
        tok2 = settings.get_or_create_api_token()
        assert tok1 == tok2
        assert tok1.startswith("aegis_")

        enc = encrypt_str("secret-value")
        assert enc.startswith("enc:fernet:")

        assert stat.S_IMODE(os.stat(data_dir).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(data_dir / ".api_token").st_mode) == 0o600
        assert stat.S_IMODE(os.stat(data_dir / ".master.key").st_mode) == 0o600
    finally:
        reset_vault_cache()
        get_settings.cache_clear()


def test_auth_ws_tickets_ssrf_oob_log_confinement_and_repeater_quoting(
    tmp_path: Path, monkeypatch, capsys
):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AEGISPT_API_TOKEN", "hardened_tok_999")
    monkeypatch.delenv("AEGISPT_PRINT_TOKEN", raising=False)
    get_settings.cache_clear()
    ws_ticket_store.clear()
    oob_module.reset_oob_rate_limits()

    class EchoTarget(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            return

    httpd = HTTPServer(("127.0.0.1", 0), EchoTarget)
    t_port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    try:
        app = create_app()
        headers = {"Authorization": "Bearer hardened_tok_999"}
        with TestClient(app) as client:
            # Startup stdout must NOT leak raw bearer token when AEGISPT_PRINT_TOKEN is unset
            captured = capsys.readouterr()
            assert "hardened_tok_999" not in captured.out

            # REST must reject ?token= query parameter
            assert client.get("/api/v1/engagements?token=hardened_tok_999").status_code == 401
            assert client.get("/api/v1/engagements", headers={"X-API-Key": "hardened_tok_999"}).status_code == 200

            # DB file permissions should be 0600 on fresh startup (including knowledge.db)
            assert stat.S_IMODE(os.stat(tmp_path / "aegispt.db").st_mode) == 0o600
            assert stat.S_IMODE(os.stat(tmp_path / "knowledge.db").st_mode) == 0o600

            # LLM SSRF endpoints must reject metadata URLs
            bad_profile = client.post(
                "/api/v1/llm-profiles",
                headers=headers,
                json={
                    "name": "Evil Meta",
                    "provider": "ollama",
                    "base_url": "http://169.254.169.254/latest",
                    "fast_model": "m1",
                    "reasoning_model": "m2",
                },
            )
            assert bad_profile.status_code == 400

            bad_discover = client.post(
                "/api/v1/llm-profiles/discover",
                headers=headers,
                json={"provider": "ollama", "base_url": "http://metadata.google.internal"},
            )
            assert bad_discover.status_code == 400

            # Create engagement for WS, Repeater, OOB, and Log Confinement checks
            eng = client.post(
                "/api/v1/engagements",
                headers=headers,
                json={
                    "name": "Hardening Eng",
                    "scope": {
                        "allowed_urls": [f"http://127.0.0.1:{t_port}"],
                        "allow_private_ips": True,
                    },
                },
            ).json()
            eng_id = eng["id"]

            # WS rejects ?token= with 4401
            with pytest.raises(WebSocketDisconnect) as exc_info:
                with client.websocket_connect(f"/api/v1/engagements/{eng_id}/ws?token=hardened_tok_999"):
                    pass
            assert exc_info.value.code == 4401

            # WS ticket is single-use
            t_resp = client.post("/api/v1/system/ws-ticket", headers=headers)
            assert t_resp.status_code == 200
            ticket = t_resp.json()["ticket"]
            assert t_resp.json()["expires_in"] == 30

            with client.websocket_connect(f"/api/v1/engagements/{eng_id}/ws?ticket={ticket}") as ws:
                ws.send_text("ping")
                assert ws.receive_json()["event_type"] == "pong"

            # Reusing the same ticket must fail with 4401
            with pytest.raises(WebSocketDisconnect) as exc_reuse:
                with client.websocket_connect(f"/api/v1/engagements/{eng_id}/ws?ticket={ticket}"):
                    pass
            assert exc_reuse.value.code == 4401

            # Repeater shell injection quoting + header CRLF rejection
            bad_hdr = client.post(
                f"/api/v1/engagements/{eng_id}/repeater",
                headers=headers,
                json={
                    "method": "POST",
                    "url": f"http://127.0.0.1:{t_port}/submit",
                    "headers": {"X-Test": "abc\r\nEvil: 1"},
                },
            )
            assert bad_hdr.status_code == 400

            payload = "a'$(id)`uname`; rm -rf /"
            rep = client.post(
                f"/api/v1/engagements/{eng_id}/repeater",
                headers=headers,
                json={
                    "method": "POST",
                    "url": f"http://127.0.0.1:{t_port}/submit",
                    "headers": {"X-Note": "foo'bar"},
                    "body": payload,
                },
            )
            assert rep.status_code == 200
            curl_cmd = rep.json()["curl_command"]
            tokens = shlex.split(curl_cmd)
            assert payload in tokens
            assert "X-Note: foo'bar" in tokens

            # Log path confinement blocks reading files outside artifacts_dir
            outside_file = tmp_path / "secret_outside.txt"
            outside_file.write_text("TOP_SECRET_DATA", encoding="utf-8")
            with sqlite3.connect(tmp_path / "aegispt.db") as conn:
                conn.execute(
                    "INSERT INTO tool_runs (id, engagement_id, tool_name, tier, target, args, argv, status, raw_log_path, summary, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "run_escape",
                        eng_id,
                        "http_probe",
                        1,
                        f"http://127.0.0.1:{t_port}",
                        "{}",
                        "[]",
                        "completed",
                        str(outside_file),
                        "{}",
                        "2026-01-01 00:00:00",
                    ),
                )
                conn.commit()
            log_resp = client.get(f"/api/v1/engagements/{eng_id}/runs/run_escape/log", headers=headers)
            assert log_resp.status_code == 403

            # OOB: inactive engagement rejected (409), active engagement bounded body + row cap (429)
            assert client.post(f"/oob/{eng_id}/tok0", content=b"hello").status_code == 409
            with sqlite3.connect(tmp_path / "aegispt.db") as conn:
                conn.execute("UPDATE engagements SET status = 'running' WHERE id = ?", (eng_id,))
                conn.commit()

            monkeypatch.setattr(oob_module, "OOB_MAX_EVENTS_PER_ENGAGEMENT", 2)
            big_body = b"A" * 10_000
            r1 = client.post(f"/oob/{eng_id}/tok1", content=big_body)
            assert r1.status_code == 200
            r2 = client.post(f"/oob/{eng_id}/tok2", content=b"second")
            assert r2.status_code == 200
            r3 = client.post(f"/oob/{eng_id}/tok3", content=b"third")
            assert r3.status_code == 429

            oob_events = client.get(f"/api/v1/engagements/{eng_id}/oob", headers=headers).json()["oob_events"]
            assert len(oob_events) == 2
            tok1_ev = next(ev for ev in oob_events if ev["token"] == "tok1")
            assert len(tok1_ev["body_preview"]) == oob_module.OOB_MAX_BODY_BYTES
    finally:
        httpd.shutdown()
        httpd.server_close()
        oob_module.reset_oob_rate_limits()
        ws_ticket_store.clear()
        get_settings.cache_clear()
