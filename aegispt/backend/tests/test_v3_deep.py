"""V3 deep architecture, security hardening, active verifier, and parser tests."""
from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.core.scope import ScopePolicy, ScopeViolationError
from app.core.vault import decrypt_or_passthrough, encrypt_dict, encrypt_str
from app.db.database import close_db, init_db, session_scope
from app.db.models import Engagement, LLMProfile, ScopePolicyModel
from app.llm.router import LLMProfileConfig, LLMRouter
from app.main import create_app
from app.tools.dnsx_tool import DnsxAdapter, DnsxArgs
from app.tools.feroxbuster_tool import FeroxbusterAdapter, FeroxbusterArgs
from app.tools.http_probe import HttpProbeAdapter
from app.tools.js_miner import analyze_js_text
from app.tools.naabu_tool import NaabuAdapter, NaabuArgs
from app.tools.nikto_tool import NiktoAdapter, NiktoArgs
from app.tools.nmap_tool import NmapAdapter, NmapArgs


def test_scope_path_normalization_blocks_dot_segment_bypass():
    policy = ScopePolicy(
        allowed_urls=["https://example.com/api"],
        excluded_paths=["/api/logout", "/admin"],
    )
    assert policy.validate_target("https://example.com/api/users", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        policy.validate_target("https://example.com/api/v1/../logout", resolve_dns=False)
    with pytest.raises(ScopeViolationError):
        policy.validate_target("https://example.com/api/../admin", resolve_dns=False)


def test_vault_encryption_and_plaintext_passthrough(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    get_settings.cache_clear()

    enc = encrypt_str("super-secret-api-key")
    assert enc.startswith("enc:fernet:")
    assert "super-secret-api-key" not in enc
    assert decrypt_or_passthrough(enc) == "super-secret-api-key"
    assert decrypt_or_passthrough("legacy_plaintext") == "legacy_plaintext"

    enc_map = encrypt_dict({"Authorization": "Bearer secret123"})
    assert enc_map["Authorization"].startswith("enc:fernet:")
    get_settings.cache_clear()


def test_defusedxml_rejects_entity_expansion(tmp_path: Path):
    xxe_payload = """<?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY lol "lol"> ]>
    <nmaprun><host><address addr="&lol;"/></host></nmaprun>"""
    (tmp_path / "nmap.xml").write_text(xxe_payload, encoding="utf-8")
    nmap = NmapAdapter()
    res = nmap.parse_output(
        target="http://example.com", args=NmapArgs(), stdout="", stderr="", work_dir=tmp_path
    )
    assert res.assets == []


def test_naabu_dnsx_feroxbuster_nikto_and_js_miner_parsers(tmp_path: Path):
    naabu = NaabuAdapter()
    r_naabu = naabu.parse_output(
        target="http://127.0.0.1",
        args=NaabuArgs(),
        stdout=json.dumps({"host": "127.0.0.1", "ip": "127.0.0.1", "port": 3000}),
        stderr="",
        work_dir=tmp_path,
    )
    assert "port:3000/tcp" in r_naabu.assets[0].technologies

    dnsx = DnsxAdapter()
    r_dnsx = dnsx.parse_output(
        target="example.com",
        args=DnsxArgs(),
        stdout=json.dumps({"host": "example.com", "a": ["93.184.216.34"], "txt": ["hello"]}),
        stderr="",
        work_dir=tmp_path,
    )
    assert r_dnsx.assets[0].ip_address == "93.184.216.34"
    assert any("SPF" in f.title for f in r_dnsx.findings)

    ferox = FeroxbusterAdapter()
    (tmp_path / "ferox.json").write_text(
        json.dumps({"type": "response", "url": "http://127.0.0.1:3000/api/Users", "method": "GET", "status": 200}),
        encoding="utf-8",
    )
    r_ferox = ferox.parse_output(
        target="http://127.0.0.1:3000", args=FeroxbusterArgs(), stdout="", stderr="", work_dir=tmp_path
    )
    assert r_ferox.endpoints[0].path == "/api/Users"

    nik = NiktoAdapter()
    (tmp_path / "nikto.json").write_text(
        json.dumps([{"vulnerabilities": [{"id": "1", "msg": "Server leaks version header", "url": "/", "method": "GET"}]}]),
        encoding="utf-8",
    )
    r_nik = nik.parse_output(
        target="http://127.0.0.1:3000", args=NiktoArgs(), stdout="", stderr="", work_dir=tmp_path
    )
    assert len(r_nik.findings) == 1

    eps, fnds = analyze_js_text(
        'fetch("/api/v2/orders"); const k = "AIzaSyDummyGoogleKey1234567890123456789";',
        "https://app.example.com/main.js",
    )
    assert any(e.path == "/api/v2/orders" for e in eps)
    assert any("Google API Key" in f.title for f in fnds)
    assert "AIzaSyDummyGoogleKey1234567890123456789" not in json.dumps(fnds[0].evidence)


def test_llm_router_retries_and_failover():
    class FailHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(503)
            self.end_headers()

        def log_message(self, *_args):
            return

    class OkHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"message": {"content": '{"recovered": true}'}}).encode())

        def log_message(self, *_args):
            return

    s1 = HTTPServer(("127.0.0.1", 0), FailHandler)
    s2 = HTTPServer(("127.0.0.1", 0), OkHandler)
    t1 = threading.Thread(target=s1.serve_forever, daemon=True)
    t2 = threading.Thread(target=s2.serve_forever, daemon=True)
    t1.start()
    t2.start()

    try:
        async def _run():
            router = LLMRouter(timeout=5.0)
            primary = LLMProfileConfig(
                name="dead",
                provider="ollama",
                base_url=f"http://127.0.0.1:{s1.server_address[1]}",
                fast_model="m1",
                reasoning_model="m1",
            )
            backup = LLMProfileConfig(
                name="alive",
                provider="ollama",
                base_url=f"http://127.0.0.1:{s2.server_address[1]}",
                fast_model="m2",
                reasoning_model="m2",
            )
            res = await router.complete_json(
                profile=primary,
                fallback_profiles=[backup],
                tier="reasoning",
                messages=[{"role": "user", "content": "plan"}],
            )
            assert res == {"recovered": True}

        asyncio.run(_run())
    finally:
        s1.shutdown(); s1.server_close()
        s2.shutdown(); s2.server_close()


def test_redirect_ssrf_bola_ssti_open_redirect_repeater_and_diff(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AEGISPT_API_TOKEN", "v3_tok")
    get_settings.cache_clear()

    class MockVulnServer(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/ssrf-redir"):
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                self.end_headers()
                return
            if self.path.startswith("/login-redir"):
                from urllib.parse import parse_qs, urlparse

                qs = parse_qs(urlparse(self.path).query)
                dest = (qs.get("next") or ["/"])[0]
                self.send_response(302)
                self.send_header("Location", dest)
                self.end_headers()
                return
            if self.path.startswith("/tpl"):
                from urllib.parse import parse_qs, urlparse

                qs = parse_qs(urlparse(self.path).query)
                name = (qs.get("name") or ["guest"])[0]
                rendered = "1850" if "{{37*50}}" in name else name
                self.send_response(200)
                self.end_headers()
                self.wfile.write(f"Hello {rendered}".encode())
                return
            if self.path.startswith("/api/orders/1"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"order_id": 1, "owner": "alice", "total": 99.5}')
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, *_args):
            return

    httpd = HTTPServer(("127.0.0.1", 0), MockVulnServer)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    try:
        app = create_app()
        headers = {"Authorization": "Bearer v3_tok"}
        with TestClient(app) as client:
            eng = client.post(
                "/api/v1/engagements",
                headers=headers,
                json={
                    "name": "V3 Deep Lab",
                    "scope": {
                        "allowed_urls": [f"http://127.0.0.1:{port}"],
                        "custom_headers": {"Authorization": "Bearer SuperSecretToken999999"},
                        "allow_private_ips": True,
                    },
                },
            ).json()
            eng_id = eng["id"]
            # Encrypted/masked in GET JSON
            assert eng["scope"]["custom_headers"]["Authorization"] == "***"

            # Snapshot 1
            client.post(f"/api/v1/engagements/{eng_id}/snapshots?label=s1", headers=headers)

            # Redirect SSRF must be blocked (403) when follow_redirects=True!
            ssrf = client.post(
                f"/api/v1/engagements/{eng_id}/repeater",
                headers=headers,
                json={"method": "GET", "url": f"http://127.0.0.1:{port}/ssrf-redir", "follow_redirects": True},
            )
            assert ssrf.status_code == 403

            # Differential BOLA check
            bola = client.post(
                f"/api/v1/engagements/{eng_id}/run-tool",
                headers=headers,
                json={
                    "tool_name": "http_probe",
                    "target": f"http://127.0.0.1:{port}/api/orders/1",
                    "args": {"mode": "differential_bola"},
                },
            )
            assert bola.status_code == 200
            run_id = bola.json()["tool_run_id"]

            # Verify raw log scrubbed secret token
            log_text = client.get(f"/api/v1/engagements/{eng_id}/runs/{run_id}/log", headers=headers).json()["log"]
            assert "SuperSecretToken999999" not in log_text

            # Benign SSTI probe
            ssti = client.post(
                f"/api/v1/engagements/{eng_id}/run-tool",
                headers=headers,
                json={
                    "tool_name": "http_probe",
                    "target": f"http://127.0.0.1:{port}/tpl?name=guest",
                    "args": {"mode": "ssti_probe", "param": "name"},
                },
            )
            assert ssti.status_code == 200

            # Open redirect probe
            redir = client.post(
                f"/api/v1/engagements/{eng_id}/run-tool",
                headers=headers,
                json={
                    "tool_name": "http_probe",
                    "target": f"http://127.0.0.1:{port}/login-redir?next=/home",
                    "args": {"mode": "open_redirect_probe", "param": "next"},
                },
            )
            assert redir.status_code == 200

            # Repeater + Promote to Finding + Snapshot Diff
            rep = client.post(
                f"/api/v1/engagements/{eng_id}/repeater",
                headers=headers,
                json={"method": "GET", "url": f"http://127.0.0.1:{port}/api/orders/1"},
            )
            assert rep.status_code == 200 and rep.json()["status_code"] == 200

            client.post(
                f"/api/v1/engagements/{eng_id}/findings",
                headers=headers,
                json={
                    "title": "Manual Repeater Finding",
                    "severity": "medium",
                    "target_url": f"http://127.0.0.1:{port}/api/orders/1",
                    "description": "Confirmed via Repeater",
                },
            )

            findings = client.get(f"/api/v1/engagements/{eng_id}/findings", headers=headers).json()["findings"]
            titles = {f["title"] for f in findings}
            assert any("BOLA" in t for t in titles)
            assert any("Server-Side Template Injection" in t for t in titles)
            assert any("Open Redirect" in t for t in titles)
            assert "Manual Repeater Finding" in titles

            client.post(f"/api/v1/engagements/{eng_id}/snapshots?label=s2", headers=headers)
            diff = client.get(f"/api/v1/engagements/{eng_id}/diff", headers=headers).json()
            assert diff["has_diff"] is True
            assert len(diff["new_findings"]) >= 4
    finally:
        httpd.shutdown()
        httpd.server_close()
        get_settings.cache_clear()
