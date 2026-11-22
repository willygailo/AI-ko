"""V2 upgrade tests: Nmap/SSLScan parsers, JWT/GraphQL probes, shared persistence, startup recovery, and executive reports."""
from __future__ import annotations

import asyncio
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import get_settings
from app.core.scope import ScopePolicy
from app.db.database import close_db, init_db, session_scope
from app.db.models import ApprovalRequest, Engagement, ToolRun
from app.knowledge.store import KnowledgeStore
from app.main import _recover_interrupted_runs, create_app
from app.tools.http_probe import audit_jwt_candidates
from app.tools.nmap_tool import NmapAdapter, NmapArgs
from app.tools.sslscan_tool import SslscanAdapter, SslscanArgs


def _fake_jwt(header: dict, payload: dict) -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h}.{p}.sig12345"


def test_nmap_and_sslscan_parsers(tmp_path: Path):
    nmap = NmapAdapter()
    (tmp_path / "nmap.xml").write_text(
        """<nmaprun>
          <host>
            <address addr="127.0.0.1" addrtype="ipv4"/>
            <hostnames><hostname name="lab.local"/></hostnames>
            <ports>
              <port protocol="tcp" portid="3000">
                <state state="open"/>
                <service name="http" product="Node.js Express" version="4.18"/>
              </port>
            </ports>
          </host>
        </nmaprun>""",
        encoding="utf-8",
    )
    res_nmap = nmap.parse_output(
        target="http://lab.local:3000", args=NmapArgs(), stdout="", stderr="", work_dir=tmp_path
    )
    assert len(res_nmap.assets) == 1
    assert any("port:3000/tcp:http" in t for t in res_nmap.assets[0].technologies)

    ssl = SslscanAdapter()
    (tmp_path / "sslscan.xml").write_text(
        """<document>
          <ssltest host="secure.example.com" port="443">
            <protocol type="tls" version="1.0" enabled="1"/>
            <protocol type="tls" version="1.2" enabled="1"/>
            <cipher status="accepted" bits="128" cipher="RC4-SHA"/>
            <certificate>
              <subject>CN=secure.example.com</subject>
              <expired>true</expired>
              <self-signed>false</self-signed>
            </certificate>
          </ssltest>
        </document>""",
        encoding="utf-8",
    )
    res_ssl = ssl.parse_output(
        target="https://secure.example.com", args=SslscanArgs(), stdout="", stderr="", work_dir=tmp_path
    )
    titles = {f.title for f in res_ssl.findings}
    assert "Deprecated TLS/SSL Protocol Enabled (TLSv1.0)" in titles
    assert "Weak TLS Cipher Suites Supported" in titles
    assert "Expired TLS Certificate" in titles

    scope = ScopePolicy(allowed_domains=["secure.example.com"])
    argv = ssl.build_argv("https://secure.example.com", SslscanArgs(), scope, tmp_path)
    assert "--no-colour" in argv and "secure.example.com:443" in argv


def test_jwt_passive_audit():
    tok_none = _fake_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "password": "pw"})
    findings = audit_jwt_candidates([f"Bearer {tok_none}"], "https://api.example.com", "http_probe")
    titles = {f.title for f in findings}
    assert "Insecure JWT Algorithm ('alg: none')" in titles
    assert "JWT Missing Expiration Claim ('exp')" in titles
    assert "Sensitive Claim Names Inside JWT Payload" in titles


def test_knowledge_base_has_12_playbooks(tmp_path: Path):
    kb = KnowledgeStore(db_path=tmp_path / "kb.db")
    kb.ensure_indexed()
    all_pbs = kb.search("", limit=50)
    assert len([p for p in all_pbs if p["id"].startswith("wstg-")]) == 12
    assert len(all_pbs) >= 21
    gql = kb.search("graphql introspection", limit=3)
    assert any(p["id"] == "wstg-graphql-hardening" for p in gql)


def test_startup_recovery_resets_stale_runs(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    get_settings.cache_clear()

    async def _run():
        await init_db(f"sqlite+aiosqlite:///{tmp_path / 'rec.db'}")
        async with session_scope() as session:
            session.add(Engagement(id="e_stale", name="Stale", status="running"))
            await session.flush()
            session.add(
                ToolRun(
                    id="r_stale",
                    engagement_id="e_stale",
                    tool_name="ffuf",
                    tier=2,
                    target="http://127.0.0.1:3000",
                    status="running",
                )
            )
            await session.flush()
            session.add(
                ApprovalRequest(
                    id="a_stale",
                    engagement_id="e_stale",
                    tool_run_id="r_stale",
                    tool_name="sqlmap",
                    tier=3,
                    target="http://127.0.0.1:3000",
                    status="pending",
                )
            )

        await _recover_interrupted_runs()

        async with session_scope() as session:
            eng = await session.get(Engagement, "e_stale")
            run = await session.get(ToolRun, "r_stale")
            ap = await session.get(ApprovalRequest, "a_stale")
            assert eng is not None and eng.status == "paused"
            assert run is not None and run.status == "failed"
            assert ap is not None and ap.status == "expired"

        await close_db()

    asyncio.run(_run())
    get_settings.cache_clear()


def test_manual_endpoint_persistence_graphql_and_print_report(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AEGISPT_API_TOKEN", "v2_tok")
    get_settings.cache_clear()

    class MockGraphQLApp(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/graphql":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"errors": []}')
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><title>GQL</title></html>")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data": {"__schema": {"queryType": {"name": "Query"}}}}')

        def log_message(self, *_args):
            return

    httpd = HTTPServer(("127.0.0.1", 0), MockGraphQLApp)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    try:
        app = create_app()
        headers = {"Authorization": "Bearer v2_tok"}
        with TestClient(app) as client:
            eng = client.post(
                "/api/v1/engagements",
                headers=headers,
                json={
                    "name": "GraphQL V2 Audit",
                    "scope": {"allowed_urls": [f"http://127.0.0.1:{port}"], "allow_private_ips": True},
                },
            ).json()
            eng_id = eng["id"]

            run_resp = client.post(
                f"/api/v1/engagements/{eng_id}/run-tool",
                headers=headers,
                json={
                    "tool_name": "http_probe",
                    "target": f"http://127.0.0.1:{port}/?view=1",
                    "args": {"mode": "api_discovery"},
                },
            )
            assert run_resp.status_code == 200
            run_id = run_resp.json()["tool_run_id"]

            detail = client.get(f"/api/v1/engagements/{eng_id}", headers=headers).json()
            ep_paths = {e["path"] for e in detail["endpoints"]}
            assert "/graphql" in ep_paths
            assert any("GraphQL Introspection" in f["title"] for f in detail["findings"])

            log_resp = client.get(f"/api/v1/engagements/{eng_id}/runs/{run_id}/log", headers=headers)
            assert log_resp.status_code == 200
            assert "status_code" in log_resp.json()["log"]

            html_rep = client.get(f"/api/v1/engagements/{eng_id}/report?format=html", headers=headers)
            assert "@media print" in html_rep.text
            assert "POSTURE SCORE" in html_rep.text
    finally:
        httpd.shutdown()
        httpd.server_close()
        get_settings.cache_clear()
