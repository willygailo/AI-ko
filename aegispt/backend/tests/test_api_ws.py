"""End-to-end FastAPI REST, Auth, Scope enforcement, Knowledge Base, and Report Export tests."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import create_app


def test_full_api_flow_against_local_mock_target(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AEGISPT_API_TOKEN", "test_token_12345")
    get_settings.cache_clear()

    # Spin up tiny local vulnerable-header mock HTTP server
    class DummyTarget(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "DemoApp/1.0")
            self.send_header("Set-Cookie", "sid=abc123; Path=/")
            self.end_headers()
            self.wfile.write(b"<html><title>Dummy Target</title><body>Hello</body></html>")

        def log_message(self, *_args):
            return

    httpd = HTTPServer(("127.0.0.1", 0), DummyTarget)
    t_port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    try:
        app = create_app()
        headers = {"Authorization": "Bearer test_token_12345"}
        with TestClient(app) as client:
            # Unauthenticated check
            assert client.get("/api/v1/system/health").status_code == 200
            assert client.get("/api/v1/engagements").status_code == 401

            # Create engagement scoped strictly to dummy target
            create_resp = client.post(
                "/api/v1/engagements",
                headers=headers,
                json={
                    "name": "Local Mock Audit",
                    "autonomy_mode": "tiered",
                    "scope": {
                        "allowed_urls": [f"http://127.0.0.1:{t_port}"],
                        "allow_private_ips": True,
                        "max_rps": 20,
                    },
                },
            )
            assert create_resp.status_code == 201
            eng_id = create_resp.json()["id"]

            # Out-of-scope manual tool call must be blocked (403)
            blocked = client.post(
                f"/api/v1/engagements/{eng_id}/run-tool",
                headers=headers,
                json={
                    "tool_name": "http_probe",
                    "target": "https://example.org",
                    "args": {"mode": "passive_audit"},
                },
            )
            assert blocked.status_code == 403

            # In-scope passive http_probe must succeed and record findings
            probe = client.post(
                f"/api/v1/engagements/{eng_id}/run-tool",
                headers=headers,
                json={
                    "tool_name": "http_probe",
                    "target": f"http://127.0.0.1:{t_port}",
                    "args": {"mode": "passive_audit", "discover_api_schemas": False},
                },
            )
            assert probe.status_code == 200
            assert probe.json()["summary"]["findings_count"] >= 2

            # Verify findings & report exports
            f_resp = client.get(f"/api/v1/engagements/{eng_id}/findings", headers=headers)
            assert f_resp.status_code == 200
            findings = f_resp.json()["findings"]
            assert any("Missing HTTP Security Headers" in f["title"] for f in findings)

            md = client.get(f"/api/v1/engagements/{eng_id}/report?format=markdown", headers=headers)
            assert md.status_code == 200
            assert "Local Mock Audit" in md.text

            html_rep = client.get(f"/api/v1/engagements/{eng_id}/report?format=html", headers=headers)
            assert html_rep.status_code == 200
            assert "<!doctype html>" in html_rep.text

            sarif = client.get(f"/api/v1/engagements/{eng_id}/report?format=sarif", headers=headers)
            assert sarif.status_code == 200
            assert sarif.json()["version"] == "2.1.0"

            # WebSocket stream replay & ping
            with client.websocket_connect(f"/ws/engagements/{eng_id}?token=test_token_12345") as ws:
                ev = ws.receive_json()
                assert ev["engagement_id"] == eng_id
                ws.send_text("ping")
                # Drain any remaining replay messages until pong
                got_pong = False
                for _ in range(10):
                    msg = ws.receive_json()
                    if msg.get("event_type") == "pong":
                        got_pong = True
                        break
                assert got_pong
    finally:
        httpd.shutdown()
        httpd.server_close()
        get_settings.cache_clear()
