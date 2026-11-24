"""Tests for CTF / HTB multi-target scope parsing, port seeding, intel extraction, API, reports, and CLI."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from aegispt_cli import main as cli_main
from aegispt_cli.main import app as cli_app
from app.config import get_settings
from app.core.scope import ScopePolicy, ScopeViolationError
from app.core.targets import parse_target_inputs, preferred_scheme_for_host
from app.db.database import configure_database, init_db, session_scope
from app.db.models import Engagement
from app.db.persistence import persist_tool_result
from app.main import create_app
from app.tools.intel_extractor import extract_intel_from_text
from app.tools.js_miner import analyze_js_text
from app.tools.naabu_tool import NaabuAdapter
from app.tools.nmap_tool import NmapAdapter

runner = CliRunner()


def test_parse_target_inputs_handles_urls_domains_ips_ports_and_cidrs():
    parsed = parse_target_inputs(
        [
            "10.10.11.42",
            "10.10.11.42:8080",
            "box.htb",
            "https://portal.example.com:8443/login",
            "10.129.2.0/30",
        ]
    )
    assert parsed.detected_private_or_lab is True
    assert "http://10.10.11.42" in parsed.allowed_urls
    assert "http://10.10.11.42:8080" in parsed.allowed_urls
    assert "https://portal.example.com:8443/login" in parsed.allowed_urls
    assert "box.htb" in parsed.allowed_domains
    assert "portal.example.com" in parsed.allowed_domains
    assert "10.10.11.42/32" in parsed.allowed_cidrs
    assert "10.129.2.0/30" in parsed.allowed_cidrs


def test_scope_policy_bare_ip_in_allowed_domains_and_http_seeds():
    policy = ScopePolicy(
        allowed_domains=["10.10.11.55", "target.htb"],
        allowed_cidrs=["10.10.12.0/30"],
        allow_private_ips=True,
    )
    assert policy.validate_target("http://10.10.11.55:8080/admin", resolve_dns=False)
    assert policy.validate_target("http://target.htb/login", resolve_dns=False)

    seeds = policy.primary_seed_urls()
    assert "http://10.10.11.55" in seeds
    assert "http://target.htb" in seeds
    assert "http://10.10.12.1" in seeds
    assert preferred_scheme_for_host("example.com") == "https"
    assert preferred_scheme_for_host("target.htb") == "http"

    # Metadata IP must ALWAYS stay blocked even with allow_private_ips=True
    with pytest.raises(ScopeViolationError):
        policy.validate_target("http://169.254.169.254/latest/meta-data/", resolve_dns=False)


def test_intel_extractor_and_js_miner_extract_flags_keys_creds_ids_names_numbers():
    sample = """
    <!-- TODO debug admin login: bob_ctf / P@ssw0rd123! flag: HTB{y0u_f0und_th3_fl4g} -->
    const cfg = {
      api_key: "sk-proj-abcdef1234567890abcdef1234",
      username: "htb_admin",
      password: "SuperSecretLabPassword99",
      user_id: "usr_424242",
      uuid: "550e8400-e29b-41d4-a716-446655440000",
      adminEmail: "ops@target.htb",
      internalHost: "10.10.14.9",
    };
    fetch("/api/v1/admin/tokens");
    """
    hits = extract_intel_from_text(sample, source_url="http://target.htb/app.js", include_html_comments=True)
    categories = {h["category"] for h in hits}
    values = {h["value"] for h in hits}
    assert {"flag", "key", "credential", "identifier", "name", "number"} <= categories
    assert "HTB{y0u_f0und_th3_fl4g}" in values
    assert "htb_admin" in values
    assert "SuperSecretLabPassword99" in values
    assert "550e8400-e29b-41d4-a716-446655440000" in values
    assert "ops@target.htb" in values
    assert "10.10.14.9" in values

    endpoints, findings = analyze_js_text(sample, "http://target.htb/static/app.js")
    assert any(ep.path == "/api/v1/admin/tokens" for ep in endpoints)
    assert any(f.severity == "critical" and "HTB{y0u_f0und_th3_fl4g}" in json.dumps(f.evidence) for f in findings)
    assert any(f.evidence.get("extracted_intel") for f in findings)


def test_persist_tool_result_merges_nmap_and_naabu_ports(tmp_path: Path):
    import asyncio

    from sqlalchemy import select

    from app.core.intel_summary import build_intel_summary
    from app.db.models import Asset

    async def _run() -> None:
        configure_database(f"sqlite+aiosqlite:///{tmp_path}/merge.db")
        await init_db()
        nmap_xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="10.10.11.42" addrtype="ipv4"/>
            <hostnames><hostname name="box.htb"/></hostnames>
            <ports>
              <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
              <port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Werkzeug" version="3.0.1"/></port>
            </ports>
          </host>
        </nmaprun>
        """
        nmap_res = NmapAdapter().parse_output(target="10.10.11.42", args=NmapAdapter.args_schema(), stdout=nmap_xml, stderr="", work_dir=tmp_path)
        naabu_res = NaabuAdapter().parse_output(
            target="box.htb",
            args=NaabuAdapter.args_schema(),
            stdout='{"host":"box.htb","ip":"10.10.11.42","port":8080}\n{"host":"box.htb","ip":"10.10.11.42","port":5000}\n',
            stderr="",
            work_dir=tmp_path,
        )
        async with session_scope() as session:
            eng = Engagement(name="Port Merge Test")
            session.add(eng)
            await session.flush()
            eng_id = eng.id
            await persist_tool_result(session, eng_id, nmap_res)
            await persist_tool_result(session, eng_id, naabu_res)

        async with session_scope() as session:
            assets = (await session.execute(select(Asset).where(Asset.engagement_id == eng_id))).scalars().all()
            summary = build_intel_summary(engagement=None, assets=assets, endpoints=[], findings=[], runs=[])
            port_nums = {p["port"] for p in summary["open_ports"]}
            assert {22, 5000, 8080} <= port_nums
            p8080 = next(p for p in summary["open_ports"] if p["port"] == 8080)
            assert p8080["service"] == "http"
            assert "Werkzeug 3.0.1" in p8080["banner"]

    asyncio.run(_run())


def test_port_tools_merge_ports_and_api_reports_expose_all_intel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AEGISPT_API_TOKEN", "test_token_ctf_123")
    get_settings.cache_clear()

    class _MockHTBHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/bundle.js":
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.end_headers()
                self.wfile.write(
                    b'const api_key = "ghp_123456789012345678901234";\n'
                    b'const user_id = "usr_777";\n'
                    b'const internal_ip = "10.10.14.9";\n'
                )
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "HTB-Box/2.4")
            self.end_headers()
            self.wfile.write(
                b"<html><title>HTB Challenge</title><body>"
                b"<!-- flag: HTB{c7f_1nt3l_exp0s3d} admin: alice_htb -->"
                b'<script src="/bundle.js"></script>'
                b"</body></html>"
            )

        def log_message(self, *_args):
            return

    httpd = HTTPServer(("127.0.0.1", 0), _MockHTBHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    try:
        app = create_app()
        headers = {"Authorization": "Bearer test_token_ctf_123"}
        with TestClient(app) as client:
            create_resp = client.post(
                "/api/v1/engagements",
                headers=headers,
                json={
                    "name": "HTB Smoke Box",
                    "autonomy_mode": "lab_autopilot",
                    "scope": {"targets": [f"127.0.0.1:{port}", "box.htb:8080"], "ctf_mode": True},
                },
            )
            assert create_resp.status_code == 201, create_resp.text
            created = create_resp.json()
            eng_id = created["id"]
            assert created["scope"]["allow_private_ips"] is True
            assert "127.0.0.1/32" in created["scope"]["allowed_cidrs"]
            assert "http://box.htb:8080" in created["scope"]["allowed_urls"]

            r_http = client.post(
                f"/api/v1/engagements/{eng_id}/run-tool",
                headers=headers,
                json={"tool_name": "http_probe", "target": f"http://127.0.0.1:{port}/", "args": {"mode": "passive_audit"}},
            )
            assert r_http.status_code == 200, r_http.text

            r_js = client.post(
                f"/api/v1/engagements/{eng_id}/run-tool",
                headers=headers,
                json={"tool_name": "js_miner", "target": f"http://127.0.0.1:{port}/", "args": {"max_bundles": 4}},
            )
            assert r_js.status_code == 200, r_js.text

            detail = client.get(f"/api/v1/engagements/{eng_id}", headers=headers).json()
            assert detail["intel_counts"]["flag"] >= 1
            assert detail["intel_counts"]["key"] >= 1
            assert any(i["value"] == "HTB{c7f_1nt3l_exp0s3d}" for i in detail["intel"])

            intel_resp = client.get(f"/api/v1/engagements/{eng_id}/intel", headers=headers).json()
            values = {i["value"] for i in intel_resp["items"]}
            assert "HTB{c7f_1nt3l_exp0s3d}" in values
            assert "ghp_123456789012345678901234" in values
            assert "10.10.14.9" in values

            assets_resp = client.get(f"/api/v1/engagements/{eng_id}/assets", headers=headers).json()
            assert len(assets_resp["assets"]) >= 1

            md_report = client.get(f"/api/v1/engagements/{eng_id}/report?format=markdown", headers=headers).text
            assert "HTB{c7f_1nt3l_exp0s3d}" in md_report
            assert "Finding ID:" in md_report

            html_report = client.get(f"/api/v1/engagements/{eng_id}/report?format=html", headers=headers).text
            assert "Extracted Intelligence" in html_report
            assert "HTB{c7f_1nt3l_exp0s3d}" in html_report

            json_report = client.get(f"/api/v1/engagements/{eng_id}/report?format=json", headers=headers).json()
            assert json_report["intel_counts"]["flag"] >= 1
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_cli_target_ctf_assets_and_intel_commands(monkeypatch: pytest.MonkeyPatch):
    captured: list[tuple[str, str, dict | None]] = []

    class _StubResp:
        def __init__(self, data: dict):
            self._data = data

        def json(self) -> dict:
            return self._data

    class _StubClient:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def post(self, path: str, json_body: dict | None = None, params: dict | None = None):
            captured.append(("POST", path, json_body))
            return _StubResp({"id": "eng-ctf-1", "name": "HTB Lab", "status": "idle", "autonomy_mode": "lab_autopilot", "tier2_auto": True})

        def get(self, path: str, params: dict | None = None):
            captured.append(("GET", path, params))
            if path == "/api/v1/engagements":
                return _StubResp({"engagements": [{"id": "eng-ctf-1", "name": "HTB Lab", "status": "idle"}]})
            if path == "/api/v1/engagements/eng-ctf-1/assets":
                return _StubResp(
                    {
                        "engagement_id": "eng-ctf-1",
                        "assets": [
                            {
                                "id": "ast-1234",
                                "asset_type": "host",
                                "value": "box.htb",
                                "ip_address": "10.10.11.42",
                                "status_code": 200,
                                "title": "Box UI",
                                "technologies": ["Express"],
                                "ports": [{"port": 80, "proto": "tcp", "service": "http", "banner": "nginx 1.18"}],
                            }
                        ],
                    }
                )
            if path == "/api/v1/engagements/eng-ctf-1/intel":
                return _StubResp(
                    {
                        "engagement_id": "eng-ctf-1",
                        "counts": {"flag": 1, "key": 1, "credential": 0, "identifier": 1, "name": 1, "number": 1},
                        "items": [
                            {
                                "category": "flag",
                                "label": "CTF / HTB Flag",
                                "value": "HTB{cli_flag_ok}",
                                "masked_value": "HTB{..._ok}",
                                "sensitive": True,
                                "location": "http://box.htb/",
                                "tool_source": "http_probe",
                                "finding_id": "fnd-999",
                            }
                        ],
                    }
                )
            return _StubResp({})

    monkeypatch.setattr(cli_main, "_open_client", lambda: _StubClient())

    res_create = runner.invoke(cli_app, ["engagement", "create", "-n", "HTB Lab", "-t", "10.10.11.42", "-t", "box.htb", "--ctf", "--start"])
    assert res_create.exit_code == 0, res_create.output
    post_create = [c for c in captured if c[0] == "POST" and c[1] == "/api/v1/engagements"][0]
    assert post_create[2]["scope"]["targets"] == ["10.10.11.42", "box.htb"]
    assert post_create[2]["scope"]["ctf_mode"] is True
    assert post_create[2]["scope"]["allow_private_ips"] is True
    assert any(c[0] == "POST" and c[1] == "/api/v1/engagements/eng-ctf-1/start" for c in captured)

    res_assets = runner.invoke(cli_app, ["assets", "eng-ctf-1"], env={"COLUMNS": "180"})
    assert res_assets.exit_code == 0, res_assets.output
    assert "ast-1234" in res_assets.output
    assert "10.10.11.42" in res_assets.output
    assert "80/tcp" in res_assets.output

    res_intel = runner.invoke(cli_app, ["intel", "eng-ctf-1"], env={"COLUMNS": "180"})
    assert res_intel.exit_code == 0, res_intel.output
    assert "HTB{cli_flag_ok}" in res_intel.output
    assert "fnd-999" in res_intel.output

    res_intel_json = runner.invoke(cli_app, ["intel", "eng-ctf-1", "--json"])
    assert res_intel_json.exit_code == 0
    assert json.loads(res_intel_json.output)["items"][0]["value"] == "HTB{cli_flag_ok}"
