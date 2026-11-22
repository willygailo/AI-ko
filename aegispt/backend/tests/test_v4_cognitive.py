"""V4 cognitive brain, modular skill packs, deep verifiers, Kali parsers, and E2E API tests."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.agents.graph_context import build_graph_context, score_endpoint_risk
from app.agents.orchestrator import EngagementOrchestrator
from app.config import get_settings
from app.core.scope import ScopePolicy
from app.db.database import close_db, init_db, session_scope
from app.db.models import Endpoint, Engagement, Finding, ScopePolicyModel
from app.db.persistence import persist_tool_result
from app.knowledge.store import knowledge_store
from app.llm.schemas import ProposedToolCall
from app.main import create_app
from app.tools.base import DiscoveredFinding, ToolResult
from app.tools.gitleaks_tool import GitleaksAdapter, GitleaksArgs
from app.tools.http_probe import HttpProbeAdapter
from app.tools.js_miner import analyze_js_text
from app.tools.paramspider_tool import ParamspiderAdapter, ParamspiderArgs
from app.tools.registry import tool_registry
from app.tools.sqlmap import SqlmapAdapter, SqlmapArgs
from app.tools.trufflehog_tool import TrufflehogAdapter, TrufflehogArgs
from app.tools.wpscan_tool import WpscanAdapter, WpscanArgs


def _make_hs256_jwt(payload: dict, secret: str) -> str:
    def _b64(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    h = _b64({"alg": "HS256", "typ": "JWT"})
    p = _b64(payload)
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode("utf-8"), f"{h}.{p}".encode("ascii"), hashlib.sha256).digest()
    ).rstrip(b"=").decode("ascii")
    return f"{h}.{p}.{sig}"


def test_modular_skill_packs_and_signal_matching(tmp_path: Path):
    kb = knowledge_store
    kb._db_path = tmp_path / "kb.db"
    kb.ensure_indexed()
    skills = kb.list_all_skills()
    assert len(skills) >= 9

    graph = {
        "assets": [{"value": "app.example.com", "waf": "Cloudflare", "technologies": ["express"]}],
        "endpoints": [
            {"url": "https://app.example.com/graphql", "method": "POST", "query_params": [], "body_params": ["query"]},
            {"url": "https://app.example.com/api/coupon/redeem", "method": "POST", "query_params": [], "body_params": ["code"]},
            {"url": "https://app.example.com/oauth/authorize", "method": "GET", "query_params": ["redirect_uri"], "body_params": []},
        ],
        "findings": [{"title": "Cookie Missing HttpOnly", "cwe_id": "CWE-614"}],
    }
    matched = kb.match_skills_for_graph(graph, "API & GraphQL audit", has_secondary_auth=True, limit=8)
    ids = {m["id"] for m in matched}
    assert "skill-graphql-assessment" in ids
    assert "skill-race-toctou-idempotency" in ids
    assert "skill-oauth-oidc-hygiene" in ids
    assert "skill-idor-bola-multi-role" in ids
    assert "skill-waf-adaptive-posture" in ids
    kb._db_path = None


def test_sqlite_auto_migration_from_v3_schema(tmp_path: Path):
    db_file = tmp_path / "legacy_v3.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE engagements (id TEXT PRIMARY KEY, name TEXT)")
    conn.execute("CREATE TABLE scope_policies (id TEXT PRIMARY KEY, engagement_id TEXT)")
    conn.execute("CREATE TABLE findings (id TEXT PRIMARY KEY, engagement_id TEXT)")
    conn.commit()
    conn.close()

    asyncio.run(init_db(f"sqlite+aiosqlite:///{db_file}"))
    asyncio.run(close_db())

    check = sqlite3.connect(db_file)
    eng_cols = {r[1] for r in check.execute("PRAGMA table_info(engagements)").fetchall()}
    scope_cols = {r[1] for r in check.execute("PRAGMA table_info(scope_policies)").fetchall()}
    find_cols = {r[1] for r in check.execute("PRAGMA table_info(findings)").fetchall()}
    check.close()
    assert "operator_hints" in eng_cols
    assert "secondary_headers" in scope_cols
    assert "secondary_cookies" in scope_cols
    assert "corroborated_by" in find_cols
    assert "verified_at" in find_cols


def test_new_kali_adapters_and_sqlmap_json_support(tmp_path: Path):
    # Registry check (all 24 registered)
    names = {t.name for t in tool_registry.list_tools()}
    assert {"trufflehog", "gitleaks", "paramspider", "wpscan", "spa_inspector"}.issubset(names)

    # SQLMap JSON Content-Type header auto-propagation
    sqlm = SqlmapAdapter()
    scope = ScopePolicy(allowed_urls=["http://127.0.0.1:3000"], allow_private_ips=True)
    argv = sqlm.build_argv(
        "http://127.0.0.1:3000/api/login",
        SqlmapArgs(method="POST", data='{"email":"a"}', param="email"),
        scope,
        tmp_path,
    )
    assert any("Content-Type: application/json" in item for item in argv)

    # TruffleHog parser
    th = TrufflehogAdapter()
    th_out = json.dumps(
        {
            "DetectorName": "AWS",
            "Raw": "AKIAIOSFODNN7EXAMPLE9",
            "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "/tmp/captured/app.js"}}},
        }
    )
    r_th = th.parse_output(target="https://example.com", args=TrufflehogArgs(), stdout=th_out, stderr="", work_dir=tmp_path)
    assert len(r_th.findings) == 1
    assert r_th.findings[0].severity == "high"
    assert "AKIAIOSFODNN7EXAMPLE9" not in json.dumps(r_th.findings[0].evidence)

    # Gitleaks parser
    (tmp_path / "gitleaks.json").write_text(
        json.dumps([{"RuleID": "generic-api-key", "File": "/tmp/captured/bundle.js", "Secret": "supersecretkey12345"}]),
        encoding="utf-8",
    )
    gl = GitleaksAdapter()
    r_gl = gl.parse_output(target="https://example.com", args=GitleaksArgs(), stdout="", stderr="", work_dir=tmp_path)
    assert len(r_gl.findings) == 1
    assert "supersecretkey12345" not in json.dumps(r_gl.findings[0].evidence)

    # ParamSpider parser
    ps = ParamspiderAdapter()
    r_ps = ps.parse_output(
        target="example.com",
        args=ParamspiderArgs(),
        stdout="https://example.com/search?q=FUZZ&page=FUZZ\nhttps://evil.com/?q=1\n",
        stderr="",
        work_dir=tmp_path,
    )
    assert len(r_ps.endpoints) == 1
    assert set(r_ps.endpoints[0].query_params) == {"q", "page"}

    # WPScan parser
    wp = WpscanAdapter()
    (tmp_path / "wpscan.json").write_text(
        json.dumps(
            {
                "version": {"number": "6.4.2"},
                "interesting_findings": [{"type": "xmlrpc", "to_s": "XML-RPC enabled", "url": "http://127.0.0.1/xmlrpc.php"}],
                "plugins": {"contact-form-7": {"vulnerabilities": [{"title": "Unrestricted Upload"}]}},
            }
        ),
        encoding="utf-8",
    )
    r_wp = wp.parse_output(target="http://127.0.0.1", args=WpscanArgs(), stdout="", stderr="", work_dir=tmp_path)
    assert any(f.severity == "high" for f in r_wp.findings)

    # Enhanced js_miner JSON body keys & DOM sinks
    js_eps, js_fnds = analyze_js_text(
        'fetch("/api/login", {method:"POST", body: JSON.stringify({username: u, password: p})}); el.innerHTML = x;',
        "https://example.com/app.js",
    )
    assert "username" in js_eps[0].body_params
    assert any("DOM Injection Sink" in f.title for f in js_fnds)


def test_risk_ranking_critic_and_cross_tool_correlation(tmp_path: Path):
    db_file = tmp_path / "rank.db"
    asyncio.run(init_db(f"sqlite+aiosqlite:///{db_file}"))

    async def _run():
        async with session_scope() as session:
            eng = Engagement(name="Ranking Test", operator_hints=["Check GraphQL & coupons"])
            session.add(eng)
            await session.flush()
            session.add(ScopePolicyModel(engagement_id=eng.id, allowed_urls=["https://example.com"]))
            for i in range(65):
                session.add(Endpoint(engagement_id=eng.id, method="GET", url=f"https://example.com/assets/pic_{i}.png", path=f"/assets/pic_{i}.png"))
            session.add(Endpoint(engagement_id=eng.id, method="POST", url="https://example.com/api/admin/export", path="/api/admin/export", body_params=["format", "table"], status_code=200))
            await session.flush()

            ctx = await build_graph_context(session, eng.id)
            assert ctx["endpoints"][0]["path"] == "/api/admin/export"
            assert "Check GraphQL & coupons" in ctx["operator_hints"]

            # Cross-tool correlation deduplicates same CWE+URL+param
            await persist_tool_result(
                session,
                eng.id,
                ToolResult(
                    tool_name="http_probe",
                    exit_code=0,
                    duration_ms=10,
                    findings=[DiscoveredFinding(title="CORS Issue A", severity="medium", target_url="https://example.com/api", cwe_id="CWE-942", tool_source="http_probe")],
                ),
            )
            added2 = await persist_tool_result(
                session,
                eng.id,
                ToolResult(
                    tool_name="nuclei",
                    exit_code=0,
                    duration_ms=10,
                    findings=[DiscoveredFinding(title="CORS Issue B", severity="medium", target_url="https://example.com/api", cwe_id="CWE-942", tool_source="nuclei")],
                ),
            )
            assert added2 == 0

            orch = EngagementOrchestrator(eng.id)
            filtered = orch._critic_filter_proposals(
                [ProposedToolCall(tool_name="wpscan", target="https://example.com", args={})],
                ctx,
            )
            assert filtered == []

    asyncio.run(_run())
    asyncio.run(close_db())


def test_v4_deep_probes_oob_chainer_and_reverify(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AEGISPT_API_TOKEN", "v4_tok")
    get_settings.cache_clear()

    valid_user_a_jwt = _make_hs256_jwt({"sub": "alice", "exp": 9999999999}, "secret")
    valid_user_b_jwt = _make_hs256_jwt({"sub": "bob", "exp": 9999999999}, "secret")

    class VulnLabHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            p = urlparse(self.path)
            auth = self.headers.get("Authorization", "")
            if p.path == "/.well-known/openid-configuration":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"response_types_supported": ["code", "token"], "code_challenge_methods_supported": ["plain"]}).encode())
                return
            if p.path == "/authorize":
                qs = parse_qs(p.query)
                redir = (qs.get("redirect_uri") or [""])[0]
                if redir:
                    self.send_response(302)
                    self.send_header("Location", redir)
                    self.end_headers()
                    return
            if p.path == "/api/orders/1":
                if valid_user_a_jwt in auth or valid_user_b_jwt in auth or "alg\":\"none\"" in str(auth) or auth.endswith("."):
                    # Also intentionally accept none/stripped JWT if unsigned (test mock!)
                    pass
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"order_id": 1, "owner": "alice", "total": 120.0}')
                return
            if p.path == "/api/admin/users":
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Forbidden")
                return
            if p.path == "/static/app.js":
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.end_headers()
                self.wfile.write(b'fetch("/api/internal/flag");\n//# sourceMappingURL=app.js.map\n')
                return
            if p.path == "/static/app.js.map":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"version": 3, "sources": ["src/AdminSecrets.tsx"]}).encode())
                return
            self.send_response(200)
            self.send_header("Set-Cookie", "sid=abc123")
            self.end_headers()
            self.wfile.write(b'<html><script src="/static/app.js"></script></html>')

        def do_PUT(self):
            if self.path == "/api/admin/users":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"updated": true}')
                return
            self.send_response(405)
            self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            if self.path == "/graphql":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                if "__typename" in raw and raw.lstrip().startswith("["):
                    self.wfile.write(json.dumps([{"data": {"__typename": "Query"}}, {"data": {"__typename": "Query"}}]).encode())
                elif "aegisNonExistentField" in raw:
                    self.wfile.write(json.dumps({"errors": [{"message": 'Did you mean "users" or "orders"?'}]}).encode())
                else:
                    self.wfile.write(json.dumps({"data": {"__typename": "Query"}}).encode())
                return
            if self.path == "/api/coupon/redeem":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"redeemed": true}')
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, *_args):
            return

    httpd = HTTPServer(("127.0.0.1", 0), VulnLabHandler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    try:
        app = create_app()
        hdrs = {"Authorization": "Bearer v4_tok"}
        with TestClient(app) as client:
            eng = client.post(
                "/api/v1/engagements",
                headers=hdrs,
                json={
                    "name": "V4 Cognitive Lab",
                    "scope": {
                        "allowed_urls": [f"http://127.0.0.1:{port}"],
                        "custom_headers": {"Authorization": f"Bearer {valid_user_a_jwt}"},
                        "secondary_headers": {"Authorization": f"Bearer {valid_user_b_jwt}"},
                        "allow_private_ips": True,
                    },
                },
            ).json()
            eng_id = eng["id"]
            assert eng["scope"]["has_secondary_auth"] is True

            # 1. Steer brain
            steer = client.post(f"/api/v1/engagements/{eng_id}/steer", headers=hdrs, json={"hint": "Focus on GraphQL & BOLA"})
            assert steer.status_code == 200
            assert "Focus on GraphQL & BOLA" in steer.json()["operator_hints"]

            # 2. Local OOB hit
            oob_hit = client.get(f"/oob/{eng_id}/ssrf-probe-1")
            assert oob_hit.status_code == 200
            oob_list = client.get(f"/api/v1/engagements/{eng_id}/oob", headers=hdrs).json()["oob_events"]
            assert len(oob_list) == 1 and oob_list[0]["token"] == "ssrf-probe-1"

            # 3. GraphQL oracle & batching check
            client.post(f"/api/v1/engagements/{eng_id}/run-tool", headers=hdrs, json={"tool_name": "http_probe", "target": f"http://127.0.0.1:{port}/graphql", "args": {"mode": "graphql_deep_audit"}})
            # 4. OAuth discovery & redirect check
            client.post(f"/api/v1/engagements/{eng_id}/run-tool", headers=hdrs, json={"tool_name": "http_probe", "target": f"http://127.0.0.1:{port}/authorize?redirect_uri=http://127.0.0.1:{port}/cb", "args": {"mode": "oauth_audit"}})
            # 5. Multi-role BOLA + JWT weak secret/alg=none + Verb Tamper + Race Burst + JS source map
            client.post(f"/api/v1/engagements/{eng_id}/run-tool", headers=hdrs, json={"tool_name": "http_probe", "target": f"http://127.0.0.1:{port}/api/orders/1", "args": {"mode": "differential_bola"}})
            client.post(f"/api/v1/engagements/{eng_id}/run-tool", headers=hdrs, json={"tool_name": "http_probe", "target": f"http://127.0.0.1:{port}/api/orders/1", "args": {"mode": "jwt_active_probe"}})
            client.post(f"/api/v1/engagements/{eng_id}/run-tool", headers=hdrs, json={"tool_name": "http_probe", "target": f"http://127.0.0.1:{port}/api/admin/users", "args": {"mode": "bfla_verb_tamper"}})
            client.post(f"/api/v1/engagements/{eng_id}/run-tool", headers=hdrs, json={"tool_name": "http_probe", "target": f"http://127.0.0.1:{port}/api/coupon/redeem", "args": {"mode": "race_burst_probe", "method": "POST", "burst_count": 4}})
            client.post(f"/api/v1/engagements/{eng_id}/run-tool", headers=hdrs, json={"tool_name": "js_miner", "target": f"http://127.0.0.1:{port}/"})

            findings = client.get(f"/api/v1/engagements/{eng_id}/findings", headers=hdrs).json()["findings"]
            titles = " | ".join(f["title"] for f in findings)
            assert "GraphQL Field Suggestion Oracle Leakage" in titles
            assert "OAuth Implicit Grant" in titles
            assert "Permissive OAuth redirect_uri" in titles
            assert "Potential Missing Authorization / BOLA" in titles
            assert "JWT Uses Known Default/Weak HMAC Signing Secret" in titles
            assert "Verb Tampering / BFLA" in titles
            assert "Concurrency / Idempotency Race Condition" in titles
            assert "Source Map File (.js.map)" in titles

            # 6. Synthesize Attack Chains
            chains_res = client.post(f"/api/v1/engagements/{eng_id}/chains/synthesize", headers=hdrs).json()
            assert chains_res["synthesized"] >= 1

            # 7. Export PoC replay bash script & Markdown with chains
            poc_sh = client.get(f"/api/v1/engagements/{eng_id}/report?format=poc_sh", headers=hdrs)
            assert poc_sh.status_code == 200 and "#!/usr/bin/env bash" in poc_sh.text
            md_rep = client.get(f"/api/v1/engagements/{eng_id}/report?format=markdown", headers=hdrs)
            assert "Synthesized Attack Chains" in md_rep.text

            # 8. Re-verify a finding
            first_id = findings[0]["id"]
            reverify = client.post(f"/api/v1/findings/{first_id}/reverify", headers=hdrs)
            assert reverify.status_code == 200 and reverify.json()["verified_at"]
    finally:
        httpd.shutdown()
        httpd.server_close()
        get_settings.cache_clear()
