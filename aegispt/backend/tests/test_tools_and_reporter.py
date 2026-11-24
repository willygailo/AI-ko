"""Comprehensive unit tests for tool adapters, PoC script reporter hardening, and KnowledgeStore."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import shlex
import signal
import sqlite3
import stat
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pydantic import BaseModel, Field, ValidationError

from app.agents.reporter import render_poc_script
from app.config import get_settings
from app.core.scope import ScopePolicy, ScopeViolationError
from app.knowledge.store import KnowledgeStore
from app.tools.arjun import ArjunAdapter, ArjunArgs
from app.tools.base import BaseToolAdapter, sanitize_argv
from app.tools.dalfox import DalfoxAdapter, DalfoxArgs
from app.tools.feroxbuster_tool import FeroxbusterAdapter, FeroxbusterArgs
from app.tools.ffuf import FfufAdapter, FfufArgs
from app.tools.gitleaks_tool import GitleaksAdapter
from app.tools.http_probe import HttpProbeAdapter, HttpProbeArgs
from app.tools.httpx_tool import _is_projectdiscovery_httpx
from app.tools.js_miner import JsMinerAdapter, JsMinerArgs
from app.tools.katana import KatanaAdapter, KatanaArgs
from app.tools.paramspider_tool import ParamspiderAdapter, ParamspiderArgs
from app.tools.spa_inspector import SpaInspectorAdapter, SpaInspectorArgs
from app.tools.sqlmap import SqlmapAdapter, SqlmapArgs
from app.tools.subfinder import SubfinderAdapter, SubfinderArgs
from app.tools.trufflehog_tool import TrufflehogAdapter, TrufflehogArgs
from app.tools.wpscan_tool import WpscanAdapter, WpscanArgs
from app.tools.zaproxy import ZapAdapter


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


def _fake_finding(**overrides):
    defaults = {
        "title": "Sample Finding",
        "severity": "high",
        "cvss_score": 7.5,
        "status": "open",
        "poc_command": "curl -s 'http://127.0.0.1:3000/api?a=1&b=2'",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _fake_engagement(**overrides):
    defaults = {"id": "eng-1", "name": "Demo Engagement"}
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# 1. reporter.py: render_poc_script shell injection defense
# ---------------------------------------------------------------------------


def test_render_poc_script_defends_against_shell_injection():
    eng = _fake_engagement(name="Lab\nrm -rf / #")
    findings = [
        _fake_finding(
            title="Valid Finding 'quote'\n$(touch /tmp/pwned)",
            poc_command="curl -i -s 'http://127.0.0.1:3000/search?a=1&b=2'",
        ),
        _fake_finding(
            title="Semicolon Injection",
            poc_command="curl -s 'http://127.0.0.1:3000/'; id",
        ),
        _fake_finding(
            title="And Chain Injection",
            poc_command="curl -s http://127.0.0.1:3000 && whoami",
        ),
        _fake_finding(
            title="Or Chain Injection",
            poc_command="curl -s http://127.0.0.1:3000 || cat /etc/passwd",
        ),
        _fake_finding(
            title="Pipe Injection",
            poc_command="curl -s http://127.0.0.1:3000 | bash",
        ),
        _fake_finding(
            title="Backtick Injection",
            poc_command="curl -s `id`",
        ),
        _fake_finding(
            title="Dollar Subshell Injection",
            poc_command='curl -s "http://127.0.0.1:3000/$(whoami)"',
        ),
        _fake_finding(
            title="Unmatched Quote",
            poc_command="curl -s 'http://127.0.0.1:3000/unterminated",
        ),
        _fake_finding(
            title="Newline Injection",
            poc_command="curl -s http://127.0.0.1:3000/\nid",
        ),
        _fake_finding(
            title="Direct Shell Exec",
            poc_command="bash -c 'id'",
        ),
    ]

    script = render_poc_script(eng, findings)
    lines = script.splitlines()

    # Engagement header must stay on a single comment line (no injected executable line)
    assert not any(line.strip().startswith("rm -rf") for line in lines)

    # Valid finding command is reconstructed safely via shlex.join
    assert "curl -i -s 'http://127.0.0.1:3000/search?a=1&b=2'" in lines

    # Malicious title must be safely single-quoted inside echo on one line
    echo_lines = [ln for ln in lines if ln.startswith("echo ")]
    assert any("Valid Finding" in ln for ln in echo_lines)
    assert not any(ln.strip().startswith("$(touch") for ln in lines)

    # Every malicious PoC command must be skipped/commented out, never emitted bare
    executable_lines = [ln for ln in lines if ln and not ln.startswith("#") and not ln.startswith("echo ") and ln != "set -uo pipefail"]
    assert executable_lines == ["curl -i -s 'http://127.0.0.1:3000/search?a=1&b=2'"]
    assert script.count("# WARNING: Skipped unsafe PoC command") == 9


# ---------------------------------------------------------------------------
# 2. arjun.py: multi-header 0o600 temp file + cleanup in finally
# ---------------------------------------------------------------------------


def test_arjun_multi_header_uses_0600_temp_file_and_cleans_up(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    get_settings.cache_clear()

    scope = ScopePolicy(
        allowed_urls=["http://127.0.0.1:3000"],
        custom_headers={
            "Authorization": "Bearer multi_hdr_secret_token_123",
            "X-Tenant-ID": "tenant-42",
        },
        auth_cookies={"session": "cookie_val_99"},
        allow_private_ips=True,
    )
    adapter = ArjunAdapter()
    arjun_args = ArjunArgs(method="GET")
    argv = adapter.build_argv(
        "http://127.0.0.1:3000/api/items",
        arjun_args,
        scope,
        tmp_path,
    )

    # Must pass sanitize_argv (no embedded \n or control characters)
    cleaned = sanitize_argv(argv)
    assert "--headers" not in cleaned
    assert "-i" in cleaned
    req_file = Path(cleaned[cleaned.index("-i") + 1])
    # build_argv() alone must NOT create secret request files on disk (e.g. if approval is rejected)
    assert not req_file.exists()

    # pre_execute() writes the 0o600 request file immediately before execution
    ctx = asyncio.run(
        adapter.pre_execute(
            engagement_id="e1",
            tool_run_id="r1",
            target="http://127.0.0.1:3000/api/items",
            args=arjun_args,
            scope=scope,
            work_dir=tmp_path,
        )
    )
    assert ctx.get("request_file") == str(req_file)
    assert req_file.is_file()

    # Verify strict 0o600 permissions
    mode = stat.S_IMODE(req_file.stat().st_mode)
    assert mode == 0o600

    # Verify content contains both headers + cookie and no secrets leaked into argv
    content = req_file.read_text(encoding="utf-8")
    assert "Authorization: Bearer multi_hdr_secret_token_123" in content
    assert "X-Tenant-ID: tenant-42" in content
    assert "Cookie: session=cookie_val_99" in content
    assert "multi_hdr_secret_token_123" not in " ".join(cleaned)

    # Verify post_execute cleans up the sensitive temp file
    asyncio.run(
        adapter.post_execute(
            engagement_id="e1",
            tool_run_id="r1",
            target="http://127.0.0.1:3000/api/items",
            args=ArjunArgs(),
            scope=scope,
            work_dir=tmp_path,
            context={},
            result=None,
        )
    )
    assert not req_file.exists()
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 3. BaseToolAdapter: timeout process-group kill, hooks, truncation, redaction
# ---------------------------------------------------------------------------


class _DummyArgs(BaseModel):
    script: str
    timeout_seconds: int = Field(default=1, ge=1, le=30)


class _DummyProcessAdapter(BaseToolAdapter):
    name = "dummy_proc"
    description = "Test subprocess adapter"
    tier = 1
    binary_name = "python3"
    args_schema = _DummyArgs

    def __init__(self) -> None:
        self.events: list[str] = []

    async def pre_execute(self, **kwargs):
        self.events.append("pre")
        return {"hook_marker": "from_pre"}

    async def post_execute(self, *, context, result, **kwargs):
        self.events.append("post")
        if result is not None:
            result.summary["hook_marker"] = context.get("hook_marker")

    def build_argv(self, target: str, args: BaseModel, scope: ScopePolicy, work_dir: Path) -> list[str]:
        assert isinstance(args, _DummyArgs)
        return [sys.executable, "-c", args.script]


def test_base_tool_adapter_timeout_kills_process_group_and_runs_hooks(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AEGISPT_MAX_OUTPUT_BYTES", "256")
    get_settings.cache_clear()

    child_pid_file = tmp_path / "grandchild.pid"
    # Spawn a grandchild process in the same process group, write its PID, print a line, and sleep
    py_script = (
        "import subprocess, sys, time, pathlib; "
        f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(p.pid)); "
        "print('Authorization: Bearer SuperSecretTokenABC123456', flush=True); "
        "time.sleep(30)"
    )

    adapter = _DummyProcessAdapter()
    scope = ScopePolicy(allowed_urls=["http://127.0.0.1:3000"], allow_private_ips=True)

    result = asyncio.run(
        adapter.execute(
            engagement_id="eng-timeout",
            tool_run_id="run-timeout",
            target="http://127.0.0.1:3000",
            raw_args={"script": py_script, "timeout_seconds": 1},
            scope=scope,
        )
    )

    assert adapter.events == ["pre", "post"]
    assert result.summary.get("hook_marker") == "from_pre"
    assert result.error is not None and "timed out" in result.error.lower()
    assert result.duration_ms >= 900
    assert result.raw_log_path is not None
    log_text = Path(result.raw_log_path).read_text(encoding="utf-8")
    assert "SuperSecretTokenABC123456" not in log_text

    # Confirm the grandchild process in the process group was actually terminated
    # (note: in Linux containers/sandboxes a killed grandchild may briefly remain as a 'Z' zombie
    # until PID 1 reaps it, in which case os.kill(pid, 0) still succeeds while /proc/<pid>/stat is 'Z')
    def _pid_is_dead(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        stat_path = Path(f"/proc/{pid}/stat")
        if not stat_path.exists():
            return True
        try:
            stat_txt = stat_path.read_text(encoding="utf-8", errors="replace")
            state = stat_txt.rsplit(")", 1)[1].strip().split()[0]
            return state in {"Z", "X", "x"}
        except Exception:
            return True

    assert child_pid_file.exists()
    gc_pid = int(child_pid_file.read_text().strip())
    dead = False
    for _ in range(20):
        if _pid_is_dead(gc_pid):
            dead = True
            break
        time.sleep(0.05)
    if not dead:
        try:
            os.kill(gc_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    assert dead, f"Grandchild PID {gc_pid} survived process-group timeout kill!"

    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 4. http_probe.py: /graphql 400, /v3/api-docs, OPTIONS BFLA, cookie JWT, Set-Cookie redaction
# ---------------------------------------------------------------------------


def test_http_probe_graphql_400_v3_apidocs_options_bfla_cookie_jwt_and_setcookie_redaction(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("AEGISPT_DATA_DIR", str(tmp_path))
    get_settings.cache_clear()

    cookie_jwt = _make_hs256_jwt({"sub": "cookie_user", "exp": 9999999999}, "secret")
    raw_cookie_secret = "SuperSensitiveSessionCookieValue987654"

    class ProbeTestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", f"sid={raw_cookie_secret}; Path=/")
                self.end_headers()
                self.wfile.write(b"<html><title>ProbeLab</title></html>")
                return
            if self.path == "/graphql":
                # Standard Apollo/GraphQL server returns 400 on GET without query
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"errors":[{"message":"GET query missing."}]}')
                return
            if self.path == "/v3/api-docs":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                doc = {
                    "openapi": "3.0.1",
                    "paths": {
                        "/api/v3/widgets": {"get": {}},
                        "/admin/secret": {"get": {}},
                    },
                }
                self.wfile.write(json.dumps(doc).encode())
                return
            if self.path == "/api/protected":
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Forbidden")
                return
            if self.path == "/api/cookie-profile":
                ck = self.headers.get("Cookie", "")
                if "access_jwt=" in ck:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"user":"cookie_user","role":"member","ok":true}')
                    return
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            if self.path == "/graphql":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
                return
            self.send_response(403)
            self.end_headers()

        def do_OPTIONS(self):
            # CORS preflight returns 200 with non-empty body on /api/protected
            self.send_response(200)
            self.send_header("Allow", "GET, OPTIONS")
            self.end_headers()
            self.wfile.write(b"GET, OPTIONS")

        def do_PUT(self):
            self.send_response(403)
            self.end_headers()

        def do_PATCH(self):
            self.send_response(403)
            self.end_headers()

        def do_DELETE(self):
            self.send_response(403)
            self.end_headers()

        def log_message(self, *_args):
            return

    httpd = HTTPServer(("127.0.0.1", 0), ProbeTestHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    try:
        adapter = HttpProbeAdapter()
        scope = ScopePolicy(
            allowed_urls=[f"http://127.0.0.1:{port}"],
            excluded_paths=["/admin"],
            auth_cookies={"access_jwt": cookie_jwt},
            allow_private_ips=True,
        )

        # 1. api_discovery: /graphql 400 + /v3/api-docs + Set-Cookie redaction + excluded_paths filter
        res_disc = asyncio.run(
            adapter.execute(
                engagement_id="e-hp",
                tool_run_id="r-disc",
                target=f"http://127.0.0.1:{port}/",
                raw_args=HttpProbeArgs(mode="api_discovery", check_cors=False).model_dump(),
                scope=scope,
            )
        )
        ep_paths = {e.path for e in res_disc.endpoints}
        assert "/graphql" in ep_paths
        assert "/api/v3/widgets" in ep_paths
        assert "/admin/secret" not in ep_paths  # filtered by excluded_paths

        titles = {f.title for f in res_disc.findings}
        assert "Unauthenticated GraphQL Introspection Enabled" in titles
        assert "Exposed OpenAPI / Swagger Specification" in titles

        # Set-Cookie raw value must be redacted in Finding.evidence
        cookie_findings = [f for f in res_disc.findings if f.cwe_id == "CWE-614"]
        assert cookie_findings
        ev_str = json.dumps(cookie_findings[0].evidence)
        assert raw_cookie_secret not in ev_str
        assert "sid=<REDACTED>" in cookie_findings[0].evidence["set_cookie"]
        assert "Path=/" in cookie_findings[0].evidence["set_cookie"]

        # 2. bfla_verb_tamper: OPTIONS returning 200 must NOT cause a false-positive BFLA finding
        res_bfla = asyncio.run(
            adapter.execute(
                engagement_id="e-hp",
                tool_run_id="r-bfla",
                target=f"http://127.0.0.1:{port}/api/protected",
                raw_args=HttpProbeArgs(mode="bfla_verb_tamper").model_dump(),
                scope=scope,
            )
        )
        assert not any("BFLA" in f.title for f in res_bfla.findings)

        # 3. jwt_active_probe: inspects scope.auth_cookies and detects bypass via cookie
        res_jwt = asyncio.run(
            adapter.execute(
                engagement_id="e-hp",
                tool_run_id="r-jwt",
                target=f"http://127.0.0.1:{port}/api/cookie-profile",
                raw_args=HttpProbeArgs(mode="jwt_active_probe").model_dump(),
                scope=scope,
            )
        )
        jwt_titles = {f.title for f in res_jwt.findings}
        assert "JWT Uses Known Default/Weak HMAC Signing Secret" in jwt_titles
        assert any("JWT Signature Verification Bypass Accepted" in t for t in jwt_titles)
        bypass_f = next(f for f in res_jwt.findings if "JWT Signature Verification Bypass" in f.title)
        assert bypass_f.evidence.get("source") == "cookie:access_jwt"
    finally:
        httpd.shutdown()
        httpd.server_close()
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 5. dalfox / sqlmap / ffuf Pydantic validation & shlex quoting
# ---------------------------------------------------------------------------


def test_dalfox_sqlmap_ffuf_pydantic_validation_and_poc_quoting(tmp_path: Path):
    # Valid args pass
    assert DalfoxArgs(param="user_id").param == "user_id"
    assert DalfoxArgs(param="filter[0]").param == "filter[0]"
    assert SqlmapArgs(param="id,user_name").param == "id,user_name"
    assert FfufArgs(match_codes="200,201-204,403").match_codes == "200,201-204,403"
    assert FfufArgs(match_codes="all").match_codes == "all"

    # Flag injection / metacharacters rejected
    for bad_param in ("--custom-alert-value", "-o", "q --proxy http://evil", "a;id", "q,--os-shell"):
        with pytest.raises(ValidationError):
            DalfoxArgs(param=bad_param)
        with pytest.raises(ValidationError):
            SqlmapArgs(param=bad_param)

    for bad_mc in ("200 -o /tmp/evil", "--proxy", "200;id", "999", ""):
        with pytest.raises(ValidationError):
            FfufArgs(match_codes=bad_mc)

    # PoC commands quote single quotes safely
    df = DalfoxAdapter()
    tricky_poc = "http://127.0.0.1:3000/?q=';id;'"
    (tmp_path / "dalfox.json").write_text(
        json.dumps([{"type": "Verified", "severity": "high", "param": "q", "data": tricky_poc}]),
        encoding="utf-8",
    )
    res_df = df.parse_output(
        target="http://127.0.0.1:3000/?q=1", args=DalfoxArgs(), stdout="", stderr="", work_dir=tmp_path
    )
    assert res_df.findings[0].poc_command is not None
    assert shlex.split(res_df.findings[0].poc_command) == ["curl", "-i", "-s", tricky_poc]

    sm = SqlmapAdapter()
    tricky_target = "http://127.0.0.1:3000/?q='1"
    sm_out = "---\nParameter: q'test (GET)\n    Type: boolean-based blind\n---\n"
    res_sm = sm.parse_output(
        target=tricky_target,
        args=SqlmapArgs(),
        stdout=sm_out,
        stderr="",
        work_dir=tmp_path,
    )
    assert res_sm.findings[0].poc_command is not None
    assert shlex.split(res_sm.findings[0].poc_command) == [
        "sqlmap",
        "-u",
        tricky_target,
        "--batch",
        "--level=1",
        "--risk=1",
        "-p",
        "q'test (GET)",
    ]


# ---------------------------------------------------------------------------
# 6. Scope filtering across discovery tools, wpscan host, httpx cache, zaproxy, DNS enforcement
# ---------------------------------------------------------------------------


def test_discovery_tools_filter_against_scope_and_wpscan_extracts_hostname(tmp_path: Path):
    scope = ScopePolicy(
        allowed_domains=["*.example.com"],
        excluded_hosts=["secret.example.com"],
        excluded_paths=["/logout", "/admin"],
    )

    # Katana
    kat = KatanaAdapter()
    kat_out = "\n".join(
        [
            json.dumps({"request": {"method": "GET", "endpoint": "https://app.example.com/api/v1/users"}}),
            json.dumps({"request": {"method": "GET", "endpoint": "https://app.example.com/logout"}}),
            json.dumps({"request": {"method": "GET", "endpoint": "https://secret.example.com/api"}}),
            json.dumps({"request": {"method": "GET", "endpoint": "https://evil.org/pwn"}}),
        ]
    )
    res_kat = kat.parse_output(
        target="https://app.example.com", args=KatanaArgs(), stdout=kat_out, stderr="", work_dir=tmp_path, scope=scope
    )
    assert [e.url for e in res_kat.endpoints] == ["https://app.example.com/api/v1/users"]

    # ParamSpider
    ps = ParamspiderAdapter()
    ps_out = "\n".join(
        [
            "https://app.example.com/search?q=FUZZ",
            "https://app.example.com/admin/panel?id=FUZZ",
            "https://secret.example.com/search?q=FUZZ",
        ]
    )
    res_ps = ps.parse_output(
        target="example.com", args=ParamspiderArgs(), stdout=ps_out, stderr="", work_dir=tmp_path, scope=scope
    )
    assert [e.url for e in res_ps.endpoints] == ["https://app.example.com/search?q=FUZZ"]

    # Subfinder
    sf = SubfinderAdapter()
    sf_out = "\n".join(
        [
            json.dumps({"host": "api.example.com", "source": "crtsh"}),
            json.dumps({"host": "secret.example.com", "source": "crtsh"}),
            json.dumps({"host": "other.org", "source": "crtsh"}),
        ]
    )
    res_sf = sf.parse_output(
        target="example.com", args=SubfinderArgs(), stdout=sf_out, stderr="", work_dir=tmp_path, scope=scope
    )
    assert [a.value for a in res_sf.assets] == ["api.example.com"]

    # Feroxbuster
    fx = FeroxbusterAdapter()
    (tmp_path / "ferox.json").write_text(
        "\n".join(
            [
                json.dumps({"type": "response", "url": "https://app.example.com/api/ok", "method": "GET", "status": 200}),
                json.dumps({"type": "response", "url": "https://app.example.com/admin/secret", "method": "GET", "status": 200}),
            ]
        ),
        encoding="utf-8",
    )
    res_fx = fx.parse_output(
        target="https://app.example.com", args=FeroxbusterArgs(), stdout="", stderr="", work_dir=tmp_path, scope=scope
    )
    assert [e.url for e in res_fx.endpoints] == ["https://app.example.com/api/ok"]

    # FFUF
    ff = FfufAdapter()
    (tmp_path / "ffuf.json").write_text(
        json.dumps(
            {
                "results": [
                    {"url": "https://app.example.com/api/ok", "status": 200},
                    {"url": "https://app.example.com/logout", "status": 200},
                ]
            }
        ),
        encoding="utf-8",
    )
    res_ff = ff.parse_output(
        target="https://app.example.com", args=FfufArgs(), stdout="", stderr="", work_dir=tmp_path, scope=scope
    )
    assert [e.url for e in res_ff.endpoints] == ["https://app.example.com/api/ok"]

    # WPScan stores hostname, not full URL
    wp = WpscanAdapter()
    (tmp_path / "wpscan.json").write_text(json.dumps({"version": {"number": "6.5"}}), encoding="utf-8")
    res_wp = wp.parse_output(
        target="https://Blog.Example.com:8443/wordpress/",
        args=WpscanArgs(),
        stdout="",
        stderr="",
        work_dir=tmp_path,
    )
    assert len(res_wp.assets) == 1
    assert res_wp.assets[0].asset_type == "host"
    assert res_wp.assets[0].value == "blog.example.com"


def test_httpx_version_probe_is_cached():
    _is_projectdiscovery_httpx.cache_clear()
    fake_proc = SimpleNamespace(stdout="Current Version: v1.6.0 (projectdiscovery)", stderr="")
    with patch("app.tools.httpx_tool.subprocess.run", return_value=fake_proc) as mock_run:
        assert _is_projectdiscovery_httpx("/fake/bin/httpx") is True
        assert _is_projectdiscovery_httpx("/fake/bin/httpx") is True
        assert mock_run.call_count == 1
    _is_projectdiscovery_httpx.cache_clear()


def test_zaproxy_allows_remote_daemon_without_local_binary(monkeypatch):
    monkeypatch.setenv("AEGISPT_ZAP_URL", "http://zap.internal.local:8080")
    get_settings.cache_clear()
    zap = ZapAdapter()
    with patch("app.tools.zaproxy.resolve_binary", return_value=None):
        available, resolved = zap.is_available()
        assert available is True
        assert resolved is not None and "zap.internal.local:8080" in resolved
    get_settings.cache_clear()


def test_trufflehog_gitleaks_reuse_base_execute_and_dns_safety_enforced(tmp_path: Path):
    # TrufflehogAdapter and GitleaksAdapter must inherit BaseToolAdapter.execute (not override it)
    assert TrufflehogAdapter.execute is BaseToolAdapter.execute
    assert GitleaksAdapter.execute is BaseToolAdapter.execute

    # Verify DNS validation (resolve_dns=True) is enforced on outbound bundle fetches
    scope = ScopePolicy(allowed_domains=["rebind.example.com"], allow_private_ips=False)
    calls: list[tuple[str, bool]] = []

    def _tracking_validate(target: str, *, resolve_dns: bool = True, dns_resolver=None) -> str:
        calls.append((target, resolve_dns))
        raise ScopeViolationError("DNS resolved to private IP")

    scope.validate_target = _tracking_validate  # type: ignore[method-assign]

    # js_miner enforces resolve_dns=True before fetching
    jm = JsMinerAdapter()
    with pytest.raises(ScopeViolationError):
        asyncio.run(
            jm.execute_native(
                engagement_id="e-dns",
                tool_run_id="r-dns",
                target="https://rebind.example.com/",
                args=JsMinerArgs(),
                scope=scope,
                work_dir=tmp_path,
            )
        )
    assert calls and calls[0] == ("https://rebind.example.com/", True)

    # trufflehog enforces resolve_dns=True before fetching
    calls.clear()
    th = TrufflehogAdapter()
    with pytest.raises(ScopeViolationError):
        asyncio.run(
            th._fetch_in_scope_artifacts(
                "e-dns", "https://rebind.example.com/", TrufflehogArgs(), scope, tmp_path
            )
        )
    assert calls and calls[0] == ("https://rebind.example.com/", True)

    # spa_inspector enforces resolve_dns=True before launching browser/navigating
    calls.clear()
    spa = SpaInspectorAdapter()
    fake_pw_mod = SimpleNamespace(async_playwright=lambda: None)
    with patch.dict(sys.modules, {"playwright": SimpleNamespace(), "playwright.async_api": fake_pw_mod}):
        with patch.object(spa, "_find_chromium", return_value="/usr/bin/chromium"):
            with pytest.raises(ScopeViolationError):
                asyncio.run(
                    spa.execute_native(
                        engagement_id="e-dns",
                        tool_run_id="r-dns",
                        target="https://rebind.example.com/",
                        args=SpaInspectorArgs(),
                        scope=scope,
                        work_dir=tmp_path,
                    )
                )
    assert calls and calls[0] == ("https://rebind.example.com/", True)


# ---------------------------------------------------------------------------
# 7. knowledge/store.py: in-memory caching, hash-gated FTS5 indexing & async API
# ---------------------------------------------------------------------------


def test_knowledge_store_caches_skills_and_hash_gates_fts5_indexing(tmp_path: Path):
    db_file = tmp_path / "kb_hash.db"
    kb = KnowledgeStore(db_path=db_file)

    # First ensure_indexed builds index, returns True, and enforces 0o600 mode on fresh DB
    assert kb.ensure_indexed() is True
    assert stat.S_IMODE(db_file.stat().st_mode) == 0o600

    # Second ensure_indexed on same instance skips rebuild (returns False)
    assert kb.ensure_indexed() is False

    # A fresh KnowledgeStore instance pointing at the same DB also skips rebuild via kb_meta hash
    kb2 = KnowledgeStore(db_path=db_file)
    assert kb2.ensure_indexed() is False

    # Skills are cached in memory: repeated list_all_skills calls do not re-parse markdown files
    with patch("app.knowledge.store._parse_markdown_skill") as mock_parse:
        skills_a = kb2.list_all_skills()
        skills_b = kb2.list_all_skills()
        assert len(skills_a) >= 9
        assert len(skills_b) == len(skills_a)
        assert mock_parse.call_count == 0

    # Corrupting/changing the stored content_hash forces a rebuild on next ensure_indexed()
    with sqlite3.connect(db_file) as conn:
        conn.execute("UPDATE kb_meta SET value = 'stale-hash' WHERE key = 'content_hash'")
        conn.commit()
    kb2.clear_cache()
    assert kb2.ensure_indexed() is True
    assert kb2.ensure_indexed() is False

    # Async wrappers work cleanly without blocking
    async def _check_async():
        rebuilt = await kb2.ensure_indexed_async()
        assert rebuilt is False
        hits = await kb2.search_async("graphql", limit=3)
        assert len(hits) >= 1

    asyncio.run(_check_async())
