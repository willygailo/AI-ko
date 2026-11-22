"""Fixture-based parser & argv compilation tests for Kali tool adapters."""
from __future__ import annotations

import json
from pathlib import Path

from app.core.scope import ScopePolicy
from app.tools.arjun import ArjunAdapter, ArjunArgs
from app.tools.dalfox import DalfoxAdapter, DalfoxArgs
from app.tools.ffuf import FfufAdapter, FfufArgs
from app.tools.httpx_tool import HttpxAdapter, HttpxArgs
from app.tools.katana import KatanaAdapter, KatanaArgs
from app.tools.nuclei import NucleiAdapter, NucleiArgs
from app.tools.sqlmap import SqlmapAdapter, SqlmapArgs
from app.tools.subfinder import SubfinderAdapter, SubfinderArgs
from app.tools.wafw00f import Wafw00fAdapter, Wafw00fArgs
from app.tools.whatweb import WhatWebAdapter, WhatWebArgs


def test_subfinder_parser(tmp_path: Path):
    adapter = SubfinderAdapter()
    stdout = '\n'.join(
        [
            json.dumps({"host": "api.example.com", "source": "crtsh"}),
            json.dumps({"host": "admin.example.com", "source": "dnsdumpster"}),
        ]
    )
    res = adapter.parse_output(
        target="example.com", args=SubfinderArgs(), stdout=stdout, stderr="", work_dir=tmp_path
    )
    assert [a.value for a in res.assets] == ["api.example.com", "admin.example.com"]


def test_httpx_and_katana_parsers(tmp_path: Path):
    hx = HttpxAdapter()
    hx_out = json.dumps(
        {
            "url": "https://app.example.com",
            "host": "app.example.com",
            "status_code": 200,
            "title": "Demo Portal",
            "tech": ["Express", "Node.js"],
        }
    )
    res_hx = hx.parse_output(
        target="https://app.example.com", args=HttpxArgs(), stdout=hx_out, stderr="", work_dir=tmp_path
    )
    assert len(res_hx.assets) == 1
    assert res_hx.assets[0].title == "Demo Portal"
    assert "Express" in res_hx.assets[0].technologies

    kat = KatanaAdapter()
    kat_out = json.dumps(
        {
            "request": {"method": "GET", "endpoint": "https://app.example.com/search?q=laptop"},
            "response": {"status_code": 200},
        }
    )
    res_kat = kat.parse_output(
        target="https://app.example.com", args=KatanaArgs(), stdout=kat_out, stderr="", work_dir=tmp_path
    )
    assert len(res_kat.endpoints) == 1
    assert res_kat.endpoints[0].query_params == ["q"]


def test_whatweb_and_wafw00f_parsers(tmp_path: Path):
    ww = WhatWebAdapter()
    (tmp_path / "whatweb.json").write_text(
        json.dumps(
            [
                {
                    "target": "http://127.0.0.1:3000",
                    "http_status": 200,
                    "plugins": {
                        "Title": {"string": ["OWASP Juice Shop"]},
                        "Express": {"version": ["4.18"]},
                    },
                }
            ]
        ),
        encoding="utf-8",
    )
    res_ww = ww.parse_output(
        target="http://127.0.0.1:3000", args=WhatWebArgs(), stdout="", stderr="", work_dir=tmp_path
    )
    assert res_ww.assets[0].title == "OWASP Juice Shop"
    assert "Express:4.18" in res_ww.assets[0].technologies

    wf = Wafw00fAdapter()
    (tmp_path / "wafw00f.json").write_text(
        json.dumps([{"url": "https://example.com", "detected": True, "firewall": "Cloudflare"}]),
        encoding="utf-8",
    )
    res_wf = wf.parse_output(
        target="https://example.com", args=Wafw00fArgs(), stdout="", stderr="", work_dir=tmp_path
    )
    assert res_wf.assets[0].waf == "Cloudflare"


def test_ffuf_arjun_nuclei_dalfox_sqlmap_parsers(tmp_path: Path):
    ff = FfufAdapter()
    (tmp_path / "ffuf.json").write_text(
        json.dumps({"results": [{"url": "http://127.0.0.1:3000/api/Users", "status": 200}]}),
        encoding="utf-8",
    )
    res_ff = ff.parse_output(
        target="http://127.0.0.1:3000", args=FfufArgs(), stdout="", stderr="", work_dir=tmp_path
    )
    assert res_ff.endpoints[0].path == "/api/Users"

    arj = ArjunAdapter()
    (tmp_path / "arjun.json").write_text(
        json.dumps({"http://127.0.0.1:3000/rest/products/search": {"params": ["q"], "method": "GET"}}),
        encoding="utf-8",
    )
    res_arj = arj.parse_output(
        target="http://127.0.0.1:3000/rest/products/search",
        args=ArjunArgs(),
        stdout="",
        stderr="",
        work_dir=tmp_path,
    )
    assert res_arj.endpoints[0].query_params == ["q"]

    nuc = NucleiAdapter()
    nuc_out = json.dumps(
        {
            "template-id": "exposed-env",
            "matched-at": "http://127.0.0.1:3000/.env",
            "info": {
                "name": "Exposed .env File",
                "severity": "high",
                "classification": {"cwe-id": ["CWE-200"], "cvss-score": 7.5},
            },
        }
    )
    res_nuc = nuc.parse_output(
        target="http://127.0.0.1:3000", args=NucleiArgs(), stdout=nuc_out, stderr="", work_dir=tmp_path
    )
    assert res_nuc.findings[0].severity == "high"
    assert res_nuc.findings[0].cwe_id == "CWE-200"

    df = DalfoxAdapter()
    (tmp_path / "dalfox.json").write_text(
        json.dumps([{"type": "Verified", "severity": "High", "param": "q", "data": "http://127.0.0.1:3000?q=<svg>"}]),
        encoding="utf-8",
    )
    res_df = df.parse_output(
        target="http://127.0.0.1:3000?q=1", args=DalfoxArgs(), stdout="", stderr="", work_dir=tmp_path
    )
    assert res_df.findings[0].cwe_id == "CWE-79"

    sm = SqlmapAdapter()
    sm_out = """---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
---"""
    res_sm = sm.parse_output(
        target="http://127.0.0.1:3000/rest/products/search?q=1",
        args=SqlmapArgs(),
        stdout=sm_out,
        stderr="",
        work_dir=tmp_path,
    )
    assert len(res_sm.findings) == 1
    assert res_sm.findings[0].severity == "critical"

    # Verify nuclei Tier 2 argv excludes intrusive tags
    scope = ScopePolicy(allowed_urls=["http://127.0.0.1:3000"], allow_private_ips=True, max_rps=10)
    argv = nuc.build_argv("http://127.0.0.1:3000", NucleiArgs(), scope, tmp_path)
    assert "-etags" in argv
    assert "-rl" in argv and "10" in argv
