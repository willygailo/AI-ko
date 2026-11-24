"""Report generation engine supporting Markdown, self-contained HTML, and SARIF 2.1.0."""
from __future__ import annotations

import html
import json
import re
import shlex
from datetime import datetime, timezone
from typing import Any

from app.db.models import Asset, AttackChain, Endpoint, Engagement, Finding, ToolRun


_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_SHELL_OPERATOR_TOKENS = frozenset({";", "&&", "||", "|", "&", ">", ">>", "<", "<<", "<>", ">&", "<&", "(", ")"})
_DISALLOWED_EXPANSION_RE = re.compile(r"`|\$\(|\$\{")
_DISALLOWED_EXECUTABLES = frozenset({"sh", "bash", "zsh", "dash", "ksh", "csh", "fish", "eval", "exec", "source", "."})


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 9),
            -(f.cvss_score or 0.0),
            f.title,
        ),
    )


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        if f.status == "false_positive":
            continue
        counts[f.severity if f.severity in counts else "info"] += 1
    return counts


def _compute_security_score(counts: dict[str, int]) -> tuple[int, str]:
    """Compute an overall posture score (0-100) and letter grade A-F."""
    penalty = (
        counts["critical"] * 25
        + counts["high"] * 15
        + counts["medium"] * 7
        + counts["low"] * 2
    )
    score = max(0, 100 - penalty)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def _owasp_breakdown(findings: list[Finding]) -> list[tuple[str, int]]:
    buckets: dict[str, int] = {}
    for f in findings:
        if f.status == "false_positive":
            continue
        cat = f.owasp_category or "Uncategorized / Informational"
        buckets[cat] = buckets.get(cat, 0) + 1
    return sorted(buckets.items(), key=lambda x: (-x[1], x[0]))


def render_markdown_report(
    engagement: Engagement,
    assets: list[Asset],
    endpoints: list[Endpoint],
    findings: list[Finding],
    runs: list[ToolRun],
    chains: list[AttackChain] | None = None,
) -> str:
    active = [f for f in _sorted_findings(findings) if f.status != "false_positive"]
    counts = _severity_counts(findings)
    score, grade = _compute_security_score(counts)
    owasp_rows_md = [f"| {cat} | {cnt} |" for cat, cnt in _owasp_breakdown(findings)]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = [
        f"# Security Assessment Report: {engagement.name}",
        "",
        f"- **Generated:** {now}",
        f"- **Engagement ID:** `{engagement.id}`",
        f"- **Autonomy Mode:** `{engagement.autonomy_mode}`",
        f"- **Security Posture Score:** **{score}/100 (Grade {grade})**",
        f"- **Objective:** {engagement.objective}",
        "",
        "## Executive Summary",
        "",
        f"Discovered **{len(assets)}** assets, **{len(endpoints)}** endpoints, executed **{len(runs)}** tool runs, and identified **{len(active)}** active findings.",
        "",
        "| Severity | Count |",
        "| :--- | ---: |",
        *(f"| {s.capitalize()} | {counts[s]} |" for s in ("critical", "high", "medium", "low", "info")),
        "",
        "### OWASP Category Distribution",
        "",
        "| OWASP Category | Count |",
        "| :--- | ---: |",
        *(owasp_rows_md or ["| _None recorded_ | 0 |"]),
        "",
        "## Attack Surface Summary",
        "",
        "| Type | Host / Value | Status | WAF | Technologies |",
        "| :--- | :--- | ---: | :--- | :--- |",
    ]
    for a in assets[:50]:
        techs = ", ".join((a.technologies or [])[:6]) or "-"
        lines.append(
            f"| {a.asset_type} | `{a.value}` | {a.status_code or '-'} | {a.waf or '-'} | {techs} |"
        )

    if chains:
        lines.extend(["", "## Synthesized Attack Chains", ""])
        for c_idx, ch in enumerate(chains, start=1):
            lines.extend(
                [
                    f"### Chain {c_idx}. [{ch.severity.upper()}] {ch.title}",
                    "",
                    f"- **Target:** `{ch.target_url}`",
                    f"- **Risk Summary:** {ch.risk_summary}",
                    "",
                    *(f"- {st}" for st in (ch.steps or [])),
                    "",
                ]
            )

    lines.extend(["", "## Findings Detail", ""])
    if not active:
        lines.append("_No active findings recorded._")
    for idx, f in enumerate(active, start=1):
        lines.extend(
            [
                f"### {idx}. [{f.severity.upper()}] {f.title}",
                "",
                f"- **Target:** `{f.target_url}`",
                f"- **Parameter:** `{f.parameter or 'N/A'}`",
                f"- **CVSS:** `{f.cvss_score if f.cvss_score is not None else 'N/A'}` | **CWE:** `{f.cwe_id or 'N/A'}` | **OWASP:** `{f.owasp_category or 'N/A'}`",
                f"- **Source Tool:** `{f.tool_source}` | **Status:** `{f.status}`",
                "",
                "**Description**",
                "",
                f.description or "_No description provided._",
                "",
            ]
        )
        if f.poc_command:
            lines.extend(["**Reproduction Command**", "", "```bash", f.poc_command, "```", ""])
        if f.evidence:
            lines.extend(
                [
                    "**Evidence**",
                    "",
                    "```json",
                    json.dumps(f.evidence, indent=2),
                    "```",
                    "",
                ]
            )
        lines.extend(["**Remediation**", "", f.remediation or "_Review and harden component._", ""])

    return "\n".join(lines)


def render_html_report(
    engagement: Engagement,
    assets: list[Asset],
    endpoints: list[Endpoint],
    findings: list[Finding],
    runs: list[ToolRun],
    chains: list[AttackChain] | None = None,
) -> str:
    active = [f for f in _sorted_findings(findings) if f.status != "false_positive"]
    counts = _severity_counts(findings)
    score, grade = _compute_security_score(counts)
    owasp_rows_html = "".join(
        f"<tr><td>{html.escape(cat)}</td><td><strong>{cnt}</strong></td></tr>"
        for cat, cnt in _owasp_breakdown(findings)
    )
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sev_colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#38bdf8",
        "info": "#94a3b8",
    }

    cards_html = []
    for s in ("critical", "high", "medium", "low", "info"):
        cards_html.append(
            f'<div class="card"><div class="card-num" style="color:{sev_colors[s]}">{counts[s]}</div>'
            f'<div class="card-lbl">{s.upper()}</div></div>'
        )

    findings_html = []
    for idx, f in enumerate(active, start=1):
        ev_json = html.escape(json.dumps(f.evidence or {}, indent=2))
        poc_block = (
            f'<div class="block"><strong>Reproduction</strong><pre>{html.escape(f.poc_command)}</pre></div>'
            if f.poc_command
            else ""
        )
        findings_html.append(
            f"""
            <article class="finding">
              <div class="finding-head">
                <span class="badge" style="background:{sev_colors.get(f.severity, '#94a3b8')}">{html.escape(f.severity.upper())}</span>
                <h3>{idx}. {html.escape(f.title)}</h3>
              </div>
              <div class="meta">
                <span><strong>Target:</strong> <code>{html.escape(f.target_url)}</code></span>
                <span><strong>Param:</strong> <code>{html.escape(f.parameter or 'N/A')}</code></span>
                <span><strong>CWE:</strong> {html.escape(f.cwe_id or 'N/A')}</span>
                <span><strong>CVSS:</strong> {html.escape(str(f.cvss_score or 'N/A'))}</span>
                <span><strong>Tool:</strong> {html.escape(f.tool_source)}</span>
              </div>
              <p>{html.escape(f.description or '')}</p>
              {poc_block}
              <div class="block"><strong>Evidence</strong><pre>{ev_json}</pre></div>
              <div class="block"><strong>Remediation</strong><p>{html.escape(f.remediation or '')}</p></div>
            </article>
            """
        )

    asset_rows = "".join(
        f"<tr><td>{html.escape(a.asset_type)}</td><td><code>{html.escape(a.value)}</code></td>"
        f"<td>{html.escape(str(a.status_code or '-'))}</td>"
        f"<td>{html.escape(a.waf or '-')}</td>"
        f"<td>{html.escape(', '.join((a.technologies or [])[:6]) or '-')}</td></tr>"
        for a in assets[:60]
    )

    chains_html = ""
    if chains:
        chain_cards = []
        for c_idx, ch in enumerate(chains, start=1):
            steps_li = "".join(f"<li>{html.escape(st)}</li>" for st in (ch.steps or []))
            chain_cards.append(
                f'<article class="finding"><div class="finding-head">'
                f'<span class="badge" style="background:{sev_colors.get(ch.severity, "#f97316")}">{html.escape(ch.severity.upper())}</span>'
                f"<h3>Chain {c_idx}. {html.escape(ch.title)}</h3></div>"
                f"<p>{html.escape(ch.risk_summary)}</p><ul>{steps_li}</ul></article>"
            )
        chains_html = f"<section><h2>Synthesized Attack Chains ({len(chains)})</h2>{''.join(chain_cards)}</section>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>AegisPT Report — {html.escape(engagement.name)}</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background:#0b1120; color:#e2e8f0; margin:0; padding:32px; line-height:1.55; }}
  .container {{ max-width: 1080px; margin: 0 auto; }}
  header {{ border-bottom: 1px solid #1e293b; padding-bottom: 20px; margin-bottom: 28px; }}
  h1 {{ margin: 0 0 8px 0; font-size: 28px; color: #f8fafc; }}
  .sub {{ color: #94a3b8; font-size: 14px; }}
  .cards {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 20px 0 32px; }}
  .card {{ background: #111827; border: 1px solid #1e293b; border-radius: 10px; padding: 16px; text-align: center; }}
  .card-num {{ font-size: 28px; font-weight: 700; }}
  .card-lbl {{ font-size: 11px; letter-spacing: 0.08em; color: #94a3b8; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0 32px; background: #111827; border-radius: 8px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #1e293b; font-size: 13px; }}
  th {{ background: #1e293b; color: #cbd5e1; }}
  .finding {{ background: #111827; border: 1px solid #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 18px; }}
  .finding-head {{ display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }}
  .finding-head h3 {{ margin: 0; font-size: 18px; color: #f8fafc; }}
  .badge {{ color: #0b1120; font-weight: 700; font-size: 11px; padding: 3px 9px; border-radius: 999px; }}
  .meta {{ display: flex; flex-wrap: wrap; gap: 16px; font-size: 12px; color: #94a3b8; margin-bottom: 12px; }}
  pre {{ background: #020617; border: 1px solid #1e293b; border-radius: 8px; padding: 12px; overflow-x: auto; font-size: 12px; color: #cbd5e1; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #7dd3fc; }}
  .block {{ margin-top: 12px; }}
  .toolbar {{ display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; }}
  .score-pill {{ background:#111827; border:1px solid #334155; border-radius:10px; padding:10px 16px; text-align:center; }}
  .print-btn {{ background:#0284c7; color:#fff; border:none; border-radius:8px; padding:8px 14px; font-weight:600; cursor:pointer; }}
  @media print {{
    body {{ background:#ffffff; color:#0f172a; padding:12px; }}
    .card, table, .finding, .score-pill {{ background:#ffffff; border-color:#cbd5e1; }}
    th {{ background:#f1f5f9; color:#0f172a; }}
    h1, .finding-head h3 {{ color:#0f172a; }}
    .sub, .meta, .card-lbl {{ color:#475569; }}
    pre {{ background:#f8fafc; color:#0f172a; border-color:#cbd5e1; }}
    code {{ color:#0369a1; }}
    .print-btn {{ display:none; }}
    .finding {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
  <div class="container">
    <header class="toolbar">
      <div>
        <h1>AegisPT Security Assessment Report</h1>
        <div class="sub">
          <strong>Engagement:</strong> {html.escape(engagement.name)} ({html.escape(engagement.id)}) &bull;
          <strong>Mode:</strong> {html.escape(engagement.autonomy_mode)} &bull;
          <strong>Generated:</strong> {now} &bull;
          <strong>Assets:</strong> {len(assets)} &bull;
          <strong>Endpoints:</strong> {len(endpoints)} &bull;
          <strong>Tool Runs:</strong> {len(runs)}
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:12px;">
        <div class="score-pill">
          <div style="font-size:22px;font-weight:800;color:#38bdf8;">{score}/100 ({grade})</div>
          <div style="font-size:10px;letter-spacing:0.08em;color:#94a3b8;">POSTURE SCORE</div>
        </div>
        <button class="print-btn" onclick="window.print()">Print / Save PDF</button>
      </div>
    </header>
    <section class="cards">{''.join(cards_html)}</section>
    <section>
      <h2>OWASP Category Breakdown</h2>
      <table>
        <thead><tr><th>OWASP Category</th><th>Findings</th></tr></thead>
        <tbody>{owasp_rows_html or '<tr><td colspan="2">No active findings recorded.</td></tr>'}</tbody>
      </table>
    </section>
    <section>
      <h2>Discovered Assets</h2>
      <table>
        <thead><tr><th>Type</th><th>Value</th><th>Status</th><th>WAF</th><th>Technologies</th></tr></thead>
        <tbody>{asset_rows or '<tr><td colspan="5">No assets recorded.</td></tr>'}</tbody>
      </table>
    </section>
    {chains_html}
    <section>
      <h2>Findings ({len(active)})</h2>
      {''.join(findings_html) or '<p>No active findings recorded.</p>'}
    </section>
  </div>
</body>
</html>"""


def render_sarif_report(engagement: Engagement, findings: list[Finding]) -> dict[str, Any]:
    active = [f for f in _sorted_findings(findings) if f.status != "false_positive"]
    rules = []
    results = []
    seen_rules: set[str] = set()

    for f in active:
        rule_id = f.cwe_id or f.fingerprint
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description or f.title},
                    "help": {"text": f.remediation or "Review security configuration."},
                }
            )
        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVEL.get(f.severity, "note"),
                "message": {"text": f"{f.title} — {f.target_url}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.target_url},
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "parameter": f.parameter,
                    "tool_source": f.tool_source,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AegisPT",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": results,
            }
        ],
    }


def _sanitize_single_line(text: str) -> str:
    """Strip control characters and newlines so text stays safely on a single line."""
    return _CONTROL_CHAR_RE.sub(" ", str(text or "")).strip()


def _sanitize_poc_command(raw_cmd: str) -> tuple[bool, str]:
    """Validate and safely quote a PoC command for bash execution.

    Returns (is_safe, rendered_command_or_reason). Rejects control chars, shell
    metacharacters/chaining operators, command substitutions, and unparseable syntax.
    """
    if not raw_cmd or not isinstance(raw_cmd, str):
        return False, "empty command"
    if _CONTROL_CHAR_RE.search(raw_cmd):
        return False, "contains newline or control characters"
    if _DISALLOWED_EXPANSION_RE.search(raw_cmd):
        return False, "contains shell command/variable expansion syntax"

    try:
        lexer = shlex.shlex(raw_cmd, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError as exc:
        return False, f"unparseable shell syntax ({exc})"

    if not tokens:
        return False, "empty command"

    for tok in tokens:
        if tok in _SHELL_OPERATOR_TOKENS:
            return False, f"contains shell operator {tok!r}"

    exe = tokens[0].rsplit("/", 1)[-1].lower()
    if exe in _DISALLOWED_EXECUTABLES:
        return False, f"disallowed shell executable {exe!r}"

    return True, shlex.join(tokens)


def render_poc_script(engagement: Engagement, findings: list[Finding]) -> str:
    """Generate an executable bash verification regression script for confirmed/open findings."""
    active = [f for f in _sorted_findings(findings) if f.status != "false_positive" and f.poc_command]
    safe_eng_name = _sanitize_single_line(engagement.name)
    safe_eng_id = _sanitize_single_line(engagement.id)
    lines = [
        "#!/usr/bin/env bash",
        f"# AegisPT Verification Replay Script — {safe_eng_name} ({safe_eng_id})",
        "# Run ONLY against authorized scope targets.",
        "set -uo pipefail",
        "",
    ]
    if not active:
        lines.append("echo 'No reproduction commands recorded for active findings.'")
        return "\n".join(lines) + "\n"

    for idx, f in enumerate(active, start=1):
        safe_sev = _sanitize_single_line(f.severity).upper()
        safe_title = _sanitize_single_line(f.title)
        banner = f"=== [{idx}] [{safe_sev}] {safe_title} ==="
        lines.append(f"echo {shlex.quote(banner)}")

        ok, rendered = _sanitize_poc_command(f.poc_command or "")
        if ok:
            lines.append(rendered)
        else:
            preview = _sanitize_single_line(f.poc_command or "")[:240]
            lines.extend(
                [
                    f"# WARNING: Skipped unsafe PoC command ({rendered}):",
                    f"# {preview}",
                    f"echo {shlex.quote(f'[SKIPPED] Unsafe PoC command for finding #{idx}: {rendered}')}",
                ]
            )
        lines.extend(["echo ''", ""])
    return "\n".join(lines)
