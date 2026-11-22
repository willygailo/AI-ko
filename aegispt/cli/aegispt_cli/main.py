"""Typer + Rich CLI for AegisPT Private AI Pentesting Platform."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Optional

import typer
import websockets
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from aegispt_cli.client import AegisClient, resolve_api_token

app = typer.Typer(name="aegispt", help="AegisPT — Private AI Web & API Penetration Testing CLI")
engagement_app = typer.Typer(help="Create, list, and manage scoped engagements")
app.add_typer(engagement_app, name="engagement")

console = Console()


def _resolve_engagement_id(client: AegisClient, engagement_id: str) -> str:
    if engagement_id and engagement_id.lower() != "latest":
        return engagement_id
    items = client.get("/api/v1/engagements").json().get("engagements", [])
    if not items:
        console.print("[red]No engagements found. Create one first with `./aegispt engagement create ...`[/red]")
        raise typer.Exit(code=1)
    chosen = items[0]["id"]
    console.print(f"[dim]Using latest engagement: {chosen} ({items[0]['name']})[/dim]")
    return chosen


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address (localhost recommended)"),
    port: int = typer.Option(8443, help="HTTP/WebSocket port"),
) -> None:
    """Start the AegisPT FastAPI + WebSocket server."""
    import os
    import uvicorn

    os.environ["AEGISPT_HOST"] = host
    os.environ["AEGISPT_PORT"] = str(port)
    uvicorn.run("app.main:app", host=host, port=port, reload=False)


@app.command()
def token() -> None:
    """Print or initialize the local API bearer token for Web Dashboard access."""
    from app.config import get_settings

    tok = resolve_api_token() or get_settings().get_or_create_api_token()
    console.print(Panel(tok, title="AegisPT Local API Token", border_style="cyan"))


@app.command()
def doctor(
    json_output: bool = typer.Option(False, "--json", help="Print raw JSON output"),
) -> None:
    """Verify installed Kali tools, OWASP playbooks, and LLM endpoint reachability."""
    client = AegisClient()
    try:
        data = client.get("/api/v1/system/doctor").json()
    except Exception:
        # Offline fallback directly using backend registry
        from app.knowledge.store import knowledge_store
        from app.llm.router import default_profile_from_settings, llm_router
        from app.tools.registry import tool_registry

        knowledge_store.ensure_indexed()
        tools = tool_registry.describe_catalog()
        llm_status = asyncio.run(llm_router.list_models(default_profile_from_settings()))
        data = {
            "tools_available": sum(1 for t in tools if t["available"]),
            "tools_total": len(tools),
            "tools": tools,
            "llm": llm_status,
            "knowledge_playbooks": len(knowledge_store.search("", limit=100)),
        }

    if json_output:
        console.print_json(json.dumps(data))
        return

    table = Table(title=f"Kali Tool Adapters ({data['tools_available']}/{data['tools_total']} ready)")
    table.add_column("Tool", style="cyan")
    table.add_column("Tier", justify="center")
    table.add_column("Status")
    table.add_column("Path / Mode", style="dim")

    for t in data["tools"]:
        status = "[green]READY[/green]" if t["available"] else "[red]MISSING[/red]"
        table.add_row(t["name"], f"Tier {t['tier']}", status, str(t.get("resolved_path") or "-"))
    console.print(table)

    llm = data["llm"]
    llm_ok = "[green]REACHABLE[/green]" if llm.get("reachable") else "[yellow]UNREACHABLE (fallback planner active)[/yellow]"
    models_str = ", ".join(llm.get("models") or []) or llm.get("error", "none")
    console.print(
        Panel(
            f"Provider: [bold]{llm.get('provider')}[/bold] | URL: {llm.get('base_url')}\n"
            f"Status: {llm_ok}\nModels: {models_str}\n"
            f"OWASP Playbooks Indexed: [cyan]{data.get('knowledge_playbooks')}[/cyan]",
            title="AI Engine & Knowledge Base",
            border_style="blue",
        )
    )


@engagement_app.command("list")
def list_engagements() -> None:
    """List all engagements."""
    client = AegisClient()
    items = client.get("/api/v1/engagements").json().get("engagements", [])
    table = Table(title="AegisPT Engagements")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Mode")
    table.add_column("Status")
    table.add_column("Targets")
    for e in items:
        sc = e.get("scope") or {}
        targets = ", ".join((sc.get("allowed_urls") or []) + (sc.get("allowed_domains") or []))
        table.add_row(e["id"], e["name"], e["autonomy_mode"], e["status"], targets)
    console.print(table)


def _parse_kv(items: list[str], sep: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in items:
        if sep in raw:
            k, v = raw.split(sep, 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


@engagement_app.command("create")
def create_engagement(
    name: str = typer.Option(..., "--name", "-n", help="Engagement name"),
    url: list[str] = typer.Option([], "--url", "-u", help="Allowlisted target URL (repeatable)"),
    domain: list[str] = typer.Option([], "--domain", "-d", help="Allowlisted domain (repeatable)"),
    exclude_path: list[str] = typer.Option([], "--exclude-path", help="Excluded path prefix/glob"),
    auth_header: list[str] = typer.Option([], "--auth-header", "-H", help="Primary Auth header 'Key: Value' (repeatable)"),
    auth_cookie: list[str] = typer.Option([], "--auth-cookie", "-C", help="Primary Auth cookie 'name=value' (repeatable)"),
    secondary_header: list[str] = typer.Option([], "--secondary-header", help="Secondary role header 'Key: Value' for BOLA/IDOR"),
    secondary_cookie: list[str] = typer.Option([], "--secondary-cookie", help="Secondary role cookie 'name=value' for BOLA/IDOR"),
    mode: str = typer.Option("tiered", "--mode", help="tiered | copilot | lab_autopilot"),
    max_rps: int = typer.Option(15, "--max-rps", help="Max requests per second"),
    allow_private_ips: bool = typer.Option(False, "--allow-private-ips", help="Allow localhost/RFC1918 lab targets"),
    objective: str = typer.Option(
        "Comprehensive Web Application & API Security Assessment", "--objective"
    ),
) -> None:
    """Create a new scoped engagement."""
    client = AegisClient()
    payload = {
        "name": name,
        "objective": objective,
        "autonomy_mode": mode,
        "max_steps": 20,
        "scope": {
            "allowed_urls": url,
            "allowed_domains": domain,
            "excluded_paths": exclude_path,
            "custom_headers": _parse_kv(auth_header, ":"),
            "auth_cookies": _parse_kv(auth_cookie, "="),
            "secondary_headers": _parse_kv(secondary_header, ":"),
            "secondary_cookies": _parse_kv(secondary_cookie, "="),
            "max_rps": max_rps,
            "allow_private_ips": allow_private_ips,
        },
    }
    created = client.post("/api/v1/engagements", json_body=payload).json()
    console.print(
        Panel(
            f"Engagement ID: [bold cyan]{created['id']}[/bold cyan]\n"
            f"Name: {created['name']}\nMode: {created['autonomy_mode']}\n"
            f"Run with: [bold]aegispt run {created['id']}[/bold]",
            title="Engagement Created",
            border_style="green",
        )
    )


@engagement_app.command("delete")
def delete_engagement(engagement_id: str = typer.Argument(..., help="Engagement ID to delete")) -> None:
    """Delete an engagement and its stored artifacts."""
    client = AegisClient()
    client.delete(f"/api/v1/engagements/{engagement_id}")
    console.print(f"[green]Deleted engagement {engagement_id}.[/green]")


@app.command()
def runs(
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
    log: Optional[str] = typer.Option(None, "--log", help="Print raw stdout/stderr log for a specific run_id"),
) -> None:
    """Inspect tool execution runs or read a run's raw stdout/stderr log."""
    client = AegisClient()
    eng_id = _resolve_engagement_id(client, engagement_id)
    if log:
        log_text = client.get(f"/api/v1/engagements/{eng_id}/runs/{log}/log").json().get("log", "")
        console.print(Panel(log_text or "(empty log)", title=f"Tool Run Log: {log}", border_style="cyan"))
        return

    detail = client.get(f"/api/v1/engagements/{eng_id}").json()
    tool_runs = detail.get("tool_runs") or []
    table = Table(title=f"Tool Runs for {eng_id} ({len(tool_runs)})")
    table.add_column("Run ID", style="cyan")
    table.add_column("Tool")
    table.add_column("Tier", justify="center")
    table.add_column("Status")
    table.add_column("Duration")
    table.add_column("Target")
    for r in tool_runs:
        table.add_row(
            r["id"],
            r["tool_name"],
            f"T{r['tier']}",
            r["status"],
            f"{r['duration_ms']}ms" if r.get("duration_ms") is not None else "-",
            r["target"],
        )
    console.print(table)


async def _stream_and_approve(client: AegisClient, engagement_id: str) -> None:
    uri = client.ws_url(engagement_id)
    async with websockets.connect(uri) as ws:
        while True:
            raw = await ws.recv()
            ev = json.loads(raw)
            etype = ev.get("event_type", "")
            agent = ev.get("agent_name", "system")
            msg = ev.get("message", "")
            payload = ev.get("payload") or {}

            if etype == "pong":
                continue
            if etype == "tool_output":
                console.print(f"[dim][{agent}] {msg}[/dim]")
                continue

            color = {
                "engagement_started": "green",
                "agent_thought": "magenta",
                "tool_started": "cyan",
                "tool_completed": "green",
                "scope_blocked": "red",
                "approval_required": "yellow",
                "approval_resolved": "blue",
                "engagement_finished": "bold green",
                "engagement_failed": "bold red",
            }.get(etype, "white")
            console.print(f"[{color}][{etype} | {agent}][/{color}] {msg}")

            if etype == "approval_required":
                approval_id = payload.get("approval_id")
                argv_preview = " ".join(payload.get("argv_preview") or [])
                console.print(
                    Panel(
                        f"Tool: [bold]{payload.get('tool_name')}[/bold] (Tier {payload.get('tier')})\n"
                        f"Target: {payload.get('target')}\n"
                        f"Command Preview:\n[cyan]{argv_preview}[/cyan]\n\n"
                        f"Rationale: {payload.get('rationale')}\n"
                        f"Risk: {payload.get('risk_summary')}",
                        title=f"Operator Approval Required ({approval_id})",
                        border_style="yellow",
                    )
                )
                choice = Prompt.ask(
                    "Decision", choices=["a", "e", "r"], default="a"
                )
                if choice == "a":
                    client.post(
                        f"/api/v1/approvals/{approval_id}/decide",
                        json_body={"decision": "approved"},
                    )
                elif choice == "e":
                    raw_args = Prompt.ask(
                        "Enter modified args JSON",
                        default=json.dumps(payload.get("proposed_args") or {}),
                    )
                    mod_args = json.loads(raw_args)
                    client.post(
                        f"/api/v1/approvals/{approval_id}/decide",
                        json_body={"decision": "modified", "modified_args": mod_args},
                    )
                else:
                    note = Prompt.ask("Rejection note (optional)", default="Rejected by operator")
                    client.post(
                        f"/api/v1/approvals/{approval_id}/decide",
                        json_body={"decision": "rejected", "operator_note": note},
                    )

            if etype in ("engagement_finished", "engagement_failed"):
                break


@app.command()
def run(engagement_id: str = typer.Argument("latest", help="Engagement ID to execute and stream (or 'latest')")) -> None:
    """Start an engagement and attach interactive live stream + approval prompt."""
    client = AegisClient()
    eng_id = _resolve_engagement_id(client, engagement_id)
    client.post(f"/api/v1/engagements/{eng_id}/start")
    console.print(f"[green]Started engagement {eng_id}. Streaming live events...[/green]")
    try:
        asyncio.run(_stream_and_approve(client, eng_id))
    except KeyboardInterrupt:
        console.print("\n[yellow]Detached from stream (engagement continues on server).[/yellow]")


@app.command()
def findings(engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')")) -> None:
    """Display discovered findings for an engagement."""
    client = AegisClient()
    eng_id = _resolve_engagement_id(client, engagement_id)
    items = client.get(f"/api/v1/engagements/{eng_id}/findings").json().get("findings", [])
    table = Table(title=f"Findings for {eng_id} ({len(items)})")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Target")
    table.add_column("Param")
    table.add_column("Tool")
    table.add_column("Status")
    for f in items:
        table.add_row(
            f["severity"].upper(),
            f["title"],
            f["target_url"],
            f.get("parameter") or "-",
            f["tool_source"],
            f["status"],
        )
    console.print(table)


@app.command()
def report(
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
    format: str = typer.Option("html", "--format", "-f", help="html | markdown | sarif | json | poc_sh"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Output file path"),
) -> None:
    """Export assessment report in HTML, Markdown, SARIF, JSON, or PoC Shell script."""
    client = AegisClient()
    eng_id = _resolve_engagement_id(client, engagement_id)
    resp = client.get(f"/api/v1/engagements/{eng_id}/report", format=format)
    if out:
        out.write_text(resp.text, encoding="utf-8")
        console.print(f"[green]Saved {format} report to {out}[/green]")
    else:
        console.print(resp.text)


@app.command()
def hypotheses(engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')")) -> None:
    """List AI-generated security hypotheses and verification status."""
    client = AegisClient()
    eng_id = _resolve_engagement_id(client, engagement_id)
    items = client.get(f"/api/v1/engagements/{eng_id}/hypotheses").json().get("hypotheses", [])
    table = Table(title=f"Hypotheses for {eng_id} ({len(items)})")
    table.add_column("Status")
    table.add_column("Confidence")
    table.add_column("CWE")
    table.add_column("Title")
    table.add_column("Target")
    for h in items:
        table.add_row(h["status"], h["confidence"], h.get("cwe_id") or "-", h["title"], h["target_url"])
    console.print(table)


@app.command()
def diff(engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')")) -> None:
    """Compare baseline vs latest scan snapshot deltas for an engagement."""
    client = AegisClient()
    eng_id = _resolve_engagement_id(client, engagement_id)
    data = client.get(f"/api/v1/engagements/{eng_id}/diff").json()
    if not data.get("has_diff"):
        console.print(f"[yellow]Need at least 2 snapshots to compute diff (found {data.get('snapshots_count', 0)}).[/yellow]")
        return
    console.print(
        Panel(
            f"Baseline: {data['baseline']['label']} -> Current: {data['current']['label']}\n"
            f"+ New Assets: {len(data['new_assets'])}\n"
            f"+ New Endpoints: {len(data['new_endpoints'])}\n"
            f"+ New Findings: {len(data['new_findings'])}\n"
            f"- Resolved Findings: {len(data['resolved_findings'])}\n"
            f"+ New Open Ports: {len(data['new_open_ports'])}",
            title="Scan Snapshot Delta",
            border_style="cyan",
        )
    )


@app.command()
def repeat(
    engagement_id: str = typer.Argument(..., help="Engagement ID (or 'latest')"),
    url: str = typer.Argument(..., help="Target URL inside engagement scope"),
    method: str = typer.Option("GET", "--method", "-X", help="HTTP method"),
    body: Optional[str] = typer.Option(None, "--data", "-d", help="Optional request body"),
) -> None:
    """Send an interactive scoped HTTP request through the AegisPT Repeater."""
    client = AegisClient()
    eng_id = _resolve_engagement_id(client, engagement_id)
    res = client.post(
        f"/api/v1/engagements/{eng_id}/repeater",
        json_body={"method": method.upper(), "url": url, "body": body},
    ).json()
    console.print(
        Panel(
            f"HTTP {res['status_code']} ({res['duration_ms']}ms) — {res['final_url']}\n\n"
            f"{res['body'][:2000]}",
            title=f"Repeater Response ({method.upper()})",
            border_style="green" if res["status_code"] < 400 else "yellow",
        )
    )


@app.command()
def steer(
    hint: str = typer.Argument(..., help="Guidance instruction for the AI planner"),
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
) -> None:
    """Send a live steering instruction to guide the engagement planner."""
    client = AegisClient()
    eng_id = _resolve_engagement_id(client, engagement_id)
    res = client.post(f"/api/v1/engagements/{eng_id}/steer", json_body={"hint": hint}).json()
    console.print(f"[green]Queued steering hint for {eng_id}:[/green] {res['operator_hints'][-1]}")


@app.command()
def chains(engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')")) -> None:
    """Synthesize and display correlated multi-step attack chains."""
    client = AegisClient()
    eng_id = _resolve_engagement_id(client, engagement_id)
    client.post(f"/api/v1/engagements/{eng_id}/chains/synthesize")
    detail = client.get(f"/api/v1/engagements/{eng_id}").json()
    items = detail.get("attack_chains") or []
    if not items:
        console.print("[yellow]No multi-step attack chains correlated yet.[/yellow]")
        return
    for ch in items:
        steps_txt = "\n".join(ch.get("steps") or [])
        console.print(
            Panel(
                f"Target: {ch['target_url']}\n{ch['risk_summary']}\n\n{steps_txt}",
                title=f"[{ch['severity'].upper()}] {ch['title']}",
                border_style="red" if ch["severity"] == "critical" else "yellow",
            )
        )


@app.command()
def checklist(engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')")) -> None:
    """Display offensive skill methodology checklist coverage."""
    client = AegisClient()
    eng_id = _resolve_engagement_id(client, engagement_id)
    items = client.get(f"/api/v1/engagements/{eng_id}").json().get("checklist_items") or []
    table = Table(title=f"Skill Checklist Coverage ({len(items)} items)")
    table.add_column("Skill", style="cyan")
    table.add_column("Status")
    table.add_column("Check Item")
    for it in items:
        table.add_row(it["skill_title"], it["status"].upper(), it["item_text"])
    console.print(table)


TOOL_ARG_EXAMPLES: dict[str, str] = {
    "http_probe": '{"mode":"passive_audit"} | {"mode":"graphql_deep_audit"} | {"mode":"differential_bola"}',
    "js_miner": '{"max_bundles": 10}',
    "spa_inspector": '{"wait_ms": 2500}',
    "trufflehog": '{"max_bundles": 8, "verify_secrets": false}',
    "gitleaks": '{"max_bundles": 8}',
    "katana": '{"depth": 2, "js_crawl": true}',
    "ffuf": '{"wordlist_profile": "builtin", "max_time_seconds": 30}',
    "feroxbuster": '{"max_time_seconds": 30}',
    "arjun": '{"method": "GET"}',
    "nmap": '{"top_ports": 100}',
    "nuclei": '{"tags": ["misconfig","exposure"], "include_intrusive": false}',
    "zaproxy": '{"mode": "spider_passive", "max_duration_seconds": 60}',
    "dalfox": '{"param": "q"}',
    "sqlmap": '{"method": "POST", "data": "{\\"id\\":\\"1\\"}", "param": "id", "level": 1, "risk": 1}',
    "wpscan": '{"detection_mode": "passive", "enumerate": "vp,vt,u"}',
}

HTTP_PROBE_MODES: list[tuple[str, str, str]] = [
    ("passive_audit", "T1", "Headers, cookie attributes, multi-origin CORS, passive JWT, OpenAPI"),
    ("api_discovery", "T1", "Probe /openapi.json, /swagger.json, /graphql, /robots.txt"),
    ("graphql_deep_audit", "T2", "Schema dump + endpoint import, field-suggestion oracle, array batching"),
    ("oauth_audit", "T2", "OIDC .well-known metadata, implicit/PKCE checks, strict redirect_uri test"),
    ("replay_request", "T3", "Scoped custom method/headers/body HTTP replay"),
    ("differential_bola", "T3", "Primary vs Secondary-role (User B) or Unauth IDOR/BOLA diff"),
    ("jwt_active_probe", "T3", "Verify alg:none / stripped signature rejection & weak placeholder HMAC"),
    ("bfla_verb_tamper", "T3", "Verb authorization matrix check across GET/POST/PUT/PATCH/DELETE/OPTIONS"),
    ("race_burst_probe", "T3", "Synchronized concurrent burst (2-15 requests) for TOCTOU/idempotency"),
    ("hpp_and_content_switch", "T3", "Duplicate param precedence (HPP) & JSON/form Content-Type strictness"),
    ("ssti_probe", "T3", "Benign 37*50 arithmetic check with template engine family fingerprinting"),
    ("open_redirect_probe", "T3", "Synthetic .invalid redirect_uri/next/url Location check"),
]


def _default_aegispt_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _write_env_config(
    env_path: Path, updates: dict[str, str], template_path: Path | None = None
) -> Path:
    """Safely update or create a 0o600 .env configuration file preserving comments."""
    cleaned: dict[str, str] = {}
    for k, v in updates.items():
        clean_k = "".join(ch for ch in str(k) if ch.isalnum() or ch == "_")
        clean_v = str(v).replace("\r", "").replace("\n", "").strip()
        if clean_k:
            cleaned[clean_k] = clean_v

    if env_path.is_file():
        lines = env_path.read_text(encoding="utf-8").splitlines()
    elif template_path and template_path.is_file():
        lines = template_path.read_text(encoding="utf-8").splitlines()
    else:
        lines = []

    seen: set[str] = set()
    out_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            out_lines.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in cleaned:
            out_lines.append(f"{key}={cleaned[key]}")
            seen.add(key)
        else:
            out_lines.append(line)

    for k, v in cleaned.items():
        if k not in seen:
            out_lines.append(f"{k}={v}")

    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    try:
        os.chmod(env_path, 0o600)
    except OSError:
        pass
    return env_path


@app.command()
def setup(
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p", help="cloud | local | offline"
    ),
    url: Optional[str] = typer.Option(None, "--url", help="Ollama base URL override"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Ollama Cloud / endpoint API key"),
    fast_model: Optional[str] = typer.Option(None, "--fast-model", help="Fast model name"),
    reasoning_model: Optional[str] = typer.Option(None, "--reasoning-model", help="Reasoning model name"),
    env_path: Optional[Path] = typer.Option(None, "--env-path", help="Custom .env destination path"),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Verify live model endpoint reachability"),
) -> None:
    """Interactive setup wizard for .env (Ollama Cloud, Lightweight Local Ollama, or Offline Fallback)."""
    root = _default_aegispt_root()
    target_env = env_path or (root / ".env")
    template_env = root / ".env.example"

    chosen = (provider or "").strip().lower()
    if chosen not in {"cloud", "local", "offline"}:
        console.print(
            Panel(
                "[bold]1) cloud[/bold]   — Ollama Cloud (https://ollama.com + API key, 0 MB local RAM)\n"
                "[bold]2) local[/bold]   — Lightweight Local Ollama (qwen2.5:1.5b + 3b for 7.5-8 GB RAM)\n"
                "[bold]3) offline[/bold] — Zero-LLM Deterministic OWASP + Skill Pack Planner",
                title="AegisPT AI Setup Modes",
                border_style="cyan",
            )
        )
        chosen = Prompt.ask("Choose mode", choices=["cloud", "local", "offline"], default="cloud")

    if chosen == "cloud":
        resolved_url = url or "https://ollama.com"
        resolved_key = api_key if api_key is not None else Prompt.ask("Ollama Cloud API Key", password=True)
        resolved_fast = fast_model or "qwen3-next:80b"
        resolved_reason = reasoning_model or "qwen3-coder:480b"
    elif chosen == "local":
        resolved_url = url or "http://127.0.0.1:11434"
        resolved_key = api_key or ""
        resolved_fast = fast_model or "qwen2.5:1.5b"
        resolved_reason = reasoning_model or "qwen2.5:3b"
    else:
        resolved_url = url or "http://127.0.0.1:11434"
        resolved_key = ""
        resolved_fast = fast_model or "qwen2.5:1.5b"
        resolved_reason = reasoning_model or "qwen2.5:3b"

    written = _write_env_config(
        target_env,
        {
            "AEGISPT_OLLAMA_URL": resolved_url,
            "AEGISPT_OLLAMA_API_KEY": resolved_key,
            "AEGISPT_OLLAMA_FAST_MODEL": resolved_fast,
            "AEGISPT_OLLAMA_REASONING_MODEL": resolved_reason,
        },
        template_path=template_env,
    )

    console.print(
        Panel(
            f"Saved config: [cyan]{written}[/cyan] (chmod 600)\n"
            f"Mode: [bold]{chosen}[/bold]\n"
            f"Endpoint: {resolved_url}\n"
            f"Fast Model: {resolved_fast} | Reasoning Model: {resolved_reason}\n"
            f"API Key: {'configured (masked)' if resolved_key else '(none)'}",
            title="Setup Complete",
            border_style="green",
        )
    )

    if chosen == "local":
        console.print("[dim]Tip: Pull compact local models anytime via: ./scripts/setup_ollama.sh --light[/dim]")
    if verify and chosen != "offline":
        from app.llm.router import LLMProfileConfig, llm_router

        probe_cfg = LLMProfileConfig(
            name=chosen,
            provider="ollama",
            base_url=resolved_url,
            api_key=resolved_key,
            fast_model=resolved_fast,
            reasoning_model=resolved_reason,
        )
        res = asyncio.run(llm_router.list_models(probe_cfg))
        if res.get("reachable"):
            console.print(f"[green]Endpoint reachable![/green] Found {len(res.get('models') or [])} model(s).")
        else:
            console.print(f"[yellow]Endpoint not reachable yet:[/yellow] {res.get('error')} (fallback planner still works).")


@app.command()
def tools(
    tier: Optional[int] = typer.Option(None, "--tier", "-t", help="Filter by tier (1, 2, or 3)"),
    json_output: bool = typer.Option(False, "--json", help="Print JSON catalog"),
) -> None:
    """List all 24 tool adapters, 12 http_probe modes, and example JSON arguments."""
    from app.tools.registry import tool_registry

    catalog = tool_registry.describe_catalog()
    if tier is not None:
        catalog = [c for c in catalog if c["tier"] == tier]

    if json_output:
        console.print_json(json.dumps({"tools": catalog, "http_probe_modes": HTTP_PROBE_MODES}))
        return

    table = Table(title=f"AegisPT Security Tool Adapters ({len(catalog)})")
    table.add_column("Tool", style="cyan")
    table.add_column("Tier", justify="center")
    table.add_column("Status")
    table.add_column("Example args JSON")
    table.add_column("Purpose")

    for c in catalog:
        st = "[green]READY[/green]" if c["available"] else "[red]MISSING[/red]"
        table.add_row(
            c["name"],
            f"T{c['tier']}",
            st,
            TOOL_ARG_EXAMPLES.get(c["name"], "{}"),
            c["description"][:85],
        )
    console.print(table)

    if tier is None or any(m_tier == f"T{tier}" for _, m_tier, _ in HTTP_PROBE_MODES):
        modes_tbl = Table(title="Native `http_probe` Deep Verification Modes (12)")
        modes_tbl.add_column("Mode (--args '{\"mode\":...}')", style="magenta")
        modes_tbl.add_column("Tier", justify="center")
        modes_tbl.add_column("Capability")
        for m_name, m_tier, m_desc in HTTP_PROBE_MODES:
            if tier is None or m_tier == f"T{tier}":
                modes_tbl.add_row(m_name, m_tier, m_desc)
        console.print(modes_tbl)


def main() -> None:
    app(prog_name="aegispt")


if __name__ == "__main__":
    main()
