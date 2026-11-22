"""Typer + Rich CLI for AegisPT Private AI Pentesting Platform."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
import websockets
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from aegispt_cli.client import AegisClient, resolve_api_token

app = typer.Typer(help="AegisPT — Private AI Web & API Penetration Testing CLI")
engagement_app = typer.Typer(help="Create, list, and manage scoped engagements")
app.add_typer(engagement_app, name="engagement")

console = Console()


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
def doctor() -> None:
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
            "knowledge_playbooks": len(knowledge_store.search("", limit=20)),
        }

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


@engagement_app.command("create")
def create_engagement(
    name: str = typer.Option(..., "--name", "-n", help="Engagement name"),
    url: list[str] = typer.Option([], "--url", "-u", help="Allowlisted target URL (repeatable)"),
    domain: list[str] = typer.Option([], "--domain", "-d", help="Allowlisted domain (repeatable)"),
    exclude_path: list[str] = typer.Option([], "--exclude-path", help="Excluded path prefix/glob"),
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
def run(engagement_id: str = typer.Argument(..., help="Engagement ID to execute and stream")) -> None:
    """Start an engagement and attach interactive live stream + approval prompt."""
    client = AegisClient()
    client.post(f"/api/v1/engagements/{engagement_id}/start")
    console.print(f"[green]Started engagement {engagement_id}. Streaming live events...[/green]")
    try:
        asyncio.run(_stream_and_approve(client, engagement_id))
    except KeyboardInterrupt:
        console.print("\n[yellow]Detached from stream (engagement continues on server).[/yellow]")


@app.command()
def findings(engagement_id: str = typer.Argument(..., help="Engagement ID")) -> None:
    """Display discovered findings for an engagement."""
    client = AegisClient()
    items = client.get(f"/api/v1/engagements/{engagement_id}/findings").json().get("findings", [])
    table = Table(title=f"Findings for {engagement_id} ({len(items)})")
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
    engagement_id: str = typer.Argument(..., help="Engagement ID"),
    format: str = typer.Option("html", "--format", "-f", help="html | markdown | sarif | json"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Output file path"),
) -> None:
    """Export assessment report in HTML, Markdown, SARIF, or JSON."""
    client = AegisClient()
    resp = client.get(f"/api/v1/engagements/{engagement_id}/report", format=format)
    if out:
        out.write_text(resp.text, encoding="utf-8")
        console.print(f"[green]Saved {format} report to {out}[/green]")
    else:
        console.print(resp.text)


if __name__ == "__main__":
    app()
