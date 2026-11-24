"""Typer + Rich CLI for AegisPT Private AI Pentesting Platform."""
from __future__ import annotations

import asyncio
import functools
import inspect
import json
import os
import sys
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional

import click
import typer
import websockets
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from aegispt_cli.client import (
    AegisAPIError,
    AegisClient,
    default_env_path,
    resolve_api_token,
)


class DefaultListGroup(typer.core.TyperGroup):
    """Allow explicit subcommands while defaulting unknown positional args to `list`."""

    def _rewrite_default_list(self, ctx: click.Context, args: list[str]) -> list[str]:
        if args and not args[0].startswith("-") and "list" in self.commands:
            cmd_name = args[0]
            cmd = self.get_command(ctx, cmd_name)
            if cmd is None and ctx.token_normalize_func is not None:
                cmd = self.get_command(ctx, ctx.token_normalize_func(cmd_name))
            if cmd is None:
                return ["list", *args]
        return args

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        return super().parse_args(ctx, self._rewrite_default_list(ctx, args))

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        return super().resolve_command(ctx, self._rewrite_default_list(ctx, args))


app = typer.Typer(name="aegispt", help="AegisPT — Private AI Web & API Penetration Testing CLI")
engagement_app = typer.Typer(help="Create, list, and manage scoped engagements")
findings_app = typer.Typer(
    cls=DefaultListGroup,
    help="Inspect, triage, and reverify discovered security findings",
)
approvals_app = typer.Typer(
    cls=DefaultListGroup,
    help="Inspect and decide Tier 2/3 operator approval requests",
)
snapshots_app = typer.Typer(
    cls=DefaultListGroup,
    help="List and capture point-in-time scan snapshots",
)
llm_profiles_app = typer.Typer(
    cls=DefaultListGroup,
    help="List, create, delete, and probe LLM provider profiles",
)

app.add_typer(engagement_app, name="engagement")
app.add_typer(findings_app, name="findings", cls=DefaultListGroup)
app.add_typer(approvals_app, name="approvals", cls=DefaultListGroup)
app.add_typer(snapshots_app, name="snapshots", cls=DefaultListGroup)
app.add_typer(llm_profiles_app, name="llm-profiles", cls=DefaultListGroup)

console = Console()
err_console = Console(stderr=True)

VALID_AUTONOMY_MODES = {"tiered", "copilot", "lab_autopilot"}
VALID_FINDING_STATUSES = {"open", "confirmed", "false_positive", "remediated"}
VALID_FINDING_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_APPROVAL_DECISIONS = {"approved", "modified", "rejected"}
VALID_LLM_PROVIDERS = {"ollama", "openai_compat"}
VALID_REPORT_FORMATS = {"html", "markdown", "sarif", "json", "poc_sh"}
TERMINAL_WS_EVENTS = {"engagement_finished", "engagement_failed", "engagement_stopped"}


@contextmanager
def _open_client() -> Iterator[AegisClient]:
    client = AegisClient()
    try:
        yield client
    finally:
        close_fn = getattr(client, "close", None)
        if callable(close_fn):
            close_fn()


def _print_api_error(exc: AegisAPIError) -> None:
    err_console.print(f"[red]Error:[/red] {escape(exc.message)}")
    if exc.hint:
        err_console.print(f"[dim]Hint: {escape(exc.hint)}[/dim]")


def _handle_api_errors(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Centralized clean error handler for API-backed CLI commands."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except AegisAPIError as exc:
            _print_api_error(exc)
            raise typer.Exit(code=1) from None

    return wrapper


def _resolve_engagement_id(client: AegisClient, engagement_id: str) -> str:
    if engagement_id and engagement_id.lower() != "latest":
        return engagement_id
    items = client.get("/api/v1/engagements").json().get("engagements", [])
    if not items:
        err_console.print(
            "[red]No engagements found. Create one first with `./aegispt engagement create ...`[/red]"
        )
        raise typer.Exit(code=1)
    chosen = items[0]["id"]
    name = escape(str(items[0].get("name", "")))
    err_console.print(f"[dim]Using latest engagement: {escape(str(chosen))} ({name})[/dim]")
    return str(chosen)


def _parse_kv(items: list[str], sep: str, label: str = "option") -> dict[str, str]:
    """Parse strict key/value CLI flags; raise typer.BadParameter on malformed entries."""
    out: dict[str, str] = {}
    for raw in items:
        if sep not in raw:
            raise typer.BadParameter(
                f"Invalid {label} {raw!r}: expected 'Key{sep}Value' format."
            )
        k, v = raw.split(sep, 1)
        if not k.strip():
            raise typer.BadParameter(f"Invalid {label} {raw!r}: key cannot be empty.")
        out[k.strip()] = v.strip()
    return out


def _parse_json_object(raw: str, param_name: str = "--args") -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"Invalid JSON for {param_name}: {exc}") from None
    if not isinstance(parsed, dict):
        raise typer.BadParameter(f"{param_name} must be a JSON object (e.g. '{{\"mode\": \"passive_audit\"}}').")
    return parsed


def _ws_connect(uri: str, headers: dict[str, str]) -> Any:
    """Connect to a WebSocket using auth headers compatible with websockets 12/13/14+."""
    connect_fn = websockets.connect
    try:
        params = inspect.signature(connect_fn).parameters
    except (TypeError, ValueError):
        params = {}

    if "additional_headers" in params:
        return connect_fn(uri, additional_headers=headers)
    if "extra_headers" in params:
        return connect_fn(uri, extra_headers=headers)
    try:
        return connect_fn(uri, additional_headers=headers)
    except TypeError:
        return connect_fn(uri, extra_headers=headers)


@app.command()
def serve(
    host: Optional[str] = typer.Option(
        None, help="Bind address (defaults to AEGISPT_HOST / 127.0.0.1)"
    ),
    port: Optional[int] = typer.Option(
        None, help="HTTP/WebSocket port (defaults to AEGISPT_PORT / 8443)"
    ),
    hide_token: bool = typer.Option(
        False, "--hide-token", help="Do not print the local API token on startup"
    ),
) -> None:
    """Start the AegisPT FastAPI + WebSocket server and display the Web Dashboard token."""
    import uvicorn

    from app.config import get_settings

    settings = get_settings()
    resolved_host = host if host is not None else settings.host
    resolved_port = port if port is not None else settings.port

    if host is not None:
        os.environ["AEGISPT_HOST"] = resolved_host
    if port is not None:
        os.environ["AEGISPT_PORT"] = str(resolved_port)
    if host is not None or port is not None:
        cache_clear = getattr(get_settings, "cache_clear", None)
        if callable(cache_clear):
            cache_clear()

    tok = resolve_api_token() or get_settings().get_or_create_api_token()
    display_host = "127.0.0.1" if resolved_host in {"0.0.0.0", ""} else resolved_host
    err_console.print(f"[bold cyan][AegisPT] Web Dashboard:[/bold cyan] http://{display_host}:{resolved_port}")
    if not hide_token and os.environ.get("AEGISPT_PRINT_TOKEN") != "0":
        err_console.print(
            "[cyan][AegisPT] Copy & paste this Local API Token into the Web Dashboard:[/cyan]"
        )
        sys.stdout.write(tok + "\n")
        sys.stdout.flush()

    uvicorn.run("app.main:app", host=resolved_host, port=resolved_port, reload=False)


@app.command()
def token(
    raw: bool = typer.Option(
        False, "--raw", "-r", help="Print only the raw API token without headers or hints"
    ),
) -> None:
    """Print or initialize the local API bearer token for Web Dashboard access."""
    from app.config import get_settings

    tok = resolve_api_token() or get_settings().get_or_create_api_token()
    if raw or not sys.stdout.isatty():
        sys.stdout.write(tok + "\n")
        sys.stdout.flush()
        return

    err_console.print(
        "[cyan]AegisPT Local API Token[/cyan] [dim](copy the line below into http://127.0.0.1:8443):[/dim]"
    )
    sys.stdout.write(tok + "\n")
    sys.stdout.flush()


@app.command()
@_handle_api_errors
def doctor(
    json_output: bool = typer.Option(False, "--json", help="Print raw JSON output"),
) -> None:
    """Verify installed Kali tools, OWASP playbooks, and LLM endpoint reachability."""
    data: dict[str, Any]
    with _open_client() as client:
        try:
            resp_json = client.get("/api/v1/system/doctor").json()
            data = resp_json if isinstance(resp_json, dict) else {}
        except AegisAPIError as exc:
            if not exc.is_connection_error:
                raise
            err_console.print(
                f"[yellow]Server unreachable ({escape(exc.message)}); running local offline diagnostics.[/yellow]"
            )
            from app.knowledge.store import knowledge_store
            from app.llm.router import default_profile_from_settings, llm_router
            from app.tools.registry import tool_registry

            knowledge_store.ensure_indexed()
            tools_catalog: list[dict[str, Any]] = list(tool_registry.describe_catalog())
            llm_status: dict[str, Any] = dict(
                asyncio.run(llm_router.list_models(default_profile_from_settings()))
            )
            data = {
                "tools_available": sum(1 for t in tools_catalog if t.get("available")),
                "tools_total": len(tools_catalog),
                "tools": tools_catalog,
                "llm": llm_status,
                "knowledge_playbooks": len(knowledge_store.search("", limit=100)),
            }

    if json_output:
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
        sys.stdout.flush()
        return

    table = Table(
        title=f"Kali Tool Adapters ({data.get('tools_available', 0)}/{data.get('tools_total', 0)} ready)"
    )
    table.add_column("Tool", style="cyan")
    table.add_column("Tier", justify="center")
    table.add_column("Status")
    table.add_column("Path / Mode", style="dim")

    raw_tools = data.get("tools")
    tools_items: list[dict[str, Any]] = (
        [t for t in raw_tools if isinstance(t, dict)] if isinstance(raw_tools, list) else []
    )
    for t in tools_items:
        status = "[green]READY[/green]" if t.get("available") else "[red]MISSING[/red]"
        table.add_row(
            escape(str(t.get("name", ""))),
            f"Tier {t.get('tier', '')}",
            status,
            escape(str(t.get("resolved_path") or "-")),
        )
    console.print(table)

    raw_llm = data.get("llm")
    llm: dict[str, Any] = raw_llm if isinstance(raw_llm, dict) else {}
    llm_ok = (
        "[green]REACHABLE[/green]"
        if llm.get("reachable")
        else "[yellow]UNREACHABLE (fallback planner active)[/yellow]"
    )
    raw_models = llm.get("models")
    model_names = [str(m) for m in raw_models] if isinstance(raw_models, list) else []
    models_str = escape(", ".join(model_names) or str(llm.get("error", "none")))
    console.print(
        Panel(
            f"Provider: [bold]{escape(str(llm.get('provider')))}[/bold] | URL: {escape(str(llm.get('base_url')))}\n"
            f"Status: {llm_ok}\nModels: {models_str}\n"
            f"OWASP Playbooks Indexed: [cyan]{escape(str(data.get('knowledge_playbooks')))}[/cyan]",
            title="AI Engine & Knowledge Base",
            border_style="blue",
        )
    )


@engagement_app.command("list")
@_handle_api_errors
def list_engagements() -> None:
    """List all engagements."""
    with _open_client() as client:
        items = client.get("/api/v1/engagements").json().get("engagements", [])
    table = Table(title="AegisPT Engagements")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Mode")
    table.add_column("Status")
    table.add_column("Targets")
    for e in items:
        sc = e.get("scope") or {}
        targets = ", ".join(
            (sc.get("allowed_urls") or [])
            + (sc.get("allowed_domains") or [])
            + (sc.get("allowed_cidrs") or [])
        )
        table.add_row(
            escape(str(e["id"])),
            escape(str(e["name"])),
            escape(str(e["autonomy_mode"])),
            escape(str(e["status"])),
            escape(targets),
        )
    console.print(table)


@engagement_app.command("create")
@_handle_api_errors
def create_engagement(
    name: str = typer.Option(..., "--name", "-n", help="Engagement name"),
    url: list[str] = typer.Option([], "--url", "-u", help="Allowlisted target URL (repeatable)"),
    domain: list[str] = typer.Option([], "--domain", "-d", help="Allowlisted domain (repeatable)"),
    allowed_cidr: list[str] = typer.Option([], "--allowed-cidr", help="Allowlisted CIDR block (repeatable)"),
    exclude_host: list[str] = typer.Option([], "--exclude-host", help="Excluded host (repeatable)"),
    exclude_path: list[str] = typer.Option([], "--exclude-path", help="Excluded path prefix/glob"),
    auth_header: list[str] = typer.Option([], "--auth-header", "-H", help="Primary Auth header 'Key: Value' (repeatable)"),
    auth_cookie: list[str] = typer.Option([], "--auth-cookie", "-C", help="Primary Auth cookie 'name=value' (repeatable)"),
    secondary_header: list[str] = typer.Option([], "--secondary-header", help="Secondary role header 'Key: Value' for BOLA/IDOR"),
    secondary_cookie: list[str] = typer.Option([], "--secondary-cookie", help="Secondary role cookie 'name=value' for BOLA/IDOR"),
    mode: str = typer.Option("tiered", "--mode", help="tiered | copilot | lab_autopilot"),
    max_steps: int = typer.Option(25, "--max-steps", min=1, max=60, help="Maximum orchestrator steps (1-60)"),
    tier2_auto: bool = typer.Option(True, "--tier2-auto/--no-tier2-auto", help="Auto-approve Tier 2 active scans"),
    llm_profile_id: Optional[str] = typer.Option(None, "--llm-profile-id", help="Optional LLM profile ID"),
    max_rps: int = typer.Option(15, "--max-rps", min=1, max=100, help="Max requests per second (1-100)"),
    max_concurrency: int = typer.Option(5, "--max-concurrency", min=1, max=30, help="Max concurrent probes (1-30)"),
    allow_private_ips: bool = typer.Option(False, "--allow-private-ips", help="Allow localhost/RFC1918 lab targets"),
    objective: str = typer.Option(
        "Comprehensive Web Application & API Security Assessment", "--objective"
    ),
) -> None:
    """Create a new scoped engagement."""
    if mode not in VALID_AUTONOMY_MODES:
        raise typer.BadParameter(
            f"Invalid --mode {mode!r}. Expected one of: {', '.join(sorted(VALID_AUTONOMY_MODES))}."
        )
    if not (url or domain or allowed_cidr):
        raise typer.BadParameter(
            "Scope must include at least one --url, --domain, or --allowed-cidr."
        )

    payload: dict[str, Any] = {
        "name": name,
        "objective": objective,
        "autonomy_mode": mode,
        "tier2_auto": tier2_auto,
        "max_steps": max_steps,
        "llm_profile_id": llm_profile_id,
        "scope": {
            "allowed_urls": url,
            "allowed_domains": domain,
            "allowed_cidrs": allowed_cidr,
            "excluded_hosts": exclude_host,
            "excluded_paths": exclude_path,
            "custom_headers": _parse_kv(auth_header, ":", label="--auth-header"),
            "auth_cookies": _parse_kv(auth_cookie, "=", label="--auth-cookie"),
            "secondary_headers": _parse_kv(secondary_header, ":", label="--secondary-header"),
            "secondary_cookies": _parse_kv(secondary_cookie, "=", label="--secondary-cookie"),
            "max_rps": max_rps,
            "max_concurrency": max_concurrency,
            "allow_private_ips": allow_private_ips,
        },
    }
    with _open_client() as client:
        created = client.post("/api/v1/engagements", json_body=payload).json()
    eng_id = escape(str(created["id"]))
    console.print(
        Panel(
            f"Engagement ID: [bold cyan]{eng_id}[/bold cyan]\n"
            f"Name: {escape(str(created['name']))}\n"
            f"Mode: {escape(str(created['autonomy_mode']))} | Max Steps: {created.get('max_steps', max_steps)}\n"
            f"Run with: [bold]aegispt run {eng_id}[/bold]",
            title="Engagement Created",
            border_style="green",
        )
    )


@engagement_app.command("delete")
@_handle_api_errors
def delete_engagement(
    engagement_id: str = typer.Argument("latest", help="Engagement ID to delete (or 'latest')"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip interactive confirmation prompt"),
) -> None:
    """Delete an engagement and its stored artifacts."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        if not yes:
            typer.confirm(f"Delete engagement {eng_id} and all stored artifacts?", abort=True)
        client.delete(f"/api/v1/engagements/{eng_id}")
    console.print(f"[green]Deleted engagement {escape(eng_id)}.[/green]")


@app.command()
@_handle_api_errors
def runs(
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
    log: Optional[str] = typer.Option(None, "--log", help="Print raw stdout/stderr log for a specific run_id"),
) -> None:
    """Inspect tool execution runs or read a run's raw stdout/stderr log."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        if log:
            log_text = client.get(f"/api/v1/engagements/{eng_id}/runs/{log}/log").json().get("log", "")
            console.print(
                Panel(
                    Text(log_text or "(empty log)"),
                    title=f"Tool Run Log: {escape(log)}",
                    border_style="cyan",
                )
            )
            return

        detail = client.get(f"/api/v1/engagements/{eng_id}").json()

    tool_runs = detail.get("tool_runs") or []
    table = Table(title=f"Tool Runs for {escape(eng_id)} ({len(tool_runs)})")
    table.add_column("Run ID", style="cyan")
    table.add_column("Tool")
    table.add_column("Tier", justify="center")
    table.add_column("Status")
    table.add_column("Duration")
    table.add_column("Target")
    for r in tool_runs:
        table.add_row(
            escape(str(r["id"])),
            escape(str(r["tool_name"])),
            f"T{r['tier']}",
            escape(str(r["status"])),
            f"{r['duration_ms']}ms" if r.get("duration_ms") is not None else "-",
            escape(str(r["target"])),
        )
    console.print(table)


async def _handle_approval_prompt(client: AegisClient, payload: dict[str, Any]) -> None:
    """Prompt the operator without blocking the asyncio loop and submit their decision."""
    approval_id = payload.get("approval_id")
    if not approval_id:
        return
    argv_preview = " ".join(str(x) for x in (payload.get("argv_preview") or []))
    body = Text()
    body.append("Tool: ", style="bold")
    body.append(f"{payload.get('tool_name')} (Tier {payload.get('tier')})\n")
    body.append(f"Target: {payload.get('target')}\n")
    body.append("Command Preview:\n")
    body.append(f"{argv_preview}\n\n", style="cyan")
    body.append(f"Rationale: {payload.get('rationale')}\n")
    body.append(f"Risk: {payload.get('risk_summary')}")

    console.print(
        Panel(
            body,
            title=f"Operator Approval Required ({escape(str(approval_id))})",
            border_style="yellow",
        )
    )

    while True:
        choice = await asyncio.to_thread(
            Prompt.ask, "Decision [a=approve, e=edit args, r=reject]", choices=["a", "e", "r"], default="a"
        )
        if choice == "a":
            decision_body: dict[str, Any] = {"decision": "approved"}
        elif choice == "e":
            default_args = json.dumps(payload.get("proposed_args") or {})
            mod_args: dict[str, Any] | None = None
            while True:
                raw_args = await asyncio.to_thread(
                    Prompt.ask,
                    "Enter modified args JSON (or 'c' to cancel)",
                    default=default_args,
                )
                if raw_args.strip().lower() == "c":
                    break
                try:
                    parsed = json.loads(raw_args)
                except json.JSONDecodeError as exc:
                    err_console.print(
                        f"[red]Invalid JSON: {escape(str(exc))}. Please try again.[/red]"
                    )
                    continue
                if not isinstance(parsed, dict):
                    err_console.print(
                        "[red]Modified args must be a JSON object (e.g. {\"mode\": \"passive_audit\"}). Please try again.[/red]"
                    )
                    continue
                mod_args = parsed
                break
            if mod_args is None:
                continue
            decision_body = {"decision": "modified", "modified_args": mod_args}
        else:
            note = await asyncio.to_thread(
                Prompt.ask, "Rejection note (optional)", default="Rejected by operator"
            )
            decision_body = {"decision": "rejected", "operator_note": note}

        try:
            await asyncio.to_thread(
                client.post,
                f"/api/v1/approvals/{approval_id}/decide",
                decision_body,
            )
            return
        except AegisAPIError as exc:
            if exc.status_code == 409:
                err_console.print(
                    f"[yellow]Approval {escape(str(approval_id))} already resolved ({escape(exc.detail or 'conflict')}); continuing stream.[/yellow]"
                )
                return
            err_console.print(
                f"[red]Failed to submit approval decision: {escape(exc.message)}[/red]"
            )
            if exc.status_code in {400, 403, 422} and choice == "e":
                err_console.print("[dim]Adjust args or choose approve/reject.[/dim]")
                continue
            return


async def _stream_and_approve(client: AegisClient, engagement_id: str) -> None:
    uri = client.ws_url(engagement_id)
    ws_headers = getattr(client, "ws_headers", None)
    if ws_headers is None:
        ws_headers = getattr(client, "headers", {})

    try:
        async with _ws_connect(uri, ws_headers) as ws:
            while True:
                try:
                    raw = await ws.recv()
                except websockets.exceptions.ConnectionClosed:
                    break
                try:
                    ev = json.loads(raw)
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(ev, dict):
                    continue

                etype = str(ev.get("event_type", ""))
                agent = str(ev.get("agent_name", "system"))
                msg = str(ev.get("message", ""))
                payload = ev.get("payload") or {}
                is_replayed = bool(ev.get("replayed", False))

                if etype == "pong":
                    continue
                if etype == "tool_output":
                    prefix = "[replay] " if is_replayed else ""
                    console.print(Text(f"{prefix}[{agent}] {msg}", style="dim"))
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
                    "engagement_stopped": "yellow",
                }.get(etype, "white")
                replay_tag = "replay | " if is_replayed else ""
                console.print(
                    f"[{color}][{replay_tag}{escape(etype)} | {escape(agent)}][/{color}] {escape(msg)}"
                )

                if is_replayed:
                    # Never re-prompt or terminate live stream on historical replay frames.
                    continue

                if etype == "approval_required":
                    await _handle_approval_prompt(client, payload if isinstance(payload, dict) else {})

                if etype in TERMINAL_WS_EVENTS:
                    break
    except OSError as exc:
        raise AegisAPIError(
            f"WebSocket connection to {uri} failed: {exc}",
            is_connection_error=True,
            hint="Verify the AegisPT server is running and reachable.",
        ) from exc


@app.command()
@_handle_api_errors
def run(
    engagement_id: str = typer.Argument(
        "latest", help="Engagement ID to execute and stream (or 'latest')"
    ),
) -> None:
    """Start an engagement and attach interactive live stream + approval prompt."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        client.post(f"/api/v1/engagements/{eng_id}/start")
        err_console.print(f"[green]Started engagement {escape(eng_id)}. Streaming live events...[/green]")
        try:
            asyncio.run(_stream_and_approve(client, eng_id))
        except KeyboardInterrupt:
            err_console.print("\n[yellow]Detached from stream (engagement continues on server).[/yellow]")


@app.command()
@_handle_api_errors
def attach(
    engagement_id: str = typer.Argument(
        "latest", help="Engagement ID to attach to without restarting (or 'latest')"
    ),
) -> None:
    """Attach to an existing engagement's live WebSocket event and approval stream."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        err_console.print(f"[cyan]Attached to engagement {escape(eng_id)}. Streaming live events...[/cyan]")
        try:
            asyncio.run(_stream_and_approve(client, eng_id))
        except KeyboardInterrupt:
            err_console.print("\n[yellow]Detached from stream (engagement continues on server).[/yellow]")


@app.command()
@_handle_api_errors
def pause(
    engagement_id: str = typer.Argument("latest", help="Engagement ID to pause (or 'latest')"),
) -> None:
    """Pause a running engagement."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        res = client.post(f"/api/v1/engagements/{eng_id}/pause").json()
    console.print(f"[yellow]Engagement {escape(eng_id)} status: {escape(str(res.get('status', 'paused')))}.[/yellow]")


@app.command()
@_handle_api_errors
def resume(
    engagement_id: str = typer.Argument("latest", help="Engagement ID to resume (or 'latest')"),
) -> None:
    """Resume a paused engagement."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        res = client.post(f"/api/v1/engagements/{eng_id}/resume").json()
    console.print(f"[green]Engagement {escape(eng_id)} status: {escape(str(res.get('status', 'running')))}.[/green]")


@app.command()
@_handle_api_errors
def stop(
    engagement_id: str = typer.Argument("latest", help="Engagement ID to stop (or 'latest')"),
) -> None:
    """Stop a running or paused engagement."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        res = client.post(f"/api/v1/engagements/{eng_id}/stop").json()
    console.print(f"[yellow]Engagement {escape(eng_id)} status: {escape(str(res.get('status', 'stopped')))}.[/yellow]")


@app.command("run-tool")
@_handle_api_errors
def run_tool(
    tool_name: str = typer.Argument(..., help="Tool adapter name (see `./aegispt tools`)"),
    target: str = typer.Argument(..., help="Target URL/host inside engagement scope"),
    engagement_id: str = typer.Option("latest", "--engagement", "-e", help="Engagement ID (or 'latest')"),
    args_json: str = typer.Option("{}", "--args", "-a", help="JSON object of tool arguments"),
    rationale: str = typer.Option(
        "Manual operator-initiated execution", "--rationale", help="Audit log rationale"
    ),
) -> None:
    """Execute a single scoped tool adapter manually against a target."""
    parsed_args = _parse_json_object(args_json, "--args")
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        res = client.post(
            f"/api/v1/engagements/{eng_id}/run-tool",
            json_body={
                "tool_name": tool_name,
                "target": target,
                "args": parsed_args,
                "rationale": rationale,
            },
        ).json()
    console.print(
        Panel(
            f"Run ID: [cyan]{escape(str(res.get('tool_run_id', '-')))}[/cyan]\n"
            f"Status: [bold]{escape(str(res.get('status', '-')))}[/bold] ({res.get('duration_ms', 0)}ms)\n"
            f"Summary: {escape(str(res.get('summary') or '-'))}",
            title=f"Manual Tool Run: {escape(tool_name)}",
            border_style="green" if res.get("status") == "completed" else "yellow",
        )
    )


def _render_findings_list(
    engagement_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
) -> None:
    if severity and severity not in VALID_FINDING_SEVERITIES:
        raise typer.BadParameter(
            f"Invalid --severity {severity!r}. Expected one of: {', '.join(sorted(VALID_FINDING_SEVERITIES))}."
        )
    if status and status not in VALID_FINDING_STATUSES:
        raise typer.BadParameter(
            f"Invalid --status {status!r}. Expected one of: {', '.join(sorted(VALID_FINDING_STATUSES))}."
        )
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        items = (
            client.get(
                f"/api/v1/engagements/{eng_id}/findings",
                severity=severity,
                status=status,
            )
            .json()
            .get("findings", [])
        )
    table = Table(title=f"Findings for {escape(eng_id)} ({len(items)})")
    table.add_column("ID", style="cyan")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Target")
    table.add_column("Param")
    table.add_column("Tool")
    table.add_column("Status")
    for f in items:
        table.add_row(
            escape(str(f.get("id", "-"))),
            escape(str(f["severity"]).upper()),
            escape(str(f["title"])),
            escape(str(f["target_url"])),
            escape(str(f.get("parameter") or "-")),
            escape(str(f["tool_source"])),
            escape(str(f["status"])),
        )
    console.print(table)


@findings_app.callback(invoke_without_command=True)
@_handle_api_errors
def findings_callback(ctx: typer.Context) -> None:
    """List findings when invoked without a subcommand."""
    if ctx.invoked_subcommand is None:
        _render_findings_list("latest")


@findings_app.command("list")
@_handle_api_errors
def list_findings(
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status"),
) -> None:
    """Display discovered findings for an engagement."""
    _render_findings_list(engagement_id, severity=severity, status=status)


@findings_app.command("triage")
@_handle_api_errors
def triage_finding(
    finding_id: str = typer.Argument(..., help="Finding ID to update"),
    status: Optional[str] = typer.Option(
        None, "--status", help="open | confirmed | false_positive | remediated"
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s", help="critical | high | medium | low | info"
    ),
) -> None:
    """Update a finding's triage status and/or severity."""
    if status is None and severity is None:
        raise typer.BadParameter("Provide at least one of --status or --severity.")
    if status is not None and status not in VALID_FINDING_STATUSES:
        raise typer.BadParameter(
            f"Invalid --status {status!r}. Expected one of: {', '.join(sorted(VALID_FINDING_STATUSES))}."
        )
    if severity is not None and severity not in VALID_FINDING_SEVERITIES:
        raise typer.BadParameter(
            f"Invalid --severity {severity!r}. Expected one of: {', '.join(sorted(VALID_FINDING_SEVERITIES))}."
        )

    body: dict[str, Any] = {}
    if status is not None:
        body["status"] = status
    if severity is not None:
        body["severity"] = severity

    with _open_client() as client:
        res = client.patch(f"/api/v1/findings/{finding_id}", json_body=body).json()
    console.print(
        f"[green]Updated finding {escape(str(res.get('id', finding_id)))}:[/green] "
        f"status={escape(str(res.get('status')))} severity={escape(str(res.get('severity')))}"
    )


@findings_app.command("reverify")
@_handle_api_errors
def reverify_finding(
    finding_id: str = typer.Argument(..., help="Finding ID to reverify"),
) -> None:
    """Re-test a finding in-scope and update its verification status."""
    with _open_client() as client:
        res = client.post(f"/api/v1/findings/{finding_id}/reverify").json()

    fid = escape(str(res.get("finding_id") or res.get("id") or finding_id))
    status = escape(str(res.get("status", "unknown")))
    manual_required = bool(res.get("manual_reverify_required", False))
    still_present = res.get("still_present")
    message = escape(str(res.get("message") or ""))

    if manual_required:
        border = "yellow"
        summary = "Manual reverification required"
    elif still_present is True:
        border = "red"
        summary = "Still present (confirmed)"
    elif still_present is False:
        border = "green"
        summary = "No longer reproduced (remediated)"
    else:
        border = "cyan"
        summary = status

    lines = [f"Finding ID: [cyan]{fid}[/cyan]", f"Status: [bold]{status}[/bold]", f"Result: {summary}"]
    if message:
        lines.append(f"Detail: {message}")
    console.print(Panel("\n".join(lines), title="Finding Reverification", border_style=border))


def _render_approvals_list(engagement_id: str, status: Optional[str] = None) -> None:
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        items = (
            client.get(f"/api/v1/engagements/{eng_id}/approvals", status=status)
            .json()
            .get("approvals", [])
        )
    table = Table(title=f"Approvals for {escape(eng_id)} ({len(items)})")
    table.add_column("ID", style="cyan")
    table.add_column("Tool")
    table.add_column("Tier", justify="center")
    table.add_column("Status")
    table.add_column("Target")
    table.add_column("Risk / Note")
    for a in items:
        table.add_row(
            escape(str(a["id"])),
            escape(str(a["tool_name"])),
            f"T{a['tier']}",
            escape(str(a["status"])),
            escape(str(a["target"])),
            escape(str(a.get("operator_note") or a.get("risk_summary") or "-")),
        )
    console.print(table)


@approvals_app.callback(invoke_without_command=True)
@_handle_api_errors
def approvals_callback(ctx: typer.Context) -> None:
    """List approval requests when invoked without a subcommand."""
    if ctx.invoked_subcommand is None:
        _render_approvals_list("latest")


@approvals_app.command("list")
@_handle_api_errors
def list_approvals(
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status (pending, approved, modified, rejected)"),
) -> None:
    """List Tier 2/3 approval requests for an engagement."""
    _render_approvals_list(engagement_id, status=status)


@approvals_app.command("decide")
@_handle_api_errors
def decide_approval(
    approval_id: str = typer.Argument(..., help="Approval request ID"),
    decision: str = typer.Option(..., "--decision", "-d", help="approved | modified | rejected"),
    args_json: Optional[str] = typer.Option(None, "--args", "-a", help="Modified tool args JSON object (required when decision=modified)"),
    note: Optional[str] = typer.Option(None, "--note", help="Optional operator note"),
) -> None:
    """Approve, modify, or reject a pending Tier 2/3 approval request."""
    if decision not in VALID_APPROVAL_DECISIONS:
        raise typer.BadParameter(
            f"Invalid --decision {decision!r}. Expected one of: {', '.join(sorted(VALID_APPROVAL_DECISIONS))}."
        )
    body: dict[str, Any] = {"decision": decision}
    if decision == "modified":
        if not args_json:
            raise typer.BadParameter("--args is required when --decision is 'modified'.")
        body["modified_args"] = _parse_json_object(args_json, "--args")
    elif args_json is not None:
        body["modified_args"] = _parse_json_object(args_json, "--args")
    if note is not None:
        body["operator_note"] = note

    with _open_client() as client:
        res = client.post(f"/api/v1/approvals/{approval_id}/decide", json_body=body).json()
    console.print(
        f"[green]Approval {escape(str(res.get('id', approval_id)))} -> {escape(str(res.get('status', decision)))}.[/green]"
    )


def _render_snapshots_list(engagement_id: str) -> None:
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        detail = client.get(f"/api/v1/engagements/{eng_id}").json()
    items = detail.get("snapshots") or []
    table = Table(title=f"Scan Snapshots for {escape(eng_id)} ({len(items)})")
    table.add_column("ID", style="cyan")
    table.add_column("Label")
    table.add_column("Assets", justify="right")
    table.add_column("Endpoints", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Created At")
    for s in items:
        table.add_row(
            escape(str(s["id"])),
            escape(str(s.get("label") or "-")),
            str(s.get("assets_count", 0)),
            str(s.get("endpoints_count", 0)),
            str(s.get("findings_count", 0)),
            escape(str(s.get("created_at") or "-")),
        )
    console.print(table)


@snapshots_app.callback(invoke_without_command=True)
@_handle_api_errors
def snapshots_callback(ctx: typer.Context) -> None:
    """List scan snapshots when invoked without a subcommand."""
    if ctx.invoked_subcommand is None:
        _render_snapshots_list("latest")


@snapshots_app.command("list")
@_handle_api_errors
def list_snapshots(
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
) -> None:
    """List saved scan snapshots for an engagement."""
    _render_snapshots_list(engagement_id)


@snapshots_app.command("create")
@_handle_api_errors
def create_snapshot(
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
    label: str = typer.Option("manual-snapshot", "--label", "-l", help="Snapshot label"),
) -> None:
    """Capture a point-in-time scan snapshot for diffing."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        snap = client.post(
            f"/api/v1/engagements/{eng_id}/snapshots",
            params={"label": label},
        ).json()
    console.print(
        Panel(
            f"Snapshot ID: [cyan]{escape(str(snap.get('id', '-')))}[/cyan]\n"
            f"Label: {escape(str(snap.get('label', label)))}\n"
            f"Assets: {snap.get('assets_count', 0)} | Endpoints: {snap.get('endpoints_count', 0)} | Findings: {snap.get('findings_count', 0)}",
            title="Snapshot Captured",
            border_style="green",
        )
    )


def _render_llm_profiles_list() -> None:
    with _open_client() as client:
        items = client.get("/api/v1/llm-profiles").json().get("profiles", [])
    table = Table(title=f"LLM Provider Profiles ({len(items)})")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Provider")
    table.add_column("Base URL")
    table.add_column("Fast Model")
    table.add_column("Reasoning Model")
    table.add_column("Default", justify="center")
    for p in items:
        table.add_row(
            escape(str(p["id"])),
            escape(str(p["name"])),
            escape(str(p["provider"])),
            escape(str(p["base_url"])),
            escape(str(p["fast_model"])),
            escape(str(p["reasoning_model"])),
            "yes" if p.get("is_default") else "-",
        )
    console.print(table)


@llm_profiles_app.callback(invoke_without_command=True)
@_handle_api_errors
def llm_profiles_callback(ctx: typer.Context) -> None:
    """List LLM profiles when invoked without a subcommand."""
    if ctx.invoked_subcommand is None:
        _render_llm_profiles_list()


@llm_profiles_app.command("list")
@_handle_api_errors
def list_llm_profiles() -> None:
    """List configured LLM provider profiles."""
    _render_llm_profiles_list()


@llm_profiles_app.command("create")
@_handle_api_errors
def create_llm_profile(
    name: str = typer.Option(..., "--name", "-n", help="Profile name"),
    provider: str = typer.Option("ollama", "--provider", "-p", help="ollama | openai_compat"),
    url: str = typer.Option(..., "--url", help="Provider base URL"),
    fast_model: str = typer.Option(..., "--fast-model", help="Fast model name"),
    reasoning_model: str = typer.Option(..., "--reasoning-model", help="Reasoning model name"),
    api_key: str = typer.Option("", "--api-key", help="Optional API key"),
    api_key_stdin: bool = typer.Option(False, "--api-key-stdin", help="Read API key from stdin"),
    redact_outbound: bool = typer.Option(True, "--redact/--no-redact", help="Redact secrets before outbound LLM calls"),
    is_default: bool = typer.Option(False, "--default/--no-default", help="Set as default LLM profile"),
) -> None:
    """Create a new LLM provider profile on the server."""
    if provider not in VALID_LLM_PROVIDERS:
        raise typer.BadParameter(
            f"Invalid --provider {provider!r}. Expected one of: {', '.join(sorted(VALID_LLM_PROVIDERS))}."
        )
    resolved_key = sys.stdin.read().strip() if api_key_stdin else api_key
    with _open_client() as client:
        created = client.post(
            "/api/v1/llm-profiles",
            json_body={
                "name": name,
                "provider": provider,
                "base_url": url,
                "api_key": resolved_key,
                "fast_model": fast_model,
                "reasoning_model": reasoning_model,
                "redact_outbound": redact_outbound,
                "is_default": is_default,
            },
        ).json()
    console.print(
        Panel(
            f"Profile ID: [cyan]{escape(str(created['id']))}[/cyan]\n"
            f"Name: {escape(str(created['name']))} ({escape(str(created['provider']))})\n"
            f"URL: {escape(str(created['base_url']))}\n"
            f"Default: {'yes' if created.get('is_default') else 'no'}",
            title="LLM Profile Created",
            border_style="green",
        )
    )


@llm_profiles_app.command("delete")
@_handle_api_errors
def delete_llm_profile(
    profile_id: str = typer.Argument(..., help="LLM profile ID to delete"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
) -> None:
    """Delete an LLM provider profile."""
    if not yes:
        typer.confirm(f"Delete LLM profile {profile_id}?", abort=True)
    with _open_client() as client:
        client.delete(f"/api/v1/llm-profiles/{profile_id}")
    console.print(f"[green]Deleted LLM profile {escape(profile_id)}.[/green]")


@llm_profiles_app.command("discover")
@_handle_api_errors
def discover_llm_models(
    provider: str = typer.Option("ollama", "--provider", "-p", help="ollama | openai_compat"),
    url: str = typer.Option("http://127.0.0.1:11434", "--url", help="Provider base URL"),
    api_key: str = typer.Option("", "--api-key", help="Optional API key"),
    api_key_stdin: bool = typer.Option(False, "--api-key-stdin", help="Read API key from stdin"),
) -> None:
    """Probe an LLM endpoint through the server and list available models."""
    if provider not in VALID_LLM_PROVIDERS:
        raise typer.BadParameter(
            f"Invalid --provider {provider!r}. Expected one of: {', '.join(sorted(VALID_LLM_PROVIDERS))}."
        )
    resolved_key = sys.stdin.read().strip() if api_key_stdin else api_key
    with _open_client() as client:
        res = client.post(
            "/api/v1/llm-profiles/discover",
            json_body={"provider": provider, "base_url": url, "api_key": resolved_key},
        ).json()
    models = res.get("models") or []
    status_str = "[green]REACHABLE[/green]" if res.get("reachable") else "[yellow]UNREACHABLE[/yellow]"
    detail = escape(", ".join(str(m) for m in models) or str(res.get("error") or "none"))
    console.print(
        Panel(
            f"Provider: {escape(provider)} | URL: {escape(url)}\n"
            f"Status: {status_str}\nModels: {detail}",
            title="LLM Model Discovery",
            border_style="cyan",
        )
    )


@app.command()
@_handle_api_errors
def report(
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
    format: str = typer.Option("html", "--format", "-f", help="html | markdown | sarif | json | poc_sh"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Output file path"),
) -> None:
    """Export assessment report in HTML, Markdown, SARIF, JSON, or PoC Shell script."""
    if format not in VALID_REPORT_FORMATS:
        raise typer.BadParameter(
            f"Invalid --format {format!r}. Expected one of: {', '.join(sorted(VALID_REPORT_FORMATS))}."
        )
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        resp = client.get(f"/api/v1/engagements/{eng_id}/report", format=format)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(resp.text, encoding="utf-8")
        err_console.print(f"[green]Saved {escape(format)} report to {escape(str(out))}[/green]")
    else:
        sys.stdout.write(resp.text)
        sys.stdout.flush()


@app.command()
@_handle_api_errors
def hypotheses(
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
) -> None:
    """List AI-generated security hypotheses and verification status."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        items = client.get(f"/api/v1/engagements/{eng_id}/hypotheses").json().get("hypotheses", [])
    table = Table(title=f"Hypotheses for {escape(eng_id)} ({len(items)})")
    table.add_column("Status")
    table.add_column("Confidence")
    table.add_column("CWE")
    table.add_column("Title")
    table.add_column("Target")
    for h in items:
        table.add_row(
            escape(str(h["status"])),
            escape(str(h["confidence"])),
            escape(str(h.get("cwe_id") or "-")),
            escape(str(h["title"])),
            escape(str(h["target_url"])),
        )
    console.print(table)


@app.command()
@_handle_api_errors
def diff(
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
    base: Optional[str] = typer.Option(None, "--base", help="Baseline snapshot ID"),
    target: Optional[str] = typer.Option(None, "--target", help="Target snapshot ID"),
) -> None:
    """Compare baseline vs latest scan snapshot deltas for an engagement."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        data = client.get(f"/api/v1/engagements/{eng_id}/diff", base=base, target=target).json()
    if not data.get("has_diff"):
        console.print(
            f"[yellow]Need at least 2 snapshots to compute diff (found {data.get('snapshots_count', 0)}).[/yellow]"
        )
        return
    console.print(
        Panel(
            f"Baseline: {escape(str(data['baseline']['label']))} -> Current: {escape(str(data['current']['label']))}\n"
            f"+ New Assets: {len(data.get('new_assets') or [])}\n"
            f"+ New Endpoints: {len(data.get('new_endpoints') or [])}\n"
            f"+ New Findings: {len(data.get('new_findings') or [])}\n"
            f"- Resolved Findings: {len(data.get('resolved_findings') or [])}\n"
            f"+ New Open Ports: {len(data.get('new_open_ports') or [])}",
            title="Scan Snapshot Delta",
            border_style="cyan",
        )
    )


@app.command()
@_handle_api_errors
def repeat(
    target_or_engagement: str = typer.Argument(
        ..., help="Target URL (uses 'latest' engagement) or Engagement ID"
    ),
    url: Optional[str] = typer.Argument(
        None, help="Target URL inside engagement scope when Engagement ID is specified first"
    ),
    method: str = typer.Option("GET", "--method", "-X", help="HTTP method"),
    header: list[str] = typer.Option([], "--header", "-H", help="Custom header 'Key: Value' (repeatable)"),
    body: Optional[str] = typer.Option(None, "--data", "-d", help="Optional request body"),
    follow_redirects: bool = typer.Option(False, "--follow-redirects", "-L", help="Follow in-scope HTTP redirects"),
    no_auth: bool = typer.Option(False, "--no-auth", help="Do not inject engagement auth headers/cookies"),
    full_body: bool = typer.Option(False, "--full-body", help="Show full response body without truncation"),
) -> None:
    """Send an interactive scoped HTTP request through the AegisPT Repeater."""
    if url is None:
        engagement_id = "latest"
        resolved_url = target_or_engagement
    else:
        engagement_id = target_or_engagement
        resolved_url = url

    headers = _parse_kv(header, ":", label="--header")
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        res = client.post(
            f"/api/v1/engagements/{eng_id}/repeater",
            json_body={
                "method": method.upper(),
                "url": resolved_url,
                "headers": headers,
                "body": body,
                "use_engagement_auth": not no_auth,
                "follow_redirects": follow_redirects,
            },
        ).json()

    resp_body = str(res.get("body") or "")
    truncated = not full_body and len(resp_body) > 2000
    display_body = resp_body if full_body else resp_body[:2000]

    panel_text = Text()
    panel_text.append(f"HTTP {res['status_code']} ({res['duration_ms']}ms) — {res['final_url']}\n")
    resp_headers = res.get("headers") or {}
    if isinstance(resp_headers, dict) and resp_headers:
        panel_text.append("\nResponse Headers:\n", style="bold")
        for hk, hv in resp_headers.items():
            panel_text.append(f"  {hk}: {hv}\n", style="dim")

    panel_text.append("\nBody:\n", style="bold")
    panel_text.append(display_body)
    if truncated:
        panel_text.append(
            f"\n... [truncated {len(resp_body) - 2000} chars; pass --full-body to display all {len(resp_body)} chars]",
            style="yellow",
        )
    if res.get("curl_command"):
        panel_text.append("\n\ncURL:\n", style="bold")
        panel_text.append(str(res["curl_command"]), style="cyan")

    console.print(
        Panel(
            panel_text,
            title=f"Repeater Response ({escape(method.upper())})",
            border_style="green" if res["status_code"] < 400 else "yellow",
        )
    )


@app.command()
@_handle_api_errors
def steer(
    hint: str = typer.Argument(..., help="Guidance instruction for the AI planner"),
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
) -> None:
    """Send a live steering instruction to guide the engagement planner."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        res = client.post(f"/api/v1/engagements/{eng_id}/steer", json_body={"hint": hint}).json()
    hints = res.get("operator_hints") or [hint]
    console.print(
        f"[green]Queued steering hint for {escape(eng_id)}:[/green] {escape(str(hints[-1]))}"
    )


@app.command()
@_handle_api_errors
def chains(
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
) -> None:
    """Synthesize and display correlated multi-step attack chains."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        client.post(f"/api/v1/engagements/{eng_id}/chains/synthesize")
        detail = client.get(f"/api/v1/engagements/{eng_id}").json()
    items = detail.get("attack_chains") or []
    if not items:
        console.print("[yellow]No multi-step attack chains correlated yet.[/yellow]")
        return
    for ch in items:
        steps_txt = "\n".join(str(s) for s in (ch.get("steps") or []))
        body = Text()
        body.append(f"Target: {ch.get('target_url', '-')}\n")
        body.append(f"{ch.get('risk_summary', '')}\n\n")
        body.append(steps_txt)
        sev = str(ch.get("severity", "medium"))
        console.print(
            Panel(
                body,
                title=f"[{escape(sev.upper())}] {escape(str(ch.get('title', 'Attack Chain')))}",
                border_style="red" if sev == "critical" else "yellow",
            )
        )


@app.command()
@_handle_api_errors
def checklist(
    engagement_id: str = typer.Argument("latest", help="Engagement ID (or 'latest')"),
) -> None:
    """Display offensive skill methodology checklist coverage."""
    with _open_client() as client:
        eng_id = _resolve_engagement_id(client, engagement_id)
        items = client.get(f"/api/v1/engagements/{eng_id}").json().get("checklist_items") or []
    table = Table(title=f"Skill Checklist Coverage ({len(items)} items)")
    table.add_column("Skill", style="cyan")
    table.add_column("Status")
    table.add_column("Check Item")
    for it in items:
        table.add_row(
            escape(str(it["skill_title"])),
            escape(str(it["status"]).upper()),
            escape(str(it["item_text"])),
        )
    console.print(table)


TOOL_ARG_EXAMPLES: dict[str, str] = {
    "http_probe": '{"mode":"passive_audit"} | {"mode":"graphql_deep_audit"} | {"mode":"differential_bola"}',
    "js_miner": '{"max_bundles": 10}',
    "spa_inspector": '{"wait_ms": 2500}',
    "trufflehog": '{"max_bundles": 8, "verify_secrets": false}',
    "gitleaks": '{"max_bundles": 8}',
    "subfinder": '{"recursive": false}',
    "dnsx": '{"timeout_seconds": 90}',
    "paramspider": '{"timeout_seconds": 90}',
    "httpx": '{"tech_detect": true, "follow_redirects": true}',
    "katana": '{"depth": 2, "js_crawl": true}',
    "whatweb": '{"aggression": 1}',
    "wafw00f": '{"find_all": false}',
    "sslscan": '{"timeout_seconds": 90}',
    "naabu": '{"top_ports": "100"}',
    "nmap": '{"top_ports": 100}',
    "ffuf": '{"wordlist_profile": "builtin", "max_time_seconds": 30}',
    "feroxbuster": '{"max_time_seconds": 30}',
    "arjun": '{"method": "GET"}',
    "nikto": '{"max_time_seconds": 60}',
    "wpscan": '{"detection_mode": "passive", "enumerate": "vp,vt,u"}',
    "nuclei": '{"tags": ["misconfig","exposure"], "include_intrusive": false}',
    "dalfox": '{"param": "q"}',
    "sqlmap": '{"method": "POST", "data": "{\\"id\\":\\"1\\"}", "param": "id", "level": 1, "risk": 1}',
    "zaproxy": '{"mode": "spider_passive", "max_duration_seconds": 60}',
}

HTTP_PROBE_MODES: list[tuple[str, str, str]] = [
    ("passive_audit", "T1", "Headers, cookie attributes, multi-origin CORS, passive JWT, OpenAPI"),
    ("api_discovery", "T1", "Probe /openapi.json, /swagger.json, /graphql, /robots.txt"),
    ("graphql_deep_audit", "T2", "Schema dump + endpoint import, field-suggestion oracle, array batching"),
    ("oauth_audit", "T2", "OIDC .well-known metadata, implicit/PKCE checks, strict redirect_uri test"),
    ("replay_request", "T3", "Scoped custom method/headers/body HTTP replay"),
    ("differential_bola", "T3", "Primary vs Secondary-role (User B) or Unauth IDOR/BOLA diff"),
    ("jwt_active_probe", "T3", "Verify alg:none / stripped signature rejection & weak placeholder HMAC"),
    ("bfla_verb_tamper", "T3", "Verb authorization matrix check across GET/POST/PUT/PATCH/DELETE"),
    ("race_burst_probe", "T3", "Synchronized concurrent burst (2-15 requests) for TOCTOU/idempotency"),
    ("hpp_and_content_switch", "T3", "Duplicate param precedence (HPP) & JSON/form Content-Type strictness"),
    ("ssti_probe", "T3", "Benign 37*50 arithmetic check with template engine family fingerprinting"),
    ("open_redirect_probe", "T3", "Synthetic .invalid redirect_uri/next/url Location check"),
]


def _format_env_value(value: str) -> str:
    clean_v = str(value).replace("\r", "").replace("\n", "").strip()
    if any(ch in clean_v for ch in (" ", "\t", "#", '"', "'", "$")):
        escaped = clean_v.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return clean_v


def _write_env_config(
    env_path: Path, updates: dict[str, str], template_path: Path | None = None
) -> Path:
    """Atomically update or create a 0o600 .env configuration file preserving comments."""
    cleaned: dict[str, str] = {}
    for k, v in updates.items():
        clean_k = "".join(ch for ch in str(k) if ch.isalnum() or ch == "_")
        if clean_k:
            cleaned[clean_k] = _format_env_value(v)

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
    content = "\n".join(out_lines) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".env.tmp.", dir=str(env_path.parent))
    tmp_path = Path(tmp_name)
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, env_path)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return env_path


@app.command()
def setup(
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p", help="cloud | local | offline"
    ),
    url: Optional[str] = typer.Option(None, "--url", help="Ollama base URL override"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Ollama Cloud / endpoint API key"),
    api_key_stdin: bool = typer.Option(
        False, "--api-key-stdin", help="Read API key securely from stdin (avoids shell history)"
    ),
    fast_model: Optional[str] = typer.Option(None, "--fast-model", help="Fast model name"),
    reasoning_model: Optional[str] = typer.Option(None, "--reasoning-model", help="Reasoning model name"),
    env_path: Optional[Path] = typer.Option(None, "--env-path", help="Custom .env destination path"),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Verify live model endpoint reachability"),
) -> None:
    """Interactive setup wizard for .env (Ollama Cloud, Lightweight Local Ollama, or Offline Fallback)."""
    default_target, template_env = default_env_path()
    target_env = env_path or default_target

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

    stdin_key = sys.stdin.read().strip() if api_key_stdin else None

    if chosen == "cloud":
        resolved_url = url or "https://ollama.com"
        if stdin_key is not None:
            resolved_key = stdin_key
        elif api_key is not None:
            resolved_key = api_key
        else:
            resolved_key = Prompt.ask("Ollama Cloud API Key", password=True)
        resolved_fast = fast_model or "qwen3-next:80b"
        resolved_reason = reasoning_model or "qwen3-coder:480b"
        llm_mode = "auto"
    elif chosen == "local":
        resolved_url = url or "http://127.0.0.1:11434"
        resolved_key = stdin_key if stdin_key is not None else (api_key or "")
        resolved_fast = fast_model or "qwen2.5:1.5b"
        resolved_reason = reasoning_model or "qwen2.5:3b"
        llm_mode = "auto"
    else:
        resolved_url = url or "http://127.0.0.1:11434"
        resolved_key = ""
        resolved_fast = fast_model or "qwen2.5:1.5b"
        resolved_reason = reasoning_model or "qwen2.5:3b"
        llm_mode = "offline"

    written = _write_env_config(
        target_env,
        {
            "AEGISPT_LLM_MODE": llm_mode,
            "AEGISPT_OLLAMA_URL": resolved_url,
            "AEGISPT_OLLAMA_API_KEY": resolved_key,
            "AEGISPT_OLLAMA_FAST_MODEL": resolved_fast,
            "AEGISPT_OLLAMA_REASONING_MODEL": resolved_reason,
        },
        template_path=template_env,
    )

    console.print(
        Panel(
            f"Saved config: [cyan]{escape(str(written))}[/cyan] (chmod 600)\n"
            f"Mode: [bold]{escape(chosen)}[/bold] (AEGISPT_LLM_MODE={llm_mode})\n"
            f"Endpoint: {escape(resolved_url)}\n"
            f"Fast Model: {escape(resolved_fast)} | Reasoning Model: {escape(resolved_reason)}\n"
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
            console.print(
                f"[yellow]Endpoint not reachable yet:[/yellow] {escape(str(res.get('error')))} (fallback planner still works)."
            )


@app.command()
def tools(
    tier: Optional[int] = typer.Option(
        None, "--tier", "-t", min=1, max=3, help="Filter by tier (1, 2, or 3)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Print JSON catalog"),
) -> None:
    """List registered tool adapters, http_probe modes, and example JSON arguments."""
    from app.tools.registry import tool_registry

    catalog = tool_registry.describe_catalog()
    if tier is not None:
        catalog = [c for c in catalog if c["tier"] == tier]

    if json_output:
        sys.stdout.write(
            json.dumps({"tools": catalog, "http_probe_modes": HTTP_PROBE_MODES}, indent=2) + "\n"
        )
        sys.stdout.flush()
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
            escape(str(c["name"])),
            f"T{c['tier']}",
            st,
            escape(TOOL_ARG_EXAMPLES.get(c["name"], "{}")),
            escape(str(c["description"])[:85]),
        )
    console.print(table)

    shown_modes = [
        (m_name, m_tier, m_desc)
        for m_name, m_tier, m_desc in HTTP_PROBE_MODES
        if tier is None or m_tier == f"T{tier}"
    ]
    if shown_modes:
        modes_tbl = Table(title=f"Native `http_probe` Deep Verification Modes ({len(shown_modes)})")
        modes_tbl.add_column("Mode (run-tool http_probe ... --args '{\"mode\":...}')", style="magenta")
        modes_tbl.add_column("Tier", justify="center")
        modes_tbl.add_column("Capability")
        for m_name, m_tier, m_desc in shown_modes:
            modes_tbl.add_row(escape(m_name), m_tier, escape(m_desc))
        console.print(modes_tbl)


def main() -> None:
    app(prog_name="aegispt")


if __name__ == "__main__":
    main()
