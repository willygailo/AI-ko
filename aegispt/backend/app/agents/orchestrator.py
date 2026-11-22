"""Multi-Agent State-Graph Orchestrator with Tiered Approval & Deterministic Fallback."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select

from app.agents.graph_context import build_graph_context
from app.core.events import event_bus
from app.core.policy import approval_coordinator
from app.core.scope import ScopePolicy, ScopeViolationError
from app.db.database import session_scope
from app.db.models import (
    Engagement,
    LLMProfile,
    ScopePolicyModel,
    ToolRun,
)
from app.db.persistence import persist_tool_result
from app.knowledge.store import knowledge_store
from app.llm.router import LLMProfileConfig, default_profile_from_settings, llm_router
from app.llm.schemas import PlannerDecision, ProposedToolCall
from app.tools.base import ToolResult
from app.tools.registry import tool_registry


PLANNER_SYSTEM_PROMPT = """You are AegisPT Planner, an expert authorized Web Application & API Security Assessment Orchestrator.
Given the current compact Attack-Surface Graph, relevant OWASP WSTG/API playbooks, and the available typed tools, decide the next 1-3 concrete tool executions.

Rules:
1. Only propose targets strictly within the engagement's allowlisted hosts/URLs.
2. Do not repeat identical (tool_name, target, args) calls already completed in recent_runs.
3. Use Tier 1/2 tools (http_probe, katana, whatweb, wafw00f, ffuf, arjun, nuclei) for mapping and safe detection before proposing Tier 3 tools (sqlmap, dalfox, nuclei with include_intrusive=true, http_probe replay_request, zaproxy active_scan).
4. Set should_stop=true once attack surface mapping, safe vulnerability checks, and key hypothesis verification steps are exhausted.
5. Output ONLY valid JSON matching this schema:
{
  "thought": "brief reasoning",
  "phase": "recon|assessment|verification|reporting|complete",
  "proposed_tools": [
    {"tool_name": "name", "target": "url_or_domain", "args": {}, "rationale": "why", "risk_summary": "impact"}
  ],
  "hypotheses": [
    {"title": "...", "target_url": "...", "parameter": null, "cwe_id": "CWE-...", "confidence": "medium", "rationale": "..."}
  ],
  "should_stop": false,
  "stop_reason": ""
}"""


class EngagementOrchestrator:
    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id
        self._stop_requested = False
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # Set = not paused
        self._executed_signatures: set[str] = set()

    def request_stop(self) -> None:
        self._stop_requested = True
        self._pause_event.set()

    def pause(self) -> None:
        self._pause_event.clear()

    def resume(self) -> None:
        self._pause_event.set()

    async def _wait_if_paused(self) -> bool:
        await self._pause_event.wait()
        return not self._stop_requested

    async def _load_state(
        self,
    ) -> tuple[Engagement, ScopePolicy, LLMProfileConfig]:
        async with session_scope() as session:
            eng = await session.get(Engagement, self.engagement_id)
            if not eng:
                raise ValueError(f"Engagement {self.engagement_id} not found.")
            scope_row = (
                await session.execute(
                    select(ScopePolicyModel).where(
                        ScopePolicyModel.engagement_id == self.engagement_id
                    )
                )
            ).scalar_one_or_none()
            if not scope_row:
                raise ValueError(f"Scope policy missing for engagement {self.engagement_id}.")
            scope = ScopePolicy.from_orm(scope_row)

            llm_cfg = default_profile_from_settings()
            if eng.llm_profile_id:
                prof = await session.get(LLMProfile, eng.llm_profile_id)
                if prof:
                    llm_cfg = LLMProfileConfig(
                        name=prof.name,
                        provider=prof.provider,  # type: ignore[arg-type]
                        base_url=prof.base_url,
                        api_key=prof.api_key,
                        fast_model=prof.fast_model,
                        reasoning_model=prof.reasoning_model,
                        redact_outbound=prof.redact_outbound,
                    )
            return eng, scope, llm_cfg

    async def _persist_tool_result(self, result: ToolResult) -> int:
        async with session_scope() as session:
            return await persist_tool_result(session, self.engagement_id, result)

    async def _dispatch_tool(
        self,
        *,
        proposal: ProposedToolCall,
        scope: ScopePolicy,
        autonomy_mode: str,
        tier2_auto: bool,
        agent_name: str,
    ) -> bool:
        if not await self._wait_if_paused():
            return False

        sig = f"{proposal.tool_name}|{proposal.target}|{json.dumps(proposal.args, sort_keys=True)}"
        if sig in self._executed_signatures:
            return False
        self._executed_signatures.add(sig)

        try:
            adapter = tool_registry.get(proposal.tool_name)
        except KeyError:
            await event_bus.publish(
                engagement_id=self.engagement_id,
                event_type="tool_blocked",
                agent_name="policy",
                message=f"Rejected unknown tool `{proposal.tool_name}`.",
            )
            return False

        available, bin_info = adapter.is_available()
        if not available:
            await event_bus.publish(
                engagement_id=self.engagement_id,
                event_type="tool_skipped",
                agent_name=agent_name,
                message=f"Skipped `{adapter.name}` (binary not installed on host).",
            )
            return False

        try:
            validated_args = adapter.validate_args(proposal.args)
            norm_target = adapter.validate_scope(proposal.target, validated_args, scope)
            tier = adapter.effective_tier(validated_args)
        except (ScopeViolationError, Exception) as exc:
            async with session_scope() as session:
                session.add(
                    ToolRun(
                        engagement_id=self.engagement_id,
                        tool_name=adapter.name,
                        tier=adapter.tier,
                        target=proposal.target,
                        args=proposal.args,
                        status="blocked",
                        error_message=str(exc),
                    )
                )
            await event_bus.publish(
                engagement_id=self.engagement_id,
                event_type="scope_blocked",
                agent_name="policy",
                message=f"Blocked `{adapter.name}` against `{proposal.target}`: {exc}",
                payload={"tool_name": adapter.name, "target": proposal.target, "reason": str(exc)},
            )
            return False

        from pathlib import Path
        from app.config import get_settings

        async with session_scope() as session:
            run = ToolRun(
                engagement_id=self.engagement_id,
                tool_name=adapter.name,
                tier=tier,
                target=norm_target,
                args=validated_args.model_dump(),
                status="queued",
            )
            session.add(run)
            await session.flush()
            run_id = run.id

        preview_dir = get_settings().artifacts_dir / self.engagement_id / run_id
        preview_dir.mkdir(parents=True, exist_ok=True)
        argv_preview = adapter.build_argv(norm_target, validated_args, scope, preview_dir)

        async with session_scope() as session:
            r = await session.get(ToolRun, run_id)
            if r:
                r.argv = argv_preview

        effective_args_dict = validated_args.model_dump()

        if approval_coordinator.requires_approval(autonomy_mode, tier, tier2_auto):
            decision = await approval_coordinator.request_and_wait(
                engagement_id=self.engagement_id,
                tool_run_id=run_id,
                tool_name=adapter.name,
                tier=tier,
                target=norm_target,
                proposed_args=effective_args_dict,
                argv_preview=argv_preview,
                rationale=proposal.rationale or f"Proposed by {agent_name} agent.",
                risk_summary=proposal.risk_summary or f"Tier {tier} active security operation.",
            )
            if decision.status not in ("approved", "modified"):
                await event_bus.publish(
                    engagement_id=self.engagement_id,
                    event_type="tool_rejected",
                    agent_name="policy",
                    message=f"Skipped `{adapter.name}` ({decision.status}): {decision.operator_note or ''}",
                )
                return False
            effective_args_dict = decision.args
            # Re-validate modified args & scope!
            validated_args = adapter.validate_args(effective_args_dict)
            norm_target = adapter.validate_scope(norm_target, validated_args, scope)

        if not await self._wait_if_paused():
            return False

        async with session_scope() as session:
            r = await session.get(ToolRun, run_id)
            if r:
                r.status = "running"
                r.started_at = datetime.now(timezone.utc)

        await event_bus.publish(
            engagement_id=self.engagement_id,
            event_type="tool_started",
            agent_name=agent_name,
            message=f"Running `{adapter.name}` (Tier {tier}) on `{norm_target}`",
            payload={"tool_run_id": run_id, "tool_name": adapter.name, "tier": tier, "target": norm_target},
        )

        try:
            result = await adapter.execute(
                engagement_id=self.engagement_id,
                tool_run_id=run_id,
                target=norm_target,
                raw_args=effective_args_dict,
                scope=scope,
            )
        except Exception as exc:
            async with session_scope() as session:
                r = await session.get(ToolRun, run_id)
                if r:
                    r.status = "failed"
                    r.error_message = str(exc)
                    r.completed_at = datetime.now(timezone.utc)
            await event_bus.publish(
                engagement_id=self.engagement_id,
                event_type="tool_failed",
                agent_name=adapter.name,
                message=f"`{adapter.name}` failed: {exc}",
                payload={"tool_run_id": run_id},
            )
            return False

        new_findings = await self._persist_tool_result(result)
        async with session_scope() as session:
            r = await session.get(ToolRun, run_id)
            if r:
                r.status = "completed" if result.exit_code == 0 or result.findings or result.assets or result.endpoints else "failed"
                if result.error and not (result.findings or result.assets or result.endpoints):
                    r.status = "failed"
                r.exit_code = result.exit_code
                r.duration_ms = result.duration_ms
                r.raw_log_path = result.raw_log_path
                r.summary = result.summary
                r.error_message = result.error
                r.completed_at = datetime.now(timezone.utc)

        await event_bus.publish(
            engagement_id=self.engagement_id,
            event_type="tool_completed",
            agent_name=agent_name,
            message=f"Completed `{adapter.name}` in {result.duration_ms}ms (+{len(result.assets)} assets, +{len(result.endpoints)} endpoints, +{new_findings} findings)",
            payload={
                "tool_run_id": run_id,
                "tool_name": adapter.name,
                "summary": result.summary,
                "new_findings": new_findings,
            },
        )
        return True

    async def _plan_next_step(
        self,
        *,
        objective: str,
        graph: dict[str, Any],
        llm_cfg: LLMProfileConfig,
        step: int,
        max_steps: int,
        scope: ScopePolicy | None = None,
    ) -> PlannerDecision:
        tech_tokens = " ".join(
            t for a in graph.get("assets", []) for t in (a.get("technologies") or [])
        )
        ep_tokens = " ".join(e.get("url", "") for e in graph.get("endpoints", [])[:15])
        playbooks = knowledge_store.search(f"{objective} {tech_tokens} {ep_tokens}", limit=4)

        user_prompt = json.dumps(
            {
                "step": step,
                "max_steps": max_steps,
                "objective": objective,
                "available_tools": [
                    {"name": t.name, "tier": t.tier, "description": t.description}
                    for t in tool_registry.list_tools()
                ],
                "owasp_playbooks": playbooks,
                "attack_surface_graph": graph,
            },
            indent=2,
        )

        try:
            raw = await llm_router.complete_json(
                profile=llm_cfg,
                tier="reasoning",
                messages=[
                    {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return PlannerDecision.model_validate(raw)
        except Exception as exc:
            await event_bus.publish(
                engagement_id=self.engagement_id,
                event_type="planner_fallback",
                agent_name="planner",
                message=f"LLM endpoint unavailable or returned non-JSON ({exc}); switching to deterministic OWASP playbook planner.",
            )
            return self._deterministic_fallback_plan(graph=graph, step=step, scope=scope)

    def _derive_nuclei_tags(self, graph: dict[str, Any]) -> list[str]:
        tags = ["misconfig", "exposure"]
        tech_blob = " ".join(
            t.lower() for a in graph.get("assets", []) for t in (a.get("technologies") or [])
        )
        mapping = {
            "wordpress": "wordpress",
            "express": "nodejs",
            "node": "nodejs",
            "nginx": "nginx",
            "apache": "apache",
            "spring": "springboot",
            "django": "django",
            "php": "php",
            "graphql": "graphql",
        }
        for needle, tag in mapping.items():
            if needle in tech_blob and tag not in tags:
                tags.append(tag)
        return tags[:5]

    def _deterministic_fallback_plan(
        self, *, graph: dict[str, Any], step: int, scope: ScopePolicy | None = None
    ) -> PlannerDecision:
        """Deterministic OWASP WSTG assessment planner with smart chaining when no LLM server is running."""
        ran_tools = {(r["tool"], r["target"]) for r in graph.get("recent_runs", [])}
        seed_urls = []
        for ep in graph.get("endpoints", []):
            u = ep.get("url")
            if u:
                p = urlparse(u)
                origin = f"{p.scheme}://{p.netloc}"
                if origin not in seed_urls:
                    seed_urls.append(origin)

        proposals: list[ProposedToolCall] = []
        nuclei_tags = self._derive_nuclei_tags(graph)
        for origin in seed_urls[:2]:
            if ("ffuf", origin) not in ran_tools:
                proposals.append(
                    ProposedToolCall(
                        tool_name="ffuf",
                        target=origin,
                        args={"wordlist_profile": "builtin", "max_time_seconds": 30},
                        rationale="Enumerate common API and administrative routes using bounded wordlist.",
                        risk_summary="Tier 2 rate-limited HTTP GET path probing.",
                    )
                )
            elif ("nuclei", origin) not in ran_tools:
                proposals.append(
                    ProposedToolCall(
                        tool_name="nuclei",
                        target=origin,
                        args={"tags": nuclei_tags, "include_intrusive": False},
                        rationale=f"Run safe Nuclei templates matched to stack ({', '.join(nuclei_tags)}).",
                        risk_summary="Tier 2 non-intrusive template checks.",
                    )
                )

        # Chain parameter discovery (arjun) on dynamic endpoints without query params
        if not proposals:
            for ep in graph.get("endpoints", []):
                u = ep.get("url") or ""
                path = ep.get("path") or "/"
                if (
                    u
                    and not (ep.get("query_params") or [])
                    and any(seg in path.lower() for seg in ("/api", "/rest", "/search", "/user", "/login"))
                    and ("arjun", u) not in ran_tools
                ):
                    proposals.append(
                        ProposedToolCall(
                            tool_name="arjun",
                            target=u,
                            args={"method": "GET"},
                            rationale=f"Discover hidden query parameters on `{path}` before injection checks.",
                            risk_summary="Tier 2 bounded parameter mining.",
                        )
                    )
                    break

        # Propose Tier 3 verification on parameterized endpoints
        if not proposals:
            for ep in graph.get("endpoints", []):
                q_params = ep.get("query_params") or []
                u = ep.get("url") or ""
                if q_params and ("dalfox", u) not in ran_tools:
                    proposals.append(
                        ProposedToolCall(
                            tool_name="dalfox",
                            target=u,
                            args={"param": q_params[0]},
                            rationale=f"Verify reflected XSS on discovered query parameter '{q_params[0]}'.",
                            risk_summary="Tier 3 active XSS payload probing.",
                        )
                    )
                    break
                if q_params and ("sqlmap", u) not in ran_tools:
                    proposals.append(
                        ProposedToolCall(
                            tool_name="sqlmap",
                            target=u,
                            args={"param": q_params[0], "level": 1, "risk": 1},
                            rationale=f"Verify SQL injection on query parameter '{q_params[0]}'.",
                            risk_summary="Tier 3 bounded SQLi verification.",
                        )
                    )
                    break

        # Propose Tier 3 auth-boundary replay if engagement has auth headers/cookies & API routes
        if not proposals and scope and (scope.custom_headers or scope.auth_cookies):
            for ep in graph.get("endpoints", []):
                u = ep.get("url") or ""
                path = ep.get("path") or ""
                if ("/api" in path.lower() or "/rest" in path.lower()) and ("http_probe", u) not in ran_tools:
                    proposals.append(
                        ProposedToolCall(
                            tool_name="http_probe",
                            target=u,
                            args={"mode": "replay_request", "method": "GET"},
                            rationale="Verify authorization enforcement on discovered API endpoint.",
                            risk_summary="Tier 3 authenticated/differential API replay.",
                        )
                    )
                    break

        if not proposals:
            return PlannerDecision(
                thought="Deterministic OWASP WSTG recon, safe scan, and verification checks completed.",
                phase="complete",
                proposed_tools=[],
                should_stop=True,
                stop_reason="All deterministic playbook phases finished.",
            )

        return PlannerDecision(
            thought=f"Deterministic OWASP planner step {step}: executing next playbook stage.",
            phase="assessment",
            proposed_tools=proposals[:2],
            should_stop=False,
        )

    async def _run_fast_triage_summary(self, llm_cfg: LLMProfileConfig) -> None:
        """Use the fast LLM tier (with deterministic fallback) to summarize assessment posture."""
        async with session_scope() as session:
            graph = await build_graph_context(session, self.engagement_id)

        findings = graph.get("findings") or []
        counts: dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity") or "info")
            counts[sev] = counts.get(sev, 0) + 1

        fallback_msg = (
            f"Triage summary: {len(graph.get('assets', []))} assets, "
            f"{len(graph.get('endpoints', []))} endpoints, {len(findings)} findings ({counts})."
        )
        try:
            res = await llm_router.complete(
                profile=llm_cfg,
                tier="fast",
                messages=[
                    {
                        "role": "system",
                        "content": "Summarize the pentest attack surface and top 2 priorities in 2 concise sentences.",
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "assets": len(graph.get("assets", [])),
                                "endpoints": len(graph.get("endpoints", [])),
                                "severity_counts": counts,
                                "top_findings": findings[:8],
                            }
                        ),
                    },
                ],
                max_tokens=220,
            )
            summary_text = (res.content or "").strip() or fallback_msg
        except Exception:
            summary_text = fallback_msg

        await event_bus.publish(
            engagement_id=self.engagement_id,
            event_type="executive_summary",
            agent_name="triage",
            message=summary_text[:800],
            payload={"severity_counts": counts},
        )

    async def run(self) -> None:
        knowledge_store.ensure_indexed()
        eng, scope, llm_cfg = await self._load_state()

        async with session_scope() as session:
            e = await session.get(Engagement, self.engagement_id)
            if e:
                e.status = "running"

        await event_bus.publish(
            engagement_id=self.engagement_id,
            event_type="engagement_started",
            agent_name="orchestrator",
            message=f"Started engagement `{eng.name}` (mode={eng.autonomy_mode}, tier2_auto={eng.tier2_auto})",
            payload={"llm_provider": llm_cfg.provider, "reasoning_model": llm_cfg.reasoning_model},
        )

        try:
            # Phase 1: Initial Tier-1 Recon Sweep
            for dom in scope.primary_domains()[:3]:
                if self._stop_requested:
                    break
                await self._dispatch_tool(
                    proposal=ProposedToolCall(
                        tool_name="subfinder",
                        target=dom,
                        args={},
                        rationale="Passive subdomain discovery for allowlisted domain.",
                    ),
                    scope=scope,
                    autonomy_mode=eng.autonomy_mode,
                    tier2_auto=eng.tier2_auto,
                    agent_name="recon",
                )

            for seed_url in scope.primary_seed_urls()[:3]:
                if self._stop_requested:
                    break
                recon_steps: list[tuple[str, dict[str, Any], str]] = [
                    ("http_probe", {"mode": "passive_audit"}, "Initial HTTP security header, CORS, cookie, JWT & OpenAPI probe."),
                    ("whatweb", {"aggression": 1}, "Passive web technology stack fingerprinting."),
                    ("wafw00f", {}, "Detect protective WAF/CDN controls."),
                    ("katana", {"depth": 2, "js_crawl": True}, "Crawl HTML & JavaScript routes for endpoints and parameters."),
                ]
                if seed_url.lower().startswith("https://"):
                    recon_steps.insert(
                        1,
                        ("sslscan", {}, "Audit TLS protocols, cipher suites, and certificate validity."),
                    )
                for tool_name, t_args, rat in recon_steps:
                    if self._stop_requested:
                        break
                    await self._dispatch_tool(
                        proposal=ProposedToolCall(
                            tool_name=tool_name,
                            target=seed_url,
                            args=t_args,
                            rationale=rat,
                        ),
                        scope=scope,
                        autonomy_mode=eng.autonomy_mode,
                        tier2_auto=eng.tier2_auto,
                        agent_name="recon",
                    )

            # Phase 2 & 3: Iterative AI-Planned Assessment & Approval-Gated Verification
            step = 0
            while not self._stop_requested and step < eng.max_steps:
                if not await self._wait_if_paused():
                    break
                step += 1
                async with session_scope() as session:
                    e = await session.get(Engagement, self.engagement_id)
                    if e:
                        e.current_step = step
                    graph = await build_graph_context(session, self.engagement_id)

                decision = await self._plan_next_step(
                    objective=eng.objective,
                    graph=graph,
                    llm_cfg=llm_cfg,
                    step=step,
                    max_steps=eng.max_steps,
                    scope=scope,
                )

                await event_bus.publish(
                    engagement_id=self.engagement_id,
                    event_type="agent_thought",
                    agent_name="planner",
                    message=decision.thought or f"Step {step} planned ({decision.phase})",
                    payload={
                        "step": step,
                        "phase": decision.phase,
                        "hypotheses": [h.model_dump() for h in decision.hypotheses],
                        "should_stop": decision.should_stop,
                    },
                )

                if decision.should_stop or not decision.proposed_tools:
                    break

                executed_any = False
                for prop in decision.proposed_tools[:3]:
                    if self._stop_requested:
                        break
                    ok = await self._dispatch_tool(
                        proposal=prop,
                        scope=scope,
                        autonomy_mode=eng.autonomy_mode,
                        tier2_auto=eng.tier2_auto,
                        agent_name="assessment" if prop.tool_name not in {"sqlmap", "dalfox"} else "verifier",
                    )
                    executed_any = executed_any or ok

                if not executed_any:
                    # Avoid spinning if all proposed tools were duplicates, blocked, or rejected
                    break

            if not self._stop_requested:
                await self._run_fast_triage_summary(llm_cfg)

            final_status = "stopped" if self._stop_requested else "completed"
            async with session_scope() as session:
                e = await session.get(Engagement, self.engagement_id)
                if e:
                    e.status = final_status
            await event_bus.publish(
                engagement_id=self.engagement_id,
                event_type="engagement_finished",
                agent_name="orchestrator",
                message=f"Engagement {final_status} after {step} planner steps.",
                payload={"status": final_status, "steps": step},
            )
        except asyncio.CancelledError:
            async with session_scope() as session:
                e = await session.get(Engagement, self.engagement_id)
                if e:
                    e.status = "stopped"
            raise
        except Exception as exc:
            async with session_scope() as session:
                e = await session.get(Engagement, self.engagement_id)
                if e:
                    e.status = "failed"
            await event_bus.publish(
                engagement_id=self.engagement_id,
                event_type="engagement_failed",
                agent_name="orchestrator",
                message=f"Engagement failed: {exc}",
                payload={"error": str(exc)},
            )


class OrchestratorManager:
    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._runners: dict[str, EngagementOrchestrator] = {}

    def is_running(self, engagement_id: str) -> bool:
        task = self._tasks.get(engagement_id)
        return task is not None and not task.done()

    async def start(self, engagement_id: str) -> None:
        if self.is_running(engagement_id):
            runner = self._runners.get(engagement_id)
            if runner:
                runner.resume()
            return
        runner = EngagementOrchestrator(engagement_id)
        self._runners[engagement_id] = runner
        task = asyncio.create_task(runner.run(), name=f"aegispt-{engagement_id}")
        self._tasks[engagement_id] = task

        def _cleanup(_t: asyncio.Task[None]) -> None:
            self._tasks.pop(engagement_id, None)
            self._runners.pop(engagement_id, None)

        task.add_done_callback(_cleanup)

    async def pause(self, engagement_id: str) -> None:
        runner = self._runners.get(engagement_id)
        if runner:
            runner.pause()
        async with session_scope() as session:
            e = await session.get(Engagement, engagement_id)
            if e and e.status == "running":
                e.status = "paused"
        await event_bus.publish(
            engagement_id=engagement_id,
            event_type="engagement_paused",
            agent_name="orchestrator",
            message="Engagement paused by operator.",
        )

    async def resume(self, engagement_id: str) -> None:
        runner = self._runners.get(engagement_id)
        if runner:
            runner.resume()
            async with session_scope() as session:
                e = await session.get(Engagement, engagement_id)
                if e and e.status == "paused":
                    e.status = "running"
            await event_bus.publish(
                engagement_id=engagement_id,
                event_type="engagement_resumed",
                agent_name="orchestrator",
                message="Engagement resumed by operator.",
            )
        else:
            await self.start(engagement_id)

    async def stop(self, engagement_id: str) -> None:
        runner = self._runners.get(engagement_id)
        if runner:
            runner.request_stop()
        await approval_coordinator.cancel_engagement_approvals(engagement_id)
        task = self._tasks.get(engagement_id)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


orchestrator_manager = OrchestratorManager()
