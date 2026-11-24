"""Cognitive Multi-Skill State-Graph Orchestrator with Critic, Self-Recovery, & Chaining."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select

from app.agents.chainer import synthesize_attack_chains
from app.agents.graph_context import build_graph_context
from app.core.events import event_bus
from app.core.policy import approval_coordinator
from app.core.ratelimit import rate_limiters
from app.core.scope import ScopePolicy, ScopeViolationError
from app.core.vault import decrypt_or_passthrough
from app.db.database import session_scope
from app.db.models import (
    Engagement,
    Hypothesis,
    LLMProfile,
    ScopePolicyModel,
    SkillChecklistItem,
    SkillOutcomeStat,
    ToolRun,
)
from app.db.persistence import persist_tool_result
from app.db.snapshots import capture_snapshot
from app.knowledge.store import knowledge_store
from app.llm.router import LLMProfileConfig, default_profile_from_settings, llm_router
from app.llm.schemas import PlannerDecision, ProposedToolCall
from app.tools.base import ToolResult
from app.tools.registry import tool_registry


PLANNER_SYSTEM_PROMPT = """You are AegisPT Planner, a cognitive multi-skill Web Application & API Security Assessment Orchestrator.
Given the Risk-Ranked Attack-Surface Graph, activated Offensive Skill Checklists, WAF posture, multi-role auth availability, live operator hints, and recent feedback, decide the next 1-3 highest-value tool calls.

Cognitive Rules:
1. STRICT SCOPE: Only propose targets strictly within allowlisted hosts/URLs (never propose out-of-scope domains).
2. NO DUPLICATES & CRITIC CHECK: Do not repeat identical (tool_name, target, args) calls in recent_runs or re-test a (target, param) pair with a disproven hypothesis using the same tool.
3. SKILL-DRIVEN ROUTING:
   - GraphQL paths -> `http_probe` {"mode": "graphql_deep_audit"} (Tier 2).
   - OAuth / OIDC hints -> `http_probe` {"mode": "oauth_audit"} (Tier 2).
   - WordPress detected -> `wpscan` (Tier 2).
   - JS secret hunting -> `trufflehog` / `gitleaks` / `js_miner` (Tier 1).
   - Dynamic routes lacking params -> `arjun` (Tier 2) before active probes.
   - Mutating / auth-sensitive APIs -> `http_probe` {"mode": "differential_bola"} (Tier 3, leverages multi-role secondary auth when configured) or `bfla_verb_tamper` (Tier 3).
   - JWT observed -> `http_probe` {"mode": "jwt_active_probe"} (Tier 3).
   - Commerce/coupon/vote/transfer endpoints -> `http_probe` {"mode": "race_burst_probe"} (Tier 3).
   - Query OR body parameters -> `dalfox` / `sqlmap` (pass method="POST" & JSON data for body_params) / `http_probe` (`ssti_probe`, `open_redirect_probe`, `hpp_and_content_switch`) (Tier 3).
4. ADAPTIVE RECOVERY: If `recent_feedback` shows a block/rejection or `waf_detected` is set, pivot technique or respect operator notes instead of repeating blocked calls.
5. LIVE STEERING: Prioritize any instructions listed in `operator_hints`.
6. Output ONLY valid JSON matching this schema:
{
  "thought": "brief reasoning referencing active skills and target risks",
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
        self._pause_event.set()
        self._executed_signatures: set[str] = set()
        self._feedback_history: list[str] = []

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
    ) -> tuple[Engagement, ScopePolicy, LLMProfileConfig, list[LLMProfileConfig]]:
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

            all_profiles = (await session.execute(select(LLMProfile))).scalars().all()
            llm_cfg = default_profile_from_settings()
            fallbacks: list[LLMProfileConfig] = []

            def _to_cfg(prof: LLMProfile) -> LLMProfileConfig:
                return LLMProfileConfig(
                    name=prof.name,
                    provider=prof.provider,  # type: ignore[arg-type]
                    base_url=prof.base_url,
                    api_key=decrypt_or_passthrough(prof.api_key),
                    fast_model=prof.fast_model,
                    reasoning_model=prof.reasoning_model,
                    redact_outbound=prof.redact_outbound,
                )

            chosen: LLMProfile | None = None
            if eng.llm_profile_id:
                chosen = next((p for p in all_profiles if p.id == eng.llm_profile_id), None)
            if chosen is None:
                chosen = next((p for p in all_profiles if p.is_default), None)
            if chosen is not None:
                llm_cfg = _to_cfg(chosen)
            chosen_id = chosen.id if chosen is not None else None
            for p in all_profiles:
                if p.id != chosen_id:
                    fallbacks.append(_to_cfg(p))

            return eng, scope, llm_cfg, fallbacks

    async def _sync_skill_checklist(
        self,
        graph: dict[str, Any],
        tool_name: str | None = None,
        new_findings: int = 0,
    ) -> None:
        """Persist activated skill checklist items and mark coverage as tools execute."""
        active_skills = graph.get("active_skills") or []
        if not active_skills:
            return
        async with session_scope() as session:
            for sk in active_skills:
                sk_id = sk["id"]
                all_meta = next((s for s in knowledge_store.list_all_skills() if s["id"] == sk_id), None)
                rec_tools = set((all_meta or {}).get("recommended_tools") or sk.get("recommended_tools") or [])
                for idx, item_txt in enumerate(sk.get("checklist") or []):
                    item_key = f"{sk_id}:{idx}"
                    row = (
                        await session.execute(
                            select(SkillChecklistItem).where(
                                SkillChecklistItem.engagement_id == self.engagement_id,
                                SkillChecklistItem.skill_id == sk_id,
                                SkillChecklistItem.item_key == item_key,
                            )
                        )
                    ).scalar_one_or_none()
                    if not row:
                        row = SkillChecklistItem(
                            engagement_id=self.engagement_id,
                            skill_id=sk_id,
                            skill_title=sk["title"],
                            wstg_id=sk.get("wstg_id") or "",
                            item_key=item_key,
                            item_text=item_txt,
                            status="pending",
                        )
                        session.add(row)
                    if tool_name and (tool_name in rec_tools or tool_name in item_txt):
                        if new_findings > 0:
                            row.status = "finding"
                            row.evidence_note = f"{tool_name} confirmed {new_findings} finding(s)."
                        elif row.status == "pending":
                            row.status = "covered"
                            row.evidence_note = f"Executed `{tool_name}` check."

    async def _record_skill_outcome(
        self,
        graph: dict[str, Any],
        tool_name: str,
        new_findings: int,
    ) -> None:
        techs = sorted({t.lower() for a in graph.get("assets", []) for t in (a.get("technologies") or [])})
        tech_sig = ",".join(techs[:3]) or "generic"
        waf_name = str(graph.get("waf_detected") or "none").lower()[:80]
        matching_skills = [
            sk["id"]
            for sk in (graph.get("active_skills") or [])
            if tool_name in (sk.get("recommended_tools") or [])
        ] or [f"tool:{tool_name}"]

        async with session_scope() as session:
            for sk_id in matching_skills[:3]:
                row = (
                    await session.execute(
                        select(SkillOutcomeStat).where(
                            SkillOutcomeStat.tech_signature == tech_sig[:120],
                            SkillOutcomeStat.waf_name == waf_name,
                            SkillOutcomeStat.skill_id == sk_id,
                        )
                    )
                ).scalar_one_or_none()
                if not row:
                    row = SkillOutcomeStat(
                        tech_signature=tech_sig[:120],
                        waf_name=waf_name,
                        skill_id=sk_id,
                        runs_count=0,
                        findings_count=0,
                    )
                    session.add(row)
                row.runs_count += 1
                row.findings_count += max(0, new_findings)

    async def _persist_hypotheses(self, hypotheses: list[Any]) -> None:
        if not hypotheses:
            return
        async with session_scope() as session:
            for h in hypotheses[:10]:
                existing = (
                    await session.execute(
                        select(Hypothesis).where(
                            Hypothesis.engagement_id == self.engagement_id,
                            Hypothesis.title == h.title,
                            Hypothesis.target_url == h.target_url,
                        )
                    )
                ).scalar_one_or_none()
                if not existing:
                    session.add(
                        Hypothesis(
                            engagement_id=self.engagement_id,
                            title=h.title[:300],
                            target_url=h.target_url[:2048],
                            parameter=h.parameter,
                            cwe_id=h.cwe_id,
                            confidence=h.confidence,
                            status="proposed",
                            rationale=h.rationale,
                        )
                    )

    @staticmethod
    def _norm_hypothesis_url(url: str) -> str:
        p = urlparse((url or "").strip())
        if p.scheme and p.netloc:
            path = (p.path or "/").rstrip("/") or "/"
            return f"{p.scheme.lower()}://{p.netloc.lower()}{path}"
        return (url or "").strip().lower().rstrip("/")

    @staticmethod
    def _tool_cwe_scope(tool_name: str, args: dict[str, Any] | None = None) -> set[str] | None:
        if tool_name == "sqlmap":
            return {"CWE-89"}
        if tool_name == "dalfox":
            return {"CWE-79"}
        if tool_name == "http_probe":
            mode = str((args or {}).get("mode") or "")
            mode_map: dict[str, set[str]] = {
                "open_redirect_probe": {"CWE-601"},
                "ssti_probe": {"CWE-1336", "CWE-94"},
                "differential_bola": {"CWE-639", "CWE-862", "CWE-863"},
                "bfla_verb_tamper": {"CWE-862", "CWE-863", "CWE-285"},
                "jwt_active_probe": {"CWE-347", "CWE-287"},
                "race_burst_probe": {"CWE-362"},
                "graphql_deep_audit": {"CWE-200", "CWE-770"},
                "oauth_audit": {"CWE-601", "CWE-346", "CWE-287"},
            }
            return mode_map.get(mode)
        return None

    async def _update_hypothesis_outcome(
        self,
        target: str,
        tool_name: str,
        new_findings: int,
        *,
        found_cwes: set[str] | None = None,
        args: dict[str, Any] | None = None,
    ) -> None:
        if tool_name not in {"dalfox", "sqlmap", "http_probe", "nuclei"}:
            return
        norm_target = self._norm_hypothesis_url(target)
        tool_cwes = self._tool_cwe_scope(tool_name, args)
        arg_param = str((args or {}).get("param") or "").strip().lower()
        found_cwes_upper = {c.upper() for c in (found_cwes or set()) if c}

        async with session_scope() as session:
            rows = (
                await session.execute(
                    select(Hypothesis).where(
                        Hypothesis.engagement_id == self.engagement_id,
                        Hypothesis.status.in_(["proposed", "testing", "awaiting_approval"]),
                    )
                )
            ).scalars().all()
            for row in rows:
                if self._norm_hypothesis_url(row.target_url) != norm_target:
                    continue
                if row.parameter and arg_param and row.parameter.strip().lower() != arg_param:
                    continue
                row_cwe = (row.cwe_id or "").strip().upper()
                if row_cwe and tool_cwes is not None and row_cwe not in tool_cwes:
                    continue
                if new_findings > 0:
                    if row_cwe and found_cwes_upper and row_cwe not in found_cwes_upper:
                        continue
                    row.status = "confirmed"
                else:
                    row.status = "disproven"
                row.evidence_note = (
                    f"Verified by `{tool_name}` ({new_findings} finding(s))."
                )

    async def _persist_tool_result(self, result: ToolResult) -> int:
        async with session_scope() as session:
            return await persist_tool_result(session, self.engagement_id, result)

    def _critic_filter_proposals(
        self, proposals: list[ProposedToolCall], graph: dict[str, Any]
    ) -> list[ProposedToolCall]:
        """Self-critic gate preventing redundant disproven checks or mismatched stack tools."""
        tech_blob = " ".join(
            str(t).lower() for a in graph.get("assets", []) for t in (a.get("technologies") or [])
        )
        ep_blob = " ".join(str(ep.get("url") or "").lower() for ep in graph.get("endpoints", []))
        has_wp = "wordpress" in tech_blob or "wp-content" in ep_blob or "wp-json" in ep_blob
        disproven_pairs: set[tuple[str, str]] = {
            (
                self._norm_hypothesis_url(str(h.get("target_url") or "")),
                str(h.get("cwe_id") or "").strip().upper(),
            )
            for h in (graph.get("hypotheses") or [])
            if h.get("status") == "disproven"
        }

        kept: list[ProposedToolCall] = []
        for prop in proposals:
            if prop.tool_name == "wpscan" and not has_wp:
                self._feedback_history.append("Critic skipped wpscan (no WordPress signal detected).")
                continue
            if prop.tool_name in {"dalfox", "sqlmap"}:
                norm_prop = self._norm_hypothesis_url(prop.target)
                expected_cwe = "CWE-79" if prop.tool_name == "dalfox" else "CWE-89"
                if (norm_prop, expected_cwe) in disproven_pairs or (norm_prop, "") in disproven_pairs:
                    self._feedback_history.append(
                        f"Critic avoided re-testing disproven target `{prop.target}` with `{prop.tool_name}`."
                    )
                    continue
            kept.append(prop)
        return kept

    async def _dispatch_tool(
        self,
        *,
        proposal: ProposedToolCall,
        scope: ScopePolicy,
        autonomy_mode: str,
        tier2_auto: bool,
        agent_name: str,
        graph: dict[str, Any] | None = None,
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
            self._feedback_history.append(f"Unknown tool `{proposal.tool_name}` requested; choose from catalog.")
            await event_bus.publish(
                engagement_id=self.engagement_id,
                event_type="tool_blocked",
                agent_name="policy",
                message=f"Rejected unknown tool `{proposal.tool_name}`.",
            )
            return False

        available, _ = adapter.is_available()
        if not available:
            self._feedback_history.append(f"Tool `{adapter.name}` unavailable on host; pick another adapter.")
            await event_bus.publish(
                engagement_id=self.engagement_id,
                event_type="tool_skipped",
                agent_name=agent_name,
                message=f"Skipped `{adapter.name}` (binary/runtime not available on host).",
            )
            return False

        try:
            validated_args = adapter.validate_args(proposal.args)
            norm_target = adapter.validate_scope(proposal.target, validated_args, scope)
            tier = adapter.effective_tier(validated_args)
        except (ScopeViolationError, Exception) as exc:
            self._feedback_history.append(f"Scope/arg block on `{adapter.name}` target `{proposal.target}`: {exc}")
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
                self._feedback_history.append(
                    f"Operator rejected `{adapter.name}` on `{norm_target}`: {decision.operator_note or decision.status}"
                )
                await event_bus.publish(
                    engagement_id=self.engagement_id,
                    event_type="tool_rejected",
                    agent_name="policy",
                    message=f"Skipped `{adapter.name}` ({decision.status}): {decision.operator_note or ''}",
                )
                return False
            effective_args_dict = decision.args
            try:
                validated_args = adapter.validate_args(effective_args_dict)
                norm_target = adapter.validate_scope(norm_target, validated_args, scope)
                effective_args_dict = validated_args.model_dump()
            except (ScopeViolationError, Exception) as exc:
                self._feedback_history.append(
                    f"Modified args for `{adapter.name}` blocked by policy/scope: {exc}"
                )
                async with session_scope() as session:
                    r = await session.get(ToolRun, run_id)
                    if r:
                        r.status = "blocked"
                        r.error_message = f"Modified args rejected: {exc}"
                        r.completed_at = datetime.now(timezone.utc)
                await event_bus.publish(
                    engagement_id=self.engagement_id,
                    event_type="scope_blocked",
                    agent_name="policy",
                    message=f"Blocked modified args for `{adapter.name}` on `{norm_target}`: {exc}",
                    payload={"tool_run_id": run_id, "reason": str(exc)},
                )
                return False

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
            self._feedback_history.append(f"Tool `{adapter.name}` raised error on `{norm_target}`: {exc}")
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
        if graph is not None:
            await self._sync_skill_checklist(graph, tool_name=adapter.name, new_findings=new_findings)
            await self._record_skill_outcome(graph, adapter.name, new_findings)
        if tier == 3:
            found_cwes = {f.cwe_id for f in result.findings if f.cwe_id}
            await self._update_hypothesis_outcome(
                norm_target,
                adapter.name,
                new_findings,
                found_cwes=found_cwes,
                args=effective_args_dict,
            )
        return True

    async def _plan_next_step(
        self,
        *,
        objective: str,
        graph: dict[str, Any],
        llm_cfg: LLMProfileConfig,
        fallback_profiles: list[LLMProfileConfig] | None = None,
        step: int,
        max_steps: int,
        scope: ScopePolicy | None = None,
    ) -> PlannerDecision:
        tech_tokens = " ".join(
            str(t) for a in graph.get("assets", []) for t in (a.get("technologies") or [])
        )
        ep_tokens = " ".join(e.get("url", "") for e in graph.get("endpoints", [])[:15])
        hint_tokens = " ".join(graph.get("operator_hints") or [])
        playbooks = await knowledge_store.search_async(f"{objective} {tech_tokens} {ep_tokens} {hint_tokens}", limit=5)

        distilled_notes = ""
        if len(graph.get("endpoints", [])) > 20 or len(graph.get("recent_runs", [])) > 8:
            try:
                distill = await llm_router.complete(
                    profile=llm_cfg,
                    fallback_profiles=fallback_profiles,
                    tier="fast",
                    messages=[
                        {
                            "role": "system",
                            "content": "Distill the top 3 untested high-risk endpoints/params and active attack signals from this graph in <=65 words.",
                        },
                        {"role": "user", "content": json.dumps(graph)[:5000]},
                    ],
                    max_tokens=180,
                    max_retries=0,
                )
                distilled_notes = (distill.content or "").strip()
            except Exception:
                distilled_notes = ""

        user_prompt = json.dumps(
            {
                "step": step,
                "max_steps": max_steps,
                "objective": objective,
                "distilled_clues": distilled_notes,
                "operator_hints": graph.get("operator_hints") or [],
                "recent_feedback": self._feedback_history[-6:],
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
                fallback_profiles=fallback_profiles,
                tier="reasoning",
                messages=[
                    {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            )
            decision = PlannerDecision.model_validate(raw)
            decision.proposed_tools = self._critic_filter_proposals(decision.proposed_tools, graph)
            return decision
        except Exception as exc:
            await event_bus.publish(
                engagement_id=self.engagement_id,
                event_type="planner_fallback",
                agent_name="planner",
                message=f"LLM endpoint unavailable or returned non-JSON ({exc}); switching to cognitive fallback planner.",
            )
            return self._deterministic_fallback_plan(graph=graph, step=step, scope=scope)

    def _derive_nuclei_tags(self, graph: dict[str, Any]) -> list[str]:
        tags = ["misconfig", "exposure"]
        tech_blob = " ".join(
            str(t).lower() for a in graph.get("assets", []) for t in (a.get("technologies") or [])
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
        """Cognitive skill-driven deterministic planner when no LLM server is running."""
        ran_tools_modes = {
            (r["tool"], r["target"], json.dumps((r.get("args") or {}), sort_keys=True))
            for r in graph.get("recent_runs", [])
        }
        ran_pairs = {(r["tool"], r["target"]) for r in graph.get("recent_runs", [])}

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
        tech_blob = " ".join(
            str(t).lower() for a in graph.get("assets", []) for t in (a.get("technologies") or [])
        )
        ep_urls_lower = [str(ep.get("url") or "").lower() for ep in graph.get("endpoints", [])]

        # 1. WordPress targeted check if detected
        if ("wordpress" in tech_blob or any("wp-json" in u or "wp-content" in u for u in ep_urls_lower)) and seed_urls:
            origin = seed_urls[0]
            if ("wpscan", origin) not in ran_pairs and tool_registry.get("wpscan").is_available()[0]:
                proposals.append(
                    ProposedToolCall(
                        tool_name="wpscan",
                        target=origin,
                        args={"detection_mode": "passive"},
                        rationale="WordPress stack detected; enumerate plugins, themes, and exposed config.",
                        risk_summary="Tier 2 passive WordPress fingerprint scan.",
                    )
                )

        # 2. Skill-specific Tier 2 GraphQL / OAuth deep audits
        for origin in seed_urls[:2]:
            if any("graphql" in u for u in ep_urls_lower) and ("http_probe", origin, "graphql_deep_audit") not in {
                (r[0], r[1], (json.loads(r[2]).get("mode") if r[2] else "")) for r in ran_tools_modes
            }:
                if "graphql_deep_audit" not in self._executed_signatures_str():
                    proposals.append(
                        ProposedToolCall(
                            tool_name="http_probe",
                            target=origin,
                            args={"mode": "graphql_deep_audit"},
                            rationale="GraphQL path detected; run schema introspection, field-suggestion oracle, and batching checks.",
                            risk_summary="Tier 2 GraphQL configuration audit.",
                        )
                    )
                    break

        if not proposals and seed_urls and any(any(tok in u for tok in ("oauth", "openid", "authorize")) for u in ep_urls_lower):
            origin = seed_urls[0]
            if f"http_probe|{origin}" not in "|".join(s for s in self._executed_signatures if "oauth_audit" in s):
                proposals.append(
                    ProposedToolCall(
                        tool_name="http_probe",
                        target=origin,
                        args={"mode": "oauth_audit"},
                        rationale="OAuth/OIDC hints detected; verify discovery metadata, PKCE S256, and redirect_uri strictness.",
                        risk_summary="Tier 2 OAuth/OIDC configuration audit.",
                    )
                )

        # 3. Core bounded discovery (ffuf, trufflehog, nuclei)
        if not proposals:
            for origin in seed_urls[:2]:
                if ("ffuf", origin) not in ran_pairs:
                    proposals.append(
                        ProposedToolCall(
                            tool_name="ffuf",
                            target=origin,
                            args={"wordlist_profile": "builtin", "max_time_seconds": 30},
                            rationale="Enumerate common API and administrative routes using bounded wordlist.",
                            risk_summary="Tier 2 rate-limited HTTP GET path probing.",
                        )
                    )
                elif ("trufflehog", origin) not in ran_pairs and tool_registry.get("trufflehog").is_available()[0]:
                    proposals.append(
                        ProposedToolCall(
                            tool_name="trufflehog",
                            target=origin,
                            args={"max_bundles": 6},
                            rationale="Run TruffleHog secret verification scan over fetched JS/HTML artifacts.",
                            risk_summary="Tier 1 offline bundle secret check.",
                        )
                    )
                elif ("nuclei", origin) not in ran_pairs:
                    proposals.append(
                        ProposedToolCall(
                            tool_name="nuclei",
                            target=origin,
                            args={"tags": nuclei_tags, "include_intrusive": False},
                            rationale=f"Run safe Nuclei templates matched to stack ({', '.join(nuclei_tags)}).",
                            risk_summary="Tier 2 non-intrusive template checks.",
                        )
                    )

        # 4. Chain parameter discovery (arjun) on dynamic endpoints without query params
        if not proposals:
            for ep in graph.get("endpoints", []):
                u = ep.get("url") or ""
                path = ep.get("path") or "/"
                if (
                    u
                    and not (ep.get("query_params") or [])
                    and any(seg in path.lower() for seg in ("/api", "/rest", "/search", "/user", "/login"))
                    and ("arjun", u) not in ran_pairs
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

        # 5. Tier 3 active verification on query OR body parameterized endpoints + TOCTOU/JWT/BOLA
        if not proposals:
            for ep in graph.get("endpoints", []):
                q_params = ep.get("query_params") or []
                b_params = ep.get("body_params") or []
                u = ep.get("url") or ""
                path_l = (ep.get("path") or "").lower()

                redir_param = next(
                    (p for p in q_params if p.lower() in {"next", "url", "redirect", "return", "dest", "to", "callback"}),
                    None,
                )
                if redir_param and f"http_probe|{u}" not in "|".join(s for s in self._executed_signatures if "open_redirect_probe" in s):
                    proposals.append(
                        ProposedToolCall(
                            tool_name="http_probe",
                            target=u,
                            args={"mode": "open_redirect_probe", "param": redir_param},
                            rationale=f"Verify open redirect behavior on parameter '{redir_param}'.",
                            risk_summary="Tier 3 synthetic Location-reflection probe.",
                        )
                    )
                    break
                if q_params and ("dalfox", u) not in ran_pairs:
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
                if q_params and ("sqlmap", u) not in ran_pairs:
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
                if b_params and ("sqlmap", u) not in ran_pairs:
                    sample_json = json.dumps({k: "1" for k in b_params[:4]})
                    proposals.append(
                        ProposedToolCall(
                            tool_name="sqlmap",
                            target=u,
                            args={"method": "POST", "data": sample_json, "param": b_params[0], "level": 1, "risk": 1},
                            rationale=f"Verify SQL injection on POST body parameter '{b_params[0]}'.",
                            risk_summary="Tier 3 bounded JSON POST SQLi verification.",
                        )
                    )
                    break
                if any(k in path_l for k in ("coupon", "redeem", "transfer", "withdraw", "vote", "checkout")) and "race_burst_probe" not in self._executed_signatures_str():
                    proposals.append(
                        ProposedToolCall(
                            tool_name="http_probe",
                            target=u,
                            args={"mode": "race_burst_probe", "method": "POST", "burst_count": 6},
                            rationale=f"Check concurrency/idempotency lock hygiene on transactional route `{path_l}`.",
                            risk_summary="Tier 3 synchronized concurrent POST burst (6 requests).",
                        )
                    )
                    break

        # 6. Multi-role BOLA / BFLA / JWT active probes
        if not proposals and scope and (scope.custom_headers or scope.auth_cookies or scope.has_secondary_auth):
            has_jwt = "Bearer eyJ" in str(scope.custom_headers) or any("jwt" in (f.get("title") or "").lower() for f in graph.get("findings", []))
            for ep in graph.get("endpoints", []):
                u = ep.get("url") or ""
                path = ep.get("path") or ""
                if ("/api" in path.lower() or "/rest" in path.lower() or "/users" in path.lower()) and "differential_bola" not in "|".join(
                    s for s in self._executed_signatures if u in s
                ):
                    proposals.append(
                        ProposedToolCall(
                            tool_name="http_probe",
                            target=u,
                            args={"mode": "differential_bola", "method": "GET"},
                            rationale="Verify object-level authorization boundary via differential multi-role/unauth replay.",
                            risk_summary="Tier 3 differential authorization comparison.",
                        )
                    )
                    break
                if has_jwt and "/api" in path.lower() and "jwt_active_probe" not in self._executed_signatures_str():
                    proposals.append(
                        ProposedToolCall(
                            tool_name="http_probe",
                            target=u,
                            args={"mode": "jwt_active_probe", "method": "GET"},
                            rationale="Verify JWT alg=none and stripped-signature rejection on authenticated API endpoint.",
                            risk_summary="Tier 3 JWT signature verification hygiene probe.",
                        )
                    )
                    break

        if not proposals:
            return PlannerDecision(
                thought="Cognitive skill checklists, safe scans, and targeted verification checks completed.",
                phase="complete",
                proposed_tools=[],
                should_stop=True,
                stop_reason="All cognitive playbook phases finished.",
            )

        return PlannerDecision(
            thought=f"Skill-guided deterministic planner step {step}: executing next playbook stage.",
            phase="assessment",
            proposed_tools=proposals[:2],
            should_stop=False,
        )

    def _executed_signatures_str(self) -> str:
        return "\n".join(self._executed_signatures)

    async def _run_fast_triage_summary(self, llm_cfg: LLMProfileConfig) -> None:
        async with session_scope() as session:
            graph = await build_graph_context(session, self.engagement_id)

        findings = graph.get("findings") or []
        counts: dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity") or "info")
            counts[sev] = counts.get(sev, 0) + 1

        fallback_msg = (
            f"Triage summary: {len(graph.get('assets', []))} assets, "
            f"{len(graph.get('endpoints', []))} endpoints, {len(findings)} findings ({counts}), "
            f"{len(graph.get('attack_chains', []))} attack chains."
        )
        try:
            res = await llm_router.complete(
                profile=llm_cfg,
                tier="fast",
                messages=[
                    {
                        "role": "system",
                        "content": "Summarize the pentest attack surface, attack chains, and top 2 priorities in 2 concise sentences.",
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "assets": len(graph.get("assets", [])),
                                "endpoints": len(graph.get("endpoints", [])),
                                "severity_counts": counts,
                                "attack_chains": graph.get("attack_chains", [])[:4],
                                "top_findings": findings[:8],
                            }
                        ),
                    },
                ],
                max_tokens=240,
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
        await knowledge_store.ensure_indexed_async()
        eng, scope, llm_cfg, fallbacks = await self._load_state()

        async with session_scope() as session:
            e = await session.get(Engagement, self.engagement_id)
            if e:
                e.status = "running"
            await capture_snapshot(session, self.engagement_id, label="pre-scan")

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
                for d_tool, d_rat in [
                    ("subfinder", "Passive subdomain discovery for allowlisted domain."),
                    ("dnsx", "DNS record resolution & SPF/DMARC posture check."),
                ]:
                    if self._stop_requested:
                        break
                    await self._dispatch_tool(
                        proposal=ProposedToolCall(tool_name=d_tool, target=dom, args={}, rationale=d_rat),
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
                    ("js_miner", {"max_bundles": 8}, "Extract hidden API routes, source maps, DOM sinks, and potential leaks from JS bundles."),
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

            # Seed initial skill checklist & chains after recon
            async with session_scope() as session:
                init_graph = await build_graph_context(session, self.engagement_id)
                await synthesize_attack_chains(session, self.engagement_id)
            await self._sync_skill_checklist(init_graph)

            # Phase 2 & 3: Iterative Cognitive Assessment & Approval-Gated Verification
            step = 0
            no_exec_streak = 0
            while not self._stop_requested and step < eng.max_steps:
                if not await self._wait_if_paused():
                    break
                step += 1
                async with session_scope() as session:
                    e = await session.get(Engagement, self.engagement_id)
                    if e:
                        e.current_step = step
                    graph = await build_graph_context(session, self.engagement_id)

                await self._sync_skill_checklist(graph)

                decision = await self._plan_next_step(
                    objective=eng.objective,
                    graph=graph,
                    llm_cfg=llm_cfg,
                    fallback_profiles=fallbacks,
                    step=step,
                    max_steps=eng.max_steps,
                    scope=scope,
                )

                await self._persist_hypotheses(decision.hypotheses)

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

                if decision.should_stop:
                    break
                if not decision.proposed_tools:
                    no_exec_streak += 1
                    if no_exec_streak >= 2:
                        break
                    self._feedback_history.append("No tools remained after critic filtering; pick different endpoint or mark should_stop=true.")
                    continue

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
                        graph=graph,
                    )
                    executed_any = executed_any or ok

                if not executed_any:
                    no_exec_streak += 1
                    if no_exec_streak >= 2:
                        break
                else:
                    no_exec_streak = 0

            async with session_scope() as session:
                new_chains = await synthesize_attack_chains(session, self.engagement_id)
            if new_chains:
                await event_bus.publish(
                    engagement_id=self.engagement_id,
                    event_type="attack_chain_synthesized",
                    agent_name="chainer",
                    message=f"Synthesized {len(new_chains)} correlated multi-step attack chain(s).",
                    payload={"count": len(new_chains)},
                )

            if not self._stop_requested:
                await self._run_fast_triage_summary(llm_cfg)

            final_status = "stopped" if self._stop_requested else "completed"
            async with session_scope() as session:
                e = await session.get(Engagement, self.engagement_id)
                if e:
                    e.status = final_status
                await capture_snapshot(session, self.engagement_id, label=f"post-scan-{final_status}")
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

        def _cleanup(finished_task: asyncio.Task[None]) -> None:
            if self._tasks.get(engagement_id) is finished_task:
                self._tasks.pop(engagement_id, None)
                if self._runners.get(engagement_id) is runner:
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
        async with session_scope() as session:
            e = await session.get(Engagement, engagement_id)
            if e and e.status != "stopped":
                e.status = "stopped"
        rate_limiters.remove(engagement_id)

    async def stop_all(self) -> None:
        active_ids = list(self._tasks.keys())
        for eid in active_ids:
            try:
                await self.stop(eid)
            except Exception:
                pass


orchestrator_manager = OrchestratorManager()
