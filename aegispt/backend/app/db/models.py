"""SQLAlchemy ORM models for AegisPT attack-surface graph, policy, runs, and audit vault."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return uuid.uuid4().hex[:16]


class LLMProfile(Base):
    __tablename__ = "llm_profiles"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)  # ollama | openai_compat
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    api_key: Mapped[str] = mapped_column(Text, default="")
    fast_model: Mapped[str] = mapped_column(String(160), nullable=False)
    reasoning_model: Mapped[str] = mapped_column(String(160), nullable=False)
    redact_outbound: Mapped[bool] = mapped_column(Boolean, default=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    objective: Mapped[str] = mapped_column(
        Text, default="Comprehensive Web Application & API Security Assessment"
    )
    status: Mapped[str] = mapped_column(
        String(32), default="idle"
    )  # idle|running|paused|awaiting_approval|completed|stopped|failed
    autonomy_mode: Mapped[str] = mapped_column(
        String(32), default="tiered"
    )  # tiered|copilot|lab_autopilot
    tier2_auto: Mapped[bool] = mapped_column(Boolean, default=True)
    max_steps: Mapped[int] = mapped_column(Integer, default=25)
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    llm_profile_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("llm_profiles.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    scope_policy: Mapped["ScopePolicyModel"] = relationship(
        back_populates="engagement", uselist=False, cascade="all, delete-orphan"
    )
    assets: Mapped[list["Asset"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    endpoints: Mapped[list["Endpoint"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    tool_runs: Mapped[list["ToolRun"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    approvals: Mapped[list["ApprovalRequest"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    events: Mapped[list["AgentEvent"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )


class ScopePolicyModel(Base):
    __tablename__ = "scope_policies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), unique=True
    )
    allowed_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowed_urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowed_cidrs: Mapped[list[str]] = mapped_column(JSON, default=list)
    excluded_hosts: Mapped[list[str]] = mapped_column(JSON, default=list)
    excluded_paths: Mapped[list[str]] = mapped_column(JSON, default=list)
    max_rps: Mapped[int] = mapped_column(Integer, default=15)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=5)
    custom_headers: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    auth_cookies: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    allow_private_ips: Mapped[bool] = mapped_column(Boolean, default=False)

    engagement: Mapped["Engagement"] = relationship(back_populates="scope_policy")


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("engagement_id", "asset_type", "value", name="uq_asset_eng_type_val"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    asset_type: Mapped[str] = mapped_column(String(32), nullable=False)  # domain|subdomain|host|ip|api
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    waf: Mapped[str | None] = mapped_column(String(128), nullable=True)
    technologies: Mapped[list[str]] = mapped_column(JSON, default=list)
    headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    discovered_by: Mapped[str] = mapped_column(String(64), default="seed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    engagement: Mapped["Engagement"] = relationship(back_populates="assets")


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("engagement_id", "method", "url", name="uq_endpoint_eng_method_url"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    method: Mapped[str] = mapped_column(String(16), default="GET")
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), default="/")
    query_params: Mapped[list[str]] = mapped_column(JSON, default=list)
    body_params: Mapped[list[str]] = mapped_column(JSON, default=list)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(256), nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="crawl")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    engagement: Mapped["Engagement"] = relationship(back_populates="endpoints")


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    tier: Mapped[int] = mapped_column(Integer, default=1)
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    args: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    argv: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(
        String(32), default="queued"
    )  # queued|awaiting_approval|running|completed|failed|rejected|blocked
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_log_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    engagement: Mapped["Engagement"] = relationship(back_populates="tool_runs")


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    tool_run_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tool_runs.id", ondelete="CASCADE"), unique=True
    )
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    tier: Mapped[int] = mapped_column(Integer, default=3)
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    proposed_args: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    argv_preview: Mapped[list[str]] = mapped_column(JSON, default=list)
    rationale: Mapped[str] = mapped_column(Text, default="")
    risk_summary: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(
        String(32), default="pending"
    )  # pending|approved|modified|rejected|expired
    modified_args: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    operator_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    engagement: Mapped["Engagement"] = relationship(back_populates="approvals")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str] = mapped_column(
        String(16), default="info"
    )  # critical|high|medium|low|info
    status: Mapped[str] = mapped_column(
        String(32), default="open"
    )  # open|confirmed|false_positive|remediated
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    parameter: Mapped[str | None] = mapped_column(String(256), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    poc_command: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str] = mapped_column(Text, default="")
    tool_source: Mapped[str] = mapped_column(String(64), default="aegispt")
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    engagement: Mapped["Engagement"] = relationship(back_populates="findings")


class AgentEvent(Base):
    __tablename__ = "agent_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_name: Mapped[str] = mapped_column(String(64), default="orchestrator")
    message: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    engagement: Mapped["Engagement"] = relationship(back_populates="events")
