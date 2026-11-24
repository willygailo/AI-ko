"""Pydantic API request and response schemas."""
from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field

from app.config import get_settings


class ScopePolicyInput(BaseModel):
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_urls: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    excluded_hosts: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    max_rps: int = Field(default=15, ge=1, le=100)
    max_concurrency: int = Field(default=5, ge=1, le=30)
    custom_headers: dict[str, str] = Field(default_factory=dict)
    auth_cookies: dict[str, str] = Field(default_factory=dict)
    secondary_headers: dict[str, str] = Field(default_factory=dict)
    secondary_cookies: dict[str, str] = Field(default_factory=dict)
    allow_private_ips: bool = False


class SteerInput(BaseModel):
    hint: str = Field(min_length=2, max_length=600)


class EngagementCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    description: str = ""
    objective: str = "Comprehensive Web Application & API Security Assessment"
    autonomy_mode: Literal["tiered", "copilot", "lab_autopilot"] = "tiered"
    tier2_auto: bool = True
    max_steps: int = Field(default_factory=lambda: get_settings().default_max_steps, ge=1, le=60)
    llm_profile_id: str | None = None
    scope: ScopePolicyInput


class ManualToolRunInput(BaseModel):
    tool_name: str
    target: str
    args: dict[str, Any] = Field(default_factory=dict)
    rationale: str = "Manual operator-initiated execution"


class ApprovalDecisionInput(BaseModel):
    decision: Literal["approved", "modified", "rejected"]
    modified_args: dict[str, Any] | None = None
    operator_note: str | None = None


class FindingUpdateInput(BaseModel):
    status: Literal["open", "confirmed", "false_positive", "remediated"] | None = None
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None


class FindingCreateInput(BaseModel):
    title: str = Field(min_length=2, max_length=300)
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    target_url: str
    parameter: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    cvss_score: float | None = None
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    poc_command: str | None = None
    remediation: str = ""


class HypothesisUpdateInput(BaseModel):
    status: Literal["proposed", "testing", "awaiting_approval", "confirmed", "disproven"]
    evidence_note: str | None = None


class RepeaterRequestInput(BaseModel):
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    use_engagement_auth: bool = True
    follow_redirects: bool = False
    timeout_seconds: int = Field(default=20, ge=3, le=60)


class LLMProfileCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    provider: Literal["ollama", "openai_compat"]
    base_url: str
    api_key: str = ""
    fast_model: str
    reasoning_model: str
    redact_outbound: bool = True
    is_default: bool = False


class LLMDiscoverInput(BaseModel):
    provider: Literal["ollama", "openai_compat"] = "ollama"
    base_url: str = "http://127.0.0.1:11434"
    api_key: str = ""
