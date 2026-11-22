"""Structured JSON schemas for multi-agent LLM planning and triage."""
from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, Field


class ProposedToolCall(BaseModel):
    tool_name: str
    target: str
    args: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    risk_summary: str = ""


class HypothesisItem(BaseModel):
    title: str
    target_url: str
    parameter: str | None = None
    cwe_id: str | None = None
    confidence: Literal["low", "medium", "high"] = "medium"
    rationale: str = ""


class PlannerDecision(BaseModel):
    thought: str = ""
    phase: Literal["recon", "assessment", "verification", "reporting", "complete"] = "assessment"
    proposed_tools: list[ProposedToolCall] = Field(default_factory=list)
    hypotheses: list[HypothesisItem] = Field(default_factory=list)
    should_stop: bool = False
    stop_reason: str = ""


class TriagedFinding(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    cwe_id: str | None = None
    owasp_category: str | None = None
    cvss_score: float | None = None
    description: str = ""
    remediation: str = ""


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def parse_json_object(raw_text: str) -> dict[str, Any]:
    """Extract a JSON object robustly from model output, handling markdown fences."""
    text = (raw_text or "").strip()
    if not text:
        raise ValueError("Empty LLM response.")

    # Direct parse
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    # Markdown code fence
    m = _JSON_FENCE_RE.search(text)
    if m:
        try:
            data = json.loads(m.group(1))
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

    # Outermost braces slice
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        data = json.loads(text[start : end + 1])
        if isinstance(data, dict):
            return data

    raise ValueError(f"Could not parse JSON object from LLM output: {text[:240]!r}")
