import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type {
  AgentEventItem,
  ApprovalItem,
  EndpointItem,
  FindingItem,
} from "../api/client.ts";
import {
  filterEndpoints,
  filterFindings,
  getMaxEventId,
  mergeDedupedEvents,
  pickAutoOpenApproval,
  resolveSelectedFinding,
  shouldTriggerDetailRefresh,
} from "../utils/events.ts";

const makeEvent = (
  id: number | null,
  eventType: string,
  replayed?: boolean
): AgentEventItem => ({
  id,
  engagement_id: "eng-1",
  event_type: eventType,
  agent_name: "orchestrator",
  message: `msg-${id ?? "x"}`,
  payload: {},
  created_at: null,
  replayed,
});

const makeApproval = (id: string, status = "pending"): ApprovalItem => ({
  id,
  tool_run_id: `run-${id}`,
  tool_name: "sqlmap",
  tier: 3,
  target: "http://127.0.0.1:3000/api/search",
  proposed_args: {},
  argv_preview: ["sqlmap", "-u", "http://127.0.0.1:3000/api/search"],
  rationale: "test",
  risk_summary: "intrusive",
  status,
  modified_args: null,
  operator_note: null,
  created_at: null,
});

const makeFinding = (
  id: string,
  severity: FindingItem["severity"],
  status: FindingItem["status"]
): FindingItem => ({
  id,
  title: `Finding ${id}`,
  severity,
  status,
  cvss_score: null,
  cwe_id: null,
  owasp_category: null,
  target_url: "http://127.0.0.1:3000/api",
  parameter: null,
  description: "",
  evidence: {},
  poc_command: null,
  remediation: "",
  tool_source: "http_probe",
  created_at: null,
});

describe("WebSocket event dedupe, approval dismiss, endpoint & finding helpers", () => {
  it("deduplicates overlapping DB and WS replay events by ev.id", () => {
    const initial = [makeEvent(1, "engagement_started"), makeEvent(2, "tool_started")];
    const replayed = [
      makeEvent(2, "tool_started", true),
      makeEvent(3, "tool_completed", true),
      makeEvent(4, "tool_output", false),
    ];
    const merged = mergeDedupedEvents(initial, replayed, 10);
    assert.deepEqual(
      merged.map((e) => e.id),
      [1, 2, 3, 4]
    );
    assert.equal(getMaxEventId(merged), 4);
  });

  it("skips detail refresh on replayed or already-seen events and triggers on new live events", () => {
    assert.equal(shouldTriggerDetailRefresh(makeEvent(10, "tool_completed", true), 5), false);
    assert.equal(shouldTriggerDetailRefresh(makeEvent(5, "tool_completed", false), 5), false);
    assert.equal(shouldTriggerDetailRefresh(makeEvent(6, "tool_output", false), 5), false);
    assert.equal(shouldTriggerDetailRefresh(makeEvent(6, "tool_completed", false), 5), true);
    assert.equal(shouldTriggerDetailRefresh(makeEvent(7, "approval_required"), 5), true);
    assert.equal(shouldTriggerDetailRefresh(makeEvent(8, "manual_tool_failed", false), 5), true);
  });

  it("does not re-open dismissed approvals while still auto-opening new ones", () => {
    const approvals = [makeApproval("ap-1", "pending"), makeApproval("ap-2", "pending")];
    const dismissed = new Set<string>(["ap-1"]);
    const next = pickAutoOpenApproval(approvals, dismissed);
    assert.equal(next?.id, "ap-2");

    dismissed.add("ap-2");
    assert.equal(pickAutoOpenApproval(approvals, dismissed), null);
  });

  it("searches endpoints across URL, method, query_params, and body_params", () => {
    const endpoints: EndpointItem[] = [
      {
        id: "e1",
        method: "POST",
        url: "http://127.0.0.1:3000/api/login",
        path: "/api/login",
        query_params: ["next"],
        body_params: ["password", "totp_code"],
        status_code: 200,
        source: "katana",
      },
    ];
    assert.equal(filterEndpoints(endpoints, "totp_code").length, 1);
    assert.equal(filterEndpoints(endpoints, "next").length, 1);
    assert.equal(filterEndpoints(endpoints, "post").length, 1);
    assert.equal(filterEndpoints(endpoints, "missing_param").length, 0);
  });

  it("resolves updated finding by selectedId so status changes reflect immediately", () => {
    const before = [makeFinding("f1", "high", "open"), makeFinding("f2", "low", "open")];
    const after = [makeFinding("f1", "high", "open"), makeFinding("f2", "low", "confirmed")];

    assert.equal(resolveSelectedFinding(before, "f2")?.status, "open");
    assert.equal(resolveSelectedFinding(after, "f2")?.status, "confirmed");
    assert.equal(resolveSelectedFinding(filterFindings(after, "high"), "f2")?.id, "f1");
    assert.equal(resolveSelectedFinding([], "f2"), null);
  });
});
