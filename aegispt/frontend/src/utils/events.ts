import type {
  AgentEventItem,
  ApprovalItem,
  EndpointItem,
  FindingItem,
} from "../api/client.ts";

export const DETAIL_REFRESH_EVENT_TYPES: ReadonlySet<string> = new Set([
  "tool_completed",
  "manual_tool_completed",
  "manual_tool_failed",
  "approval_required",
  "approval_resolved",
  "attack_chain_synthesized",
  "operator_steer",
  "oob_callback_received",
  "executive_summary",
  "engagement_finished",
  "engagement_failed",
  "scope_blocked",
]);

export function getMaxEventId(events: readonly AgentEventItem[]): number {
  let maxId = 0;
  for (const ev of events) {
    if (typeof ev.id === "number" && ev.id > maxId) {
      maxId = ev.id;
    }
  }
  return maxId;
}

export function mergeDedupedEvents(
  existing: readonly AgentEventItem[],
  incoming: readonly AgentEventItem[],
  limit = 300
): AgentEventItem[] {
  if (incoming.length === 0) {
    return existing.length > limit ? existing.slice(-limit) : [...existing];
  }
  const seenIds = new Set<number>();
  const result: AgentEventItem[] = [];

  for (const ev of existing) {
    if (typeof ev.id === "number") {
      if (seenIds.has(ev.id)) continue;
      seenIds.add(ev.id);
    }
    result.push(ev);
  }

  for (const ev of incoming) {
    if (typeof ev.id === "number") {
      if (seenIds.has(ev.id)) continue;
      seenIds.add(ev.id);
    }
    result.push(ev);
  }

  return result.length > limit ? result.slice(-limit) : result;
}

export function shouldTriggerDetailRefresh(ev: AgentEventItem, maxSeenId: number): boolean {
  if (ev.replayed === true) {
    return false;
  }
  if (typeof ev.id === "number" && ev.id <= maxSeenId) {
    return false;
  }
  return DETAIL_REFRESH_EVENT_TYPES.has(ev.event_type);
}

export function pickAutoOpenApproval(
  approvals: readonly ApprovalItem[],
  dismissedIds: ReadonlySet<string>
): ApprovalItem | null {
  for (const ap of approvals) {
    if (ap.status === "pending" && !dismissedIds.has(ap.id)) {
      return ap;
    }
  }
  return null;
}

export function filterEndpoints(endpoints: readonly EndpointItem[], query: string): EndpointItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return [...endpoints];
  return endpoints.filter(
    (ep) =>
      ep.url.toLowerCase().includes(q) ||
      ep.path.toLowerCase().includes(q) ||
      ep.method.toLowerCase().includes(q) ||
      ep.query_params.some((p) => p.toLowerCase().includes(q)) ||
      ep.body_params.some((p) => p.toLowerCase().includes(q))
  );
}

export function filterFindings(findings: readonly FindingItem[], severity: string): FindingItem[] {
  if (severity === "all") return [...findings];
  return findings.filter((f) => f.severity === severity);
}

export function resolveSelectedFinding(
  findings: readonly FindingItem[],
  selectedId: string | null
): FindingItem | null {
  if (findings.length === 0) return null;
  if (selectedId) {
    const match = findings.find((f) => f.id === selectedId);
    if (match) return match;
  }
  return findings[0];
}
