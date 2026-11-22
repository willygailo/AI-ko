export interface ScopePolicy {
  allowed_domains: string[];
  allowed_urls: string[];
  allowed_cidrs: string[];
  excluded_hosts: string[];
  excluded_paths: string[];
  max_rps: number;
  max_concurrency: number;
  custom_headers: Record<string, string>;
  auth_cookies_keys?: string[];
  secondary_header_keys?: string[];
  secondary_cookies_keys?: string[];
  has_secondary_auth?: boolean;
  allow_private_ips: boolean;
}

export interface AttackChainItem {
  id: string;
  title: string;
  severity: string;
  risk_summary: string;
  target_url: string;
  steps: string[];
  finding_ids: string[];
  created_at: string | null;
}

export interface SkillChecklistEntry {
  id: string;
  skill_id: string;
  skill_title: string;
  wstg_id: string;
  item_key: string;
  item_text: string;
  status: "pending" | "covered" | "finding" | "skipped";
  evidence_note: string;
}

export interface OOBEventItem {
  id: string;
  token: string;
  method: string;
  path: string;
  source_ip: string;
  created_at: string | null;
}

export interface Engagement {
  id: string;
  name: string;
  description: string;
  objective: string;
  status: string;
  autonomy_mode: "tiered" | "copilot" | "lab_autopilot";
  tier2_auto: boolean;
  max_steps: number;
  current_step: number;
  llm_profile_id: string | null;
  created_at: string | null;
  scope?: ScopePolicy;
}

export interface AssetItem {
  id: string;
  asset_type: string;
  value: string;
  ip_address: string | null;
  status_code: number | null;
  title: string | null;
  waf: string | null;
  technologies: string[];
  discovered_by: string;
}

export interface EndpointItem {
  id: string;
  method: string;
  url: string;
  path: string;
  query_params: string[];
  body_params: string[];
  status_code: number | null;
  source: string;
}

export interface ToolRunItem {
  id: string;
  tool_name: string;
  tier: number;
  target: string;
  args: Record<string, unknown>;
  argv: string[];
  status: string;
  exit_code: number | null;
  duration_ms: number | null;
  summary: Record<string, unknown>;
  error_message: string | null;
  created_at: string | null;
}

export interface ApprovalItem {
  id: string;
  tool_run_id: string;
  tool_name: string;
  tier: number;
  target: string;
  proposed_args: Record<string, unknown>;
  argv_preview: string[];
  rationale: string;
  risk_summary: string;
  status: string;
  modified_args: Record<string, unknown> | null;
  operator_note: string | null;
  created_at: string | null;
}

export interface FindingItem {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "open" | "confirmed" | "false_positive" | "remediated";
  cvss_score: number | null;
  cwe_id: string | null;
  owasp_category: string | null;
  target_url: string;
  parameter: string | null;
  description: string;
  evidence: Record<string, unknown>;
  poc_command: string | null;
  remediation: string;
  tool_source: string;
  corroborated_by?: string[];
  verified_at?: string | null;
  created_at: string | null;
}

export interface AgentEventItem {
  id: number | null;
  engagement_id: string;
  event_type: string;
  agent_name: string;
  message: string;
  payload: Record<string, unknown>;
  created_at: string | null;
}

export interface HypothesisItem {
  id: string;
  title: string;
  target_url: string;
  parameter: string | null;
  cwe_id: string | null;
  confidence: string;
  status: "proposed" | "testing" | "awaiting_approval" | "confirmed" | "disproven";
  rationale: string;
  evidence_note: string;
  updated_at: string | null;
}

export interface SnapshotItem {
  id: string;
  label: string;
  assets_count: number;
  endpoints_count: number;
  findings_count: number;
  created_at: string | null;
}

export interface ScanDiffResponse {
  has_diff: boolean;
  snapshots_count: number;
  baseline?: { id: string; label: string; created_at: string | null };
  current?: { id: string; label: string; created_at: string | null };
  new_assets?: string[];
  removed_assets?: string[];
  new_endpoints?: string[];
  new_findings?: string[];
  resolved_findings?: string[];
  new_open_ports?: string[];
}

export interface RepeaterResponse {
  status_code: number;
  final_url: string;
  duration_ms: number;
  headers: Record<string, string>;
  body: string;
  curl_command: string;
}

export interface EngagementDetail extends Engagement {
  operator_hints?: string[];
  assets: AssetItem[];
  endpoints: EndpointItem[];
  tool_runs: ToolRunItem[];
  approvals: ApprovalItem[];
  findings: FindingItem[];
  events: AgentEventItem[];
  hypotheses: HypothesisItem[];
  snapshots: SnapshotItem[];
  attack_chains?: AttackChainItem[];
  checklist_items?: SkillChecklistEntry[];
  oob_events?: OOBEventItem[];
}

export interface LLMProfileItem {
  id: string;
  name: string;
  provider: "ollama" | "openai_compat";
  base_url: string;
  has_api_key: boolean;
  fast_model: string;
  reasoning_model: string;
  redact_outbound: boolean;
  is_default: boolean;
}

export interface ToolCatalogItem {
  name: string;
  tier: number;
  description: string;
  available: boolean;
  resolved_path: string | null;
}

export interface DoctorResponse {
  status: string;
  tools_available: number;
  tools_total: number;
  tools: ToolCatalogItem[];
  llm: {
    reachable: boolean;
    provider: string;
    base_url: string;
    models: string[];
    error?: string;
  };
  knowledge_playbooks: number;
}

const TOKEN_STORAGE_KEY = "aegispt_api_token";

export function getStoredToken(): string {
  return localStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

export function setStoredToken(tok: string): void {
  localStorage.setItem(TOKEN_STORAGE_KEY, tok.trim());
}

async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  const headers = new Headers(init.headers || {});
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const resp = await fetch(path, { ...init, headers });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`${resp.status}: ${text}`);
  }
  return resp.json() as Promise<T>;
}

export const api = {
  doctor: () => apiFetch<DoctorResponse>("/api/v1/system/doctor"),
  listEngagements: () => apiFetch<{ engagements: Engagement[] }>("/api/v1/engagements"),
  getEngagement: (id: string) => apiFetch<EngagementDetail>(`/api/v1/engagements/${id}`),
  createEngagement: (payload: unknown) =>
    apiFetch<Engagement>("/api/v1/engagements", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteEngagement: (id: string) =>
    apiFetch<{ deleted: string }>(`/api/v1/engagements/${id}`, { method: "DELETE" }),
  startEngagement: (id: string) =>
    apiFetch(`/api/v1/engagements/${id}/start`, { method: "POST" }),
  pauseEngagement: (id: string) =>
    apiFetch(`/api/v1/engagements/${id}/pause`, { method: "POST" }),
  resumeEngagement: (id: string) =>
    apiFetch(`/api/v1/engagements/${id}/resume`, { method: "POST" }),
  stopEngagement: (id: string) =>
    apiFetch(`/api/v1/engagements/${id}/stop`, { method: "POST" }),
  runManualTool: (id: string, payload: { tool_name: string; target: string; args: Record<string, unknown> }) =>
    apiFetch(`/api/v1/engagements/${id}/run-tool`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getRunLog: (id: string, runId: string) =>
    apiFetch<{ log: string }>(`/api/v1/engagements/${id}/runs/${runId}/log`),
  decideApproval: (
    approvalId: string,
    payload: { decision: "approved" | "modified" | "rejected"; modified_args?: Record<string, unknown>; operator_note?: string }
  ) =>
    apiFetch(`/api/v1/approvals/${approvalId}/decide`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateFinding: (findingId: string, payload: { status?: string; severity?: string }) =>
    apiFetch(`/api/v1/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  createFinding: (
    engagementId: string,
    payload: {
      title: string;
      severity: string;
      target_url: string;
      parameter?: string | null;
      cwe_id?: string | null;
      description: string;
      evidence: Record<string, unknown>;
      poc_command?: string | null;
      remediation?: string;
    }
  ) =>
    apiFetch(`/api/v1/engagements/${engagementId}/findings`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateHypothesis: (hypothesisId: string, payload: { status: string; evidence_note?: string }) =>
    apiFetch(`/api/v1/hypotheses/${hypothesisId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  createSnapshot: (engagementId: string, label: string) =>
    apiFetch<SnapshotItem>(`/api/v1/engagements/${engagementId}/snapshots?label=${encodeURIComponent(label)}`, {
      method: "POST",
    }),
  getScanDiff: (engagementId: string, base?: string, target?: string) => {
    const qs = new URLSearchParams();
    if (base) qs.set("base", base);
    if (target) qs.set("target", target);
    const qStr = qs.toString();
    return apiFetch<ScanDiffResponse>(`/api/v1/engagements/${engagementId}/diff${qStr ? `?${qStr}` : ""}`);
  },
  runRepeater: (
    engagementId: string,
    payload: {
      method: string;
      url: string;
      headers: Record<string, string>;
      body?: string | null;
      use_engagement_auth: boolean;
      follow_redirects: boolean;
    }
  ) =>
    apiFetch<RepeaterResponse>(`/api/v1/engagements/${engagementId}/repeater`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  listLLMProfiles: () => apiFetch<{ profiles: LLMProfileItem[] }>("/api/v1/llm-profiles"),
  createLLMProfile: (payload: unknown) =>
    apiFetch<LLMProfileItem>("/api/v1/llm-profiles", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  discoverLLMModels: (payload: { provider: string; base_url: string; api_key: string }) =>
    apiFetch<{ reachable: boolean; models: string[]; error?: string }>("/api/v1/llm-profiles/discover", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  reverifyFinding: (findingId: string) =>
    apiFetch<{ id: string; status: string; still_present: boolean; verified_at: string }>(
      `/api/v1/findings/${findingId}/reverify`,
      { method: "POST" }
    ),
  steerEngagement: (engagementId: string, hint: string) =>
    apiFetch<{ engagement_id: string; operator_hints: string[] }>(
      `/api/v1/engagements/${engagementId}/steer`,
      {
        method: "POST",
        body: JSON.stringify({ hint }),
      }
    ),
  synthesizeChains: (engagementId: string) =>
    apiFetch<{ engagement_id: string; synthesized: number }>(
      `/api/v1/engagements/${engagementId}/chains/synthesize`,
      { method: "POST" }
    ),
  downloadReport: async (id: string, format: "html" | "markdown" | "sarif" | "poc_sh") => {
    const token = getStoredToken();
    const resp = await fetch(`/api/v1/engagements/${id}/report?format=${format}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok) throw new Error("Report export failed");
    const blob = await resp.blob();
    const ext =
      format === "markdown"
        ? "md"
        : format === "sarif"
        ? "sarif.json"
        : format === "poc_sh"
        ? "poc.sh"
        : "html";
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegispt-report-${id}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  },
};

export function createEngagementWebSocket(
  engagementId: string,
  onEvent: (ev: AgentEventItem) => void
): WebSocket {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const tok = encodeURIComponent(getStoredToken());
  const ws = new WebSocket(`${proto}//${window.location.host}/ws/engagements/${engagementId}?token=${tok}`);
  ws.onmessage = (msg) => {
    try {
      const parsed = JSON.parse(msg.data) as AgentEventItem;
      if (parsed.event_type !== "pong") {
        onEvent(parsed);
      }
    } catch {
      // ignore malformed frames
    }
  };
  return ws;
}
