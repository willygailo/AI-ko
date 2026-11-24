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

export interface ScopePolicyInputPayload {
  allowed_domains?: string[];
  allowed_urls?: string[];
  allowed_cidrs?: string[];
  excluded_hosts?: string[];
  excluded_paths?: string[];
  max_rps?: number;
  max_concurrency?: number;
  custom_headers?: Record<string, string>;
  auth_cookies?: Record<string, string>;
  secondary_headers?: Record<string, string>;
  secondary_cookies?: Record<string, string>;
  allow_private_ips?: boolean;
}

export interface EngagementCreatePayload {
  name: string;
  description?: string;
  objective?: string;
  autonomy_mode: "tiered" | "copilot" | "lab_autopilot";
  tier2_auto: boolean;
  max_steps: number;
  llm_profile_id: string | null;
  scope: ScopePolicyInputPayload;
}

export interface LLMProfileCreatePayload {
  name: string;
  provider: "ollama" | "openai_compat";
  base_url: string;
  api_key: string;
  fast_model: string;
  reasoning_model: string;
  redact_outbound: boolean;
  is_default: boolean;
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
  engagement_id?: string;
  event_type: string;
  agent_name: string;
  message: string;
  payload: Record<string, unknown>;
  created_at: string | null;
  replayed?: boolean;
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

export interface ReverifyFindingResponse {
  id?: string;
  finding_id?: string;
  status: string;
  still_present: boolean | null;
  manual_reverify_required?: boolean;
  message?: string;
  verified_at?: string | null;
}

export interface WsTicketResponse {
  ticket: string;
  expires_in: number;
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

export interface EngagementActionResponse {
  status?: string;
  engagement_id?: string;
  message?: string;
}

export interface ApprovalDecisionResponse {
  id?: string;
  status: string;
}

export interface FindingMutationResponse {
  id: string;
  title?: string;
  status?: string;
  severity?: string;
}

export interface HypothesisMutationResponse {
  id: string;
  status: string;
  evidence_note?: string;
}

export interface ManualToolRunResponse {
  tool_run_id?: string;
  status?: string;
  summary?: Record<string, unknown>;
}

export type ReportFormat = "html" | "markdown" | "sarif" | "json" | "poc_sh";

export class ApiError extends Error {
  status: number;
  detail: string;
  rawBody: string;

  constructor(status: number, detail: string, rawBody = "") {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.rawBody = rawBody;
  }
}

export function parseApiErrorMessage(status: number, bodyText: string): string {
  const trimmed = bodyText.trim();
  if (!trimmed) {
    return `Request failed with HTTP ${status}.`;
  }
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (parsed && typeof parsed === "object" && "detail" in parsed) {
      const detail = (parsed as { detail: unknown }).detail;
      if (typeof detail === "string" && detail.trim()) {
        return detail.trim();
      }
      if (Array.isArray(detail) && detail.length > 0) {
        const parts = detail
          .map((item) => {
            if (typeof item === "string") return item;
            if (item && typeof item === "object") {
              const rec = item as { loc?: unknown; msg?: unknown };
              const loc = Array.isArray(rec.loc)
                ? rec.loc.filter((segment) => segment !== "body").join(".")
                : "";
              const msg = typeof rec.msg === "string" ? rec.msg : JSON.stringify(item);
              return loc ? `${loc}: ${msg}` : msg;
            }
            return String(item);
          })
          .filter(Boolean);
        if (parts.length > 0) {
          return parts.join("; ");
        }
      }
    }
  } catch {
    // Plain-text body fallback
  }
  return `${status}: ${trimmed}`;
}

const TOKEN_STORAGE_KEY = "aegispt_api_token";

export function normalizeApiToken(raw: string): string {
  if (!raw) return "";
  // Strip terminal box-drawing chars, quotes, and zero-width chars
  let cleaned = raw
    .replace(/[│╭╮╰╯─━┃┏┓┗┛┌┐└┘├┤┬┴┼"|'`\u200B-\u200D\uFEFF]/g, " ")
    .trim();
  cleaned = cleaned.replace(/^authorization\s*:\s*/i, "").trim();
  cleaned = cleaned.replace(/^bearer\s+/i, "").trim();

  // If the user pasted a terminal panel or wrapped lines containing `aegis_...`, stitch & extract it
  const compact = cleaned.replace(/\s+/g, "");
  const match = compact.match(/aegis_[A-Za-z0-9_-]{6,}/);
  if (match) {
    return match[0];
  }
  return compact;
}

type UnauthorizedHandler = (reason?: string) => void;
let unauthorizedHandler: UnauthorizedHandler | null = null;

export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler;
}

export function getStoredToken(): string {
  if (typeof localStorage === "undefined") return "";
  return normalizeApiToken(localStorage.getItem(TOKEN_STORAGE_KEY) || "");
}

export function setStoredToken(tok: string): void {
  if (typeof localStorage === "undefined") return;
  localStorage.setItem(TOKEN_STORAGE_KEY, normalizeApiToken(tok));
}

export function clearStoredToken(): void {
  if (typeof localStorage === "undefined") return;
  localStorage.removeItem(TOKEN_STORAGE_KEY);
}

export interface ApiFetchOptions extends RequestInit {
  skipUnauthorizedHandler?: boolean;
}

export async function apiFetch<T>(path: string, init: ApiFetchOptions = {}): Promise<T> {
  const { skipUnauthorizedHandler = false, ...fetchInit } = init;
  const token = getStoredToken();
  const headers = new Headers(fetchInit.headers || {});
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (fetchInit.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const resp = await fetch(path, { ...fetchInit, headers });
  if (!resp.ok) {
    const text = await resp.text();
    const detail = parseApiErrorMessage(resp.status, text);
    if (resp.status === 401 && !skipUnauthorizedHandler) {
      clearStoredToken();
      unauthorizedHandler?.(detail || "Session expired or invalid API token.");
    }
    throw new ApiError(resp.status, detail, text);
  }
  return (await resp.json()) as T;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
}

export const api = {
  health: async (): Promise<HealthResponse> => {
    const resp = await fetch("/api/v1/system/health");
    if (!resp.ok) {
      throw new ApiError(resp.status, `Health check failed with HTTP ${resp.status}`);
    }
    return (await resp.json()) as HealthResponse;
  },
  doctor: () => apiFetch<DoctorResponse>("/api/v1/system/doctor"),
  listTools: () => apiFetch<{ tools: ToolCatalogItem[] }>("/api/v1/system/tools"),
  getWsTicket: () => apiFetch<WsTicketResponse>("/api/v1/system/ws-ticket", { method: "POST" }),
  listEngagements: (opts?: { skipUnauthorizedHandler?: boolean }) =>
    apiFetch<{ engagements: Engagement[] }>("/api/v1/engagements", opts),
  getEngagement: (id: string, signal?: AbortSignal) =>
    apiFetch<EngagementDetail>(`/api/v1/engagements/${id}`, { signal }),
  createEngagement: (payload: EngagementCreatePayload) =>
    apiFetch<Engagement>("/api/v1/engagements", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteEngagement: (id: string) =>
    apiFetch<{ deleted: string }>(`/api/v1/engagements/${id}`, { method: "DELETE" }),
  startEngagement: (id: string) =>
    apiFetch<EngagementActionResponse>(`/api/v1/engagements/${id}/start`, { method: "POST" }),
  pauseEngagement: (id: string) =>
    apiFetch<EngagementActionResponse>(`/api/v1/engagements/${id}/pause`, { method: "POST" }),
  resumeEngagement: (id: string) =>
    apiFetch<EngagementActionResponse>(`/api/v1/engagements/${id}/resume`, { method: "POST" }),
  stopEngagement: (id: string) =>
    apiFetch<EngagementActionResponse>(`/api/v1/engagements/${id}/stop`, { method: "POST" }),
  runManualTool: (id: string, payload: { tool_name: string; target: string; args: Record<string, unknown> }) =>
    apiFetch<ManualToolRunResponse>(`/api/v1/engagements/${id}/run-tool`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getRunLog: (id: string, runId: string) =>
    apiFetch<{ log: string }>(`/api/v1/engagements/${id}/runs/${runId}/log`),
  decideApproval: (
    approvalId: string,
    payload: {
      decision: "approved" | "modified" | "rejected";
      modified_args?: Record<string, unknown>;
      operator_note?: string;
    }
  ) =>
    apiFetch<ApprovalDecisionResponse>(`/api/v1/approvals/${approvalId}/decide`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateFinding: (
    findingId: string,
    payload: { status?: FindingItem["status"]; severity?: FindingItem["severity"] }
  ) =>
    apiFetch<FindingMutationResponse>(`/api/v1/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  createFinding: (
    engagementId: string,
    payload: {
      title: string;
      severity: FindingItem["severity"];
      target_url: string;
      parameter?: string | null;
      cwe_id?: string | null;
      description: string;
      evidence: Record<string, unknown>;
      poc_command?: string | null;
      remediation?: string;
    }
  ) =>
    apiFetch<FindingMutationResponse>(`/api/v1/engagements/${engagementId}/findings`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateHypothesis: (
    hypothesisId: string,
    payload: { status: HypothesisItem["status"]; evidence_note?: string }
  ) =>
    apiFetch<HypothesisMutationResponse>(`/api/v1/hypotheses/${hypothesisId}`, {
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
  createLLMProfile: (payload: LLMProfileCreatePayload) =>
    apiFetch<LLMProfileItem>("/api/v1/llm-profiles", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteLLMProfile: (profileId: string) =>
    apiFetch<{ deleted: string }>(`/api/v1/llm-profiles/${encodeURIComponent(profileId)}`, {
      method: "DELETE",
    }),
  setDefaultLLMProfile: (profileId: string) =>
    apiFetch<LLMProfileItem>(`/api/v1/llm-profiles/${encodeURIComponent(profileId)}/default`, {
      method: "POST",
    }),
  discoverLLMModels: (payload: { provider: string; base_url: string; api_key: string }) =>
    apiFetch<{ reachable: boolean; models: string[]; error?: string }>("/api/v1/llm-profiles/discover", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  reverifyFinding: (findingId: string) =>
    apiFetch<ReverifyFindingResponse>(`/api/v1/findings/${findingId}/reverify`, { method: "POST" }),
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
  downloadReport: async (id: string, format: ReportFormat) => {
    const token = getStoredToken();
    const endpoint = `/api/v1/engagements/${id}/report?format=${format}`;
    const resp = await fetch(endpoint, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!resp.ok) {
      const text = await resp.text();
      const detail = parseApiErrorMessage(resp.status, text);
      if (resp.status === 401) {
        clearStoredToken();
        unauthorizedHandler?.(detail || "Session expired or invalid API token.");
      }
      throw new ApiError(resp.status, detail, text);
    }
    const blob = await resp.blob();
    const ext =
      format === "markdown"
        ? "md"
        : format === "sarif"
        ? "sarif.json"
        : format === "json"
        ? "json"
        : format === "poc_sh"
        ? "poc.sh"
        : "html";
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegispt-report-${id}.${ext}`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
};

export function buildEngagementWsUrl(
  protocol: string,
  host: string,
  engagementId: string,
  ticket: string
): string {
  const wsProto = protocol === "https:" ? "wss:" : "ws:";
  return `${wsProto}//${host}/api/v1/engagements/${encodeURIComponent(engagementId)}/ws?ticket=${encodeURIComponent(ticket)}`;
}

export interface WsConnectionHandlers {
  onEvent: (ev: AgentEventItem) => void;
  onStatusChange?: (connected: boolean) => void;
  onUnauthorized?: (reason: string) => void;
}

export interface WsConnectionOptions {
  heartbeatMs?: number;
  initialRetryMs?: number;
  maxRetryMs?: number;
  requestTicket?: () => Promise<WsTicketResponse>;
  createSocket?: (url: string) => WebSocket;
  getLocation?: () => { protocol: string; host: string };
}

export function connectEngagementWS(
  engagementId: string,
  handlers: WsConnectionHandlers,
  options: WsConnectionOptions = {}
): { close: () => void } {
  const heartbeatMs = options.heartbeatMs ?? 25_000;
  const initialRetryMs = options.initialRetryMs ?? 1_000;
  const maxRetryMs = options.maxRetryMs ?? 12_000;
  const requestTicket = options.requestTicket ?? api.getWsTicket;
  const createSocket = options.createSocket ?? ((url: string) => new WebSocket(url));
  const getLocation =
    options.getLocation ?? (() => ({ protocol: window.location.protocol, host: window.location.host }));

  let disposed = false;
  let retryDelay = initialRetryMs;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;
  let heartbeatTimer: ReturnType<typeof setInterval> | undefined;
  let activeWs: WebSocket | null = null;

  const clearTimers = () => {
    if (retryTimer !== undefined) {
      clearTimeout(retryTimer);
      retryTimer = undefined;
    }
    if (heartbeatTimer !== undefined) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = undefined;
    }
  };

  const scheduleReconnect = () => {
    if (disposed) return;
    retryTimer = setTimeout(() => {
      void connect();
    }, retryDelay);
    retryDelay = Math.min(retryDelay * 2, maxRetryMs);
  };

  const connect = async () => {
    if (disposed) return;
    let ticket: string;
    try {
      const res = await requestTicket();
      ticket = res.ticket;
    } catch (err) {
      handlers.onStatusChange?.(false);
      if (err instanceof ApiError && err.status === 401) {
        disposed = true;
        handlers.onUnauthorized?.(err.detail || "Authentication expired.");
        return;
      }
      scheduleReconnect();
      return;
    }

    if (disposed) return;
    const loc = getLocation();
    const url = buildEngagementWsUrl(loc.protocol, loc.host, engagementId, ticket);
    const ws = createSocket(url);
    activeWs = ws;

    ws.onopen = () => {
      if (disposed) {
        ws.close();
        return;
      }
      retryDelay = initialRetryMs;
      handlers.onStatusChange?.(true);
      if (heartbeatTimer !== undefined) clearInterval(heartbeatTimer);
      heartbeatTimer = setInterval(() => {
        if (ws.readyState === 1) {
          ws.send("ping");
        }
      }, heartbeatMs);
    };

    ws.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(String(msg.data)) as AgentEventItem;
        if (parsed && parsed.event_type !== "pong") {
          handlers.onEvent(parsed);
        }
      } catch {
        // ignore malformed frames
      }
    };

    ws.onclose = (closeEvent) => {
      if (heartbeatTimer !== undefined) {
        clearInterval(heartbeatTimer);
        heartbeatTimer = undefined;
      }
      handlers.onStatusChange?.(false);
      if (disposed) return;

      if (closeEvent.code === 4401) {
        disposed = true;
        clearStoredToken();
        const reason = "WebSocket authentication failed (4401). Please sign in again.";
        handlers.onUnauthorized?.(reason);
        unauthorizedHandler?.(reason);
        return;
      }

      scheduleReconnect();
    };
  };

  void connect();

  return {
    close: () => {
      disposed = true;
      clearTimers();
      if (activeWs) {
        activeWs.close();
        activeWs = null;
      }
    },
  };
}
