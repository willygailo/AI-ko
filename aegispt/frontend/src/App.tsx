import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Camera,
  FileText,
  GitCompare,
  KeyRound,
  Pause,
  Play,
  Plus,
  Search,
  Send,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Square,
  Terminal,
  Trash2,
  Wifi,
  WifiOff,
  X,
} from "lucide-react";
import {
  AgentEventItem,
  ApprovalItem,
  Engagement,
  EngagementDetail,
  LLMProfileItem,
  ScanDiffResponse,
  ToolRunItem,
  api,
  createEngagementWebSocket,
  getStoredToken,
  setStoredToken,
} from "./api/client";
import { ApprovalModal } from "./components/ApprovalModal";
import { AttackGraph } from "./components/AttackGraph";
import { FindingsPanel } from "./components/FindingsPanel";
import { RepeaterPanel } from "./components/RepeaterPanel";
import { ScopeWizardModal } from "./components/ScopeWizardModal";
import { SettingsModal } from "./components/SettingsModal";

const EVENT_COLORS: Record<string, string> = {
  engagement_started: "text-emerald-400",
  agent_thought: "text-fuchsia-300",
  tool_started: "text-cyan-400",
  tool_completed: "text-emerald-300",
  manual_tool_completed: "text-emerald-300",
  tool_output: "text-slate-500",
  scope_blocked: "text-red-400",
  approval_required: "text-amber-300",
  approval_resolved: "text-sky-300",
  planner_fallback: "text-amber-400",
  attack_chain_synthesized: "text-orange-300 font-semibold",
  operator_steer: "text-cyan-300 font-semibold",
  oob_callback_received: "text-rose-300 font-semibold",
  executive_summary: "text-cyan-200 font-semibold",
  engagement_finished: "text-emerald-400 font-bold",
  engagement_failed: "text-red-400 font-bold",
};

type WorkspaceTab =
  | "graph"
  | "chains"
  | "checklist"
  | "endpoints"
  | "findings"
  | "hypotheses"
  | "repeater"
  | "runs"
  | "approvals"
  | "diff";

export default function App() {
  const [tokenInput, setTokenInput] = useState(getStoredToken());
  const [authenticated, setAuthenticated] = useState(Boolean(getStoredToken()));
  const [authError, setAuthError] = useState("");

  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [detail, setDetail] = useState<EngagementDetail | null>(null);
  const [events, setEvents] = useState<AgentEventItem[]>([]);
  const [profiles, setProfiles] = useState<LLMProfileItem[]>([]);
  const [wsConnected, setWsConnected] = useState(false);

  const [showWizard, setShowWizard] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [activeApproval, setActiveApproval] = useState<ApprovalItem | null>(null);
  const [activeTab, setActiveTab] = useState<WorkspaceTab>("graph");

  const [endpointSearch, setEndpointSearch] = useState("");
  const [selectedRunLog, setSelectedRunLog] = useState<{ run: ToolRunItem; log: string } | null>(null);
  const [repeaterUrl, setRepeaterUrl] = useState("");
  const [scanDiff, setScanDiff] = useState<ScanDiffResponse | null>(null);

  const [manualTool, setManualTool] = useState("http_probe");
  const [manualTarget, setManualTarget] = useState("");
  const [manualArgsJson, setManualArgsJson] = useState("");
  const [manualError, setManualError] = useState("");
  const [manualBusy, setManualBusy] = useState(false);
  const [steerInput, setSteerInput] = useState("");
  const [steerBusy, setSteerBusy] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const logEndRef = useRef<HTMLDivElement | null>(null);

  const refreshList = useCallback(async () => {
    const res = await api.listEngagements();
    setEngagements(res.engagements);
    if (res.engagements.length === 0) {
      setSelectedId("");
      setDetail(null);
    } else if (!selectedId || !res.engagements.some((e) => e.id === selectedId)) {
      setSelectedId(res.engagements[0].id);
    }
  }, [selectedId]);

  const refreshDetail = useCallback(async (id: string) => {
    if (!id) return;
    const d = await api.getEngagement(id);
    setDetail(d);
    setEvents(d.events || []);
    const seed =
      d.scope?.allowed_urls?.[0] ||
      (d.scope?.allowed_domains?.[0] ? `https://${d.scope.allowed_domains[0]}` : "");
    if (seed) {
      setManualTarget((prev) => prev || seed);
      setRepeaterUrl((prev) => prev || seed);
    }
  }, []);

  const refreshProfiles = useCallback(async () => {
    const res = await api.listLLMProfiles();
    setProfiles(res.profiles);
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    Promise.all([refreshList(), refreshProfiles()]).catch((err) => {
      if (String(err).includes("401")) {
        setAuthenticated(false);
        setAuthError("Invalid local API token.");
      }
    });
  }, [authenticated, refreshList, refreshProfiles]);

  // WebSocket with automatic exponential backoff reconnect
  useEffect(() => {
    if (!authenticated || !selectedId) return;
    refreshDetail(selectedId).catch(() => {});

    let closedByEffect = false;
    let retryDelay = 1000;
    let retryTimer: number | undefined;

    const connect = () => {
      if (closedByEffect) return;
      const ws = createEngagementWebSocket(selectedId, (ev) => {
        setEvents((prev) => [...prev.slice(-240), ev]);
        if (
          [
            "tool_completed",
            "manual_tool_completed",
            "approval_required",
            "approval_resolved",
            "attack_chain_synthesized",
            "operator_steer",
            "oob_callback_received",
            "executive_summary",
            "engagement_finished",
            "engagement_failed",
            "scope_blocked",
          ].includes(ev.event_type)
        ) {
          refreshDetail(selectedId).catch(() => {});
        }
      });
      ws.onopen = () => {
        setWsConnected(true);
        retryDelay = 1000;
      };
      ws.onclose = () => {
        setWsConnected(false);
        if (!closedByEffect) {
          retryTimer = window.setTimeout(connect, retryDelay);
          retryDelay = Math.min(retryDelay * 2, 12000);
        }
      };
      wsRef.current = ws;
    };

    connect();
    return () => {
      closedByEffect = true;
      if (retryTimer) window.clearTimeout(retryTimer);
      wsRef.current?.close();
    };
  }, [authenticated, selectedId, refreshDetail]);

  useEffect(() => {
    if (activeTab === "diff" && selectedId) {
      api.getScanDiff(selectedId).then(setScanDiff).catch(() => {});
    }
  }, [activeTab, selectedId, detail?.snapshots?.length]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length]);

  const pendingApprovals = useMemo(
    () => (detail?.approvals || []).filter((a) => a.status === "pending"),
    [detail]
  );

  useEffect(() => {
    if (!activeApproval && pendingApprovals.length > 0) {
      setActiveApproval(pendingApprovals[0]);
    }
  }, [pendingApprovals, activeApproval]);

  const filteredEndpoints = useMemo(() => {
    const q = endpointSearch.trim().toLowerCase();
    return (detail?.endpoints || []).filter(
      (ep) =>
        !q ||
        ep.url.toLowerCase().includes(q) ||
        ep.method.toLowerCase().includes(q) ||
        ep.query_params.some((p) => p.toLowerCase().includes(q))
    );
  }, [detail?.endpoints, endpointSearch]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");
    setStoredToken(tokenInput);
    try {
      await api.listEngagements();
      setAuthenticated(true);
    } catch {
      setAuthError("Token rejected by AegisPT server. Run `./aegispt token` in terminal to get the local token.");
    }
  };

  const handleManualRun = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedId || !manualTarget) return;
    setManualError("");
    let parsedArgs: Record<string, unknown> = {};
    if (manualArgsJson.trim()) {
      try {
        parsedArgs = JSON.parse(manualArgsJson);
      } catch {
        setManualError("Invalid JSON in optional args field.");
        return;
      }
    }
    setManualBusy(true);
    try {
      await api.runManualTool(selectedId, {
        tool_name: manualTool,
        target: manualTarget,
        args: parsedArgs,
      });
      await refreshDetail(selectedId);
    } catch (err) {
      setManualError(String(err));
    } finally {
      setManualBusy(false);
    }
  };

  const handleOpenRunLog = async (run: ToolRunItem) => {
    if (!selectedId) return;
    try {
      const res = await api.getRunLog(selectedId, run.id);
      setSelectedRunLog({ run, log: res.log || "(no log output recorded)" });
    } catch (err) {
      setSelectedRunLog({ run, log: `Failed to load log: ${String(err)}` });
    }
  };

  const handleDeleteEngagement = async () => {
    if (!detail) return;
    if (!window.confirm(`Delete engagement "${detail.name}" and its findings?`)) return;
    await api.deleteEngagement(detail.id);
    await refreshList();
  };

  if (!authenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 p-6">
        <form
          onSubmit={handleLogin}
          className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-2xl"
        >
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/15 border border-cyan-500/30">
              <ShieldCheck className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white">AegisPT</h1>
              <p className="text-xs text-slate-400">Private AI Web & API Pentesting Platform</p>
            </div>
          </div>

          <div className="text-xs text-slate-300 bg-slate-950 border border-slate-800 rounded-lg p-3">
            Enter your local API token (printed on server startup or via{" "}
            <code className="text-cyan-300">./aegispt token</code>).
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Local API Token</label>
            <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg px-3">
              <KeyRound className="w-4 h-4 text-slate-500" />
              <input
                type="password"
                required
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder="aegis_..."
                className="w-full bg-transparent py-2.5 text-sm text-white focus:outline-none font-mono"
              />
            </div>
          </div>

          {authError && <div className="text-xs text-red-400">{authError}</div>}

          <button
            type="submit"
            className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold"
          >
            Connect to Local Engine
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col bg-slate-950 text-slate-100 overflow-hidden">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 bg-slate-900 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <span className="font-bold text-sm tracking-wide">AegisPT</span>
          </div>

          <select
            value={selectedId}
            onChange={(e) => {
              setSelectedId(e.target.value);
              setManualTarget("");
              setRepeaterUrl("");
            }}
            className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white min-w-[220px]"
          >
            {engagements.length === 0 && <option value="">No engagements yet</option>}
            {engagements.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name} ({e.status})
              </option>
            ))}
          </select>

          {detail && (
            <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-cyan-300 uppercase font-semibold">
              {detail.status} • {detail.autonomy_mode}
            </span>
          )}

          {selectedId && (
            <span
              className={`flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full border ${
                wsConnected
                  ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-300"
                  : "bg-amber-500/10 border-amber-500/40 text-amber-300"
              }`}
            >
              {wsConnected ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
              {wsConnected ? "Live" : "Reconnecting"}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {detail && (
            <>
              {detail.status === "paused" ? (
                <button
                  onClick={() => api.resumeEngagement(detail.id).then(() => refreshDetail(detail.id))}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold"
                >
                  <Play className="w-3.5 h-3.5" /> Resume
                </button>
              ) : (
                <button
                  onClick={() => api.startEngagement(detail.id).then(() => refreshDetail(detail.id))}
                  disabled={detail.status === "running"}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-xs font-semibold"
                >
                  <Play className="w-3.5 h-3.5" /> Start Auto
                </button>
              )}
              <button
                onClick={() => api.pauseEngagement(detail.id).then(() => refreshDetail(detail.id))}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs"
              >
                <Pause className="w-3.5 h-3.5" /> Pause
              </button>
              <button
                onClick={() => api.stopEngagement(detail.id).then(() => refreshDetail(detail.id))}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-red-950/70 hover:bg-red-900 border border-red-800/60 text-red-200 text-xs"
              >
                <Square className="w-3.5 h-3.5" /> Stop
              </button>
              <button
                onClick={handleDeleteEngagement}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-red-950 text-slate-400 hover:text-red-300"
                title="Delete engagement"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </>
          )}

          {pendingApprovals.length > 0 && (
            <button
              onClick={() => setActiveApproval(pendingApprovals[0])}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/20 border border-amber-500 text-amber-200 text-xs font-bold animate-pulse"
            >
              <ShieldAlert className="w-4 h-4" /> {pendingApprovals.length} Approval Pending
            </button>
          )}

          <button
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
          >
            <Plus className="w-3.5 h-3.5" /> New
          </button>
          <button
            onClick={() => setShowSettings(true)}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
            title="LLM & Kali Tool Settings"
          >
            <Settings className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* Main Workspace */}
      {!detail ? (
        <div className="flex-1 flex flex-col items-center justify-center text-slate-400 space-y-3">
          <ShieldCheck className="w-12 h-12 text-slate-700" />
          <p className="text-sm">Create a scoped engagement to begin an automated AI assessment.</p>
          <button
            onClick={() => setShowWizard(true)}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
          >
            + Create First Engagement
          </button>
        </div>
      ) : (
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-3 p-3 min-h-0">
          {/* Left 7 Columns */}
          <div className="lg:col-span-7 flex flex-col gap-2 min-h-0">
            <div className="flex flex-wrap items-center gap-1.5">
              {[
                { id: "graph", label: "Attack Graph" },
                { id: "chains", label: `Chains (${detail.attack_chains?.length || 0})` },
                {
                  id: "checklist",
                  label: `Skills (${
                    (detail.checklist_items || []).filter((c) => c.status !== "pending").length
                  }/${detail.checklist_items?.length || 0})`,
                },
                { id: "endpoints", label: `Endpoints (${detail.endpoints.length})` },
                { id: "findings", label: `Findings (${detail.findings.length})` },
                { id: "hypotheses", label: `Hypotheses (${detail.hypotheses?.length || 0})` },
                { id: "repeater", label: "Repeater" },
                { id: "runs", label: `Runs (${detail.tool_runs.length})` },
                { id: "approvals", label: `Approvals (${detail.approvals.length})` },
                { id: "diff", label: `Diff (${detail.snapshots?.length || 0})` },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as WorkspaceTab)}
                  className={`px-2.5 py-1.5 rounded-lg text-xs font-semibold ${
                    activeTab === tab.id
                      ? "bg-cyan-600 text-white"
                      : "bg-slate-900 border border-slate-800 text-slate-400 hover:text-white"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="flex-1 min-h-0">
              {activeTab === "graph" && (
                <AttackGraph
                  engagementName={detail.name}
                  assets={detail.assets}
                  endpoints={detail.endpoints}
                  findings={detail.findings}
                  onPivotTarget={(u) => setManualTarget(u)}
                />
              )}

              {activeTab === "chains" && (
                <div className="h-full flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden text-xs">
                  <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800 bg-slate-900">
                    <span className="font-semibold uppercase tracking-wider text-slate-300">
                      Synthesized Attack Chains ({detail.attack_chains?.length || 0})
                    </span>
                    <button
                      onClick={() => api.synthesizeChains(detail.id).then(() => refreshDetail(detail.id))}
                      className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold"
                    >
                      Synthesize Chains
                    </button>
                  </div>
                  <div className="flex-1 overflow-auto p-3 space-y-3">
                    {(!detail.attack_chains || detail.attack_chains.length === 0) && (
                      <div className="text-slate-500 text-center mt-8">
                        No multi-step chains correlated yet. Run an engagement or click "Synthesize Chains".
                      </div>
                    )}
                    {(detail.attack_chains || []).map((ch) => (
                      <div key={ch.id} className="bg-slate-950/70 border border-slate-800 rounded-xl p-3 space-y-1.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-bold text-slate-100">{ch.title}</span>
                          <span className="px-2 py-0.5 rounded bg-orange-500/20 text-orange-300 uppercase text-[10px] font-bold">
                            {ch.severity}
                          </span>
                        </div>
                        <div className="text-slate-300">{ch.risk_summary}</div>
                        <ul className="list-disc pl-5 text-[11px] text-slate-400 space-y-0.5">
                          {(ch.steps || []).map((st, sIdx) => (
                            <li key={sIdx}>{st}</li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {activeTab === "checklist" && (
                <div className="h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-auto divide-y divide-slate-800/70 text-xs">
                  {(!detail.checklist_items || detail.checklist_items.length === 0) && (
                    <div className="p-6 text-center text-slate-500">
                      Offensive skill methodology items activate automatically as target signals are detected.
                    </div>
                  )}
                  {(detail.checklist_items || []).map((it) => (
                    <div key={it.id} className="p-3 flex items-start justify-between gap-3">
                      <div className="space-y-0.5">
                        <div className="font-semibold text-cyan-300">
                          {it.skill_title}{" "}
                          <span className="text-[10px] text-slate-500 font-normal">({it.wstg_id})</span>
                        </div>
                        <div className="text-slate-200">{it.item_text}</div>
                        {it.evidence_note && <div className="text-[11px] text-emerald-300">{it.evidence_note}</div>}
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 ${
                          it.status === "finding"
                            ? "bg-amber-500/20 text-amber-300"
                            : it.status === "covered"
                            ? "bg-emerald-500/20 text-emerald-300"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {it.status}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === "endpoints" && (
                <div className="h-full flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 bg-slate-900">
                    <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                      Discovered Endpoints ({filteredEndpoints.length})
                    </span>
                    <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1">
                      <Search className="w-3.5 h-3.5 text-slate-500" />
                      <input
                        value={endpointSearch}
                        onChange={(e) => setEndpointSearch(e.target.value)}
                        placeholder="Search path or param..."
                        className="bg-transparent text-xs text-white focus:outline-none w-44"
                      />
                    </div>
                  </div>
                  <div className="flex-1 overflow-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="p-2.5">Method</th>
                          <th className="p-2.5">URL</th>
                          <th className="p-2.5">Params</th>
                          <th className="p-2.5">Source</th>
                          <th className="p-2.5">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70">
                        {filteredEndpoints.map((ep) => (
                          <tr key={ep.id} className="hover:bg-slate-800/40">
                            <td className="p-2.5 font-mono font-semibold text-indigo-300">{ep.method}</td>
                            <td className="p-2.5 font-mono text-slate-200 truncate max-w-[230px]" title={ep.url}>
                              {ep.url}
                            </td>
                            <td className="p-2.5 text-[11px] text-cyan-300 font-mono">
                              {[...ep.query_params, ...ep.body_params].join(", ") || "-"}
                            </td>
                            <td className="p-2.5 text-slate-400">{ep.source}</td>
                            <td className="p-2.5 flex items-center gap-2">
                              <button
                                onClick={() => setManualTarget(ep.url)}
                                className="flex items-center gap-1 text-[11px] text-emerald-400 hover:text-emerald-300 font-semibold"
                              >
                                <Send className="w-3 h-3" /> Tool
                              </button>
                              <button
                                onClick={() => {
                                  setRepeaterUrl(ep.url);
                                  setActiveTab("repeater");
                                }}
                                className="text-[11px] text-cyan-400 hover:text-cyan-300 font-semibold"
                              >
                                Repeat
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {activeTab === "findings" && (
                <FindingsPanel
                  engagementId={detail.id}
                  findings={detail.findings}
                  onRefresh={() => refreshDetail(detail.id)}
                  onSendToRepeater={(u) => {
                    setRepeaterUrl(u);
                    setActiveTab("repeater");
                  }}
                />
              )}

              {activeTab === "hypotheses" && (
                <div className="h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-auto divide-y divide-slate-800/70">
                  {(!detail.hypotheses || detail.hypotheses.length === 0) && (
                    <div className="p-6 text-center text-xs text-slate-500">
                      AI-generated hypotheses will appear here as the planner analyzes discovered endpoints.
                    </div>
                  )}
                  {(detail.hypotheses || []).map((h) => (
                    <div key={h.id} className="p-3.5 text-xs flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-slate-100">{h.title}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-cyan-300 uppercase">
                            {h.status} • {h.confidence}
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-slate-400">{h.target_url}</div>
                        <div className="text-slate-300">{h.rationale}</div>
                        {h.evidence_note && <div className="text-[11px] text-emerald-300">{h.evidence_note}</div>}
                      </div>
                      <select
                        value={h.status}
                        onChange={(e) =>
                          api
                            .updateHypothesis(h.id, { status: e.target.value })
                            .then(() => refreshDetail(detail.id))
                        }
                        className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-[11px] text-white"
                      >
                        <option value="proposed">proposed</option>
                        <option value="testing">testing</option>
                        <option value="confirmed">confirmed</option>
                        <option value="disproven">disproven</option>
                      </select>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === "repeater" && (
                <RepeaterPanel
                  engagementId={detail.id}
                  initialUrl={repeaterUrl}
                  onFindingCreated={() => refreshDetail(detail.id)}
                />
              )}

              {activeTab === "runs" && (
                <div className="h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="p-3">Tool</th>
                        <th className="p-3">Tier</th>
                        <th className="p-3">Target</th>
                        <th className="p-3">Status</th>
                        <th className="p-3">Duration</th>
                        <th className="p-3">Log</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {detail.tool_runs.map((r) => (
                        <tr key={r.id} className="hover:bg-slate-800/40">
                          <td className="p-3 font-mono text-cyan-300">{r.tool_name}</td>
                          <td className="p-3">Tier {r.tier}</td>
                          <td className="p-3 font-mono text-slate-300 truncate max-w-[220px]">{r.target}</td>
                          <td className="p-3 uppercase text-[11px] font-semibold">{r.status}</td>
                          <td className="p-3 text-slate-400">{r.duration_ms ? `${r.duration_ms}ms` : "-"}</td>
                          <td className="p-3">
                            <button
                              onClick={() => handleOpenRunLog(r)}
                              className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                            >
                              <FileText className="w-3.5 h-3.5" /> View
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {activeTab === "approvals" && (
                <div className="h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-auto divide-y divide-slate-800/70">
                  {detail.approvals.length === 0 && (
                    <div className="p-6 text-center text-xs text-slate-500">
                      No Tier 2/3 approval requests recorded yet.
                    </div>
                  )}
                  {detail.approvals.map((ap) => (
                    <div key={ap.id} className="p-3.5 text-xs flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-cyan-300">{ap.tool_name}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase">
                            Tier {ap.tier} • {ap.status}
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-slate-400">{ap.target}</div>
                        <div className="text-slate-300">{ap.rationale}</div>
                        {ap.operator_note && (
                          <div className="text-[11px] text-amber-300">Note: {ap.operator_note}</div>
                        )}
                      </div>
                      {ap.status === "pending" && (
                        <button
                          onClick={() => setActiveApproval(ap)}
                          className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-semibold shrink-0"
                        >
                          Review
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {activeTab === "diff" && (
                <div className="h-full flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden text-xs">
                  <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800 bg-slate-900">
                    <span className="font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                      <GitCompare className="w-4 h-4 text-cyan-400" /> Scan Snapshot Delta
                    </span>
                    <button
                      onClick={() =>
                        api
                          .createSnapshot(detail.id, `manual-${(detail.snapshots?.length || 0) + 1}`)
                          .then(() => refreshDetail(detail.id))
                      }
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold"
                    >
                      <Camera className="w-3.5 h-3.5" /> Capture Snapshot
                    </button>
                  </div>
                  <div className="flex-1 overflow-auto p-4 space-y-3">
                    {!scanDiff?.has_diff ? (
                      <div className="text-slate-500 text-center mt-8">
                        Need at least 2 scan snapshots to compute deltas (currently {scanDiff?.snapshots_count || 0}).
                      </div>
                    ) : (
                      <>
                        <div className="text-slate-300">
                          Comparing <strong>{scanDiff.baseline?.label}</strong> →{" "}
                          <strong>{scanDiff.current?.label}</strong>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                            <div className="text-lg font-bold text-cyan-300">+{scanDiff.new_assets?.length || 0}</div>
                            <div className="text-[11px] text-slate-400">New Assets</div>
                          </div>
                          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                            <div className="text-lg font-bold text-indigo-300">+{scanDiff.new_endpoints?.length || 0}</div>
                            <div className="text-[11px] text-slate-400">New Endpoints</div>
                          </div>
                          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                            <div className="text-lg font-bold text-amber-300">+{scanDiff.new_findings?.length || 0}</div>
                            <div className="text-[11px] text-slate-400">New Findings</div>
                          </div>
                          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                            <div className="text-lg font-bold text-emerald-300">-{scanDiff.resolved_findings?.length || 0}</div>
                            <div className="text-[11px] text-slate-400">Resolved</div>
                          </div>
                        </div>
                        {(scanDiff.new_findings?.length || 0) > 0 && (
                          <div>
                            <div className="text-slate-400 font-semibold mb-1">New Findings</div>
                            <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 text-amber-200 font-mono text-[11px] overflow-x-auto">
                              {scanDiff.new_findings?.join("\n")}
                            </pre>
                          </div>
                        )}
                        {(scanDiff.new_endpoints?.length || 0) > 0 && (
                          <div>
                            <div className="text-slate-400 font-semibold mb-1">New Endpoints</div>
                            <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 text-cyan-200 font-mono text-[11px] overflow-x-auto max-h-40">
                              {scanDiff.new_endpoints?.slice(0, 50).join("\n")}
                            </pre>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Right 5 Columns: Live Agent Stream + Manual Scoped Runner */}
          <div className="lg:col-span-5 flex flex-col gap-3 min-h-0">
            <div className="flex-1 flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden min-h-0">
              <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800 bg-slate-900">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" /> Live Agent & Tool Stream
                </span>
                <span className="text-[11px] text-slate-400">
                  Step {detail.current_step}/{detail.max_steps}
                </span>
              </div>

              <div className="flex-1 overflow-y-auto p-3 space-y-1.5 font-mono text-[11px] bg-[#070b14]">
                {events.length === 0 && (
                  <div className="text-slate-500 p-3">Waiting for agent stream events...</div>
                )}
                {events.map((ev, idx) => (
                  <div key={idx} className="leading-relaxed break-words">
                    <span className="text-slate-600 mr-1.5">[{ev.agent_name}]</span>
                    <span className={EVENT_COLORS[ev.event_type] || "text-slate-300"}>
                      {ev.message}
                    </span>
                  </div>
                ))}
                <div ref={logEndRef} />
              </div>

              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (!steerInput.trim() || !detail) return;
                  setSteerBusy(true);
                  try {
                    await api.steerEngagement(detail.id, steerInput.trim());
                    setSteerInput("");
                    await refreshDetail(detail.id);
                  } finally {
                    setSteerBusy(false);
                  }
                }}
                className="flex gap-2 p-2 border-t border-slate-800 bg-slate-900/90 text-xs"
              >
                <input
                  value={steerInput}
                  onChange={(e) => setSteerInput(e.target.value)}
                  placeholder="Steer AI Brain (e.g. 'Focus on GraphQL, JWT alg=none & checkout race')..."
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200"
                />
                <button
                  disabled={steerBusy}
                  type="submit"
                  className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-semibold"
                >
                  {steerBusy ? "..." : "Steer"}
                </button>
              </form>
            </div>

            {/* Scoped Quick Tool Runner */}
            <form
              onSubmit={handleManualRun}
              className="bg-slate-900/80 border border-slate-800 rounded-xl p-3 space-y-2 text-xs"
            >
              <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" /> Scoped Manual Tool Execution
              </div>
              <div className="flex gap-2">
                <select
                  value={manualTool}
                  onChange={(e) => setManualTool(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white font-mono"
                >
                  <option value="http_probe">http_probe (T1/2/3)</option>
                  <option value="js_miner">js_miner (T1)</option>
                  <option value="spa_inspector">spa_inspector (T1)</option>
                  <option value="trufflehog">trufflehog (T1)</option>
                  <option value="gitleaks">gitleaks (T1)</option>
                  <option value="subfinder">subfinder (T1)</option>
                  <option value="dnsx">dnsx (T1)</option>
                  <option value="paramspider">paramspider (T1)</option>
                  <option value="httpx">httpx (T1)</option>
                  <option value="whatweb">whatweb (T1)</option>
                  <option value="wafw00f">wafw00f (T1)</option>
                  <option value="sslscan">sslscan (T1)</option>
                  <option value="katana">katana (T1)</option>
                  <option value="naabu">naabu (T2)</option>
                  <option value="nmap">nmap (T2)</option>
                  <option value="ffuf">ffuf (T2)</option>
                  <option value="feroxbuster">feroxbuster (T2)</option>
                  <option value="arjun">arjun (T2)</option>
                  <option value="nikto">nikto (T2)</option>
                  <option value="wpscan">wpscan (T2)</option>
                  <option value="nuclei">nuclei (T2/3)</option>
                  <option value="zaproxy">zaproxy (T2/3)</option>
                  <option value="dalfox">dalfox (T3)</option>
                  <option value="sqlmap">sqlmap (T3)</option>
                </select>
                <input
                  value={manualTarget}
                  onChange={(e) => setManualTarget(e.target.value)}
                  placeholder="Target URL inside allowlist"
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-cyan-300"
                />
                <button
                  disabled={manualBusy}
                  type="submit"
                  className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold"
                >
                  {manualBusy ? "..." : "Run"}
                </button>
              </div>
              <input
                value={manualArgsJson}
                onChange={(e) => setManualArgsJson(e.target.value)}
                placeholder='Optional args JSON e.g. {"mode":"differential_bola"}'
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 font-mono text-[11px] text-slate-300"
              />
              {manualError && <div className="text-red-400 text-[11px]">{manualError}</div>}
            </form>
          </div>
        </div>
      )}

      {showWizard && (
        <ScopeWizardModal
          profiles={profiles}
          onCreated={async (id) => {
            await refreshList();
            setSelectedId(id);
          }}
          onClose={() => setShowWizard(false)}
        />
      )}

      {showSettings && (
        <SettingsModal
          profiles={profiles}
          onRefreshProfiles={refreshProfiles}
          onClose={() => setShowSettings(false)}
        />
      )}

      {activeApproval && (
        <ApprovalModal
          approval={activeApproval}
          onDecide={async (id, decision, modifiedArgs, note) => {
            await api.decideApproval(id, {
              decision,
              modified_args: modifiedArgs,
              operator_note: note,
            });
            if (detail) await refreshDetail(detail.id);
          }}
          onClose={() => setActiveApproval(null)}
        />
      )}

      {selectedRunLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
          <div className="w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[82vh]">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800">
              <div className="text-xs">
                <span className="font-mono font-bold text-cyan-300">{selectedRunLog.run.tool_name}</span>
                <span className="text-slate-400 ml-2">{selectedRunLog.run.target}</span>
              </div>
              <button onClick={() => setSelectedRunLog(null)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-4 space-y-3 overflow-y-auto text-xs flex-1">
              {selectedRunLog.run.argv?.length > 0 && (
                <div>
                  <div className="text-slate-400 font-semibold mb-1">Compiled Command (shell=False)</div>
                  <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 text-cyan-300 font-mono overflow-x-auto">
                    {selectedRunLog.run.argv.join(" ")}
                  </pre>
                </div>
              )}
              <div>
                <div className="text-slate-400 font-semibold mb-1">Raw Output Log</div>
                <pre className="bg-slate-950 border border-slate-800 rounded p-3 text-slate-200 font-mono whitespace-pre-wrap break-words max-h-96 overflow-y-auto">
                  {selectedRunLog.log}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
