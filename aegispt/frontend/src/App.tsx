import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  KeyRound,
  Pause,
  Play,
  Plus,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Square,
  Terminal,
} from "lucide-react";
import {
  AgentEventItem,
  ApprovalItem,
  Engagement,
  EngagementDetail,
  LLMProfileItem,
  api,
  createEngagementWebSocket,
  getStoredToken,
  setStoredToken,
} from "./api/client";
import { ApprovalModal } from "./components/ApprovalModal";
import { AttackGraph } from "./components/AttackGraph";
import { FindingsPanel } from "./components/FindingsPanel";
import { ScopeWizardModal } from "./components/ScopeWizardModal";
import { SettingsModal } from "./components/SettingsModal";

const EVENT_COLORS: Record<string, string> = {
  engagement_started: "text-emerald-400",
  agent_thought: "text-fuchsia-300",
  tool_started: "text-cyan-400",
  tool_completed: "text-emerald-300",
  tool_output: "text-slate-500",
  scope_blocked: "text-red-400",
  approval_required: "text-amber-300",
  approval_resolved: "text-sky-300",
  planner_fallback: "text-amber-400",
  engagement_finished: "text-emerald-400 font-bold",
  engagement_failed: "text-red-400 font-bold",
};

export default function App() {
  const [tokenInput, setTokenInput] = useState(getStoredToken());
  const [authenticated, setAuthenticated] = useState(Boolean(getStoredToken()));
  const [authError, setAuthError] = useState("");

  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [detail, setDetail] = useState<EngagementDetail | null>(null);
  const [events, setEvents] = useState<AgentEventItem[]>([]);
  const [profiles, setProfiles] = useState<LLMProfileItem[]>([]);

  const [showWizard, setShowWizard] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [activeApproval, setActiveApproval] = useState<ApprovalItem | null>(null);
  const [activeTab, setActiveTab] = useState<"graph" | "findings" | "runs">("graph");

  const [manualTool, setManualTool] = useState("http_probe");
  const [manualTarget, setManualTarget] = useState("");
  const [manualError, setManualError] = useState("");
  const [manualBusy, setManualBusy] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const logEndRef = useRef<HTMLDivElement | null>(null);

  const refreshList = useCallback(async () => {
    const res = await api.listEngagements();
    setEngagements(res.engagements);
    if (!selectedId && res.engagements.length > 0) {
      setSelectedId(res.engagements[0].id);
    }
  }, [selectedId]);

  const refreshDetail = useCallback(async (id: string) => {
    if (!id) return;
    const d = await api.getEngagement(id);
    setDetail(d);
    setEvents(d.events || []);
    const seed = d.scope?.allowed_urls?.[0] || (d.scope?.allowed_domains?.[0] ? `https://${d.scope.allowed_domains[0]}` : "");
    if (seed) setManualTarget((prev) => prev || seed);
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

  useEffect(() => {
    if (!authenticated || !selectedId) return;
    refreshDetail(selectedId).catch(() => {});

    if (wsRef.current) {
      wsRef.current.close();
    }
    const ws = createEngagementWebSocket(selectedId, (ev) => {
      setEvents((prev) => [...prev.slice(-240), ev]);
      if (
        ["tool_completed", "approval_required", "approval_resolved", "engagement_finished", "engagement_failed", "scope_blocked"].includes(
          ev.event_type
        )
      ) {
        refreshDetail(selectedId).catch(() => {});
      }
    });
    wsRef.current = ws;
    return () => ws.close();
  }, [authenticated, selectedId, refreshDetail]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length]);

  const pendingApprovals = useMemo(
    () => (detail?.approvals || []).filter((a) => a.status === "pending"),
    [detail]
  );

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");
    setStoredToken(tokenInput);
    try {
      await api.listEngagements();
      setAuthenticated(true);
    } catch {
      setAuthError("Token rejected by AegisPT server. Run `aegispt token` in terminal to get the local token.");
    }
  };

  const handleManualRun = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedId || !manualTarget) return;
    setManualError("");
    setManualBusy(true);
    try {
      await api.runManualTool(selectedId, {
        tool_name: manualTool,
        target: manualTarget,
        args: {},
      });
      await refreshDetail(selectedId);
    } catch (err) {
      setManualError(String(err));
    } finally {
      setManualBusy(false);
    }
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
            <code className="text-cyan-300">aegispt token</code>).
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
            onChange={(e) => setSelectedId(e.target.value)}
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
          {/* Left 7 Columns: Graph / Findings / Tool Runs */}
          <div className="lg:col-span-7 flex flex-col gap-2 min-h-0">
            <div className="flex items-center gap-2">
              {[
                { id: "graph", label: "Attack-Surface Graph" },
                { id: "findings", label: `Findings (${detail.findings.length})` },
                { id: "runs", label: `Tool Runs (${detail.tool_runs.length})` },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as typeof activeTab)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold ${
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
                />
              )}
              {activeTab === "findings" && (
                <FindingsPanel
                  engagementId={detail.id}
                  findings={detail.findings}
                  onRefresh={() => refreshDetail(detail.id)}
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
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {detail.tool_runs.map((r) => (
                        <tr key={r.id} className="hover:bg-slate-800/40">
                          <td className="p-3 font-mono text-cyan-300">{r.tool_name}</td>
                          <td className="p-3">Tier {r.tier}</td>
                          <td className="p-3 font-mono text-slate-300 truncate max-w-[240px]">{r.target}</td>
                          <td className="p-3 uppercase text-[11px] font-semibold">{r.status}</td>
                          <td className="p-3 text-slate-400">{r.duration_ms ? `${r.duration_ms}ms` : "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
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
                  <option value="http_probe">http_probe (T1)</option>
                  <option value="whatweb">whatweb (T1)</option>
                  <option value="wafw00f">wafw00f (T1)</option>
                  <option value="katana">katana (T1)</option>
                  <option value="ffuf">ffuf (T2)</option>
                  <option value="arjun">arjun (T2)</option>
                  <option value="nuclei">nuclei (T2)</option>
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
    </div>
  );
}
