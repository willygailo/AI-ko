import React, { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import {
  Camera,
  Check,
  Copy,
  FileText,
  GitCompare,
  KeyRound,
  LogOut,
  Pause,
  Play,
  Plus,
  Radio,
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
} from "lucide-react";
import {
  type ApprovalItem,
  type Engagement,
  type EngagementDetail,
  type HypothesisItem,
  type LLMProfileItem,
  type ScanDiffResponse,
  type ToolCatalogItem,
  type ToolRunItem,
  api,
  clearStoredToken,
  getStoredToken,
  setStoredToken,
  setUnauthorizedHandler,
} from "./api/client";
import { AgentStreamPanel } from "./components/AgentStreamPanel";
import { ApprovalModal } from "./components/ApprovalModal";
import { AttackGraph } from "./components/AttackGraph";
import { ConfirmDialog } from "./components/ConfirmDialog";
import { FindingsPanel } from "./components/FindingsPanel";
import { ModalFrame } from "./components/ModalFrame";
import { RepeaterPanel } from "./components/RepeaterPanel";
import { ScopeWizardModal } from "./components/ScopeWizardModal";
import { SettingsModal } from "./components/SettingsModal";
import { ToastBar, type ToastKind, type ToastMessage } from "./components/ToastBar";
import { copyTextToClipboard } from "./utils/clipboard";
import { filterEndpoints, pickAutoOpenApproval } from "./utils/events";
import { parseJsonObject } from "./utils/parsing";

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
  | "oob"
  | "diff";

const FALLBACK_TOOLS: ToolCatalogItem[] = [
  { name: "http_probe", tier: 1, description: "HTTP/API security probe", available: true, resolved_path: null },
  { name: "js_miner", tier: 1, description: "JavaScript endpoint & secret miner", available: true, resolved_path: null },
  { name: "spa_inspector", tier: 1, description: "SPA DOM & route inspector", available: true, resolved_path: null },
  { name: "httpx", tier: 1, description: "Fast HTTP prober", available: true, resolved_path: null },
  { name: "katana", tier: 1, description: "Web crawler", available: true, resolved_path: null },
  { name: "nuclei", tier: 2, description: "Template vulnerability scanner", available: true, resolved_path: null },
];

export default function App() {
  const tokenInputId = useId();
  const [tokenInput, setTokenInput] = useState(getStoredToken());
  const [authenticated, setAuthenticated] = useState(Boolean(getStoredToken()));
  const [authError, setAuthError] = useState("");
  const [loginBusy, setLoginBusy] = useState(false);

  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [detail, setDetail] = useState<EngagementDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [profiles, setProfiles] = useState<LLMProfileItem[]>([]);
  const [toolsCatalog, setToolsCatalog] = useState<ToolCatalogItem[]>([]);
  const [wsConnected, setWsConnected] = useState(false);

  const [showWizard, setShowWizard] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [confirmDeleteOpen, setConfirmDeleteOpen] = useState(false);
  const [activeApproval, setActiveApproval] = useState<ApprovalItem | null>(null);
  const [dismissedApprovalIds, setDismissedApprovalIds] = useState<Set<string>>(() => new Set());
  const [activeTab, setActiveTab] = useState<WorkspaceTab>("graph");

  const [endpointSearch, setEndpointSearch] = useState("");
  const [selectedRunLog, setSelectedRunLog] = useState<{ run: ToolRunItem; log: string } | null>(null);
  const [copiedField, setCopiedField] = useState<string>("");
  const [repeaterUrl, setRepeaterUrl] = useState("");

  const [scanDiff, setScanDiff] = useState<ScanDiffResponse | null>(null);
  const [diffBaseId, setDiffBaseId] = useState("");
  const [diffTargetId, setDiffTargetId] = useState("");

  const [manualTool, setManualTool] = useState("http_probe");
  const [manualTarget, setManualTarget] = useState("");
  const [manualArgsJson, setManualArgsJson] = useState("");
  const [manualError, setManualError] = useState("");
  const [manualBusy, setManualBusy] = useState(false);

  const [busyAction, setBusyAction] = useState<string>("");
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const detailAbortRef = useRef<AbortController | null>(null);
  const detailSeqRef = useRef(0);

  const pushToast = useCallback((kind: ToastKind, text: string) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    setToasts((prev) => [...prev.slice(-3), { id, kind, text }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 5000);
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const resetSessionState = useCallback((reason?: string) => {
    detailAbortRef.current?.abort();
    setAuthenticated(false);
    setEngagements([]);
    setSelectedId("");
    setDetail(null);
    setProfiles([]);
    setToolsCatalog([]);
    setWsConnected(false);
    setActiveApproval(null);
    setDismissedApprovalIds(new Set());
    setSelectedRunLog(null);
    setConfirmDeleteOpen(false);
    setShowWizard(false);
    setShowSettings(false);
    setAuthError(reason || "");
  }, []);

  useEffect(() => {
    setUnauthorizedHandler((reason) => {
      resetSessionState(reason || "Session expired or invalid API token. Please sign in again.");
    });
    return () => setUnauthorizedHandler(null);
  }, [resetSessionState]);

  const handleSignOut = () => {
    clearStoredToken();
    setTokenInput("");
    resetSessionState("");
  };

  const refreshList = useCallback(async () => {
    const res = await api.listEngagements();
    setEngagements(res.engagements);
    if (res.engagements.length === 0) {
      setSelectedId("");
      setDetail(null);
      return;
    }
    setSelectedId((prev) => {
      if (prev && res.engagements.some((e) => e.id === prev)) {
        return prev;
      }
      return res.engagements[0].id;
    });
  }, []);

  const refreshProfiles = useCallback(async () => {
    const res = await api.listLLMProfiles();
    setProfiles(res.profiles);
  }, []);

  const refreshTools = useCallback(async () => {
    try {
      const res = await api.listTools();
      setToolsCatalog(res.tools || []);
    } catch {
      // Non-fatal; fallback list remains available
    }
  }, []);

  const refreshDetail = useCallback(
    async (id: string, opts?: { showLoader?: boolean }) => {
      if (!id) return;
      detailAbortRef.current?.abort();
      const controller = new AbortController();
      detailAbortRef.current = controller;
      const reqSeq = ++detailSeqRef.current;

      if (opts?.showLoader) {
        setLoadingDetail(true);
      }

      try {
        const d = await api.getEngagement(id, controller.signal);
        if (controller.signal.aborted || reqSeq !== detailSeqRef.current) return;
        setDetail(d);
        // Keep header engagement selector status synchronized with live detail status
        setEngagements((prev) =>
          prev.map((eng) =>
            eng.id === d.id
              ? { ...eng, status: d.status, name: d.name, current_step: d.current_step }
              : eng
          )
        );
        const seed =
          d.scope?.allowed_urls?.[0] ||
          (d.scope?.allowed_domains?.[0] ? `https://${d.scope.allowed_domains[0]}` : "");
        if (seed) {
          setManualTarget((prev) => prev || seed);
          setRepeaterUrl((prev) => prev || seed);
        }
      } catch (err) {
        if (controller.signal.aborted) return;
        pushToast("error", err instanceof Error ? err.message : String(err));
      } finally {
        if (reqSeq === detailSeqRef.current) {
          setLoadingDetail(false);
        }
      }
    },
    [pushToast]
  );

  // Initial load once authenticated (stable deps: never re-runs on engagement switch)
  useEffect(() => {
    if (!authenticated) return;
    Promise.all([refreshList(), refreshProfiles(), refreshTools()]).catch((err) => {
      pushToast("error", err instanceof Error ? err.message : String(err));
    });
  }, [authenticated, refreshList, refreshProfiles, refreshTools, pushToast]);

  // Fetch engagement detail on selectedId change and reset engagement-scoped UI state
  useEffect(() => {
    if (!authenticated || !selectedId) return;
    setActiveApproval(null);
    setDismissedApprovalIds(new Set());
    setScanDiff(null);
    setDiffBaseId("");
    setDiffTargetId("");
    void refreshDetail(selectedId, { showLoader: true });

    return () => {
      detailAbortRef.current?.abort();
    };
  }, [authenticated, selectedId, refreshDetail]);

  // Load snapshot diff whenever diff tab is active or base/target changes
  useEffect(() => {
    if (activeTab !== "diff" || !selectedId) return;
    api
      .getScanDiff(selectedId, diffBaseId || undefined, diffTargetId || undefined)
      .then(setScanDiff)
      .catch((err) => {
        pushToast("error", err instanceof Error ? err.message : String(err));
      });
  }, [activeTab, selectedId, detail?.snapshots?.length, diffBaseId, diffTargetId, pushToast]);

  const pendingApprovals = useMemo(
    () => (detail?.approvals || []).filter((a) => a.status === "pending"),
    [detail?.approvals]
  );

  // Auto-open ApprovalModal at most once per pending approval ID (fixes dismiss trap)
  useEffect(() => {
    if (activeApproval) return;
    const next = pickAutoOpenApproval(pendingApprovals, dismissedApprovalIds);
    if (next) {
      setActiveApproval(next);
    }
  }, [pendingApprovals, activeApproval, dismissedApprovalIds]);

  const filteredEndpoints = useMemo(
    () => filterEndpoints(detail?.endpoints || [], endpointSearch),
    [detail?.endpoints, endpointSearch]
  );

  const availableTools = toolsCatalog.length > 0 ? toolsCatalog : FALLBACK_TOOLS;

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");
    setLoginBusy(true);
    setStoredToken(tokenInput);
    try {
      await api.listEngagements({ skipUnauthorizedHandler: true });
      setAuthenticated(true);
    } catch {
      clearStoredToken();
      setAuthError(
        "Token rejected by AegisPT server. Run `./aegispt token` in terminal to get the local token."
      );
    } finally {
      setLoginBusy(false);
    }
  };

  const runAction = async (
    actionKey: string,
    fn: () => Promise<void>,
    successMsg?: string
  ) => {
    setBusyAction(actionKey);
    try {
      await fn();
      if (successMsg) pushToast("success", successMsg);
    } catch (err) {
      pushToast("error", err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction("");
    }
  };

  const handleManualRun = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedId || !manualTarget.trim()) return;
    setManualError("");
    const parsed = parseJsonObject(manualArgsJson, "optional args");
    if (!parsed.ok) {
      setManualError(parsed.error);
      return;
    }
    setManualBusy(true);
    try {
      await api.runManualTool(selectedId, {
        tool_name: manualTool,
        target: manualTarget.trim(),
        args: parsed.value,
      });
      pushToast("success", `Executed ${manualTool} against ${manualTarget.trim()}.`);
      await refreshDetail(selectedId);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setManualError(msg);
      pushToast("error", msg);
      await refreshDetail(selectedId);
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
      const msg = err instanceof Error ? err.message : String(err);
      setSelectedRunLog({ run, log: `Failed to load log: ${msg}` });
      pushToast("error", msg);
    }
  };

  const handleConfirmDeleteEngagement = async () => {
    if (!detail) return;
    await runAction(
      "delete",
      async () => {
        await api.deleteEngagement(detail.id);
        setConfirmDeleteOpen(false);
        await refreshList();
      },
      `Deleted engagement "${detail.name}".`
    );
  };

  const handleCopyText = async (key: string, text: string) => {
    const ok = await copyTextToClipboard(text);
    if (ok) {
      setCopiedField(key);
      window.setTimeout(() => setCopiedField(""), 1500);
    } else {
      pushToast("error", "Clipboard copy failed.");
    }
  };

  const handleLiveStateChange = useCallback(() => {
    if (selectedId) {
      void refreshDetail(selectedId);
    }
  }, [selectedId, refreshDetail]);

  const handleRefreshCurrentDetail = useCallback(async () => {
    if (selectedId) {
      await refreshDetail(selectedId);
    }
  }, [selectedId, refreshDetail]);

  const handlePivotTarget = useCallback((url: string) => {
    setManualTarget(url);
  }, []);

  const handleSendToRepeater = useCallback((url: string) => {
    setRepeaterUrl(url);
    setActiveTab("repeater");
  }, []);

  if (!authenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 p-6">
        <form
          onSubmit={(e) => void handleLogin(e)}
          className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-2xl"
        >
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/15 border border-cyan-500/30">
              <ShieldCheck className="w-6 h-6 text-cyan-400" aria-hidden="true" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white">AegisPT</h1>
              <p className="text-xs text-slate-400">Private AI Web & API Pentesting Platform</p>
            </div>
          </div>

          <div className="text-xs text-slate-300 bg-slate-950 border border-slate-800 rounded-lg p-3">
            Enter your local API token (retrieved via{" "}
            <code className="text-cyan-300">./aegispt token</code>).
          </div>

          <div>
            <label htmlFor={tokenInputId} className="block text-xs font-medium text-slate-300 mb-1">
              Local API Token
            </label>
            <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg px-3 focus-within:ring-2 focus-within:ring-cyan-500">
              <KeyRound className="w-4 h-4 text-slate-500 shrink-0" aria-hidden="true" />
              <input
                id={tokenInputId}
                type="password"
                required
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder="aegis_..."
                className="w-full bg-transparent py-2.5 text-sm text-white focus:outline-none focus:ring-0 font-mono"
              />
            </div>
          </div>

          {authError && (
            <div role="alert" className="text-xs text-red-400">
              {authError}
            </div>
          )}

          <button
            type="submit"
            disabled={loginBusy}
            className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-400"
          >
            {loginBusy ? "Connecting..." : "Connect to Local Engine"}
          </button>
        </form>
      </div>
    );
  }

  const tabs: { id: WorkspaceTab; label: string }[] = detail
    ? [
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
        { id: "oob", label: `OOB (${detail.oob_events?.length || 0})` },
        { id: "diff", label: `Diff (${detail.snapshots?.length || 0})` },
      ]
    : [];

  return (
    <div className="min-h-screen lg:h-screen lg:overflow-hidden flex flex-col bg-slate-950 text-slate-100">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 bg-slate-900 border-b border-slate-800">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" aria-hidden="true" />
            <span className="font-bold text-sm tracking-wide">AegisPT</span>
          </div>

          <select
            aria-label="Select engagement"
            value={selectedId}
            onChange={(e) => {
              setSelectedId(e.target.value);
              setManualTarget("");
              setRepeaterUrl("");
            }}
            className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white min-w-[220px] focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            {engagements.length === 0 && <option value="">No engagements yet</option>}
            {engagements.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name} ({e.id === detail?.id ? detail.status : e.status})
              </option>
            ))}
          </select>

          {detail && (
            <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-cyan-300 uppercase font-semibold">
              {detail.status} • {detail.autonomy_mode}
            </span>
          )}

          {loadingDetail && (
            <span className="text-[11px] text-slate-400 animate-pulse">Loading...</span>
          )}

          {selectedId && (
            <span
              className={`flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full border ${
                wsConnected
                  ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-300"
                  : "bg-amber-500/10 border-amber-500/40 text-amber-300"
              }`}
            >
              {wsConnected ? (
                <Wifi className="w-3 h-3" aria-hidden="true" />
              ) : (
                <WifiOff className="w-3 h-3" aria-hidden="true" />
              )}
              {wsConnected ? "Live" : "Reconnecting"}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {detail && (
            <>
              {detail.status === "paused" ? (
                <button
                  type="button"
                  disabled={busyAction !== ""}
                  onClick={() =>
                    void runAction(
                      "resume",
                      async () => {
                        await api.resumeEngagement(detail.id);
                        await refreshDetail(detail.id);
                      },
                      "Engagement resumed."
                    )
                  }
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-emerald-400"
                >
                  <Play className="w-3.5 h-3.5" aria-hidden="true" />{" "}
                  {busyAction === "resume" ? "..." : "Resume"}
                </button>
              ) : (
                <button
                  type="button"
                  disabled={detail.status === "running" || busyAction !== ""}
                  onClick={() =>
                    void runAction(
                      "start",
                      async () => {
                        await api.startEngagement(detail.id);
                        await refreshDetail(detail.id);
                      },
                      "Engagement started."
                    )
                  }
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-emerald-400"
                >
                  <Play className="w-3.5 h-3.5" aria-hidden="true" />{" "}
                  {busyAction === "start" ? "..." : "Start Auto"}
                </button>
              )}
              <button
                type="button"
                disabled={
                  busyAction !== "" ||
                  (detail.status !== "running" && detail.status !== "awaiting_approval")
                }
                onClick={() =>
                  void runAction(
                    "pause",
                    async () => {
                      await api.pauseEngagement(detail.id);
                      await refreshDetail(detail.id);
                    },
                    "Engagement paused."
                  )
                }
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-xs focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                <Pause className="w-3.5 h-3.5" aria-hidden="true" />{" "}
                {busyAction === "pause" ? "..." : "Pause"}
              </button>
              <button
                type="button"
                disabled={
                  busyAction !== "" ||
                  detail.status === "stopped" ||
                  detail.status === "completed" ||
                  detail.status === "created"
                }
                onClick={() =>
                  void runAction(
                    "stop",
                    async () => {
                      await api.stopEngagement(detail.id);
                      await refreshDetail(detail.id);
                    },
                    "Engagement stopped."
                  )
                }
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-red-950/70 hover:bg-red-900 disabled:opacity-50 border border-red-800/60 text-red-200 text-xs focus:outline-none focus:ring-2 focus:ring-red-400"
              >
                <Square className="w-3.5 h-3.5" aria-hidden="true" />{" "}
                {busyAction === "stop" ? "..." : "Stop"}
              </button>
              <button
                type="button"
                disabled={busyAction !== ""}
                onClick={() => setConfirmDeleteOpen(true)}
                aria-label="Delete engagement"
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-red-950 disabled:opacity-50 text-slate-400 hover:text-red-300 focus:outline-none focus:ring-2 focus:ring-red-400"
                title="Delete engagement"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </>
          )}

          {pendingApprovals.length > 0 && (
            <button
              type="button"
              onClick={() => {
                const target = pendingApprovals[0];
                setDismissedApprovalIds((prev) => {
                  const next = new Set(prev);
                  next.delete(target.id);
                  return next;
                });
                setActiveApproval(target);
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/20 border border-amber-500 text-amber-200 text-xs font-bold animate-pulse focus:outline-none focus:ring-2 focus:ring-amber-400"
            >
              <ShieldAlert className="w-4 h-4" aria-hidden="true" /> {pendingApprovals.length} Approval Pending
            </button>
          )}

          <button
            type="button"
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-400"
          >
            <Plus className="w-3.5 h-3.5" aria-hidden="true" /> New
          </button>
          <button
            type="button"
            onClick={() => setShowSettings(true)}
            aria-label="LLM and Kali Tool Settings"
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            title="LLM & Kali Tool Settings"
          >
            <Settings className="w-4 h-4" />
          </button>
          <button
            type="button"
            onClick={handleSignOut}
            aria-label="Sign out"
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs focus:outline-none focus:ring-2 focus:ring-cyan-500"
            title="Sign out / Change API token"
          >
            <LogOut className="w-3.5 h-3.5" aria-hidden="true" />
            <span className="hidden sm:inline">Sign Out</span>
          </button>
        </div>
      </header>

      {/* Main Workspace */}
      {!detail ? (
        <div className="flex-1 flex flex-col items-center justify-center text-slate-400 space-y-3 p-6">
          <ShieldCheck className="w-12 h-12 text-slate-700" aria-hidden="true" />
          <p className="text-sm text-center">
            {loadingDetail
              ? "Loading engagement workspace..."
              : "Create a scoped engagement to begin an automated AI assessment."}
          </p>
          {!loadingDetail && (
            <button
              type="button"
              onClick={() => setShowWizard(true)}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-400"
            >
              + Create First Engagement
            </button>
          )}
        </div>
      ) : (
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-3 p-3 min-h-0">
          {/* Left 7 Columns */}
          <div className="lg:col-span-7 flex flex-col gap-2 min-h-0">
            <div role="tablist" aria-label="Engagement workspace views" className="flex flex-wrap items-center gap-1.5">
              {tabs.map((tab) => (
                <button
                  type="button"
                  key={tab.id}
                  role="tab"
                  id={`tab-${tab.id}`}
                  aria-selected={activeTab === tab.id}
                  aria-controls={`tabpanel-${tab.id}`}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-2.5 py-1.5 rounded-lg text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-500 ${
                    activeTab === tab.id
                      ? "bg-cyan-600 text-white"
                      : "bg-slate-900 border border-slate-800 text-slate-400 hover:text-white"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div
              role="tabpanel"
              id={`tabpanel-${activeTab}`}
              aria-labelledby={`tab-${activeTab}`}
              className="flex-1 min-h-0"
            >
              {activeTab === "graph" && (
                <AttackGraph
                  key={detail.id}
                  engagementName={detail.name}
                  assets={detail.assets}
                  endpoints={detail.endpoints}
                  findings={detail.findings}
                  onPivotTarget={handlePivotTarget}
                />
              )}

              {activeTab === "chains" && (
                <div className="h-full flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden text-xs min-h-[360px]">
                  <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800 bg-slate-900">
                    <span className="font-semibold uppercase tracking-wider text-slate-300">
                      Synthesized Attack Chains ({detail.attack_chains?.length || 0})
                    </span>
                    <button
                      type="button"
                      disabled={busyAction !== ""}
                      onClick={() =>
                        void runAction(
                          "chains",
                          async () => {
                            const res = await api.synthesizeChains(detail.id);
                            await refreshDetail(detail.id);
                            pushToast("info", `Synthesized ${res.synthesized} attack chain(s).`);
                          }
                        )
                      }
                      className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-400"
                    >
                      {busyAction === "chains" ? "Synthesizing..." : "Synthesize Chains"}
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
                <div className="h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-auto divide-y divide-slate-800/70 text-xs min-h-[360px]">
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
                <div className="h-full flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden min-h-[360px]">
                  <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 border-b border-slate-800 bg-slate-900">
                    <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                      Discovered Endpoints ({filteredEndpoints.length})
                    </span>
                    <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1">
                      <Search className="w-3.5 h-3.5 text-slate-500" aria-hidden="true" />
                      <input
                        aria-label="Search endpoints by URL, method, query param, or body param"
                        value={endpointSearch}
                        onChange={(e) => setEndpointSearch(e.target.value)}
                        placeholder="Search path, query or body param..."
                        className="bg-transparent text-xs text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 rounded px-0.5 w-48"
                      />
                    </div>
                  </div>
                  <div className="flex-1 overflow-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="sticky top-0 z-10 bg-slate-900 text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="p-2.5">Method</th>
                          <th className="p-2.5">URL</th>
                          <th className="p-2.5">Params</th>
                          <th className="p-2.5">Source</th>
                          <th className="p-2.5">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70">
                        {filteredEndpoints.length === 0 && (
                          <tr>
                            <td colSpan={5} className="p-6 text-center text-slate-500">
                              No discovered endpoints match the current filter.
                            </td>
                          </tr>
                        )}
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
                                type="button"
                                onClick={() => setManualTarget(ep.url)}
                                className="flex items-center gap-1 rounded px-1 text-[11px] text-emerald-400 hover:text-emerald-300 font-semibold focus:outline-none focus:ring-2 focus:ring-emerald-500"
                              >
                                <Send className="w-3 h-3" aria-hidden="true" /> Tool
                              </button>
                              <button
                                type="button"
                                onClick={() => handleSendToRepeater(ep.url)}
                                className="rounded px-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-500"
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
                  key={detail.id}
                  engagementId={detail.id}
                  findings={detail.findings}
                  onRefresh={handleRefreshCurrentDetail}
                  onSendToRepeater={handleSendToRepeater}
                  onToast={pushToast}
                />
              )}

              {activeTab === "hypotheses" && (
                <div className="h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-auto divide-y divide-slate-800/70 min-h-[360px]">
                  {(!detail.hypotheses || detail.hypotheses.length === 0) && (
                    <div className="p-6 text-center text-xs text-slate-500">
                      AI-generated hypotheses will appear here as the planner analyzes discovered endpoints.
                    </div>
                  )}
                  {(detail.hypotheses || []).map((h) => (
                    <div key={h.id} className="p-3.5 text-xs flex items-start justify-between gap-3">
                      <div className="space-y-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-bold text-slate-100">{h.title}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-cyan-300 uppercase">
                            {h.status} • {h.confidence}
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-slate-400 break-all">{h.target_url}</div>
                        <div className="text-slate-300">{h.rationale}</div>
                        {h.evidence_note && <div className="text-[11px] text-emerald-300">{h.evidence_note}</div>}
                      </div>
                      <select
                        aria-label={`Status for hypothesis ${h.title}`}
                        disabled={busyAction === `hyp-${h.id}`}
                        value={h.status}
                        onChange={(e) => {
                          const nextStatus = e.target.value as HypothesisItem["status"];
                          void runAction(
                            `hyp-${h.id}`,
                            async () => {
                              await api.updateHypothesis(h.id, { status: nextStatus });
                              await refreshDetail(detail.id);
                            },
                            `Hypothesis status updated to ${nextStatus}.`
                          );
                        }}
                        className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-[11px] text-white shrink-0 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                      >
                        <option value="proposed">proposed</option>
                        <option value="testing">testing</option>
                        <option value="awaiting_approval">awaiting_approval</option>
                        <option value="confirmed">confirmed</option>
                        <option value="disproven">disproven</option>
                      </select>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === "repeater" && (
                <RepeaterPanel
                  key={detail.id}
                  engagementId={detail.id}
                  initialUrl={repeaterUrl}
                  onFindingCreated={handleRefreshCurrentDetail}
                  onToast={pushToast}
                />
              )}

              {activeTab === "runs" && (
                <div className="h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-auto min-h-[360px]">
                  <table className="w-full text-left text-xs">
                    <thead className="sticky top-0 z-10 bg-slate-900 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="p-3">Tool</th>
                        <th className="p-3">Tier</th>
                        <th className="p-3">Target</th>
                        <th className="p-3">Status / Exit</th>
                        <th className="p-3">Duration</th>
                        <th className="p-3">Log</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {detail.tool_runs.length === 0 && (
                        <tr>
                          <td colSpan={6} className="p-6 text-center text-slate-500">
                            No tool runs recorded yet.
                          </td>
                        </tr>
                      )}
                      {detail.tool_runs.map((r) => (
                        <tr key={r.id} className="hover:bg-slate-800/40 align-top">
                          <td className="p-3 font-mono text-cyan-300">{r.tool_name}</td>
                          <td className="p-3">Tier {r.tier}</td>
                          <td className="p-3 font-mono text-slate-300 truncate max-w-[200px]" title={r.target}>
                            {r.target}
                          </td>
                          <td className="p-3">
                            <div className="flex items-center gap-1.5">
                              <span
                                className={`uppercase text-[11px] font-semibold ${
                                  r.status === "failed"
                                    ? "text-red-400"
                                    : r.status === "completed"
                                    ? "text-emerald-300"
                                    : "text-slate-200"
                                }`}
                              >
                                {r.status}
                              </span>
                              {r.exit_code !== null && (
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                                  exit {r.exit_code}
                                </span>
                              )}
                            </div>
                            {r.error_message && (
                              <div className="text-[11px] text-red-300 mt-1 break-words max-w-[240px]">
                                {r.error_message}
                              </div>
                            )}
                          </td>
                          <td className="p-3 text-slate-400">{r.duration_ms ? `${r.duration_ms}ms` : "-"}</td>
                          <td className="p-3">
                            <button
                              type="button"
                              onClick={() => void handleOpenRunLog(r)}
                              className="flex items-center gap-1 rounded px-1 text-[11px] text-cyan-400 hover:text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                            >
                              <FileText className="w-3.5 h-3.5" aria-hidden="true" /> View
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {activeTab === "approvals" && (
                <div className="h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-auto divide-y divide-slate-800/70 min-h-[360px]">
                  {detail.approvals.length === 0 && (
                    <div className="p-6 text-center text-xs text-slate-500">
                      No Tier 2/3 approval requests recorded yet.
                    </div>
                  )}
                  {detail.approvals.map((ap) => (
                    <div key={ap.id} className="p-3.5 text-xs flex items-start justify-between gap-3">
                      <div className="space-y-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono font-bold text-cyan-300">{ap.tool_name}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase">
                            Tier {ap.tier} • {ap.status}
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-slate-400 break-all">{ap.target}</div>
                        <div className="text-slate-300">{ap.rationale}</div>
                        {ap.operator_note && (
                          <div className="text-[11px] text-amber-300">Note: {ap.operator_note}</div>
                        )}
                      </div>
                      {ap.status === "pending" && (
                        <button
                          type="button"
                          onClick={() => {
                            setDismissedApprovalIds((prev) => {
                              const next = new Set(prev);
                              next.delete(ap.id);
                              return next;
                            });
                            setActiveApproval(ap);
                          }}
                          className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-semibold shrink-0 focus:outline-none focus:ring-2 focus:ring-amber-400"
                        >
                          Review
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {activeTab === "oob" && (
                <div className="h-full flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden text-xs min-h-[360px]">
                  <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800 bg-slate-900">
                    <span className="font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                      <Radio className="w-4 h-4 text-rose-400" aria-hidden="true" /> Out-of-Band (OOB) Callbacks (
                      {detail.oob_events?.length || 0})
                    </span>
                  </div>
                  <div className="flex-1 overflow-auto">
                    {(!detail.oob_events || detail.oob_events.length === 0) ? (
                      <div className="p-6 text-center text-slate-500">
                        No out-of-band SSRF/blind callback hits received for this engagement yet.
                      </div>
                    ) : (
                      <table className="w-full text-left text-xs">
                        <thead className="sticky top-0 z-10 bg-slate-900 text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="p-2.5">Method</th>
                            <th className="p-2.5">Path</th>
                            <th className="p-2.5">Source IP</th>
                            <th className="p-2.5">Token</th>
                            <th className="p-2.5">Received</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/70">
                          {detail.oob_events.map((oob) => (
                            <tr key={oob.id} className="hover:bg-slate-800/40">
                              <td className="p-2.5 font-mono font-semibold text-rose-300">{oob.method}</td>
                              <td className="p-2.5 font-mono text-slate-200 break-all">{oob.path}</td>
                              <td className="p-2.5 font-mono text-slate-300">{oob.source_ip}</td>
                              <td className="p-2.5">
                                <div className="flex items-center gap-1.5">
                                  <code className="text-cyan-300">{oob.token}</code>
                                  <button
                                    type="button"
                                    aria-label={`Copy OOB token ${oob.token}`}
                                    onClick={() => void handleCopyText(`oob-${oob.id}`, oob.token)}
                                    className="p-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                                  >
                                    {copiedField === `oob-${oob.id}` ? (
                                      <Check className="w-3 h-3 text-emerald-400" />
                                    ) : (
                                      <Copy className="w-3 h-3" />
                                    )}
                                  </button>
                                </div>
                              </td>
                              <td className="p-2.5 text-slate-400 font-mono text-[11px]">
                                {oob.created_at ? new Date(oob.created_at).toLocaleString() : "-"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              )}

              {activeTab === "diff" && (
                <div className="h-full flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden text-xs min-h-[360px]">
                  <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 border-b border-slate-800 bg-slate-900">
                    <span className="font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                      <GitCompare className="w-4 h-4 text-cyan-400" aria-hidden="true" /> Scan Snapshot Delta
                    </span>
                    <div className="flex flex-wrap items-center gap-2">
                      {(detail.snapshots?.length || 0) >= 2 && (
                        <>
                          <select
                            aria-label="Baseline snapshot"
                            value={diffBaseId}
                            onChange={(e) => setDiffBaseId(e.target.value)}
                            className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-[11px] text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                          >
                            <option value="">Baseline (oldest)</option>
                            {detail.snapshots.map((s) => (
                              <option key={s.id} value={s.id}>
                                {s.label} ({s.findings_count}F)
                              </option>
                            ))}
                          </select>
                          <span className="text-slate-500">→</span>
                          <select
                            aria-label="Target snapshot"
                            value={diffTargetId}
                            onChange={(e) => setDiffTargetId(e.target.value)}
                            className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-[11px] text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                          >
                            <option value="">Target (latest)</option>
                            {detail.snapshots.map((s) => (
                              <option key={s.id} value={s.id}>
                                {s.label} ({s.findings_count}F)
                              </option>
                            ))}
                          </select>
                        </>
                      )}
                      <button
                        type="button"
                        disabled={busyAction !== ""}
                        onClick={() =>
                          void runAction(
                            "snapshot",
                            async () => {
                              await api.createSnapshot(
                                detail.id,
                                `manual-${(detail.snapshots?.length || 0) + 1}`
                              );
                              await refreshDetail(detail.id);
                            },
                            "Captured scan snapshot."
                          )
                        }
                        className="flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-400"
                      >
                        <Camera className="w-3.5 h-3.5" aria-hidden="true" />{" "}
                        {busyAction === "snapshot" ? "Saving..." : "Capture Snapshot"}
                      </button>
                    </div>
                  </div>
                  <div className="flex-1 overflow-auto p-4 space-y-3">
                    {!scanDiff?.has_diff ? (
                      <div className="text-slate-500 text-center mt-8">
                        Need at least 2 scan snapshots to compute deltas (currently{" "}
                        {scanDiff?.snapshots_count ?? detail.snapshots?.length ?? 0}).
                      </div>
                    ) : (
                      <>
                        <div className="text-slate-300">
                          Comparing <strong>{scanDiff.baseline?.label}</strong> →{" "}
                          <strong>{scanDiff.current?.label}</strong>
                        </div>
                        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2">
                          <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                            <div className="text-base font-bold text-cyan-300">+{scanDiff.new_assets?.length || 0}</div>
                            <div className="text-[11px] text-slate-400">New Assets</div>
                          </div>
                          <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                            <div className="text-base font-bold text-slate-300">-{scanDiff.removed_assets?.length || 0}</div>
                            <div className="text-[11px] text-slate-400">Removed Assets</div>
                          </div>
                          <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                            <div className="text-base font-bold text-indigo-300">+{scanDiff.new_endpoints?.length || 0}</div>
                            <div className="text-[11px] text-slate-400">New Endpoints</div>
                          </div>
                          <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                            <div className="text-base font-bold text-fuchsia-300">+{scanDiff.new_open_ports?.length || 0}</div>
                            <div className="text-[11px] text-slate-400">New Ports</div>
                          </div>
                          <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                            <div className="text-base font-bold text-amber-300">+{scanDiff.new_findings?.length || 0}</div>
                            <div className="text-[11px] text-slate-400">New Findings</div>
                          </div>
                          <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                            <div className="text-base font-bold text-emerald-300">-{scanDiff.resolved_findings?.length || 0}</div>
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
                        {(scanDiff.resolved_findings?.length || 0) > 0 && (
                          <div>
                            <div className="text-slate-400 font-semibold mb-1">Resolved Findings</div>
                            <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 text-emerald-200 font-mono text-[11px] overflow-x-auto">
                              {scanDiff.resolved_findings?.join("\n")}
                            </pre>
                          </div>
                        )}
                        {(scanDiff.new_assets?.length || 0) > 0 && (
                          <div>
                            <div className="text-slate-400 font-semibold mb-1">New Assets</div>
                            <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 text-cyan-200 font-mono text-[11px] overflow-x-auto max-h-36">
                              {scanDiff.new_assets?.join("\n")}
                            </pre>
                          </div>
                        )}
                        {(scanDiff.removed_assets?.length || 0) > 0 && (
                          <div>
                            <div className="text-slate-400 font-semibold mb-1">Removed Assets</div>
                            <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 text-slate-300 font-mono text-[11px] overflow-x-auto max-h-36">
                              {scanDiff.removed_assets?.join("\n")}
                            </pre>
                          </div>
                        )}
                        {(scanDiff.new_open_ports?.length || 0) > 0 && (
                          <div>
                            <div className="text-slate-400 font-semibold mb-1">New Open Ports</div>
                            <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 text-fuchsia-200 font-mono text-[11px] overflow-x-auto max-h-36">
                              {scanDiff.new_open_ports?.join("\n")}
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

          {/* Right 5 Columns: Isolated Live Agent Stream + Manual Scoped Runner */}
          <div className="lg:col-span-5 flex flex-col gap-3 min-h-0">
            <AgentStreamPanel
              key={detail.id}
              engagementId={detail.id}
              initialEvents={detail.events || []}
              currentStep={detail.current_step}
              maxSteps={detail.max_steps}
              onLiveStateChange={handleLiveStateChange}
              onWsStatusChange={setWsConnected}
              onSteered={handleRefreshCurrentDetail}
              onToast={pushToast}
            />

            {/* Scoped Quick Tool Runner */}
            <form
              onSubmit={(e) => void handleManualRun(e)}
              className="bg-slate-900/80 border border-slate-800 rounded-xl p-3 space-y-2 text-xs"
            >
              <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" /> Scoped Manual Tool Execution
              </div>
              <div className="flex flex-wrap sm:flex-nowrap gap-2">
                <select
                  aria-label="Select security tool"
                  value={manualTool}
                  onChange={(e) => setManualTool(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white font-mono focus:outline-none focus:ring-2 focus:ring-cyan-500"
                >
                  {availableTools.map((t) => (
                    <option key={t.name} value={t.name} disabled={!t.available}>
                      {t.name} (T{t.tier}){!t.available ? " [missing]" : ""}
                    </option>
                  ))}
                </select>
                <input
                  aria-label="Manual tool target URL"
                  value={manualTarget}
                  onChange={(e) => setManualTarget(e.target.value)}
                  placeholder="Target URL inside allowlist"
                  className="flex-1 min-w-[160px] bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <button
                  disabled={manualBusy || !manualTarget.trim()}
                  type="submit"
                  className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-400"
                >
                  {manualBusy ? "..." : "Run"}
                </button>
              </div>
              <input
                aria-label="Optional JSON tool arguments"
                value={manualArgsJson}
                onChange={(e) => setManualArgsJson(e.target.value)}
                placeholder='Optional args JSON e.g. {"mode":"differential_bola"}'
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 font-mono text-[11px] text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
              {manualError && (
                <div role="alert" className="text-red-400 text-[11px]">
                  {manualError}
                </div>
              )}
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
            pushToast("success", "Created scoped engagement.");
          }}
          onClose={() => setShowWizard(false)}
        />
      )}

      {showSettings && (
        <SettingsModal
          profiles={profiles}
          onRefreshProfiles={refreshProfiles}
          onClose={() => setShowSettings(false)}
          onToast={pushToast}
        />
      )}

      {activeApproval && (
        <ApprovalModal
          key={activeApproval.id}
          approval={activeApproval}
          onDecide={async (id, decision, modifiedArgs, note) => {
            await api.decideApproval(id, {
              decision,
              modified_args: modifiedArgs,
              operator_note: note,
            });
            setDismissedApprovalIds((prev) => {
              const next = new Set(prev);
              next.delete(id);
              return next;
            });
            pushToast("success", `Approval ${decision}.`);
            if (detail) await refreshDetail(detail.id);
          }}
          onClose={() => {
            const dismissedId = activeApproval.id;
            setDismissedApprovalIds((prev) => {
              const next = new Set(prev);
              next.add(dismissedId);
              return next;
            });
            setActiveApproval(null);
          }}
        />
      )}

      {confirmDeleteOpen && detail && (
        <ConfirmDialog
          title="Delete Engagement"
          message={`Delete engagement "${detail.name}" and all of its assets, runs, and findings? This cannot be undone.`}
          confirmLabel="Delete Engagement"
          busy={busyAction === "delete"}
          onConfirm={handleConfirmDeleteEngagement}
          onCancel={() => setConfirmDeleteOpen(false)}
        />
      )}

      {selectedRunLog && (
        <ModalFrame
          title={
            <span className="font-mono text-cyan-300">{selectedRunLog.run.tool_name}</span>
          }
          subtitle={
            <span className="font-mono break-all">
              {selectedRunLog.run.target}
              {selectedRunLog.run.exit_code !== null
                ? ` • exit ${selectedRunLog.run.exit_code}`
                : ""}
            </span>
          }
          onClose={() => setSelectedRunLog(null)}
          maxWidthClass="max-w-3xl"
        >
          <div className="p-4 space-y-3 text-xs">
            {selectedRunLog.run.error_message && (
              <div role="alert" className="bg-red-950/40 border border-red-800 rounded-lg p-2.5 text-red-200">
                <span className="font-semibold">Error: </span>
                {selectedRunLog.run.error_message}
              </div>
            )}
            {selectedRunLog.run.argv?.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-slate-400 font-semibold">Compiled Command (shell=False)</span>
                  <button
                    type="button"
                    onClick={() => void handleCopyText("run-argv", selectedRunLog.run.argv.join(" "))}
                    className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    {copiedField === "run-argv" ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" /> Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" /> Copy
                      </>
                    )}
                  </button>
                </div>
                <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 text-cyan-300 font-mono overflow-x-auto">
                  {selectedRunLog.run.argv.join(" ")}
                </pre>
              </div>
            )}
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-slate-400 font-semibold">Raw Output Log</span>
                <button
                  type="button"
                  onClick={() => void handleCopyText("run-log", selectedRunLog.log)}
                  className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] focus:outline-none focus:ring-2 focus:ring-cyan-500"
                >
                  {copiedField === "run-log" ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" /> Copied
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" /> Copy Log
                    </>
                  )}
                </button>
              </div>
              <pre className="bg-slate-950 border border-slate-800 rounded p-3 text-slate-200 font-mono whitespace-pre-wrap break-words max-h-96 overflow-y-auto">
                {selectedRunLog.log}
              </pre>
            </div>
          </div>
        </ModalFrame>
      )}

      <ToastBar toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}
