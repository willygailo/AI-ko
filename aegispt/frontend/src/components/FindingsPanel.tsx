import React, { useMemo, useState } from "react";
import {
  Check,
  CheckCircle2,
  Copy,
  Download,
  RefreshCw,
  Send,
  Shield,
  X,
  XCircle,
} from "lucide-react";
import {
  type FindingItem,
  type ReportFormat,
  type ReverifyFindingResponse,
  api,
} from "../api/client";
import { copyTextToClipboard } from "../utils/clipboard";
import { filterFindings, resolveSelectedFinding } from "../utils/events";
import type { ToastKind } from "./ToastBar";

interface Props {
  engagementId: string;
  findings: FindingItem[];
  onRefresh: () => Promise<void>;
  onSendToRepeater?: (url: string) => void;
  onToast?: (kind: ToastKind, text: string) => void;
}

const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  low: "bg-sky-500/20 text-sky-300 border-sky-500/40",
  info: "bg-slate-500/20 text-slate-300 border-slate-500/40",
};

const REPORT_FORMATS: { fmt: ReportFormat; label: string }[] = [
  { fmt: "html", label: "HTML" },
  { fmt: "markdown", label: "MARKDOWN" },
  { fmt: "sarif", label: "SARIF" },
  { fmt: "json", label: "JSON" },
  { fmt: "poc_sh", label: "PoC .sh" },
];

export const FindingsPanel: React.FC<Props> = React.memo(
  ({ engagementId, findings, onRefresh, onSendToRepeater, onToast }) => {
    const [selectedId, setSelectedId] = useState<string | null>(findings[0]?.id ?? null);
    const [sevFilter, setSevFilter] = useState<string>("all");
    const [verifyingId, setVerifyingId] = useState<string>("");
    const [mutatingId, setMutatingId] = useState<string>("");
    const [downloadingFmt, setDownloadingFmt] = useState<string>("");
    const [copiedPocId, setCopiedPocId] = useState<string>("");
    const [reverifyBanner, setReverifyBanner] = useState<{
      findingId: string;
      result: ReverifyFindingResponse;
    } | null>(null);

    const filtered = useMemo(() => filterFindings(findings, sevFilter), [findings, sevFilter]);
    const selected = useMemo(
      () => resolveSelectedFinding(filtered, selectedId),
      [filtered, selectedId]
    );

    const notify = (kind: ToastKind, msg: string) => {
      onToast?.(kind, msg);
    };

    const updateStatus = async (id: string, status: FindingItem["status"]) => {
      setMutatingId(id);
      try {
        await api.updateFinding(id, { status });
        await onRefresh();
        notify("success", `Finding marked as ${status.replace("_", " ")}.`);
      } catch (err) {
        notify("error", err instanceof Error ? err.message : String(err));
      } finally {
        setMutatingId("");
      }
    };

    const handleReverify = async (id: string) => {
      setVerifyingId(id);
      setReverifyBanner(null);
      try {
        const res = await api.reverifyFinding(id);
        setReverifyBanner({ findingId: id, result: res });
        await onRefresh();
        if (res.manual_reverify_required || res.still_present === null) {
          notify("info", res.message || "Manual re-verification required for this finding.");
        } else if (res.still_present) {
          notify("info", "Re-verification confirmed the finding is still present.");
        } else {
          notify("success", "Re-verification did not detect the issue; marked remediated.");
        }
      } catch (err) {
        notify("error", err instanceof Error ? err.message : String(err));
      } finally {
        setVerifyingId("");
      }
    };

    const handleDownload = async (fmt: ReportFormat) => {
      setDownloadingFmt(fmt);
      try {
        await api.downloadReport(engagementId, fmt);
        notify("success", `Exported ${fmt.toUpperCase()} report.`);
      } catch (err) {
        notify("error", err instanceof Error ? err.message : String(err));
      } finally {
        setDownloadingFmt("");
      }
    };

    const handleCopyPoc = async (finding: FindingItem) => {
      if (!finding.poc_command) return;
      const ok = await copyTextToClipboard(finding.poc_command);
      if (ok) {
        setCopiedPocId(finding.id);
        setTimeout(() => setCopiedPocId(""), 1500);
      } else {
        notify("error", "Clipboard copy failed.");
      }
    };

    const activeBanner =
      reverifyBanner && selected && reverifyBanner.findingId === selected.id
        ? reverifyBanner.result
        : null;

    return (
      <div className="flex flex-col h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden min-h-[360px]">
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 border-b border-slate-800 bg-slate-900">
          <div className="flex flex-wrap items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" aria-hidden="true" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-200">
              Findings & Report Studio ({filtered.length})
            </span>
            <div className="flex flex-wrap items-center gap-1 ml-1" role="group" aria-label="Filter findings by severity">
              {["all", "critical", "high", "medium", "low", "info"].map((s) => (
                <button
                  type="button"
                  key={s}
                  aria-pressed={sevFilter === s}
                  onClick={() => setSevFilter(s)}
                  className={`px-2 py-0.5 rounded text-[11px] uppercase font-medium focus:outline-none focus:ring-2 focus:ring-cyan-500 ${
                    sevFilter === s
                      ? "bg-cyan-600 text-white"
                      : "bg-slate-800 text-slate-400 hover:text-white"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {REPORT_FORMATS.map(({ fmt, label }) => (
              <button
                type="button"
                key={fmt}
                disabled={downloadingFmt === fmt}
                onClick={() => void handleDownload(fmt)}
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-[11px] font-medium border border-slate-700 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                <Download className="w-3 h-3" aria-hidden="true" />
                {downloadingFmt === fmt ? "..." : label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 flex-1 min-h-0">
          <div className="lg:col-span-5 border-b lg:border-b-0 lg:border-r border-slate-800 overflow-y-auto divide-y divide-slate-800/70 max-h-64 lg:max-h-none">
            {filtered.length === 0 && (
              <div className="p-6 text-center text-xs text-slate-500">
                No findings match this filter yet.
              </div>
            )}
            {filtered.map((f) => (
              <button
                type="button"
                key={f.id}
                onClick={() => setSelectedId(f.id)}
                aria-current={selected?.id === f.id ? "true" : undefined}
                className={`w-full text-left px-3.5 py-2.5 hover:bg-slate-800/60 transition focus:outline-none focus:ring-2 focus:ring-inset focus:ring-cyan-500 ${
                  selected?.id === f.id ? "bg-slate-800/80" : ""
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span
                    className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded-full border ${
                      SEV_BADGE[f.severity] || SEV_BADGE.info
                    }`}
                  >
                    {f.severity}
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    {f.tool_source} • {f.status}
                  </span>
                </div>
                <div className="text-xs font-medium text-slate-100 truncate">{f.title}</div>
                <div className="text-[11px] text-slate-400 truncate font-mono">{f.target_url}</div>
              </button>
            ))}
          </div>

          <div className="lg:col-span-7 overflow-y-auto p-4 text-xs">
            {!selected ? (
              <div className="text-slate-500 text-center mt-10">
                Select a finding to inspect evidence & remediation.
              </div>
            ) : (
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h3 className="text-sm font-bold text-white break-words">{selected.title}</h3>
                    <div className="text-[11px] text-slate-400 font-mono mt-0.5 break-all">
                      {selected.target_url}
                      {selected.parameter ? ` • param=${selected.parameter}` : ""}
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0 flex-wrap justify-end">
                    <button
                      type="button"
                      disabled={verifyingId === selected.id || mutatingId === selected.id}
                      onClick={() => void handleReverify(selected.id)}
                      className="flex items-center gap-1 px-2 py-1 rounded bg-cyan-950/60 border border-cyan-700/60 text-cyan-300 hover:bg-cyan-900/70 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    >
                      <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />{" "}
                      {verifyingId === selected.id ? "..." : "Re-Verify"}
                    </button>
                    {onSendToRepeater && (
                      <button
                        type="button"
                        onClick={() => onSendToRepeater(selected.target_url)}
                        className="flex items-center gap-1 px-2 py-1 rounded bg-indigo-950/60 border border-indigo-700/60 text-indigo-300 hover:bg-indigo-900/70 focus:outline-none focus:ring-2 focus:ring-indigo-400"
                      >
                        <Send className="w-3.5 h-3.5" aria-hidden="true" /> Repeat
                      </button>
                    )}
                    <button
                      type="button"
                      disabled={mutatingId === selected.id}
                      onClick={() => void updateStatus(selected.id, "confirmed")}
                      className="flex items-center gap-1 px-2 py-1 rounded bg-emerald-950/60 border border-emerald-700/60 text-emerald-300 hover:bg-emerald-900/70 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-emerald-400"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" /> Confirm
                    </button>
                    <button
                      type="button"
                      disabled={mutatingId === selected.id}
                      onClick={() => void updateStatus(selected.id, "false_positive")}
                      className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    >
                      <XCircle className="w-3.5 h-3.5" aria-hidden="true" /> False Positive
                    </button>
                  </div>
                </div>

                {activeBanner && (
                  <div
                    role="status"
                    className={`flex items-start justify-between gap-2 rounded-lg border px-3 py-2 text-xs ${
                      activeBanner.manual_reverify_required || activeBanner.still_present === null
                        ? "bg-amber-950/40 border-amber-700/60 text-amber-200"
                        : activeBanner.still_present
                        ? "bg-red-950/40 border-red-700/60 text-red-200"
                        : "bg-emerald-950/40 border-emerald-700/60 text-emerald-200"
                    }`}
                  >
                    <div>
                      <span className="font-semibold uppercase mr-1.5">
                        {activeBanner.manual_reverify_required || activeBanner.still_present === null
                          ? "Manual Verification Needed:"
                          : activeBanner.still_present
                          ? "Still Present:"
                          : "Remediated:"}
                      </span>
                      <span>
                        {activeBanner.message ||
                          (activeBanner.still_present
                            ? `Issue reproduced during automated probe (status: ${activeBanner.status}).`
                            : `Issue no longer detected during automated probe (status: ${activeBanner.status}).`)}
                      </span>
                    </div>
                    <button
                      type="button"
                      aria-label="Dismiss reverification result"
                      onClick={() => setReverifyBanner(null)}
                      className="p-0.5 opacity-80 hover:opacity-100 rounded focus:outline-none focus:ring-2 focus:ring-cyan-400"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}

                <div className="flex flex-wrap gap-2 text-[11px]">
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 uppercase font-semibold">
                    Status: {selected.status}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    CVSS: {selected.cvss_score ?? "N/A"}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    CWE: {selected.cwe_id ?? "N/A"}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {selected.owasp_category ?? "OWASP WSTG"}
                  </span>
                  {selected.corroborated_by && selected.corroborated_by.length > 0 && (
                    <span className="px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/50 text-cyan-300">
                      Sources: {selected.corroborated_by.join(", ")}
                    </span>
                  )}
                </div>

                <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-3">
                  <div className="text-slate-400 font-semibold mb-1">Description</div>
                  <p className="text-slate-200 leading-relaxed">{selected.description}</p>
                </div>

                {selected.poc_command && (
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-slate-400 font-semibold">Reproduction Command</span>
                      <button
                        type="button"
                        onClick={() => void handleCopyPoc(selected)}
                        className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-[11px] focus:outline-none focus:ring-2 focus:ring-cyan-500"
                      >
                        {copiedPocId === selected.id ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" /> Copied
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" /> Copy PoC
                          </>
                        )}
                      </button>
                    </div>
                    <pre className="bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-cyan-300 font-mono overflow-x-auto">
                      {selected.poc_command}
                    </pre>
                  </div>
                )}

                <div>
                  <div className="text-slate-400 font-semibold mb-1">Evidence</div>
                  <pre className="bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-300 font-mono overflow-x-auto max-h-40">
                    {JSON.stringify(selected.evidence, null, 2)}
                  </pre>
                </div>

                <div className="bg-emerald-950/20 border border-emerald-800/40 rounded-lg p-3">
                  <div className="text-emerald-300 font-semibold mb-1">Remediation Guidance</div>
                  <p className="text-slate-200 leading-relaxed">{selected.remediation}</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }
);

FindingsPanel.displayName = "FindingsPanel";
