import React, { useState } from "react";
import { Download, CheckCircle2, XCircle, Shield, RefreshCw, Send } from "lucide-react";
import { FindingItem, api } from "../api/client";

interface Props {
  engagementId: string;
  findings: FindingItem[];
  onRefresh: () => Promise<void>;
  onSendToRepeater?: (url: string) => void;
}

const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  low: "bg-sky-500/20 text-sky-300 border-sky-500/40",
  info: "bg-slate-500/20 text-slate-300 border-slate-500/40",
};

export const FindingsPanel: React.FC<Props> = ({
  engagementId,
  findings,
  onRefresh,
  onSendToRepeater,
}) => {
  const [selected, setSelected] = useState<FindingItem | null>(findings[0] || null);
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [verifyingId, setVerifyingId] = useState<string>("");

  const filtered = findings.filter((f) => sevFilter === "all" || f.severity === sevFilter);

  const updateStatus = async (id: string, status: FindingItem["status"]) => {
    await api.updateFinding(id, { status });
    await onRefresh();
  };

  const handleReverify = async (id: string) => {
    setVerifyingId(id);
    try {
      await api.reverifyFinding(id);
      await onRefresh();
    } finally {
      setVerifyingId("");
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 border-b border-slate-800 bg-slate-900">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-200">
            Findings & Report Studio ({filtered.length})
          </span>
          <div className="flex items-center gap-1 ml-2">
            {["all", "critical", "high", "medium", "low", "info"].map((s) => (
              <button
                key={s}
                onClick={() => setSevFilter(s)}
                className={`px-2 py-0.5 rounded text-[11px] uppercase font-medium ${
                  sevFilter === s ? "bg-cyan-600 text-white" : "bg-slate-800 text-slate-400 hover:text-white"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          {(["html", "markdown", "sarif", "poc_sh"] as const).map((fmt) => (
            <button
              key={fmt}
              onClick={() => api.downloadReport(engagementId, fmt)}
              className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-medium border border-slate-700"
            >
              <Download className="w-3 h-3" /> {fmt === "poc_sh" ? "PoC .sh" : fmt.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 flex-1 min-h-0">
        <div className="lg:col-span-5 border-r border-slate-800 overflow-y-auto divide-y divide-slate-800/70">
          {filtered.length === 0 && (
            <div className="p-6 text-center text-xs text-slate-500">
              No findings match this filter yet.
            </div>
          )}
          {filtered.map((f) => (
            <button
              key={f.id}
              onClick={() => setSelected(f)}
              className={`w-full text-left px-3.5 py-2.5 hover:bg-slate-800/60 transition ${
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
            <div className="text-slate-500 text-center mt-10">Select a finding to inspect evidence & remediation.</div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="text-sm font-bold text-white">{selected.title}</h3>
                  <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                    {selected.target_url}
                    {selected.parameter ? ` • param=${selected.parameter}` : ""}
                  </div>
                </div>
                <div className="flex items-center gap-1.5 shrink-0 flex-wrap justify-end">
                  <button
                    disabled={verifyingId === selected.id}
                    onClick={() => handleReverify(selected.id)}
                    className="flex items-center gap-1 px-2 py-1 rounded bg-cyan-950/60 border border-cyan-700/60 text-cyan-300 hover:bg-cyan-900/70 disabled:opacity-50"
                  >
                    <RefreshCw className="w-3.5 h-3.5" /> {verifyingId === selected.id ? "..." : "Re-Verify"}
                  </button>
                  {onSendToRepeater && (
                    <button
                      onClick={() => onSendToRepeater(selected.target_url)}
                      className="flex items-center gap-1 px-2 py-1 rounded bg-indigo-950/60 border border-indigo-700/60 text-indigo-300 hover:bg-indigo-900/70"
                    >
                      <Send className="w-3.5 h-3.5" /> Repeat
                    </button>
                  )}
                  <button
                    onClick={() => updateStatus(selected.id, "confirmed")}
                    className="flex items-center gap-1 px-2 py-1 rounded bg-emerald-950/60 border border-emerald-700/60 text-emerald-300 hover:bg-emerald-900/70"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" /> Confirm
                  </button>
                  <button
                    onClick={() => updateStatus(selected.id, "false_positive")}
                    className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700"
                  >
                    <XCircle className="w-3.5 h-3.5" /> False Positive
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap gap-2 text-[11px]">
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
                  <div className="text-slate-400 font-semibold mb-1">Reproduction Command</div>
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
};
