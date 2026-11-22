import React, { useState } from "react";
import { ShieldAlert, Check, X, Edit3 } from "lucide-react";
import { ApprovalItem } from "../api/client";

interface Props {
  approval: ApprovalItem;
  onDecide: (
    approvalId: string,
    decision: "approved" | "modified" | "rejected",
    modifiedArgs?: Record<string, unknown>,
    note?: string
  ) => Promise<void>;
  onClose: () => void;
}

export const ApprovalModal: React.FC<Props> = ({ approval, onDecide, onClose }) => {
  const [argsText, setArgsText] = useState(JSON.stringify(approval.proposed_args, null, 2));
  const [note, setNote] = useState("");
  const [editMode, setEditMode] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleAction = async (decision: "approved" | "modified" | "rejected") => {
    setError("");
    let parsedArgs: Record<string, unknown> | undefined;
    if (decision === "modified") {
      try {
        parsedArgs = JSON.parse(argsText);
      } catch {
        setError("Invalid JSON in modified arguments.");
        return;
      }
    }
    setSubmitting(true);
    try {
      await onDecide(approval.id, decision, parsedArgs, note || undefined);
      onClose();
    } catch (err) {
      setError(String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
      <div className="w-full max-w-2xl bg-slate-900 border border-amber-500/50 rounded-2xl shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 bg-amber-950/30 border-b border-amber-500/30">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            <div>
              <h2 className="text-sm font-bold text-amber-200">
                Operator Approval Required — Tier {approval.tier}
              </h2>
              <p className="text-xs text-slate-400">
                Tool <span className="text-cyan-300 font-mono">{approval.tool_name}</span> against{" "}
                <span className="font-mono text-slate-200">{approval.target}</span>
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-xs">
            Dismiss
          </button>
        </div>

        <div className="p-5 space-y-4 text-xs">
          <div>
            <div className="text-slate-400 uppercase font-semibold mb-1">Exact Command Preview (shell=False)</div>
            <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-cyan-300 font-mono overflow-x-auto">
              {approval.argv_preview.join(" ")}
            </pre>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
              <div className="text-slate-400 font-semibold mb-1">AI Rationale</div>
              <p className="text-slate-200">{approval.rationale || "No rationale provided."}</p>
            </div>
            <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
              <div className="text-slate-400 font-semibold mb-1">Risk Summary</div>
              <p className="text-amber-200/90">{approval.risk_summary || "Active intrusive validation."}</p>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-slate-400 uppercase font-semibold">Arguments (JSON)</span>
              <button
                onClick={() => setEditMode(!editMode)}
                className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
              >
                <Edit3 className="w-3.5 h-3.5" />
                {editMode ? "Cancel Edit" : "Edit Args"}
              </button>
            </div>
            <textarea
              value={argsText}
              onChange={(e) => setArgsText(e.target.value)}
              readOnly={!editMode}
              rows={5}
              className={`w-full font-mono text-xs rounded-lg p-2.5 border ${
                editMode
                  ? "bg-slate-950 border-cyan-500 text-slate-100"
                  : "bg-slate-950/60 border-slate-800 text-slate-300"
              }`}
            />
          </div>

          <div>
            <label className="block text-slate-400 font-semibold mb-1">Operator Note (optional)</label>
            <input
              type="text"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="e.g. Approved for single parameter verification"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100"
            />
          </div>

          {error && <div className="text-red-400 bg-red-950/40 border border-red-800 rounded-lg p-2">{error}</div>}
        </div>

        <div className="flex items-center justify-end gap-2.5 px-5 py-3.5 bg-slate-950 border-t border-slate-800">
          <button
            disabled={submitting}
            onClick={() => handleAction("rejected")}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-red-950/60 hover:bg-red-900/70 border border-red-700/60 text-red-200 text-xs font-semibold"
          >
            <X className="w-4 h-4" /> Reject
          </button>
          {editMode && (
            <button
              disabled={submitting}
              onClick={() => handleAction("modified")}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-semibold"
            >
              <Edit3 className="w-4 h-4" /> Modify & Approve
            </button>
          )}
          <button
            disabled={submitting}
            onClick={() => handleAction("approved")}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold"
          >
            <Check className="w-4 h-4" /> Approve & Run
          </button>
        </div>
      </div>
    </div>
  );
};
