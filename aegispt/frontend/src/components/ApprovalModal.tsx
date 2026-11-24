import React, { useId, useState } from "react";
import { Check, Copy, Edit3, ShieldAlert, X } from "lucide-react";
import type { ApprovalItem } from "../api/client";
import { copyTextToClipboard } from "../utils/clipboard";
import { parseJsonObject } from "../utils/parsing";
import { ModalFrame } from "./ModalFrame";

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
  const argsInputId = useId();
  const noteInputId = useId();

  const [argsText, setArgsText] = useState(JSON.stringify(approval.proposed_args, null, 2));
  const [note, setNote] = useState("");
  const [editMode, setEditMode] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const commandPreview = approval.argv_preview.join(" ");

  const handleAction = async (decision: "approved" | "modified" | "rejected") => {
    setError("");
    let parsedArgs: Record<string, unknown> | undefined;
    if (decision === "modified") {
      const parsed = parseJsonObject(argsText, "modified arguments");
      if (!parsed.ok) {
        setError(parsed.error);
        return;
      }
      parsedArgs = parsed.value;
    }
    setSubmitting(true);
    try {
      await onDecide(approval.id, decision, parsedArgs, note || undefined);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleCopyCommand = async () => {
    const ok = await copyTextToClipboard(commandPreview);
    if (ok) {
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 1500);
    }
  };

  return (
    <ModalFrame
      title={
        <span className="flex items-center gap-2 text-amber-200">
          <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0" aria-hidden="true" />
          <span>Operator Approval Required — Tier {approval.tier}</span>
        </span>
      }
      subtitle={
        <>
          Tool <span className="text-cyan-300 font-mono">{approval.tool_name}</span> against{" "}
          <span className="font-mono text-slate-200 break-all">{approval.target}</span>
        </>
      }
      onClose={onClose}
      disableClose={submitting}
      closeLabel="Dismiss approval dialog"
      closeText="Dismiss"
      borderClass="border-amber-500/50"
      headerClass="bg-amber-950/30 border-amber-500/30"
      footer={
        <>
          <button
            type="button"
            disabled={submitting}
            onClick={() => void handleAction("rejected")}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-red-950/60 hover:bg-red-900/70 disabled:opacity-50 border border-red-700/60 text-red-200 text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-red-400"
          >
            <X className="w-4 h-4" aria-hidden="true" /> Reject
          </button>
          {editMode && (
            <button
              type="button"
              disabled={submitting}
              onClick={() => void handleAction("modified")}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-400"
            >
              <Edit3 className="w-4 h-4" aria-hidden="true" /> Modify & Approve
            </button>
          )}
          <button
            type="button"
            disabled={submitting}
            onClick={() => void handleAction("approved")}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-emerald-400"
          >
            <Check className="w-4 h-4" aria-hidden="true" /> {submitting ? "Submitting..." : "Approve & Run"}
          </button>
        </>
      }
    >
      <div className="p-5 space-y-4 text-xs">
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="text-slate-400 uppercase font-semibold">Exact Command Preview (shell=False)</span>
            <button
              type="button"
              onClick={() => void handleCopyCommand()}
              className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-[11px] focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              {copiedCmd ? (
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
          <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-cyan-300 font-mono overflow-x-auto">
            {commandPreview}
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
            <label htmlFor={argsInputId} className="text-slate-400 uppercase font-semibold">
              Arguments (JSON)
            </label>
            <button
              type="button"
              onClick={() => setEditMode(!editMode)}
              className="flex items-center gap-1 rounded px-1 text-cyan-400 hover:text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <Edit3 className="w-3.5 h-3.5" aria-hidden="true" />
              {editMode ? "Cancel Edit" : "Edit Args"}
            </button>
          </div>
          <textarea
            id={argsInputId}
            value={argsText}
            onChange={(e) => setArgsText(e.target.value)}
            readOnly={!editMode}
            rows={5}
            className={`w-full font-mono text-xs rounded-lg p-2.5 border focus:outline-none focus:ring-2 focus:ring-cyan-500 ${
              editMode
                ? "bg-slate-950 border-cyan-500 text-slate-100"
                : "bg-slate-950/60 border-slate-800 text-slate-300"
            }`}
          />
        </div>

        <div>
          <label htmlFor={noteInputId} className="block text-slate-400 font-semibold mb-1">
            Operator Note (optional)
          </label>
          <input
            id={noteInputId}
            type="text"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="e.g. Approved for single parameter verification"
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>

        {error && (
          <div role="alert" className="text-red-400 bg-red-950/40 border border-red-800 rounded-lg p-2">
            {error}
          </div>
        )}
      </div>
    </ModalFrame>
  );
};
