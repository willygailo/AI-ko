import React from "react";
import { AlertTriangle } from "lucide-react";
import { ModalFrame } from "./ModalFrame";

interface Props {
  title: string;
  message: string;
  confirmLabel?: string;
  busy?: boolean;
  onConfirm: () => Promise<void> | void;
  onCancel: () => void;
}

export const ConfirmDialog: React.FC<Props> = ({
  title,
  message,
  confirmLabel = "Confirm",
  busy = false,
  onConfirm,
  onCancel,
}) => {
  return (
    <ModalFrame
      title={
        <>
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{title}</span>
        </>
      }
      onClose={onCancel}
      disableClose={busy}
      maxWidthClass="max-w-md"
      borderClass="border-red-800/60"
      footer={
        <>
          <button
            type="button"
            disabled={busy}
            onClick={onCancel}
            className="px-3.5 py-2 rounded-lg text-xs text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void onConfirm()}
            className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white focus:outline-none focus:ring-2 focus:ring-red-400"
          >
            {busy ? "Working..." : confirmLabel}
          </button>
        </>
      }
    >
      <div className="p-5 text-xs text-slate-300 leading-relaxed">{message}</div>
    </ModalFrame>
  );
};
