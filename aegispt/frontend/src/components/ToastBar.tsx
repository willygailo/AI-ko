import React from "react";
import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";

export type ToastKind = "error" | "success" | "info";

export interface ToastMessage {
  id: string;
  kind: ToastKind;
  text: string;
}

interface Props {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

const TOAST_STYLES: Record<ToastKind, string> = {
  error: "bg-red-950/95 border-red-700/70 text-red-100",
  success: "bg-emerald-950/95 border-emerald-700/70 text-emerald-100",
  info: "bg-slate-900/95 border-cyan-700/60 text-slate-100",
};

export const ToastBar: React.FC<Props> = ({ toasts, onDismiss }) => {
  if (toasts.length === 0) return null;

  return (
    <div
      aria-live="polite"
      className="fixed bottom-4 right-4 z-[60] flex flex-col gap-2 max-w-md w-[calc(100vw-2rem)] pointer-events-none"
    >
      {toasts.map((t) => {
        const Icon =
          t.kind === "error" ? AlertCircle : t.kind === "success" ? CheckCircle2 : Info;
        return (
          <div
            key={t.id}
            role={t.kind === "error" ? "alert" : "status"}
            className={`pointer-events-auto flex items-start gap-2.5 px-3.5 py-2.5 rounded-xl border shadow-xl text-xs ${TOAST_STYLES[t.kind]}`}
          >
            <Icon className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
            <div className="flex-1 break-words leading-relaxed">{t.text}</div>
            <button
              type="button"
              onClick={() => onDismiss(t.id)}
              aria-label="Dismiss notification"
              className="p-0.5 rounded opacity-80 hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-cyan-400"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
