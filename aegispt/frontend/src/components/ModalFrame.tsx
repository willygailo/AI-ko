import React, { useEffect, useId, useRef } from "react";
import { X } from "lucide-react";

interface Props {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
  maxWidthClass?: string;
  borderClass?: string;
  headerClass?: string;
  closeLabel?: string;
  closeText?: string;
  disableClose?: boolean;
  headerExtra?: React.ReactNode;
}

export const ModalFrame: React.FC<Props> = ({
  title,
  subtitle,
  onClose,
  children,
  footer,
  maxWidthClass = "max-w-2xl",
  borderClass = "border-slate-700",
  headerClass = "border-slate-800",
  closeLabel = "Close dialog",
  closeText,
  disableClose = false,
  headerExtra,
}) => {
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const onCloseRef = useRef(onClose);
  const disableCloseRef = useRef(disableClose);

  onCloseRef.current = onClose;
  disableCloseRef.current = disableClose;

  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    dialogRef.current?.focus();

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !disableCloseRef.current) {
        e.stopPropagation();
        onCloseRef.current();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      previouslyFocused?.focus?.();
    };
  }, []);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !disableClose) {
          onClose();
        }
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={`w-full ${maxWidthClass} bg-slate-900 border ${borderClass} rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[88vh] focus:outline-none focus:ring-2 focus:ring-cyan-500`}
      >
        <div className={`flex items-center justify-between gap-3 px-5 py-3.5 border-b ${headerClass}`}>
          <div className="min-w-0">
            <h2 id={titleId} className="text-sm font-bold text-white flex items-center gap-2">
              {title}
            </h2>
            {subtitle && <div className="text-xs text-slate-400 mt-0.5">{subtitle}</div>}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {headerExtra}
            <button
              type="button"
              disabled={disableClose}
              onClick={onClose}
              aria-label={closeLabel}
              className="px-2 py-1 rounded text-xs text-slate-400 hover:text-white disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              {closeText ? closeText : <X className="w-4 h-4" />}
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">{children}</div>

        {footer && (
          <div className="flex items-center justify-end gap-2 px-5 py-3.5 bg-slate-950 border-t border-slate-800">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};
