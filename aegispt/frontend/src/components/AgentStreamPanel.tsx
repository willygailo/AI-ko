import React, { useEffect, useMemo, useRef, useState } from "react";
import { Activity, ArrowDownCircle, Check, Copy, PauseCircle } from "lucide-react";
import { AgentEventItem, api, connectEngagementWS } from "../api/client";
import { copyTextToClipboard } from "../utils/clipboard";
import {
  getMaxEventId,
  mergeDedupedEvents,
  shouldTriggerDetailRefresh,
} from "../utils/events";
import type { ToastKind } from "./ToastBar";

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

type StreamFilter = "all" | "thoughts" | "tools" | "approvals" | "alerts";

interface Props {
  engagementId: string;
  initialEvents: AgentEventItem[];
  currentStep: number;
  maxSteps: number;
  onLiveStateChange: () => void;
  onWsStatusChange: (connected: boolean) => void;
  onSteered: () => Promise<void>;
  onToast: (kind: ToastKind, text: string) => void;
}

function matchesFilter(ev: AgentEventItem, filter: StreamFilter): boolean {
  if (filter === "all") return true;
  if (filter === "thoughts") {
    return (
      ev.event_type === "agent_thought" ||
      ev.event_type === "operator_steer" ||
      ev.event_type === "executive_summary" ||
      ev.event_type === "planner_fallback"
    );
  }
  if (filter === "tools") {
    return (
      ev.event_type === "tool_started" ||
      ev.event_type === "tool_completed" ||
      ev.event_type === "manual_tool_completed" ||
      ev.event_type === "tool_output"
    );
  }
  if (filter === "approvals") {
    return ev.event_type === "approval_required" || ev.event_type === "approval_resolved";
  }
  return (
    ev.event_type === "scope_blocked" ||
    ev.event_type === "oob_callback_received" ||
    ev.event_type === "attack_chain_synthesized" ||
    ev.event_type === "engagement_failed" ||
    ev.event_type === "engagement_finished"
  );
}

export const AgentStreamPanel: React.FC<Props> = React.memo(
  ({
    engagementId,
    initialEvents,
    currentStep,
    maxSteps,
    onLiveStateChange,
    onWsStatusChange,
    onSteered,
    onToast,
  }) => {
    const [events, setEvents] = useState<AgentEventItem[]>(() =>
      mergeDedupedEvents([], initialEvents, 300)
    );
    const [filter, setFilter] = useState<StreamFilter>("all");
    const [autoScroll, setAutoScroll] = useState(true);
    const [steerInput, setSteerInput] = useState("");
    const [steerBusy, setSteerBusy] = useState(false);
    const [copied, setCopied] = useState(false);

    const maxSeenIdRef = useRef<number>(getMaxEventId(initialEvents));
    const scrollBoxRef = useRef<HTMLDivElement | null>(null);
    const logEndRef = useRef<HTMLDivElement | null>(null);
    const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
    const onLiveStateChangeRef = useRef(onLiveStateChange);
    const onWsStatusChangeRef = useRef(onWsStatusChange);

    onLiveStateChangeRef.current = onLiveStateChange;
    onWsStatusChangeRef.current = onWsStatusChange;

    // Merge server-fetched detail.events whenever detail refreshes without losing live frames
    useEffect(() => {
      const incomingMax = getMaxEventId(initialEvents);
      if (incomingMax > maxSeenIdRef.current) {
        maxSeenIdRef.current = incomingMax;
      }
      setEvents((prev) => mergeDedupedEvents(prev, initialEvents, 300));
    }, [initialEvents]);

    // WebSocket lifecycle scoped exclusively to AgentStreamPanel
    useEffect(() => {
      const connection = connectEngagementWS(engagementId, {
        onStatusChange: (connected) => {
          onWsStatusChangeRef.current(connected);
        },
        onEvent: (ev) => {
          const triggerRefresh = shouldTriggerDetailRefresh(ev, maxSeenIdRef.current);
          if (typeof ev.id === "number" && ev.id > maxSeenIdRef.current) {
            maxSeenIdRef.current = ev.id;
          }
          setEvents((prev) => mergeDedupedEvents(prev, [ev], 300));

          if (triggerRefresh) {
            if (debounceRef.current !== undefined) {
              clearTimeout(debounceRef.current);
            }
            debounceRef.current = setTimeout(() => {
              debounceRef.current = undefined;
              onLiveStateChangeRef.current();
            }, 300);
          }
        },
      });

      return () => {
        if (debounceRef.current !== undefined) {
          clearTimeout(debounceRef.current);
          debounceRef.current = undefined;
        }
        connection.close();
        onWsStatusChangeRef.current(false);
      };
    }, [engagementId]);

    const visibleEvents = useMemo(
      () => events.filter((ev) => matchesFilter(ev, filter)),
      [events, filter]
    );

    useEffect(() => {
      if (autoScroll) {
        logEndRef.current?.scrollIntoView({ behavior: "smooth" });
      }
    }, [visibleEvents.length, autoScroll]);

    const handleScroll = () => {
      const el = scrollBoxRef.current;
      if (!el) return;
      const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
      setAutoScroll(distanceFromBottom <= 32);
    };

    const handleCopyStream = async () => {
      const text = visibleEvents.map((ev) => `[${ev.agent_name}] ${ev.message}`).join("\n");
      const ok = await copyTextToClipboard(text);
      if (ok) {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      } else {
        onToast("error", "Clipboard copy failed.");
      }
    };

    const handleSteerSubmit = async (e: React.FormEvent) => {
      e.preventDefault();
      const trimmed = steerInput.trim();
      if (trimmed.length < 2) {
        onToast("error", "Steering instruction must be at least 2 characters.");
        return;
      }
      setSteerBusy(true);
      try {
        await api.steerEngagement(engagementId, trimmed);
        setSteerInput("");
        onToast("success", "Steering hint sent to AI planner.");
        await onSteered();
      } catch (err) {
        onToast("error", err instanceof Error ? err.message : String(err));
      } finally {
        setSteerBusy(false);
      }
    };

    return (
      <div className="flex-1 flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden min-h-[280px] lg:min-h-0">
        <div className="flex flex-wrap items-center justify-between gap-2 px-3.5 py-2 border-b border-slate-800 bg-slate-900">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" aria-hidden="true" /> Live Agent & Tool Stream
          </span>
          <div className="flex items-center gap-2">
            <select
              aria-label="Filter stream events"
              value={filter}
              onChange={(e) => setFilter(e.target.value as StreamFilter)}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-0.5 text-[11px] text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="all">All ({events.length})</option>
              <option value="thoughts">Thoughts & Steer</option>
              <option value="tools">Tool Output</option>
              <option value="approvals">Approvals</option>
              <option value="alerts">Alerts & OOB</option>
            </select>

            <button
              type="button"
              onClick={() => {
                const next = !autoScroll;
                setAutoScroll(next);
                if (next) {
                  logEndRef.current?.scrollIntoView({ behavior: "smooth" });
                }
              }}
              aria-label={autoScroll ? "Pause auto-scroll" : "Resume auto-scroll"}
              title={autoScroll ? "Auto-scrolling (click to pause)" : "Scroll paused (click to jump to latest)"}
              className={`flex items-center gap-1 px-2 py-0.5 rounded text-[11px] border focus:outline-none focus:ring-2 focus:ring-cyan-500 ${
                autoScroll
                  ? "bg-slate-800 border-slate-700 text-slate-300 hover:text-white"
                  : "bg-amber-500/15 border-amber-500/40 text-amber-300 hover:bg-amber-500/25"
              }`}
            >
              {autoScroll ? (
                <>
                  <PauseCircle className="w-3 h-3" aria-hidden="true" /> Live
                </>
              ) : (
                <>
                  <ArrowDownCircle className="w-3 h-3" aria-hidden="true" /> Latest
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => void handleCopyStream()}
              aria-label="Copy visible stream log"
              title="Copy visible stream log"
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>

            <span className="text-[11px] text-slate-400 font-mono">
              Step {currentStep}/{maxSteps}
            </span>
          </div>
        </div>

        <div
          ref={scrollBoxRef}
          onScroll={handleScroll}
          role="log"
          aria-live="polite"
          aria-label="Live agent and tool event stream"
          className="flex-1 overflow-y-auto p-3 space-y-1.5 font-mono text-[11px] bg-[#070b14]"
        >
          {visibleEvents.length === 0 && (
            <div className="text-slate-500 p-3">
              {events.length === 0
                ? "Waiting for agent stream events..."
                : "No events match the selected stream filter."}
            </div>
          )}
          {visibleEvents.map((ev, idx) => (
            <div key={ev.id ?? `evt-${idx}`} className="leading-relaxed break-words">
              <span className="text-slate-600 mr-1.5">[{ev.agent_name}]</span>
              <span className={EVENT_COLORS[ev.event_type] || "text-slate-300"}>{ev.message}</span>
            </div>
          ))}
          <div ref={logEndRef} />
        </div>

        <form
          onSubmit={(e) => void handleSteerSubmit(e)}
          className="flex gap-2 p-2 border-t border-slate-800 bg-slate-900/90 text-xs"
        >
          <input
            aria-label="Steer AI Brain instruction"
            value={steerInput}
            onChange={(e) => setSteerInput(e.target.value)}
            minLength={2}
            placeholder="Steer AI Brain (e.g. 'Focus on GraphQL, JWT alg=none & checkout race')..."
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
          <button
            disabled={steerBusy || steerInput.trim().length < 2}
            type="submit"
            className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-semibold focus:outline-none focus:ring-2 focus:ring-indigo-400"
          >
            {steerBusy ? "..." : "Steer"}
          </button>
        </form>
      </div>
    );
  }
);

AgentStreamPanel.displayName = "AgentStreamPanel";
