import React, { useId, useMemo, useState } from "react";
import { Search, ZoomIn, ZoomOut, Send, Info } from "lucide-react";
import type { AssetItem, EndpointItem, FindingItem } from "../api/client";
import { buildAttackGraphLayout, type GraphNode } from "../utils/graph";

interface Props {
  engagementName: string;
  assets: AssetItem[];
  endpoints: EndpointItem[];
  findings: FindingItem[];
  onPivotTarget?: (url: string) => void;
}

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#38bdf8",
  info: "#94a3b8",
};

export const AttackGraph: React.FC<Props> = React.memo(
  ({ engagementName, assets, endpoints, findings, onPivotTarget }) => {
    const clipId = useId();
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [query, setQuery] = useState("");
    const [zoom, setZoom] = useState(1);

    const { nodes, edges, height, totals, shown } = useMemo(
      () => buildAttackGraphLayout(engagementName, assets, endpoints, findings, query),
      [engagementName, assets, endpoints, findings, query]
    );

    const nodeById = useMemo(() => {
      const map = new Map<string, GraphNode>();
      nodes.forEach((n) => map.set(n.id, n));
      return map;
    }, [nodes]);

    const selected = selectedId ? nodeById.get(selectedId) ?? null : null;

    const truncationParts: string[] = [];
    if (shown.assets < totals.assets) {
      truncationParts.push(`${shown.assets} of ${totals.assets} assets`);
    }
    if (shown.endpoints < totals.endpoints) {
      truncationParts.push(`${shown.endpoints} of ${totals.endpoints} endpoints`);
    }
    if (shown.findings < totals.findings) {
      truncationParts.push(`${shown.findings} of ${totals.findings} findings`);
    }

    return (
      <div className="flex flex-col h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden min-h-[360px]">
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 border-b border-slate-800 bg-slate-900">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Attack-Surface Graph
            </span>
            <span className="text-[11px] text-slate-400">
              {assets.length} assets • {endpoints.length} endpoints • {findings.length} findings
            </span>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2 py-1">
              <Search className="w-3.5 h-3.5 text-slate-500" aria-hidden="true" />
              <input
                aria-label="Filter attack graph nodes"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter nodes..."
                className="bg-transparent text-[11px] text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500 rounded px-0.5 w-28"
              />
            </div>
            <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-lg px-1.5 py-0.5 text-[11px]">
              <button
                type="button"
                aria-label="Zoom out graph"
                onClick={() => setZoom((z) => Math.max(0.7, Number((z - 0.15).toFixed(2))))}
                className="p-0.5 rounded text-slate-400 hover:text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                title="Zoom out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                aria-label="Reset graph zoom"
                onClick={() => setZoom(1)}
                className="px-1 rounded text-slate-300 font-mono focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                {Math.round(zoom * 100)}%
              </button>
              <button
                type="button"
                aria-label="Zoom in graph"
                onClick={() => setZoom((z) => Math.min(1.6, Number((z + 0.15).toFixed(2))))}
                className="p-0.5 rounded text-slate-400 hover:text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                title="Zoom in"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

        {truncationParts.length > 0 && (
          <div className="flex items-center gap-2 px-4 py-1.5 bg-amber-950/30 border-b border-amber-800/40 text-[11px] text-amber-200">
            <Info className="w-3.5 h-3.5 shrink-0 text-amber-400" aria-hidden="true" />
            <span>
              Showing {truncationParts.join(", ")}. Use the filter box above to narrow visible nodes.
            </span>
          </div>
        )}

        <div className="relative flex-1 overflow-auto bg-[#070b14]">
          <svg
            role="img"
            aria-label={`Attack surface graph for ${engagementName}`}
            viewBox={`0 0 840 ${height}`}
            style={{ width: `${Math.round(840 * zoom)}px`, height: `${Math.round(height * zoom)}px` }}
          >
            <defs>
              <clipPath id={clipId}>
                <rect x={6} y={2} width={124} height={32} rx={4} />
              </clipPath>
            </defs>

            {edges.map((e, i) => {
              const a = nodeById.get(e.from);
              const b = nodeById.get(e.to);
              if (!a || !b) return null;
              const mx = (a.x + b.x) / 2;
              return (
                <path
                  key={`${e.from}-${e.to}-${i}`}
                  d={`M ${a.x + 68} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x - 68} ${b.y}`}
                  fill="none"
                  stroke="#1e293b"
                  strokeWidth={1.5}
                />
              );
            })}

            {nodes.map((n) => {
              const stroke =
                n.kind === "root"
                  ? "#22d3ee"
                  : n.kind === "asset"
                  ? "#06b6d4"
                  : n.kind === "endpoint"
                  ? "#6366f1"
                  : SEV_COLOR[n.severity || "info"] || "#94a3b8";
              const isSelected = selected?.id === n.id;

              return (
                <g
                  key={n.id}
                  transform={`translate(${n.x - 68}, ${n.y - 18})`}
                  role="button"
                  tabIndex={0}
                  aria-label={`${n.kind}: ${n.label}${n.sublabel ? `, ${n.sublabel}` : ""}`}
                  aria-pressed={isSelected}
                  onClick={() => setSelectedId(n.id)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      setSelectedId(n.id);
                    }
                  }}
                  className="cursor-pointer focus:outline-none focus:ring-2 focus:ring-cyan-400"
                >
                  <title>{`${n.label} — ${n.sublabel}`}</title>
                  <rect
                    width={136}
                    height={36}
                    rx={8}
                    fill="#0f172a"
                    stroke={isSelected ? "#f8fafc" : stroke}
                    strokeWidth={isSelected ? 2 : 1.25}
                  />
                  <g clipPath={`url(#${clipId})`}>
                    <text
                      x={10}
                      y={15}
                      fill="#f1f5f9"
                      fontSize={10.5}
                      fontWeight={600}
                      fontFamily="ui-monospace, monospace"
                    >
                      {n.label}
                    </text>
                    <text x={10} y={28} fill="#94a3b8" fontSize={9}>
                      {n.sublabel}
                    </text>
                  </g>
                </g>
              );
            })}
          </svg>
        </div>

        {selected && (
          <div className="border-t border-slate-800 bg-slate-900/95 px-4 py-2.5 text-xs">
            <div className="flex items-center justify-between mb-1 gap-2">
              <span className="font-semibold text-cyan-300 uppercase truncate">
                {selected.kind}: {selected.label}
              </span>
              <div className="flex items-center gap-3 shrink-0">
                {selected.pivotUrl && onPivotTarget && (
                  <button
                    type="button"
                    onClick={() => onPivotTarget(selected.pivotUrl!)}
                    className="flex items-center gap-1 rounded px-1 text-emerald-400 hover:text-emerald-300 font-semibold focus:outline-none focus:ring-2 focus:ring-emerald-500"
                  >
                    <Send className="w-3 h-3" /> Send to Tool Runner
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setSelectedId(null)}
                  className="rounded px-1 text-slate-400 hover:text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                >
                  Close
                </button>
              </div>
            </div>
            <pre className="text-[11px] text-slate-300 max-h-24 overflow-auto">
              {JSON.stringify(selected.raw, null, 2)}
            </pre>
          </div>
        )}
      </div>
    );
  }
);

AttackGraph.displayName = "AttackGraph";
