import React, { useMemo, useState } from "react";
import { Search, ZoomIn, ZoomOut, Send } from "lucide-react";
import { AssetItem, EndpointItem, FindingItem } from "../api/client";

interface Props {
  engagementName: string;
  assets: AssetItem[];
  endpoints: EndpointItem[];
  findings: FindingItem[];
  onPivotTarget?: (url: string) => void;
}

interface GraphNode {
  id: string;
  label: string;
  sublabel?: string;
  kind: "root" | "asset" | "endpoint" | "finding";
  severity?: string;
  pivotUrl?: string;
  x: number;
  y: number;
  raw: unknown;
}

interface GraphEdge {
  from: string;
  to: string;
}

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#38bdf8",
  info: "#94a3b8",
};

export const AttackGraph: React.FC<Props> = ({
  engagementName,
  assets,
  endpoints,
  findings,
  onPivotTarget,
}) => {
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [query, setQuery] = useState("");
  const [zoom, setZoom] = useState(1);

  const { nodes, edges, height } = useMemo(() => {
    const q = query.trim().toLowerCase();
    const gNodes: GraphNode[] = [];
    const gEdges: GraphEdge[] = [];

    const filteredAssets = assets
      .filter(
        (a) =>
          !q ||
          a.value.toLowerCase().includes(q) ||
          (a.technologies || []).some((t) => t.toLowerCase().includes(q))
      )
      .slice(0, 14);
    const filteredEndpoints = endpoints
      .filter(
        (ep) =>
          !q ||
          ep.url.toLowerCase().includes(q) ||
          ep.path.toLowerCase().includes(q) ||
          ep.query_params.some((p) => p.toLowerCase().includes(q))
      )
      .slice(0, 22);
    const filteredFindings = findings
      .filter((f) => f.status !== "false_positive")
      .filter((f) => !q || f.title.toLowerCase().includes(q) || f.target_url.toLowerCase().includes(q))
      .slice(0, 16);

    const maxRows = Math.max(filteredAssets.length, filteredEndpoints.length, filteredFindings.length, 2);
    const canvasHeight = Math.max(380, maxRows * 46 + 64);

    gNodes.push({
      id: "root",
      label: engagementName || "Engagement",
      sublabel: "Scope Root",
      kind: "root",
      x: 90,
      y: canvasHeight / 2,
      raw: { engagementName },
    });

    const colX = { asset: 270, endpoint: 495, finding: 720 };

    filteredAssets.forEach((a, idx) => {
      const y = ((idx + 1) / (filteredAssets.length + 1)) * canvasHeight;
      const nid = `asset-${a.id}`;
      gNodes.push({
        id: nid,
        label: a.value.length > 22 ? a.value.slice(0, 20) + "…" : a.value,
        sublabel: `${a.asset_type}${a.status_code ? ` • ${a.status_code}` : ""}`,
        kind: "asset",
        pivotUrl: a.value.includes("://") ? a.value : `https://${a.value}`,
        x: colX.asset,
        y,
        raw: a,
      });
      gEdges.push({ from: "root", to: nid });
    });

    filteredEndpoints.forEach((ep, idx) => {
      const y = ((idx + 1) / (filteredEndpoints.length + 1)) * canvasHeight;
      const nid = `ep-${ep.id}`;
      const shortPath = ep.path.length > 24 ? ep.path.slice(0, 22) + "…" : ep.path;
      gNodes.push({
        id: nid,
        label: `${ep.method} ${shortPath}`,
        sublabel: ep.query_params.length ? `params: ${ep.query_params.join(",")}` : ep.source,
        kind: "endpoint",
        pivotUrl: ep.url,
        x: colX.endpoint,
        y,
        raw: ep,
      });
      let parentId = "root";
      for (const a of filteredAssets) {
        if (ep.url.includes(a.value)) {
          parentId = `asset-${a.id}`;
          break;
        }
      }
      gEdges.push({ from: parentId, to: nid });
    });

    filteredFindings.forEach((f, idx) => {
      const y = ((idx + 1) / (filteredFindings.length + 1)) * canvasHeight;
      const nid = `find-${f.id}`;
      gNodes.push({
        id: nid,
        label: f.title.length > 22 ? f.title.slice(0, 20) + "…" : f.title,
        sublabel: `${f.severity.toUpperCase()}${f.cwe_id ? ` • ${f.cwe_id}` : ""}`,
        kind: "finding",
        severity: f.severity,
        pivotUrl: f.target_url,
        x: colX.finding,
        y,
        raw: f,
      });
      let parentId = filteredAssets[0] ? `asset-${filteredAssets[0].id}` : "root";
      for (const ep of filteredEndpoints) {
        if (f.target_url.startsWith(ep.url) || f.target_url.includes(ep.path)) {
          parentId = `ep-${ep.id}`;
          break;
        }
      }
      gEdges.push({ from: parentId, to: nid });
    });

    return { nodes: gNodes, edges: gEdges, height: canvasHeight };
  }, [engagementName, assets, endpoints, findings, query]);

  const nodeById = useMemo(() => {
    const map = new Map<string, GraphNode>();
    nodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [nodes]);

  return (
    <div className="flex flex-col h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 border-b border-slate-800 bg-slate-900">
        <div className="flex items-center gap-3">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Attack-Surface Graph
          </span>
          <span className="text-[11px] text-slate-400">
            {assets.length} assets • {endpoints.length} endpoints • {findings.length} findings
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2 py-1">
            <Search className="w-3.5 h-3.5 text-slate-500" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter nodes..."
              className="bg-transparent text-[11px] text-slate-200 focus:outline-none w-28"
            />
          </div>
          <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-lg px-1.5 py-0.5 text-[11px]">
            <button
              onClick={() => setZoom((z) => Math.max(0.7, Number((z - 0.15).toFixed(2))))}
              className="p-0.5 text-slate-400 hover:text-white"
              title="Zoom out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button onClick={() => setZoom(1)} className="px-1 text-slate-300 font-mono">
              {Math.round(zoom * 100)}%
            </button>
            <button
              onClick={() => setZoom((z) => Math.min(1.6, Number((z + 0.15).toFixed(2))))}
              className="p-0.5 text-slate-400 hover:text-white"
              title="Zoom in"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      <div className="relative flex-1 overflow-auto bg-[#070b14]">
        <svg
          viewBox={`0 0 840 ${height}`}
          style={{ width: `${Math.round(840 * zoom)}px`, height: `${Math.round(height * zoom)}px` }}
        >
          {edges.map((e, i) => {
            const a = nodeById.get(e.from);
            const b = nodeById.get(e.to);
            if (!a || !b) return null;
            const mx = (a.x + b.x) / 2;
            return (
              <path
                key={i}
                d={`M ${a.x + 64} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x - 64} ${b.y}`}
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

            return (
              <g
                key={n.id}
                transform={`translate(${n.x - 68}, ${n.y - 18})`}
                onClick={() => setSelected(n)}
                className="cursor-pointer"
              >
                <rect
                  width={136}
                  height={36}
                  rx={8}
                  fill="#0f172a"
                  stroke={selected?.id === n.id ? "#f8fafc" : stroke}
                  strokeWidth={selected?.id === n.id ? 2 : 1.25}
                />
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
            );
          })}
        </svg>
      </div>

      {selected && (
        <div className="border-t border-slate-800 bg-slate-900/95 px-4 py-2.5 text-xs">
          <div className="flex items-center justify-between mb-1">
            <span className="font-semibold text-cyan-300 uppercase">
              {selected.kind}: {selected.label}
            </span>
            <div className="flex items-center gap-3">
              {selected.pivotUrl && onPivotTarget && (
                <button
                  onClick={() => onPivotTarget(selected.pivotUrl!)}
                  className="flex items-center gap-1 text-emerald-400 hover:text-emerald-300 font-semibold"
                >
                  <Send className="w-3 h-3" /> Send to Tool Runner
                </button>
              )}
              <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-white">
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
};
