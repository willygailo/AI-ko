import React, { useMemo, useState } from "react";
import { AssetItem, EndpointItem, FindingItem } from "../api/client";

interface Props {
  engagementName: string;
  assets: AssetItem[];
  endpoints: EndpointItem[];
  findings: FindingItem[];
}

interface GraphNode {
  id: string;
  label: string;
  sublabel?: string;
  kind: "root" | "asset" | "endpoint" | "finding";
  severity?: string;
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
}) => {
  const [selected, setSelected] = useState<GraphNode | null>(null);

  const { nodes, edges, height } = useMemo(() => {
    const gNodes: GraphNode[] = [];
    const gEdges: GraphEdge[] = [];

    const displayAssets = assets.slice(0, 8);
    const displayEndpoints = endpoints.slice(0, 14);
    const displayFindings = findings.filter((f) => f.status !== "false_positive").slice(0, 12);

    const maxRows = Math.max(displayAssets.length, displayEndpoints.length, displayFindings.length, 2);
    const canvasHeight = Math.max(360, maxRows * 46 + 60);

    const rootNode: GraphNode = {
      id: "root",
      label: engagementName || "Engagement",
      sublabel: "Scope Root",
      kind: "root",
      x: 90,
      y: canvasHeight / 2,
      raw: { engagementName },
    };
    gNodes.push(rootNode);

    const colX = { asset: 270, endpoint: 495, finding: 720 };

    displayAssets.forEach((a, idx) => {
      const y = ((idx + 1) / (displayAssets.length + 1)) * canvasHeight;
      const nid = `asset-${a.id}`;
      gNodes.push({
        id: nid,
        label: a.value.length > 22 ? a.value.slice(0, 20) + "…" : a.value,
        sublabel: `${a.asset_type}${a.status_code ? ` • ${a.status_code}` : ""}`,
        kind: "asset",
        x: colX.asset,
        y,
        raw: a,
      });
      gEdges.push({ from: "root", to: nid });
    });

    displayEndpoints.forEach((ep, idx) => {
      const y = ((idx + 1) / (displayEndpoints.length + 1)) * canvasHeight;
      const nid = `ep-${ep.id}`;
      const shortPath = ep.path.length > 24 ? ep.path.slice(0, 22) + "…" : ep.path;
      gNodes.push({
        id: nid,
        label: `${ep.method} ${shortPath}`,
        sublabel: ep.query_params.length ? `params: ${ep.query_params.join(",")}` : ep.source,
        kind: "endpoint",
        x: colX.endpoint,
        y,
        raw: ep,
      });
      // Link to matching asset host if found, otherwise root
      let parentId = "root";
      for (const a of displayAssets) {
        if (ep.url.includes(a.value)) {
          parentId = `asset-${a.id}`;
          break;
        }
      }
      gEdges.push({ from: parentId, to: nid });
    });

    displayFindings.forEach((f, idx) => {
      const y = ((idx + 1) / (displayFindings.length + 1)) * canvasHeight;
      const nid = `find-${f.id}`;
      gNodes.push({
        id: nid,
        label: f.title.length > 22 ? f.title.slice(0, 20) + "…" : f.title,
        sublabel: `${f.severity.toUpperCase()}${f.cwe_id ? ` • ${f.cwe_id}` : ""}`,
        kind: "finding",
        severity: f.severity,
        x: colX.finding,
        y,
        raw: f,
      });
      let parentId = displayAssets[0] ? `asset-${displayAssets[0].id}` : "root";
      for (const ep of displayEndpoints) {
        if (f.target_url.startsWith(ep.url) || f.target_url.includes(ep.path)) {
          parentId = `ep-${ep.id}`;
          break;
        }
      }
      gEdges.push({ from: parentId, to: nid });
    });

    return { nodes: gNodes, edges: gEdges, height: canvasHeight };
  }, [engagementName, assets, endpoints, findings]);

  const nodeById = useMemo(() => {
    const map = new Map<string, GraphNode>();
    nodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [nodes]);

  return (
    <div className="flex flex-col h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800 bg-slate-900">
        <div className="flex items-center gap-3">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Attack-Surface Graph
          </span>
          <span className="text-xs text-slate-400">
            {assets.length} assets • {endpoints.length} endpoints • {findings.length} findings
          </span>
        </div>
        <div className="flex items-center gap-3 text-[11px] text-slate-400">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyan-400" />Asset</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-indigo-400" />Endpoint</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-400" />Finding</span>
        </div>
      </div>

      <div className="relative flex-1 overflow-auto bg-[#070b14]">
        <svg viewBox={`0 0 840 ${height}`} className="w-full min-w-[700px]" style={{ height }}>
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
            <span className="font-semibold text-cyan-300 uppercase">{selected.kind}: {selected.label}</span>
            <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-white">
              Close
            </button>
          </div>
          <pre className="text-[11px] text-slate-300 max-h-24 overflow-auto">
            {JSON.stringify(selected.raw, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
