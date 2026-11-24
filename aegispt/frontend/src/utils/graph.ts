import type { AssetItem, EndpointItem, FindingItem } from "../api/client.ts";

export interface GraphNode {
  id: string;
  label: string;
  sublabel: string;
  kind: "root" | "asset" | "endpoint" | "finding";
  severity?: string;
  pivotUrl?: string;
  x: number;
  y: number;
  raw: unknown;
}

export interface GraphEdge {
  from: string;
  to: string;
}

export interface AttackGraphLayout {
  nodes: GraphNode[];
  edges: GraphEdge[];
  height: number;
  totals: { assets: number; endpoints: number; findings: number };
  shown: { assets: number; endpoints: number; findings: number };
}

export const GRAPH_LIMITS = {
  assets: 14,
  endpoints: 22,
  findings: 16,
} as const;

export function truncateText(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  if (maxLen <= 1) return text.slice(0, maxLen);
  return `${text.slice(0, maxLen - 1)}…`;
}

export function parseSafeUrl(raw: string): URL | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    return new URL(trimmed);
  } catch {
    if (!trimmed.includes("://") && !trimmed.startsWith("/")) {
      try {
        return new URL(`http://${trimmed}`);
      } catch {
        return null;
      }
    }
    return null;
  }
}

export function normalizePathname(pathname: string): string {
  const clean = pathname || "/";
  if (clean.length > 1 && clean.endsWith("/")) {
    return clean.slice(0, -1);
  }
  return clean;
}

function effectivePort(u: URL): string {
  if (u.port) return u.port;
  return u.protocol === "https:" ? "443" : "80";
}

function assetMatchesUrl(asset: AssetItem, targetUrl: URL): boolean {
  const assetVal = asset.value.trim();
  if (!assetVal) return false;
  const hasScheme = assetVal.includes("://");
  const parsedAsset = parseSafeUrl(assetVal);
  if (!parsedAsset) return false;

  const sameHost = parsedAsset.hostname.toLowerCase() === targetUrl.hostname.toLowerCase();
  if (!sameHost) return false;

  if (hasScheme) {
    return (
      parsedAsset.protocol === targetUrl.protocol &&
      effectivePort(parsedAsset) === effectivePort(targetUrl)
    );
  }
  // Host-only asset (e.g. "example.com" or "example.com:3000")
  if (parsedAsset.port) {
    return parsedAsset.port === effectivePort(targetUrl);
  }
  return true;
}

export function matchEndpointParentAsset(endpoint: EndpointItem, assets: readonly AssetItem[]): string {
  const epUrl = parseSafeUrl(endpoint.url);
  if (!epUrl) return "root";

  // Prefer exact origin match first (assets with explicit scheme)
  for (const a of assets) {
    if (a.value.includes("://") && assetMatchesUrl(a, epUrl)) {
      return `asset-${a.id}`;
    }
  }
  // Fall back to host-only asset match
  for (const a of assets) {
    if (!a.value.includes("://") && assetMatchesUrl(a, epUrl)) {
      return `asset-${a.id}`;
    }
  }
  return "root";
}

export function matchFindingParent(
  finding: FindingItem,
  endpoints: readonly EndpointItem[],
  assets: readonly AssetItem[]
): string {
  const fUrl = parseSafeUrl(finding.target_url);
  if (fUrl) {
    const fPath = normalizePathname(fUrl.pathname);

    // 1. Exact origin + exact pathname match
    for (const ep of endpoints) {
      const epUrl = parseSafeUrl(ep.url);
      if (!epUrl) continue;
      if (epUrl.origin === fUrl.origin && normalizePathname(epUrl.pathname) === fPath) {
        return `ep-${ep.id}`;
      }
    }

    // 2. Same origin + longest non-root prefix pathname segment match
    let bestEpId: string | null = null;
    let bestPrefixLen = -1;
    for (const ep of endpoints) {
      const epUrl = parseSafeUrl(ep.url);
      if (!epUrl || epUrl.origin !== fUrl.origin) continue;
      const epPath = normalizePathname(epUrl.pathname);
      // Never allow root "/" to capture deeper paths like "/api/users"
      if (epPath === "/" && fPath !== "/") continue;
      const isSegmentPrefix = fPath === epPath || fPath.startsWith(`${epPath}/`);
      if (isSegmentPrefix && epPath.length > bestPrefixLen) {
        bestPrefixLen = epPath.length;
        bestEpId = `ep-${ep.id}`;
      }
    }
    if (bestEpId) return bestEpId;

    // 3. Fall back to matching asset by origin/host
    for (const a of assets) {
      if (a.value.includes("://") && assetMatchesUrl(a, fUrl)) {
        return `asset-${a.id}`;
      }
    }
    for (const a of assets) {
      if (!a.value.includes("://") && assetMatchesUrl(a, fUrl)) {
        return `asset-${a.id}`;
      }
    }
  }

  return "root";
}

export function buildAttackGraphLayout(
  engagementName: string,
  assets: readonly AssetItem[],
  endpoints: readonly EndpointItem[],
  findings: readonly FindingItem[],
  query: string
): AttackGraphLayout {
  const q = query.trim().toLowerCase();
  const gNodes: GraphNode[] = [];
  const gEdges: GraphEdge[] = [];

  const matchedAssets = assets.filter(
    (a) =>
      !q ||
      a.value.toLowerCase().includes(q) ||
      (a.technologies || []).some((t) => t.toLowerCase().includes(q))
  );
  const matchedEndpoints = endpoints.filter(
    (ep) =>
      !q ||
      ep.url.toLowerCase().includes(q) ||
      ep.path.toLowerCase().includes(q) ||
      ep.query_params.some((p) => p.toLowerCase().includes(q)) ||
      ep.body_params.some((p) => p.toLowerCase().includes(q))
  );
  const matchedFindings = findings
    .filter((f) => f.status !== "false_positive")
    .filter((f) => !q || f.title.toLowerCase().includes(q) || f.target_url.toLowerCase().includes(q));

  const filteredAssets = matchedAssets.slice(0, GRAPH_LIMITS.assets);
  const filteredEndpoints = matchedEndpoints.slice(0, GRAPH_LIMITS.endpoints);
  const filteredFindings = matchedFindings.slice(0, GRAPH_LIMITS.findings);

  const maxRows = Math.max(filteredAssets.length, filteredEndpoints.length, filteredFindings.length, 2);
  const canvasHeight = Math.max(380, maxRows * 46 + 64);

  gNodes.push({
    id: "root",
    label: truncateText(engagementName || "Engagement", 18),
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
    const defaultScheme =
      /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|localhost$)/i.test(a.value) ||
      /\.(htb|thm|local|internal|lan|ctf)$/i.test(a.value)
        ? "http"
        : "https";
    gNodes.push({
      id: nid,
      label: truncateText(a.value, 18),
      sublabel: truncateText(`${a.asset_type}${a.status_code ? ` • ${a.status_code}` : ""}`, 22),
      kind: "asset",
      pivotUrl: a.value.includes("://") ? a.value : `${defaultScheme}://${a.value}`,
      x: colX.asset,
      y,
      raw: a,
    });
    gEdges.push({ from: "root", to: nid });
  });

  filteredEndpoints.forEach((ep, idx) => {
    const y = ((idx + 1) / (filteredEndpoints.length + 1)) * canvasHeight;
    const nid = `ep-${ep.id}`;
    const allParams = [...ep.query_params, ...ep.body_params];
    const sub = allParams.length ? `params: ${allParams.join(",")}` : ep.source;
    gNodes.push({
      id: nid,
      label: truncateText(`${ep.method} ${ep.path}`, 18),
      sublabel: truncateText(sub, 22),
      kind: "endpoint",
      pivotUrl: ep.url,
      x: colX.endpoint,
      y,
      raw: ep,
    });
    gEdges.push({ from: matchEndpointParentAsset(ep, filteredAssets), to: nid });
  });

  filteredFindings.forEach((f, idx) => {
    const y = ((idx + 1) / (filteredFindings.length + 1)) * canvasHeight;
    const nid = `find-${f.id}`;
    gNodes.push({
      id: nid,
      label: truncateText(f.title, 18),
      sublabel: truncateText(`${f.severity.toUpperCase()}${f.cwe_id ? ` • ${f.cwe_id}` : ""}`, 22),
      kind: "finding",
      severity: f.severity,
      pivotUrl: f.target_url,
      x: colX.finding,
      y,
      raw: f,
    });
    gEdges.push({ from: matchFindingParent(f, filteredEndpoints, filteredAssets), to: nid });
  });

  return {
    nodes: gNodes,
    edges: gEdges,
    height: canvasHeight,
    totals: {
      assets: matchedAssets.length,
      endpoints: matchedEndpoints.length,
      findings: matchedFindings.length,
    },
    shown: {
      assets: filteredAssets.length,
      endpoints: filteredEndpoints.length,
      findings: filteredFindings.length,
    },
  };
}
