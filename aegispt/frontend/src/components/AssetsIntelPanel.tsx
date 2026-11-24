import { useMemo, useState } from "react";
import { Check, Copy, Eye, EyeOff, Globe, KeyRound, Network, Play, Search, Server, ShieldAlert } from "lucide-react";
import type { AssetItem, IntelItem, OpenPortRecord, ScopePolicy } from "../api/client";

interface AssetsIntelPanelProps {
  engagementId: string;
  scope?: ScopePolicy;
  assets: AssetItem[];
  openPorts?: OpenPortRecord[];
  intel?: IntelItem[];
  onPivotRepeater: (url: string) => void;
  onSelectFinding?: (findingId: string) => void;
}

type IntelCategoryFilter = "all" | "flag" | "key" | "credential" | "identifier" | "name" | "number";

const CAT_BADGE: Record<string, string> = {
  flag: "bg-rose-500/20 text-rose-300 border-rose-500/40",
  key: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  credential: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  identifier: "bg-sky-500/20 text-sky-300 border-sky-500/40",
  name: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  number: "bg-violet-500/20 text-violet-300 border-violet-500/40",
};

function inferSeedUrlForAsset(a: AssetItem, ports: OpenPortRecord[]): string {
  if (a.value.includes("://")) return a.value;
  const host = a.value.includes(":") && !a.value.startsWith("[") ? `[${a.value}]` : a.value;
  const webPort = ports.find(
    (p) => [80, 443, 3000, 5000, 8000, 8008, 8080, 8443, 8888, 9000].includes(Number(p.port)) || p.service.toLowerCase().includes("http"),
  );
  const pNum = webPort ? Number(webPort.port) : null;
  const isLab =
    /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|localhost$)/i.test(a.value) ||
    /\.(htb|thm|local|internal|lan|ctf)$/i.test(a.value);
  const scheme = pNum === 443 || pNum === 8443 || webPort?.service.toLowerCase().includes("https") ? "https" : isLab || (pNum !== null && pNum !== 443) ? "http" : "https";
  if (pNum && !((scheme === "http" && pNum === 80) || (scheme === "https" && pNum === 443))) {
    return `${scheme}://${host}:${pNum}`;
  }
  return `${scheme}://${host}`;
}

export function AssetsIntelPanel({
  engagementId,
  scope,
  assets,
  openPorts = [],
  intel = [],
  onPivotRepeater,
  onSelectFinding,
}: AssetsIntelPanelProps) {
  const [catFilter, setCatFilter] = useState<IntelCategoryFilter>("all");
  const [search, setSearch] = useState("");
  const [revealSecrets, setRevealSecrets] = useState<boolean>(scope?.allow_private_ips ?? true);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (key: string, value: string) => {
    navigator.clipboard.writeText(value);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const portsByAsset = useMemo(() => {
    const map = new Map<string, OpenPortRecord[]>();
    for (const p of openPorts) {
      if (!p.asset_id) continue;
      const arr = map.get(p.asset_id) || [];
      arr.push(p);
      map.set(p.asset_id, arr);
    }
    return map;
  }, [openPorts]);

  const catCounts = useMemo(() => {
    const counts: Record<IntelCategoryFilter, number> = {
      all: intel.length,
      flag: 0,
      key: 0,
      credential: 0,
      identifier: 0,
      name: 0,
      number: 0,
    };
    for (const item of intel) {
      const c = item.category as IntelCategoryFilter;
      if (c in counts) counts[c] += 1;
    }
    return counts;
  }, [intel]);

  const filteredIntel = useMemo(() => {
    const q = search.trim().toLowerCase();
    return intel.filter((item) => {
      if (catFilter !== "all" && item.category !== catFilter) return false;
      if (!q) return true;
      return (
        item.label.toLowerCase().includes(q) ||
        item.value.toLowerCase().includes(q) ||
        item.location.toLowerCase().includes(q) ||
        item.tool_source.toLowerCase().includes(q) ||
        (item.finding_id || "").toLowerCase().includes(q)
      );
    });
  }, [intel, catFilter, search]);

  return (
    <div className="space-y-4">
      {/* Scope & Engagement ID Summary Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400">Engagement ID:</span>
          <button
            onClick={() => handleCopy("eng-id", engagementId)}
            className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-950 border border-slate-700 font-mono text-sky-300 hover:border-sky-500/60"
            title="Copy Engagement ID"
          >
            {engagementId}
            {copiedKey === "eng-id" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-slate-400" />}
          </button>
          {scope && (
            <>
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                URLs: <strong className="text-white">{scope.allowed_urls.length}</strong>
              </span>
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                Domains: <strong className="text-white">{scope.allowed_domains.length}</strong>
              </span>
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                CIDRs: <strong className="text-white">{scope.allowed_cidrs.length}</strong>
              </span>
              <span
                className={`px-2 py-0.5 rounded border ${
                  scope.allow_private_ips
                    ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
                    : "bg-slate-800 text-slate-400 border-slate-700"
                }`}
              >
                Lab/Private IPs: {scope.allow_private_ips ? "Enabled" : "Disabled"}
              </span>
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                Max RPS: <strong className="text-white">{scope.max_rps}</strong>
              </span>
            </>
          )}
        </div>
        <button
          onClick={() => setRevealSecrets((v) => !v)}
          className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200"
        >
          {revealSecrets ? <EyeOff className="w-3.5 h-3.5 text-amber-400" /> : <Eye className="w-3.5 h-3.5 text-sky-400" />}
          {revealSecrets ? "Mask Keys & Flags" : "Reveal Full Keys & Flags"}
        </button>
      </div>

      {/* Section 1: Assets, IPs, Open Ports & Technologies */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-3 border-b border-slate-800 flex items-center justify-between gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 flex items-center gap-1.5">
            <Server className="w-4 h-4 text-sky-400" />
            Discovered Hosts, IPs &amp; Open Ports ({assets.length} assets / {openPorts.length} ports)
          </h3>
        </div>
        <div className="overflow-x-auto max-h-72 overflow-y-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-slate-950/70 text-slate-400 uppercase text-[10px] sticky top-0">
              <tr>
                <th className="px-3 py-2">Asset ID</th>
                <th className="px-3 py-2">Host / Target</th>
                <th className="px-3 py-2">IP Address</th>
                <th className="px-3 py-2">Status / Title</th>
                <th className="px-3 py-2">Open Ports &amp; Service Versions</th>
                <th className="px-3 py-2">Technologies / WAF</th>
                <th className="px-3 py-2 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {assets.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-slate-500">
                    No assets or open ports recorded yet. Run Auto Assessment or nmap/http_probe.
                  </td>
                </tr>
              )}
              {assets.map((a) => {
                const aPorts = portsByAsset.get(a.id) || [];
                const portTags = (a.technologies || []).filter((t) => t.startsWith("port:"));
                const otherTechs = (a.technologies || []).filter((t) => !t.startsWith("port:"));
                const pivot = inferSeedUrlForAsset(a, aPorts);
                return (
                  <tr key={a.id} className="hover:bg-slate-800/40 align-top">
                    <td className="px-3 py-2 font-mono text-[10px]">
                      <button
                        onClick={() => handleCopy(`asset-${a.id}`, a.id)}
                        className="inline-flex items-center gap-1 text-slate-400 hover:text-sky-300"
                        title={`Copy Asset ID: ${a.id}`}
                      >
                        <span>{a.id.slice(0, 8)}</span>
                        {copiedKey === `asset-${a.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1.5 font-mono text-slate-100">
                        <Globe className="w-3 h-3 text-sky-400 shrink-0" />
                        <span>{a.value}</span>
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5">
                        {a.asset_type} · {a.discovered_by}
                      </div>
                    </td>
                    <td className="px-3 py-2 font-mono text-emerald-300">
                      {a.ip_address ? (
                        <button
                          onClick={() => handleCopy(`ip-${a.id}`, a.ip_address || "")}
                          className="inline-flex items-center gap-1 hover:underline"
                          title="Copy IP Address"
                        >
                          {a.ip_address}
                          {copiedKey === `ip-${a.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-2.5 h-2.5 text-slate-500" />}
                        </button>
                      ) : (
                        <span className="text-slate-600">-</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {a.status_code ? (
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 font-mono text-sky-300 mr-1.5">
                          {a.status_code}
                        </span>
                      ) : null}
                      <span className="text-slate-300">{a.title || "-"}</span>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-1">
                        {aPorts.length > 0
                          ? aPorts.map((p, i) => (
                              <span
                                key={`${p.port}-${p.proto}-${i}`}
                                className="px-1.5 py-0.5 rounded bg-violet-500/15 border border-violet-500/30 text-violet-200 font-mono text-[10px]"
                              >
                                {p.port}/{p.proto}
                                {p.service ? ` ${p.service}` : ""}
                                {p.banner ? ` (${p.banner})` : ""}
                              </span>
                            ))
                          : portTags.length > 0
                            ? portTags.map((pt, i) => (
                                <span
                                  key={i}
                                  className="px-1.5 py-0.5 rounded bg-violet-500/15 border border-violet-500/30 text-violet-200 font-mono text-[10px]"
                                >
                                  {pt.replace(/^port:/, "")}
                                </span>
                              ))
                            : <span className="text-slate-600">-</span>}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-[10px] text-slate-300">
                      {a.waf && <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 mr-1">WAF: {a.waf}</span>}
                      {otherTechs.slice(0, 6).join(", ") || (!a.waf ? "-" : "")}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        onClick={() => onPivotRepeater(pivot)}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded bg-sky-600/20 hover:bg-sky-600/40 text-sky-300 border border-sky-500/30 text-[11px]"
                        title={`Open ${pivot} in Repeater`}
                      >
                        <Play className="w-3 h-3" /> Repeat
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Section 2: Exposed Keys, Flags, IDs, Names, Credentials & Numbers */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-amber-400" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
              Exposed Keys, Flags, IDs, Names &amp; Numbers ({filteredIntel.length})
            </h3>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            {(
              [
                ["all", "All"],
                ["flag", "Flags"],
                ["key", "Keys/Tokens"],
                ["credential", "Creds"],
                ["identifier", "IDs"],
                ["name", "Names/Emails"],
                ["number", "IPs/Ports/Nums"],
              ] as Array<[IntelCategoryFilter, string]>
            ).map(([cid, label]) => (
              <button
                key={cid}
                onClick={() => setCatFilter(cid)}
                className={`px-2 py-1 rounded text-[11px] font-medium transition ${
                  catFilter === cid ? "bg-sky-600 text-white" : "bg-slate-950 text-slate-400 hover:text-white border border-slate-800"
                }`}
              >
                {label} ({catCounts[cid]})
              </button>
            ))}
            <div className="relative ml-1">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-1/2 -translate-y-1/2" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter keys, IDs, flags..."
                className="pl-7 pr-2.5 py-1 text-xs rounded bg-slate-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>
        </div>
        <div className="overflow-x-auto max-h-96 overflow-y-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-slate-950/70 text-slate-400 uppercase text-[10px] sticky top-0">
              <tr>
                <th className="px-3 py-2">Category</th>
                <th className="px-3 py-2">Type / Label</th>
                <th className="px-3 py-2">Exposed Value</th>
                <th className="px-3 py-2">Location / Source</th>
                <th className="px-3 py-2">Finding ID</th>
                <th className="px-3 py-2 text-right">Copy</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filteredIntel.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                    <Network className="w-5 h-5 mx-auto mb-1 text-slate-600" />
                    No exposed keys, flags, IDs, names, or numbers match this filter yet.
                  </td>
                </tr>
              )}
              {filteredIntel.map((item, idx) => {
                const shownVal = revealSecrets || !item.sensitive ? item.value : item.masked_value;
                const copyKey = `intel-${idx}`;
                return (
                  <tr key={`${item.category}-${item.label}-${idx}`} className="hover:bg-slate-800/40">
                    <td className="px-3 py-2">
                      <span
                        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-semibold uppercase ${
                          CAT_BADGE[item.category] || "bg-slate-800 text-slate-300 border-slate-700"
                        }`}
                      >
                        {item.category === "flag" && <ShieldAlert className="w-2.5 h-2.5" />}
                        {item.category}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-200 font-medium">{item.label}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-amber-200 break-all max-w-md">{shownVal}</td>
                    <td className="px-3 py-2 font-mono text-[10px] text-slate-400 max-w-xs truncate" title={item.location}>
                      {item.location || "-"} <span className="text-slate-600">({item.tool_source})</span>
                    </td>
                    <td className="px-3 py-2 font-mono text-[10px]">
                      {item.finding_id ? (
                        <button
                          onClick={() => onSelectFinding?.(item.finding_id!)}
                          className="text-sky-400 hover:underline"
                          title={`Inspect finding ${item.finding_id}`}
                        >
                          {item.finding_id.slice(0, 8)}
                        </button>
                      ) : (
                        <span className="text-slate-600">-</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        onClick={() => handleCopy(copyKey, item.value)}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[10px]"
                        title="Copy raw value"
                      >
                        {copiedKey === copyKey ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        Copy
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
