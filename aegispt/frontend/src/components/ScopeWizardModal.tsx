import React, { useId, useState } from "react";
import { FlaskConical, Lock, Plus } from "lucide-react";
import { type LLMProfileItem, api } from "../api/client";
import { parseKVLines, splitLines } from "../utils/parsing";
import { ModalFrame } from "./ModalFrame";

interface Props {
  profiles: LLMProfileItem[];
  onCreated: (id: string) => Promise<void>;
  onClose: () => void;
}

export const ScopeWizardModal: React.FC<Props> = ({ profiles, onCreated, onClose }) => {
  const formId = useId();
  const idPrefix = useId();
  const defaultProfileId = profiles.find((p) => p.is_default)?.id ?? "";

  const [name, setName] = useState("");
  const [objective, setObjective] = useState("Comprehensive Web Application & API Security Assessment");
  const [quickTargetsText, setQuickTargetsText] = useState("");
  const [urlsText, setUrlsText] = useState("");
  const [domainsText, setDomainsText] = useState("");
  const [cidrsText, setCidrsText] = useState("");
  const [excludedHostsText, setExcludedHostsText] = useState("");
  const [excludedPathsText, setExcludedPathsText] = useState("/logout\n/billing");
  const [headersText, setHeadersText] = useState("");
  const [cookiesText, setCookiesText] = useState("");
  const [secHeadersText, setSecHeadersText] = useState("");
  const [secCookiesText, setSecCookiesText] = useState("");
  const [showAuthVault, setShowAuthVault] = useState(false);
  const [mode, setMode] = useState<"tiered" | "copilot" | "lab_autopilot">("tiered");
  const [tier2Auto, setTier2Auto] = useState(true);
  const [allowPrivateIps, setAllowPrivateIps] = useState(false);
  const [ctfMode, setCtfMode] = useState(false);
  const [maxRps, setMaxRps] = useState(15);
  const [maxSteps, setMaxSteps] = useState(20);
  const [llmProfileId, setLlmProfileId] = useState<string>(defaultProfileId);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const loadCtfPreset = () => {
    setName("HTB / CTF Lab Box");
    setObjective("CTF & HTB Lab Enumeration: Ports, Flags, Keys, IDs, Credentials & Exploitable Services");
    if (!quickTargetsText.trim() && !urlsText.trim() && !domainsText.trim() && !cidrsText.trim()) {
      setQuickTargetsText("10.10.11.1\nhttp://target.htb");
    }
    setExcludedHostsText("");
    setExcludedPathsText("");
    setMode("lab_autopilot");
    setTier2Auto(true);
    setAllowPrivateIps(true);
    setCtfMode(true);
    setMaxRps(25);
    setMaxSteps(30);
    setError("");
  };

  const loadJuiceShopPreset = () => {
    setName("Local Juice Shop Assessment");
    setObjective("Comprehensive Web Application & API Security Assessment");
    setQuickTargetsText("http://127.0.0.1:3000");
    setUrlsText("http://127.0.0.1:3000");
    setDomainsText("");
    setCidrsText("");
    setExcludedHostsText("");
    setExcludedPathsText("/logout\n/billing");
    setMode("tiered");
    setTier2Auto(true);
    setAllowPrivateIps(true);
    setCtfMode(true);
    setMaxRps(15);
    setMaxSteps(20);
    setError("");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    const quickTargets = splitLines(quickTargetsText);
    const allowedUrls = splitLines(urlsText);
    const allowedDomains = splitLines(domainsText);
    const allowedCidrs = splitLines(cidrsText);
    if (
      quickTargets.length === 0 &&
      allowedUrls.length === 0 &&
      allowedDomains.length === 0 &&
      allowedCidrs.length === 0
    ) {
      setError("Provide at least one target (URL, Domain, IP, IP:Port, or CIDR).");
      return;
    }

    setLoading(true);
    try {
      const created = await api.createEngagement({
        name: name.trim(),
        objective: objective.trim(),
        autonomy_mode: mode,
        tier2_auto: tier2Auto,
        max_steps: Math.min(60, Math.max(1, Math.round(maxSteps) || 20)),
        llm_profile_id: llmProfileId || null,
        scope: {
          targets: quickTargets,
          allowed_urls: allowedUrls,
          allowed_domains: allowedDomains,
          allowed_cidrs: allowedCidrs,
          excluded_hosts: splitLines(excludedHostsText),
          excluded_paths: splitLines(excludedPathsText),
          custom_headers: parseKVLines(headersText, ":"),
          auth_cookies: parseKVLines(cookiesText, "="),
          secondary_headers: parseKVLines(secHeadersText, ":"),
          secondary_cookies: parseKVLines(secCookiesText, "="),
          max_rps: Math.min(100, Math.max(1, Math.round(maxRps) || 15)),
          allow_private_ips: allowPrivateIps || ctfMode,
          ctf_mode: ctfMode,
        },
      });
      await onCreated(created.id);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <ModalFrame
      title={
        <>
          <Plus className="w-4 h-4 text-cyan-400" aria-hidden="true" />
          <span>New Scoped Engagement</span>
        </>
      }
      onClose={onClose}
      disableClose={loading}
      maxWidthClass="max-w-2xl"
      headerExtra={
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={loadCtfPreset}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-950/60 hover:bg-emerald-900/60 border border-emerald-700/60 text-[11px] font-medium text-emerald-300 focus:outline-none focus:ring-2 focus:ring-emerald-500"
          >
            <FlaskConical className="w-3.5 h-3.5" aria-hidden="true" />
            Load HTB / CTF Lab Preset
          </button>
          <button
            type="button"
            onClick={loadJuiceShopPreset}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-[11px] font-medium text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <FlaskConical className="w-3.5 h-3.5" aria-hidden="true" />
            Load Juice Shop Lab Preset
          </button>
        </div>
      }
      footer={
        <>
          <button
            type="button"
            disabled={loading}
            onClick={onClose}
            className="px-3.5 py-2 rounded-lg text-xs text-slate-400 hover:text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            Cancel
          </button>
          <button
            form={formId}
            disabled={loading}
            type="submit"
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-400"
          >
            {loading ? "Creating..." : "Create Engagement"}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={(e) => void handleSubmit(e)} className="p-5 space-y-3.5 text-xs">
        <div>
          <label htmlFor={`${idPrefix}-name`} className="block text-slate-300 font-medium mb-1">
            Engagement Name
          </label>
          <input
            id={`${idPrefix}-name`}
            required
            minLength={2}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Staging API Security Assessment"
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>

        <div>
          <label htmlFor={`${idPrefix}-objective`} className="block text-slate-300 font-medium mb-1">
            Assessment Objective
          </label>
          <input
            id={`${idPrefix}-objective`}
            value={objective}
            onChange={(e) => setObjective(e.target.value)}
            placeholder="Comprehensive Web Application & API Security Assessment"
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>

        <div className="bg-slate-950/80 border border-cyan-900/50 rounded-lg p-3">
          <label htmlFor={`${idPrefix}-quick-targets`} className="block text-cyan-300 font-semibold mb-1">
            Quick Targets — URL, Domain, IP, IP:Port, or CIDR (Recommended for HTB / CTF)
          </label>
          <textarea
            id={`${idPrefix}-quick-targets`}
            rows={2}
            value={quickTargetsText}
            onChange={(e) => {
              const nextVal = e.target.value;
              setQuickTargetsText(nextVal);
              if (/\b(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|localhost)\b|\.(?:htb|thm|local|internal|lan|ctf)\b/i.test(nextVal)) {
                setAllowPrivateIps(true);
              }
            }}
            placeholder="10.10.11.42&#10;10.10.11.42:8080&#10;target.htb&#10;https://app.example.com"
            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 font-mono text-emerald-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
          <p className="text-[10px] text-slate-400 mt-1">
            Automatically splits URLs, domains, bare IPs, ports, and CIDRs; auto-enables private/HTB lab IPs when detected.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label htmlFor={`${idPrefix}-urls`} className="block text-slate-300 font-medium mb-1">
              Allowlisted URLs (optional)
            </label>
            <textarea
              id={`${idPrefix}-urls`}
              rows={2}
              value={urlsText}
              onChange={(e) => setUrlsText(e.target.value)}
              placeholder="https://staging.example.com&#10;http://127.0.0.1:3000"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 font-mono text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label htmlFor={`${idPrefix}-domains`} className="block text-slate-300 font-medium mb-1">
              Allowlisted Domains (optional)
            </label>
            <textarea
              id={`${idPrefix}-domains`}
              rows={2}
              value={domainsText}
              onChange={(e) => setDomainsText(e.target.value)}
              placeholder="*.staging.example.com"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 font-mono text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label htmlFor={`${idPrefix}-cidrs`} className="block text-slate-300 font-medium mb-1">
              Allowlisted CIDRs (optional)
            </label>
            <textarea
              id={`${idPrefix}-cidrs`}
              rows={2}
              value={cidrsText}
              onChange={(e) => setCidrsText(e.target.value)}
              placeholder="10.10.0.0/24"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 font-mono text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label htmlFor={`${idPrefix}-excluded-hosts`} className="block text-slate-300 font-medium mb-1">
              Excluded Hosts (optional)
            </label>
            <textarea
              id={`${idPrefix}-excluded-hosts`}
              rows={2}
              value={excludedHostsText}
              onChange={(e) => setExcludedHostsText(e.target.value)}
              placeholder="prod.example.com&#10;payments.staging.example.com"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 font-mono text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label htmlFor={`${idPrefix}-excluded-paths`} className="block text-slate-300 font-medium mb-1">
              Excluded Paths
            </label>
            <textarea
              id={`${idPrefix}-excluded-paths`}
              rows={2}
              value={excludedPathsText}
              onChange={(e) => setExcludedPathsText(e.target.value)}
              placeholder="/logout&#10;/billing"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 font-mono text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
          <div className="space-y-2">
            <label htmlFor={`${idPrefix}-mode`} className="block text-slate-300 font-medium">
              Autonomy Mode
            </label>
            <select
              id={`${idPrefix}-mode`}
              value={mode}
              onChange={(e) => setMode(e.target.value as typeof mode)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="tiered">Tiered Autonomy (Recommended)</option>
              <option value="copilot">Interactive Copilot (Approve Every Tool)</option>
              <option value="lab_autopilot">Isolated Lab Autopilot (Unattended)</option>
            </select>
            <div className="flex items-center gap-3 pt-1">
              <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={allowPrivateIps}
                  onChange={(e) => setAllowPrivateIps(e.target.checked)}
                />
                Allow Private / Localhost IPs
              </label>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label htmlFor={`${idPrefix}-max-rps`} className="block text-slate-300 font-medium mb-1">
              Max RPS
            </label>
            <input
              id={`${idPrefix}-max-rps`}
              type="number"
              min={1}
              max={100}
              value={maxRps}
              onChange={(e) => setMaxRps(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label htmlFor={`${idPrefix}-max-steps`} className="block text-slate-300 font-medium mb-1">
              Max Steps (1–60)
            </label>
            <input
              id={`${idPrefix}-max-steps`}
              type="number"
              min={1}
              max={60}
              value={maxSteps}
              onChange={(e) => setMaxSteps(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label htmlFor={`${idPrefix}-llm`} className="block text-slate-300 font-medium mb-1">
              LLM Profile
            </label>
            <select
              id={`${idPrefix}-llm`}
              value={llmProfileId}
              onChange={(e) => setLlmProfileId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="">Server Default</option>
              {profiles.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.reasoning_model}){p.is_default ? " [Default]" : ""}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="border border-slate-800 rounded-xl bg-slate-950/60">
          <button
            type="button"
            aria-expanded={showAuthVault}
            onClick={() => setShowAuthVault(!showAuthVault)}
            className="w-full flex items-center justify-between px-3 py-2 rounded-xl text-slate-300 hover:text-white font-medium focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <span className="flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" /> Auth Headers & Session Cookies (Optional)
            </span>
            <span className="text-[11px] text-slate-500">{showAuthVault ? "Hide" : "Configure"}</span>
          </button>
          {showAuthVault && (
            <div className="p-3 pt-2 grid grid-cols-1 md:grid-cols-2 gap-3 border-t border-slate-800">
              <div>
                <label htmlFor={`${idPrefix}-headers`} className="block text-slate-400 mb-1">
                  Headers (Key: Value per line)
                </label>
                <textarea
                  id={`${idPrefix}-headers`}
                  rows={3}
                  value={headersText}
                  onChange={(e) => setHeadersText(e.target.value)}
                  placeholder="Authorization: Bearer eyJ..."
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 font-mono text-[11px] text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>
              <div>
                <label htmlFor={`${idPrefix}-cookies`} className="block text-slate-400 mb-1">
                  Cookies (name=value per line)
                </label>
                <textarea
                  id={`${idPrefix}-cookies`}
                  rows={3}
                  value={cookiesText}
                  onChange={(e) => setCookiesText(e.target.value)}
                  placeholder="session_id=abc123"
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 font-mono text-[11px] text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>
              <div>
                <label htmlFor={`${idPrefix}-sec-headers`} className="block text-slate-400 mb-1">
                  Secondary User/Role Headers (BOLA/IDOR)
                </label>
                <textarea
                  id={`${idPrefix}-sec-headers`}
                  rows={2}
                  value={secHeadersText}
                  onChange={(e) => setSecHeadersText(e.target.value)}
                  placeholder="Authorization: Bearer userB_jwt"
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 font-mono text-[11px] text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>
              <div>
                <label htmlFor={`${idPrefix}-sec-cookies`} className="block text-slate-400 mb-1">
                  Secondary User/Role Cookies
                </label>
                <textarea
                  id={`${idPrefix}-sec-cookies`}
                  rows={2}
                  value={secCookiesText}
                  onChange={(e) => setSecCookiesText(e.target.value)}
                  placeholder="session_id=userB_cookie"
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 font-mono text-[11px] text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>
            </div>
          )}
        </div>

        <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={tier2Auto}
            onChange={(e) => setTier2Auto(e.target.checked)}
          />
          Auto-approve bounded Tier 2 scans (ffuf, arjun, safe nuclei, nmap); always gate Tier 3
        </label>

        {error && (
          <div role="alert" className="text-red-400 bg-red-950/40 border border-red-800 rounded p-2">
            {error}
          </div>
        )}
      </form>
    </ModalFrame>
  );
};
