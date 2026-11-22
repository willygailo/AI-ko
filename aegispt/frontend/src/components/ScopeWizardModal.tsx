import React, { useState } from "react";
import { Plus, X, Lock } from "lucide-react";
import { LLMProfileItem, api } from "../api/client";

interface Props {
  profiles: LLMProfileItem[];
  onCreated: (id: string) => Promise<void>;
  onClose: () => void;
}

export const ScopeWizardModal: React.FC<Props> = ({ profiles, onCreated, onClose }) => {
  const [name, setName] = useState("Local Juice Shop Assessment");
  const [objective, setObjective] = useState("Comprehensive Web Application & API Security Assessment");
  const [urlsText, setUrlsText] = useState("http://127.0.0.1:3000");
  const [domainsText, setDomainsText] = useState("");
  const [excludedPathsText, setExcludedPathsText] = useState("/logout\n/billing");
  const [headersText, setHeadersText] = useState("");
  const [cookiesText, setCookiesText] = useState("");
  const [showAuthVault, setShowAuthVault] = useState(false);
  const [mode, setMode] = useState<"tiered" | "copilot" | "lab_autopilot">("tiered");
  const [tier2Auto, setTier2Auto] = useState(true);
  const [allowPrivateIps, setAllowPrivateIps] = useState(true);
  const [maxRps, setMaxRps] = useState(15);
  const [llmProfileId, setLlmProfileId] = useState<string>(profiles[0]?.id || "");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const splitLines = (txt: string) =>
    txt
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);

  const parseKVLines = (txt: string, sep: ":" | "=") => {
    const out: Record<string, string> = {};
    for (const raw of txt.split("\n")) {
      const line = raw.trim();
      if (!line) continue;
      const idx = line.indexOf(sep);
      if (idx > 0) {
        out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      }
    }
    return out;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const created = await api.createEngagement({
        name,
        objective,
        autonomy_mode: mode,
        tier2_auto: tier2Auto,
        max_steps: 20,
        llm_profile_id: llmProfileId || null,
        scope: {
          allowed_urls: splitLines(urlsText),
          allowed_domains: splitLines(domainsText),
          excluded_paths: splitLines(excludedPathsText),
          custom_headers: parseKVLines(headersText, ":"),
          auth_cookies: parseKVLines(cookiesText, "="),
          max_rps: maxRps,
          allow_private_ips: allowPrivateIps,
        },
      });
      await onCreated(created.id);
      onClose();
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden"
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Plus className="w-4 h-4 text-cyan-400" /> New Scoped Engagement
          </h2>
          <button type="button" onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-3.5 text-xs max-h-[75vh] overflow-y-auto">
          <div>
            <label className="block text-slate-300 font-medium mb-1">Engagement Name</label>
            <input
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white"
            />
          </div>

          <div>
            <label className="block text-slate-300 font-medium mb-1">Assessment Objective</label>
            <input
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Allowlisted URLs</label>
              <textarea
                rows={3}
                value={urlsText}
                onChange={(e) => setUrlsText(e.target.value)}
                placeholder="https://staging.example.com"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 font-mono text-cyan-300"
              />
            </div>
            <div>
              <label className="block text-slate-300 font-medium mb-1">Allowlisted Domains (optional)</label>
              <textarea
                rows={3}
                value={domainsText}
                onChange={(e) => setDomainsText(e.target.value)}
                placeholder="*.staging.example.com"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 font-mono text-cyan-300"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Excluded Paths</label>
              <textarea
                rows={2}
                value={excludedPathsText}
                onChange={(e) => setExcludedPathsText(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 font-mono text-slate-300"
              />
            </div>
            <div className="space-y-2">
              <label className="block text-slate-300 font-medium">Autonomy Mode</label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value as typeof mode)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white"
              >
                <option value="tiered">Tiered Autonomy (Recommended)</option>
                <option value="copilot">Interactive Copilot (Approve Every Tool)</option>
                <option value="lab_autopilot">Isolated Lab Autopilot (Unattended)</option>
              </select>
              <div className="flex items-center gap-3 pt-1">
                <label className="flex items-center gap-1.5 text-slate-300">
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

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Max RPS</label>
              <input
                type="number"
                min={1}
                max={100}
                value={maxRps}
                onChange={(e) => setMaxRps(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white"
              />
            </div>
            <div>
              <label className="block text-slate-300 font-medium mb-1">LLM Profile</label>
              <select
                value={llmProfileId}
                onChange={(e) => setLlmProfileId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white"
              >
                <option value="">Default Settings</option>
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.reasoning_model})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="border border-slate-800 rounded-xl bg-slate-950/60">
            <button
              type="button"
              onClick={() => setShowAuthVault(!showAuthVault)}
              className="w-full flex items-center justify-between px-3 py-2 text-slate-300 hover:text-white font-medium"
            >
              <span className="flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-cyan-400" /> Auth Headers & Session Cookies (Optional)
              </span>
              <span className="text-[11px] text-slate-500">{showAuthVault ? "Hide" : "Configure"}</span>
            </button>
            {showAuthVault && (
              <div className="p-3 pt-1 grid grid-cols-1 md:grid-cols-2 gap-3 border-t border-slate-800">
                <div>
                  <label className="block text-slate-400 mb-1">Headers (Key: Value per line)</label>
                  <textarea
                    rows={3}
                    value={headersText}
                    onChange={(e) => setHeadersText(e.target.value)}
                    placeholder="Authorization: Bearer eyJ..."
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 font-mono text-[11px] text-slate-200"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Cookies (name=value per line)</label>
                  <textarea
                    rows={3}
                    value={cookiesText}
                    onChange={(e) => setCookiesText(e.target.value)}
                    placeholder="session_id=abc123"
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 font-mono text-[11px] text-slate-200"
                  />
                </div>
              </div>
            )}
          </div>

          <label className="flex items-center gap-2 text-slate-300">
            <input
              type="checkbox"
              checked={tier2Auto}
              onChange={(e) => setTier2Auto(e.target.checked)}
            />
            Auto-approve bounded Tier 2 scans (ffuf, arjun, safe nuclei, nmap); always gate Tier 3
          </label>

          {error && <div className="text-red-400 bg-red-950/40 border border-red-800 rounded p-2">{error}</div>}
        </div>

        <div className="flex justify-end gap-2 px-5 py-3.5 bg-slate-950 border-t border-slate-800">
          <button type="button" onClick={onClose} className="px-3.5 py-2 text-xs text-slate-400 hover:text-white">
            Cancel
          </button>
          <button
            disabled={loading}
            type="submit"
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
          >
            {loading ? "Creating..." : "Create Engagement"}
          </button>
        </div>
      </form>
    </div>
  );
};
