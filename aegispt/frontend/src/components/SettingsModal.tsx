import React, { useEffect, useState } from "react";
import { Settings, X, Cpu, Wrench } from "lucide-react";
import { DoctorResponse, LLMProfileItem, api } from "../api/client";

interface Props {
  profiles: LLMProfileItem[];
  onRefreshProfiles: () => Promise<void>;
  onClose: () => void;
}

export const SettingsModal: React.FC<Props> = ({ profiles, onRefreshProfiles, onClose }) => {
  const [doctor, setDoctor] = useState<DoctorResponse | null>(null);
  const [name, setName] = useState("Remote vLLM Server");
  const [provider, setProvider] = useState<"ollama" | "openai_compat">("openai_compat");
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:8000");
  const [apiKey, setApiKey] = useState("");
  const [fastModel, setFastModel] = useState("qwen2.5:3b");
  const [reasoningModel, setReasoningModel] = useState("qwen2.5-coder:7b");
  const [redactOutbound, setRedactOutbound] = useState(true);
  const [discovered, setDiscovered] = useState<string[]>([]);
  const [probeMsg, setProbeMsg] = useState("");

  useEffect(() => {
    api.doctor().then(setDoctor).catch(() => {});
  }, []);

  const handleDiscover = async () => {
    setProbeMsg("Probing endpoint...");
    try {
      const res = await api.discoverLLMModels({ provider, base_url: baseUrl, api_key: apiKey });
      if (res.reachable) {
        setDiscovered(res.models);
        setProbeMsg(`Connected! Found ${res.models.length} model(s).`);
        if (res.models[0]) {
          setFastModel(res.models[0]);
          setReasoningModel(res.models[res.models.length - 1]);
        }
      } else {
        setProbeMsg(`Unreachable: ${res.error || "connection failed"}`);
      }
    } catch (e) {
      setProbeMsg(String(e));
    }
  };

  const handleAddProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    await api.createLLMProfile({
      name,
      provider,
      base_url: baseUrl,
      api_key: apiKey,
      fast_model: fastModel,
      reasoning_model: reasoningModel,
      redact_outbound: redactOutbound,
      is_default: false,
    });
    await onRefreshProfiles();
    setProbeMsg("Saved LLM profile.");
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
      <div className="w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Settings className="w-4 h-4 text-cyan-400" /> LLM Providers & Kali Toolchain Doctor
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 grid grid-cols-1 md:grid-cols-2 gap-5 text-xs max-h-[78vh] overflow-y-auto">
          <div className="space-y-3">
            <div className="flex items-center gap-2 font-semibold text-slate-200 uppercase">
              <Cpu className="w-4 h-4 text-cyan-400" /> Configured LLM Profiles
            </div>
            <div className="space-y-2">
              {profiles.map((p) => (
                <div key={p.id} className="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white">{p.name}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 uppercase">
                      {p.provider}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono truncate">{p.base_url}</div>
                  <div className="text-[11px] text-slate-300 mt-1">
                    Fast: <code>{p.fast_model}</code> | Reasoning: <code>{p.reasoning_model}</code>
                  </div>
                </div>
              ))}
            </div>

            <form onSubmit={handleAddProfile} className="bg-slate-950/60 border border-slate-800 rounded-xl p-3 space-y-2.5">
              <div className="font-semibold text-slate-300">Add Provider Endpoint</div>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Profile Name"
                className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
              />
              <div className="grid grid-cols-2 gap-2">
                <select
                  value={provider}
                  onChange={(e) => setProvider(e.target.value as typeof provider)}
                  className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                >
                  <option value="ollama">Local Ollama</option>
                  <option value="openai_compat">OpenAI-Compat / vLLM</option>
                </select>
                <button
                  type="button"
                  onClick={handleDiscover}
                  className="bg-slate-800 hover:bg-slate-700 rounded px-2.5 py-1.5 text-cyan-300 font-medium"
                >
                  Probe Models
                </button>
              </div>
              <input
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="http://127.0.0.1:11434 or https://vllm.local:8000"
                className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 font-mono text-white"
              />
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="Optional API Key"
                className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
              />
              {discovered.length > 0 && (
                <div className="text-[11px] text-emerald-300">Discovered: {discovered.join(", ")}</div>
              )}
              <div className="grid grid-cols-2 gap-2">
                <input
                  value={fastModel}
                  onChange={(e) => setFastModel(e.target.value)}
                  placeholder="Fast model"
                  className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                />
                <input
                  value={reasoningModel}
                  onChange={(e) => setReasoningModel(e.target.value)}
                  placeholder="Reasoning model"
                  className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                />
              </div>
              <label className="flex items-center gap-2 text-slate-300">
                <input
                  type="checkbox"
                  checked={redactOutbound}
                  onChange={(e) => setRedactOutbound(e.target.checked)}
                />
                Redact Bearer tokens/cookies/JWTs on remote endpoints
              </label>
              {probeMsg && <div className="text-[11px] text-cyan-300">{probeMsg}</div>}
              <button
                type="submit"
                className="w-full py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold"
              >
                Save LLM Profile
              </button>
            </form>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 font-semibold text-slate-200 uppercase">
                <Wrench className="w-4 h-4 text-cyan-400" /> Kali Toolchain Status
              </span>
              {doctor && (
                <span className="text-emerald-400 font-semibold">
                  {doctor.tools_available}/{doctor.tools_total} Ready
                </span>
              )}
            </div>
            <div className="bg-slate-950 border border-slate-800 rounded-xl divide-y divide-slate-800/70 max-h-96 overflow-y-auto">
              {(doctor?.tools || []).map((t) => (
                <div key={t.name} className="flex items-center justify-between px-3 py-2">
                  <div>
                    <div className="font-mono font-semibold text-slate-100">
                      {t.name}{" "}
                      <span className="text-[10px] text-slate-400 font-sans">Tier {t.tier}</span>
                    </div>
                    <div className="text-[10px] text-slate-500 truncate max-w-[230px]">
                      {t.resolved_path || "missing"}
                    </div>
                  </div>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      t.available
                        ? "bg-emerald-500/20 text-emerald-300"
                        : "bg-red-500/20 text-red-300"
                    }`}
                  >
                    {t.available ? "READY" : "MISSING"}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
