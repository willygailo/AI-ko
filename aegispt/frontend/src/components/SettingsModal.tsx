import React, { useCallback, useEffect, useId, useState } from "react";
import { Cpu, RefreshCw, Settings, Trash2, Wrench } from "lucide-react";
import { type DoctorResponse, type LLMProfileItem, api } from "../api/client";
import { ConfirmDialog } from "./ConfirmDialog";
import { ModalFrame } from "./ModalFrame";
import type { ToastKind } from "./ToastBar";

interface Props {
  profiles: LLMProfileItem[];
  onRefreshProfiles: () => Promise<void>;
  onClose: () => void;
  onToast?: (kind: ToastKind, text: string) => void;
}

export const SettingsModal: React.FC<Props> = ({
  profiles,
  onRefreshProfiles,
  onClose,
  onToast,
}) => {
  const idPrefix = useId();
  const [doctor, setDoctor] = useState<DoctorResponse | null>(null);
  const [doctorLoading, setDoctorLoading] = useState(true);
  const [doctorError, setDoctorError] = useState("");

  const [name, setName] = useState("Remote vLLM Server");
  const [provider, setProvider] = useState<"ollama" | "openai_compat">("openai_compat");
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:8000");
  const [apiKey, setApiKey] = useState("");
  const [fastModel, setFastModel] = useState("qwen2.5:3b");
  const [reasoningModel, setReasoningModel] = useState("qwen2.5-coder:7b");
  const [redactOutbound, setRedactOutbound] = useState(true);
  const [isDefault, setIsDefault] = useState(false);

  const [discovered, setDiscovered] = useState<string[]>([]);
  const [probeMsg, setProbeMsg] = useState("");
  const [probeBusy, setProbeBusy] = useState(false);
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  const [pendingDelete, setPendingDelete] = useState<LLMProfileItem | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [settingDefaultId, setSettingDefaultId] = useState<string>("");

  const loadDoctor = useCallback(async () => {
    setDoctorLoading(true);
    setDoctorError("");
    try {
      const res = await api.doctor();
      setDoctor(res);
    } catch (err) {
      setDoctorError(err instanceof Error ? err.message : String(err));
    } finally {
      setDoctorLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDoctor();
  }, [loadDoctor]);

  const handleDiscover = async () => {
    setProbeBusy(true);
    setFormError("");
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
    } catch (err) {
      setProbeMsg("");
      setFormError(err instanceof Error ? err.message : String(err));
    } finally {
      setProbeBusy(false);
    }
  };

  const handleAddProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");
    setProbeMsg("");
    setSaving(true);
    try {
      await api.createLLMProfile({
        name: name.trim(),
        provider,
        base_url: baseUrl.trim(),
        api_key: apiKey,
        fast_model: fastModel.trim(),
        reasoning_model: reasoningModel.trim(),
        redact_outbound: redactOutbound,
        is_default: isDefault,
      });
      await onRefreshProfiles();
      setProbeMsg("Saved LLM profile.");
      setApiKey("");
      onToast?.("success", `Saved LLM profile "${name.trim()}".`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setFormError(msg);
      onToast?.("error", msg);
    } finally {
      setSaving(false);
    }
  };

  const handleConfirmDelete = async () => {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      await api.deleteLLMProfile(pendingDelete.id);
      await onRefreshProfiles();
      onToast?.("success", `Deleted LLM profile "${pendingDelete.name}".`);
      setPendingDelete(null);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setFormError(msg);
      onToast?.("error", msg);
    } finally {
      setDeleting(false);
    }
  };

  const handleSetDefault = async (profile: LLMProfileItem) => {
    setFormError("");
    setSettingDefaultId(profile.id);
    try {
      await api.setDefaultLLMProfile(profile.id);
      await onRefreshProfiles();
      onToast?.("success", `"${profile.name}" is now the default LLM profile.`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setFormError(msg);
      onToast?.("error", msg);
    } finally {
      setSettingDefaultId("");
    }
  };

  return (
    <>
      <ModalFrame
        title={
          <>
            <Settings className="w-4 h-4 text-cyan-400" aria-hidden="true" />
            <span>LLM Providers & Kali Toolchain Doctor</span>
          </>
        }
        onClose={onClose}
        disableClose={saving || deleting || settingDefaultId !== "" || Boolean(pendingDelete)}
        maxWidthClass="max-w-3xl"
      >
        <div className="p-5 grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
          <div className="space-y-3">
            <div className="flex items-center gap-2 font-semibold text-slate-200 uppercase">
              <Cpu className="w-4 h-4 text-cyan-400" aria-hidden="true" /> Configured LLM Profiles
            </div>
            <div className="space-y-2">
              {profiles.length === 0 && (
                <div className="text-slate-500 bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  No custom LLM profiles configured yet.
                </div>
              )}
              {profiles.map((p) => (
                <div key={p.id} className="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span className="font-semibold text-white truncate">{p.name}</span>
                      {p.is_default && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold uppercase shrink-0">
                          Default
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 uppercase">
                        {p.provider}
                      </span>
                      {!p.is_default && (
                        <button
                          type="button"
                          disabled={settingDefaultId !== "" || deleting}
                          onClick={() => void handleSetDefault(p)}
                          aria-label={`Set ${p.name} as default LLM profile`}
                          className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-emerald-950/70 disabled:opacity-50 border border-slate-700 hover:border-emerald-700/60 text-[10px] text-slate-300 hover:text-emerald-300 font-medium focus:outline-none focus:ring-2 focus:ring-emerald-400"
                        >
                          {settingDefaultId === p.id ? "Saving..." : "Set Default"}
                        </button>
                      )}
                      <button
                        type="button"
                        disabled={deleting || settingDefaultId !== ""}
                        aria-label={`Delete LLM profile ${p.name}`}
                        title="Delete profile"
                        onClick={() => setPendingDelete(p)}
                        className="p-1 rounded text-slate-400 hover:text-red-300 hover:bg-red-950/50 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-red-400"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono truncate">{p.base_url}</div>
                  <div className="text-[11px] text-slate-300 mt-1">
                    Fast: <code>{p.fast_model}</code> | Reasoning: <code>{p.reasoning_model}</code>
                  </div>
                </div>
              ))}
            </div>

            <form
              onSubmit={(e) => void handleAddProfile(e)}
              className="bg-slate-950/60 border border-slate-800 rounded-xl p-3 space-y-2.5"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-slate-300">Add Provider Endpoint</span>
                <div className="flex gap-1">
                  <button
                    type="button"
                    onClick={() => {
                      setName("Local Ollama");
                      setProvider("ollama");
                      setBaseUrl("http://127.0.0.1:11434");
                      setFastModel("qwen2.5:3b");
                      setReasoningModel("qwen2.5-coder:7b");
                    }}
                    className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[10px] text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    Local
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setName("Ollama Cloud");
                      setProvider("ollama");
                      setBaseUrl("https://ollama.com");
                      setFastModel("qwen3-next:80b");
                      setReasoningModel("qwen3-coder:480b");
                    }}
                    className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[10px] text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    Ollama Cloud
                  </button>
                </div>
              </div>

              <div>
                <label htmlFor={`${idPrefix}-name`} className="block text-[11px] text-slate-400 mb-1">
                  Profile Name
                </label>
                <input
                  id={`${idPrefix}-name`}
                  required
                  minLength={2}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Profile Name"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-2 items-end">
                <div>
                  <label htmlFor={`${idPrefix}-provider`} className="block text-[11px] text-slate-400 mb-1">
                    Provider
                  </label>
                  <select
                    id={`${idPrefix}-provider`}
                    value={provider}
                    onChange={(e) => setProvider(e.target.value as typeof provider)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    <option value="ollama">Ollama (Local / Cloud)</option>
                    <option value="openai_compat">OpenAI-Compat / vLLM</option>
                  </select>
                </div>
                <button
                  type="button"
                  disabled={probeBusy}
                  onClick={() => void handleDiscover()}
                  className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 rounded px-2.5 py-1.5 text-cyan-300 font-medium focus:outline-none focus:ring-2 focus:ring-cyan-500"
                >
                  {probeBusy ? "Probing..." : "Probe Models"}
                </button>
              </div>

              <div>
                <label htmlFor={`${idPrefix}-url`} className="block text-[11px] text-slate-400 mb-1">
                  Endpoint Base URL
                </label>
                <input
                  id={`${idPrefix}-url`}
                  required
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder="http://127.0.0.1:11434 or https://vllm.local:8000"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 font-mono text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>

              <div>
                <label htmlFor={`${idPrefix}-apikey`} className="block text-[11px] text-slate-400 mb-1">
                  API Key (optional)
                </label>
                <input
                  id={`${idPrefix}-apikey`}
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="Optional API Key"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>

              {discovered.length > 0 && (
                <div className="text-[11px] text-emerald-300">Discovered: {discovered.join(", ")}</div>
              )}

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label htmlFor={`${idPrefix}-fast`} className="block text-[11px] text-slate-400 mb-1">
                    Fast Model
                  </label>
                  <input
                    id={`${idPrefix}-fast`}
                    required
                    value={fastModel}
                    onChange={(e) => setFastModel(e.target.value)}
                    placeholder="Fast model"
                    className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  />
                </div>
                <div>
                  <label htmlFor={`${idPrefix}-reason`} className="block text-[11px] text-slate-400 mb-1">
                    Reasoning Model
                  </label>
                  <input
                    id={`${idPrefix}-reason`}
                    required
                    value={reasoningModel}
                    onChange={(e) => setReasoningModel(e.target.value)}
                    placeholder="Reasoning model"
                    className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  />
                </div>
              </div>

              <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={redactOutbound}
                  onChange={(e) => setRedactOutbound(e.target.checked)}
                />
                Redact Bearer tokens/cookies/JWTs on remote endpoints
              </label>

              <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={isDefault}
                  onChange={(e) => setIsDefault(e.target.checked)}
                />
                Set as default LLM profile for new engagements
              </label>

              {probeMsg && <div className="text-[11px] text-cyan-300">{probeMsg}</div>}
              {formError && (
                <div role="alert" className="text-[11px] text-red-400 bg-red-950/40 border border-red-800 rounded p-2">
                  {formError}
                </div>
              )}

              <button
                type="submit"
                disabled={saving}
                className="w-full py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-400"
              >
                {saving ? "Saving..." : "Save LLM Profile"}
              </button>
            </form>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2">
              <span className="flex items-center gap-2 font-semibold text-slate-200 uppercase">
                <Wrench className="w-4 h-4 text-cyan-400" aria-hidden="true" /> Kali Toolchain Status
              </span>
              <div className="flex items-center gap-2">
                {doctor && (
                  <span className="text-emerald-400 font-semibold">
                    {doctor.tools_available}/{doctor.tools_total} Ready
                  </span>
                )}
                <button
                  type="button"
                  disabled={doctorLoading}
                  onClick={() => void loadDoctor()}
                  aria-label="Refresh toolchain diagnostics"
                  className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${doctorLoading ? "animate-spin" : ""}`} />
                </button>
              </div>
            </div>

            {doctorError && (
              <div role="alert" className="text-red-300 bg-red-950/40 border border-red-800 rounded-lg p-3 space-y-2">
                <div>Failed to load diagnostics: {doctorError}</div>
                <button
                  type="button"
                  onClick={() => void loadDoctor()}
                  className="px-2.5 py-1 rounded bg-red-900/60 hover:bg-red-800/70 text-red-100 text-[11px] font-semibold focus:outline-none focus:ring-2 focus:ring-red-400"
                >
                  Retry
                </button>
              </div>
            )}

            {doctor && (
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-[11px] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Active LLM ({doctor.llm.provider})</span>
                  <span className={doctor.llm.reachable ? "text-emerald-400 font-semibold" : "text-amber-300 font-semibold"}>
                    {doctor.llm.reachable ? "REACHABLE" : "UNREACHABLE"}
                  </span>
                </div>
                <div className="font-mono text-slate-300 truncate">{doctor.llm.base_url}</div>
                {doctor.llm.error && <div className="text-amber-300">{doctor.llm.error}</div>}
              </div>
            )}

            <div className="bg-slate-950 border border-slate-800 rounded-xl divide-y divide-slate-800/70 max-h-96 overflow-y-auto">
              {doctorLoading && !doctor && (
                <div className="p-4 text-center text-slate-500">Checking installed tools...</div>
              )}
              {(doctor?.tools || []).map((t) => (
                <div key={t.name} className="flex items-center justify-between px-3 py-2 gap-2">
                  <div className="min-w-0">
                    <div className="font-mono font-semibold text-slate-100">
                      {t.name}{" "}
                      <span className="text-[10px] text-slate-400 font-sans">Tier {t.tier}</span>
                    </div>
                    <div className="text-[10px] text-slate-500 truncate max-w-[230px]" title={t.resolved_path || t.description}>
                      {t.resolved_path || "missing"}
                    </div>
                  </div>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded shrink-0 ${
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
      </ModalFrame>

      {pendingDelete && (
        <ConfirmDialog
          title="Delete LLM Profile"
          message={`Delete LLM profile "${pendingDelete.name}" (${pendingDelete.base_url})? Engagements referencing it will fall back to the default profile.`}
          confirmLabel="Delete Profile"
          busy={deleting}
          onConfirm={handleConfirmDelete}
          onCancel={() => setPendingDelete(null)}
        />
      )}
    </>
  );
};
