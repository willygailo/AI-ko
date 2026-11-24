import React, { useEffect, useState } from "react";
import { Check, Copy, Flag, Send } from "lucide-react";
import { type FindingItem, type RepeaterResponse, api } from "../api/client";
import { copyTextToClipboard } from "../utils/clipboard";
import { parseHeaders } from "../utils/parsing";
import type { ToastKind } from "./ToastBar";

interface Props {
  engagementId: string;
  initialUrl: string;
  onFindingCreated: () => Promise<void>;
  onToast?: (kind: ToastKind, text: string) => void;
}

export const RepeaterPanel: React.FC<Props> = ({
  engagementId,
  initialUrl,
  onFindingCreated,
  onToast,
}) => {
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState(initialUrl);
  const [headersText, setHeadersText] = useState("");
  const [body, setBody] = useState("");
  const [useAuth, setUseAuth] = useState(true);
  const [followRedirects, setFollowRedirects] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState("");
  const [response, setResponse] = useState<RepeaterResponse | null>(null);

  const [promoteTitle, setPromoteTitle] = useState("");
  const [promoteSev, setPromoteSev] = useState<FindingItem["severity"]>("medium");
  const [promoting, setPromoting] = useState(false);
  const [promotedMsg, setPromotedMsg] = useState("");
  const [promoteError, setPromoteError] = useState("");
  const [copiedCurl, setCopiedCurl] = useState(false);

  useEffect(() => {
    if (initialUrl) setUrl(initialUrl);
  }, [initialUrl]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setPromotedMsg("");
    setPromoteError("");
    setSending(true);
    try {
      const res = await api.runRepeater(engagementId, {
        method,
        url,
        headers: parseHeaders(headersText),
        body: body || null,
        use_engagement_auth: useAuth,
        follow_redirects: followRedirects,
      });
      setResponse(res);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      onToast?.("error", msg);
    } finally {
      setSending(false);
    }
  };

  const handlePromoteFinding = async () => {
    if (!response || !promoteTitle.trim() || promoting) return;
    setPromoteError("");
    setPromotedMsg("");
    setPromoting(true);
    try {
      await api.createFinding(engagementId, {
        title: promoteTitle.trim(),
        severity: promoteSev,
        target_url: response.final_url || url,
        description: `Verified interactively via Repeater (${method} -> HTTP ${response.status_code}).`,
        evidence: {
          status_code: response.status_code,
          headers: response.headers,
          body_preview: response.body.slice(0, 1200),
        },
        poc_command: response.curl_command,
        remediation: "Review authorization, input validation, and server response handling.",
      });
      setPromotedMsg("Saved finding to engagement!");
      setPromoteTitle("");
      onToast?.("success", "Promoted Repeater response to finding.");
      await onFindingCreated();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setPromoteError(msg);
      onToast?.("error", msg);
    } finally {
      setPromoting(false);
    }
  };

  const handleCopyCurl = async () => {
    if (!response?.curl_command) return;
    const ok = await copyTextToClipboard(response.curl_command);
    if (ok) {
      setCopiedCurl(true);
      setTimeout(() => setCopiedCurl(false), 1500);
    } else {
      onToast?.("error", "Clipboard copy failed.");
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden text-xs min-h-[360px]">
      <form onSubmit={(e) => void handleSend(e)} className="p-3 border-b border-slate-800 bg-slate-900 space-y-2">
        <div className="flex gap-2">
          <select
            aria-label="HTTP method"
            value={method}
            onChange={(e) => setMethod(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-indigo-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            {["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
          <input
            aria-label="Target URL"
            required
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://staging.example.com/api/..."
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
          <button
            disabled={sending}
            type="submit"
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-400"
          >
            <Send className="w-3.5 h-3.5" aria-hidden="true" /> {sending ? "Sending..." : "Send"}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <textarea
            aria-label="Custom request headers"
            rows={2}
            value={headersText}
            onChange={(e) => setHeadersText(e.target.value)}
            placeholder="Custom Headers (Key: Value per line)"
            className="bg-slate-950 border border-slate-800 rounded-lg p-2 font-mono text-[11px] text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
          <textarea
            aria-label="Request body"
            rows={2}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder='Request Body (e.g. {"id": 1})'
            className="bg-slate-950 border border-slate-800 rounded-lg p-2 font-mono text-[11px] text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-300">
          <label className="flex items-center gap-1.5 cursor-pointer">
            <input type="checkbox" checked={useAuth} onChange={(e) => setUseAuth(e.target.checked)} />
            Attach Engagement Auth Headers/Cookies
          </label>
          <label className="flex items-center gap-1.5 cursor-pointer">
            <input
              type="checkbox"
              checked={followRedirects}
              onChange={(e) => setFollowRedirects(e.target.checked)}
            />
            Follow Scope-Checked Redirects
          </label>
        </div>
        {error && (
          <div role="alert" className="text-red-400">
            {error}
          </div>
        )}
      </form>

      <div className="flex-1 overflow-auto p-3 space-y-3 bg-[#070b14]">
        {!response ? (
          <div className="text-slate-500 text-center mt-10">
            Send a scope-validated HTTP request to inspect headers, response body, and promote verified issues to findings.
          </div>
        ) : (
          <>
            <div className="flex flex-wrap items-center justify-between gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2">
              <div className="flex items-center gap-3 min-w-0">
                <span
                  className={`font-bold px-2 py-0.5 rounded shrink-0 ${
                    response.status_code < 400
                      ? "bg-emerald-500/20 text-emerald-300"
                      : "bg-amber-500/20 text-amber-300"
                  }`}
                >
                  HTTP {response.status_code}
                </span>
                <span className="text-slate-400 shrink-0">{response.duration_ms}ms</span>
                <span className="font-mono text-slate-300 truncate">{response.final_url}</span>
              </div>
            </div>

            <div className="space-y-1.5 bg-slate-900/70 border border-slate-800 rounded-lg p-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <input
                  aria-label="Finding title"
                  value={promoteTitle}
                  onChange={(e) => setPromoteTitle(e.target.value)}
                  placeholder="Promote as Finding Title (e.g. Unauthenticated Admin Access)"
                  className="flex-1 min-w-[200px] bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <select
                  aria-label="Finding severity"
                  value={promoteSev}
                  onChange={(e) => setPromoteSev(e.target.value as FindingItem["severity"])}
                  className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                >
                  <option value="critical">CRITICAL</option>
                  <option value="high">HIGH</option>
                  <option value="medium">MEDIUM</option>
                  <option value="low">LOW</option>
                  <option value="info">INFO</option>
                </select>
                <button
                  type="button"
                  disabled={promoting || !promoteTitle.trim()}
                  onClick={() => void handlePromoteFinding()}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold focus:outline-none focus:ring-2 focus:ring-emerald-400"
                >
                  <Flag className="w-3 h-3" aria-hidden="true" /> {promoting ? "Saving..." : "Save Finding"}
                </button>
                {promotedMsg && <span className="text-emerald-400">{promotedMsg}</span>}
              </div>
              {promoteError && (
                <div role="alert" className="text-red-400">
                  {promoteError}
                </div>
              )}
            </div>

            {response.curl_command && (
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-slate-400 font-semibold">Reproducible cURL Command</span>
                  <button
                    type="button"
                    onClick={() => void handleCopyCurl()}
                    className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-[11px] focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    {copiedCurl ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" /> Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" /> Copy cURL
                      </>
                    )}
                  </button>
                </div>
                <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 text-cyan-300 font-mono text-[11px] overflow-x-auto">
                  {response.curl_command}
                </pre>
              </div>
            )}

            <div>
              <div className="text-slate-400 font-semibold mb-1">Response Headers</div>
              <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 text-cyan-200 font-mono text-[11px] overflow-x-auto max-h-36">
                {JSON.stringify(response.headers, null, 2)}
              </pre>
            </div>

            <div>
              <div className="text-slate-400 font-semibold mb-1">Response Body</div>
              <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 text-slate-200 font-mono text-[11px] whitespace-pre-wrap break-words max-h-64 overflow-y-auto">
                {response.body || "(empty body)"}
              </pre>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
