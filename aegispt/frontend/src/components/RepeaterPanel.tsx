import React, { useEffect, useState } from "react";
import { Send, Flag } from "lucide-react";
import { RepeaterResponse, api } from "../api/client";

interface Props {
  engagementId: string;
  initialUrl: string;
  onFindingCreated: () => Promise<void>;
}

export const RepeaterPanel: React.FC<Props> = ({
  engagementId,
  initialUrl,
  onFindingCreated,
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
  const [promoteSev, setPromoteSev] = useState<"high" | "medium" | "low" | "info">("medium");
  const [promotedMsg, setPromotedMsg] = useState("");

  useEffect(() => {
    if (initialUrl) setUrl(initialUrl);
  }, [initialUrl]);

  const parseHeaders = (raw: string): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const line of raw.split("\n")) {
      const idx = line.indexOf(":");
      if (idx > 0) {
        out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      }
    }
    return out;
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setPromotedMsg("");
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
      setError(String(err));
    } finally {
      setSending(false);
    }
  };

  const handlePromoteFinding = async () => {
    if (!response || !promoteTitle.trim()) return;
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
    await onFindingCreated();
  };

  return (
    <div className="flex flex-col h-full bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden text-xs">
      <form onSubmit={handleSend} className="p-3 border-b border-slate-800 bg-slate-900 space-y-2">
        <div className="flex gap-2">
          <select
            value={method}
            onChange={(e) => setMethod(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-indigo-300"
          >
            {["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
          <input
            required
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="http://127.0.0.1:3000/api/..."
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-cyan-300"
          />
          <button
            disabled={sending}
            type="submit"
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold"
          >
            <Send className="w-3.5 h-3.5" /> {sending ? "Sending..." : "Send"}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <textarea
            rows={2}
            value={headersText}
            onChange={(e) => setHeadersText(e.target.value)}
            placeholder="Custom Headers (Key: Value per line)"
            className="bg-slate-950 border border-slate-800 rounded-lg p-2 font-mono text-[11px] text-slate-200"
          />
          <textarea
            rows={2}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder='Request Body (e.g. {"id": 1})'
            className="bg-slate-950 border border-slate-800 rounded-lg p-2 font-mono text-[11px] text-slate-200"
          />
        </div>

        <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-300">
          <label className="flex items-center gap-1.5">
            <input type="checkbox" checked={useAuth} onChange={(e) => setUseAuth(e.target.checked)} />
            Attach Engagement Auth Headers/Cookies
          </label>
          <label className="flex items-center gap-1.5">
            <input
              type="checkbox"
              checked={followRedirects}
              onChange={(e) => setFollowRedirects(e.target.checked)}
            />
            Follow Scope-Checked Redirects
          </label>
        </div>
        {error && <div className="text-red-400">{error}</div>}
      </form>

      <div className="flex-1 overflow-auto p-3 space-y-3 bg-[#070b14]">
        {!response ? (
          <div className="text-slate-500 text-center mt-10">
            Send a scope-validated HTTP request to inspect headers, response body, and promote verified issues to findings.
          </div>
        ) : (
          <>
            <div className="flex flex-wrap items-center justify-between gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2">
              <div className="flex items-center gap-3">
                <span
                  className={`font-bold px-2 py-0.5 rounded ${
                    response.status_code < 400
                      ? "bg-emerald-500/20 text-emerald-300"
                      : "bg-amber-500/20 text-amber-300"
                  }`}
                >
                  HTTP {response.status_code}
                </span>
                <span className="text-slate-400">{response.duration_ms}ms</span>
                <span className="font-mono text-slate-300 truncate max-w-[300px]">{response.final_url}</span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 bg-slate-900/70 border border-slate-800 rounded-lg p-2.5">
              <input
                value={promoteTitle}
                onChange={(e) => setPromoteTitle(e.target.value)}
                placeholder="Promote as Finding Title (e.g. Unauthenticated Admin Access)"
                className="flex-1 bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-white"
              />
              <select
                value={promoteSev}
                onChange={(e) => setPromoteSev(e.target.value as typeof promoteSev)}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-white"
              >
                <option value="high">HIGH</option>
                <option value="medium">MEDIUM</option>
                <option value="low">LOW</option>
                <option value="info">INFO</option>
              </select>
              <button
                type="button"
                onClick={handlePromoteFinding}
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-semibold"
              >
                <Flag className="w-3 h-3" /> Save Finding
              </button>
              {promotedMsg && <span className="text-emerald-400">{promotedMsg}</span>}
            </div>

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
