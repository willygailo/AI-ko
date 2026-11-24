import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ApiError,
  api,
  apiFetch,
  buildEngagementWsUrl,
  clearStoredToken,
  connectEngagementWS,
  getStoredToken,
  normalizeApiToken,
  parseApiErrorMessage,
  setStoredToken,
  setUnauthorizedHandler,
  type AgentEventItem,
} from "../api/client.ts";

class MemoryStorage implements Storage {
  private store = new Map<string, string>();
  get length(): number {
    return this.store.size;
  }
  clear(): void {
    this.store.clear();
  }
  getItem(key: string): string | null {
    return this.store.has(key) ? this.store.get(key)! : null;
  }
  key(index: number): string | null {
    return Array.from(this.store.keys())[index] ?? null;
  }
  removeItem(key: string): void {
    this.store.delete(key);
  }
  setItem(key: string, value: string): void {
    this.store.set(key, String(value));
  }
}

class FakeWebSocket {
  url: string;
  readyState = 1;
  sent: string[] = [];
  closed = false;
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;

  constructor(url: string) {
    this.url = url;
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(): void {
    this.closed = true;
    this.readyState = 3;
  }

  emitOpen(): void {
    this.onopen?.({} as Event);
  }

  emitMessage(payload: unknown): void {
    this.onmessage?.({ data: JSON.stringify(payload) } as MessageEvent);
  }

  emitClose(code: number): void {
    this.readyState = 3;
    this.onclose?.({ code } as CloseEvent);
  }
}

const originalFetch = globalThis.fetch;
const originalStorage = globalThis.localStorage;

describe("api/client error parsing, 401 handling, and WebSocket lifecycle", () => {
  beforeEach(() => {
    Object.defineProperty(globalThis, "localStorage", {
      value: new MemoryStorage(),
      configurable: true,
      writable: true,
    });
    setUnauthorizedHandler(null);
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    Object.defineProperty(globalThis, "localStorage", {
      value: originalStorage,
      configurable: true,
      writable: true,
    });
    setUnauthorizedHandler(null);
  });

  it("parses FastAPI string detail and 422 validation arrays cleanly", () => {
    assert.equal(
      parseApiErrorMessage(409, JSON.stringify({ detail: "LLM profile 'Local' already exists." })),
      "LLM profile 'Local' already exists."
    );
    assert.equal(
      parseApiErrorMessage(
        422,
        JSON.stringify({
          detail: [{ loc: ["body", "hint"], msg: "String should have at least 2 characters" }],
        })
      ),
      "hint: String should have at least 2 characters"
    );
    assert.equal(parseApiErrorMessage(500, "Plain error"), "500: Plain error");
    assert.equal(parseApiErrorMessage(503, ""), "Request failed with HTTP 503.");
  });

  it("normalizes pasted API tokens with box borders, Bearer prefix, quotes, or wrapped lines", () => {
    assert.equal(
      normalizeApiToken("  │ aegis_AbCdEf123456_xyz-789 │  "),
      "aegis_AbCdEf123456_xyz-789"
    );
    assert.equal(
      normalizeApiToken("Authorization: Bearer 'aegis_my_token_999'"),
      "aegis_my_token_999"
    );
    assert.equal(
      normalizeApiToken(
        "╭─── AegisPT Local API Token ───╮\n│ aegis_wrapped_part1_\n│ part2_end │\n╰───────────────────────────────╯"
      ),
      "aegis_wrapped_part1_part2_end"
    );
    setStoredToken("  Bearer  │ aegis_stored_clean │ ");
    assert.equal(getStoredToken(), "aegis_stored_clean");
  });

  it("clears token and invokes global unauthorized handler on HTTP 401", async () => {
    setStoredToken("aegis_secret_token");
    let unauthorizedReason = "";
    setUnauthorizedHandler((reason) => {
      unauthorizedReason = reason || "called";
    });

    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ detail: "Invalid API token" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;

    await assert.rejects(
      () => apiFetch("/api/v1/engagements"),
      (err: unknown) => err instanceof ApiError && err.status === 401 && err.detail === "Invalid API token"
    );
    assert.equal(getStoredToken(), "");
    assert.equal(unauthorizedReason, "Invalid API token");
  });

  it("skips global unauthorized handler when skipUnauthorizedHandler is true", async () => {
    setStoredToken("aegis_bad_token");
    let called = false;
    setUnauthorizedHandler(() => {
      called = true;
    });

    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ detail: "Unauthorized" }), { status: 401 })) as typeof fetch;

    await assert.rejects(() =>
      apiFetch("/api/v1/engagements", { skipUnauthorizedHandler: true })
    );
    assert.equal(called, false);
    assert.equal(getStoredToken(), "aegis_bad_token");
    clearStoredToken();
  });

  it("calls POST /api/v1/llm-profiles/{id}/default via setDefaultLLMProfile", async () => {
    setStoredToken("aegis_test_tok");
    let capturedUrl = "";
    let capturedMethod = "";
    let capturedAuth = "";

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = String(input);
      capturedMethod = init?.method || "GET";
      capturedAuth = new Headers(init?.headers).get("Authorization") || "";
      return new Response(
        JSON.stringify({
          id: "prof-2",
          name: "Remote vLLM",
          provider: "openai_compat",
          base_url: "http://127.0.0.1:8000",
          has_api_key: false,
          fast_model: "qwen2.5:3b",
          reasoning_model: "qwen2.5-coder:7b",
          redact_outbound: true,
          is_default: true,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }) as typeof fetch;

    const updated = await api.setDefaultLLMProfile("prof-2");
    assert.equal(capturedUrl, "/api/v1/llm-profiles/prof-2/default");
    assert.equal(capturedMethod, "POST");
    assert.equal(capturedAuth, "Bearer aegis_test_tok");
    assert.equal(updated.id, "prof-2");
    assert.equal(updated.is_default, true);
  });

  it("builds WS ticket URL on /api/v1/engagements/{id}/ws without ?token=", () => {
    const httpUrl = buildEngagementWsUrl("http:", "127.0.0.1:8443", "eng-1", "tkt/abc");
    assert.equal(httpUrl, "ws://127.0.0.1:8443/api/v1/engagements/eng-1/ws?ticket=tkt%2Fabc");
    assert.doesNotMatch(httpUrl, /token=/);

    const httpsUrl = buildEngagementWsUrl("https:", "app.local", "eng-2", "xyz");
    assert.equal(httpsUrl, "wss://app.local/api/v1/engagements/eng-2/ws?ticket=xyz");
  });

  it("requests WS ticket, sends ping heartbeat, ignores pong, and stops reconnect on 4401", async () => {
    setStoredToken("aegis_live");
    const sockets: FakeWebSocket[] = [];
    const received: AgentEventItem[] = [];
    let ticketRequests = 0;
    let unauthTriggered = false;
    setUnauthorizedHandler(() => {
      unauthTriggered = true;
    });

    const conn = connectEngagementWS(
      "eng-42",
      {
        onEvent: (ev) => received.push(ev),
      },
      {
        heartbeatMs: 20,
        initialRetryMs: 25,
        requestTicket: async () => {
          ticketRequests += 1;
          return { ticket: `ticket-${ticketRequests}`, expires_in: 30 };
        },
        createSocket: (url) => {
          const sock = new FakeWebSocket(url);
          sockets.push(sock);
          return sock as unknown as WebSocket;
        },
        getLocation: () => ({ protocol: "http:", host: "127.0.0.1:8443" }),
      }
    );

    await new Promise((r) => setTimeout(r, 10));
    assert.equal(sockets.length, 1);
    assert.equal(
      sockets[0].url,
      "ws://127.0.0.1:8443/api/v1/engagements/eng-42/ws?ticket=ticket-1"
    );

    sockets[0].emitOpen();
    sockets[0].emitMessage({ event_type: "pong" });
    sockets[0].emitMessage({
      id: 7,
      engagement_id: "eng-42",
      event_type: "tool_completed",
      agent_name: "executor",
      message: "done",
      payload: {},
      created_at: null,
      replayed: false,
    });
    assert.equal(received.length, 1);
    assert.equal(received[0].id, 7);

    // Wait for at least one ping heartbeat
    await new Promise((r) => setTimeout(r, 35));
    assert.ok(sockets[0].sent.includes("ping"));

    // Close with 4401 -> must clear token, trigger unauthorized, and NEVER reconnect
    sockets[0].emitClose(4401);
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(unauthTriggered, true);
    assert.equal(getStoredToken(), "");
    assert.equal(ticketRequests, 1);
    assert.equal(sockets.length, 1);

    conn.close();
  });
});
