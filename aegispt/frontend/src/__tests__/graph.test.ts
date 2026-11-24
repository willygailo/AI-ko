import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AssetItem, EndpointItem, FindingItem } from "../api/client.ts";
import {
  buildAttackGraphLayout,
  matchEndpointParentAsset,
  matchFindingParent,
  truncateText,
} from "../utils/graph.ts";

const makeAsset = (id: string, value: string): AssetItem => ({
  id,
  asset_type: "web",
  value,
  ip_address: null,
  status_code: 200,
  title: null,
  waf: null,
  technologies: [],
  discovered_by: "httpx",
});

const makeEndpoint = (
  id: string,
  url: string,
  path: string,
  bodyParams: string[] = []
): EndpointItem => ({
  id,
  method: "GET",
  url,
  path,
  query_params: [],
  body_params: bodyParams,
  status_code: 200,
  source: "katana",
});

const makeFinding = (id: string, title: string, targetUrl: string): FindingItem => ({
  id,
  title,
  severity: "high",
  status: "open",
  cvss_score: 7.5,
  cwe_id: "CWE-89",
  owasp_category: null,
  target_url: targetUrl,
  parameter: null,
  description: "",
  evidence: {},
  poc_command: null,
  remediation: "",
  tool_source: "http_probe",
  created_at: null,
});

describe("AttackGraph URL/origin parent matching and layout truncation", () => {
  it("matches endpoints to assets by parsed origin/host rather than substring", () => {
    const assets = [
      makeAsset("a1", "http://127.0.0.1:3000"),
      makeAsset("a2", "http://127.0.0.1:30000"),
      makeAsset("a3", "api.example.com"),
    ];

    assert.equal(
      matchEndpointParentAsset(makeEndpoint("e1", "http://127.0.0.1:30000/v1/users", "/v1/users"), assets),
      "asset-a2"
    );
    assert.equal(
      matchEndpointParentAsset(makeEndpoint("e2", "http://127.0.0.1:3000/rest/login", "/rest/login"), assets),
      "asset-a1"
    );
    assert.equal(
      matchEndpointParentAsset(makeEndpoint("e3", "https://api.example.com/health", "/health"), assets),
      "asset-a3"
    );
    assert.equal(
      matchEndpointParentAsset(makeEndpoint("e4", "https://evil-api.example.com/health", "/health"), assets),
      "root"
    );
  });

  it("does NOT allow root '/' endpoint to capture deeper finding URLs and picks longest prefix", () => {
    const assets = [makeAsset("a1", "http://127.0.0.1:3000")];
    const endpoints = [
      makeEndpoint("root-ep", "http://127.0.0.1:3000/", "/"),
      makeEndpoint("api-ep", "http://127.0.0.1:3000/api", "/api"),
      makeEndpoint("users-ep", "http://127.0.0.1:3000/api/users", "/api/users"),
    ];

    // Exact match to root endpoint
    assert.equal(
      matchFindingParent(makeFinding("f1", "Missing CSP", "http://127.0.0.1:3000/"), endpoints, assets),
      "ep-root-ep"
    );
    // Longest segment prefix match (/api/users over /api)
    assert.equal(
      matchFindingParent(
        makeFinding("f2", "IDOR on user profile", "http://127.0.0.1:3000/api/users/42"),
        endpoints,
        assets
      ),
      "ep-users-ep"
    );
    // Unmatched deep path falls back to matching asset, NOT root-ep '/'
    assert.equal(
      matchFindingParent(
        makeFinding("f3", "Admin debug leak", "http://127.0.0.1:3000/admin/debug"),
        endpoints,
        assets
      ),
      "asset-a1"
    );
  });

  it("reports accurate truncation totals when inputs exceed graph column caps", () => {
    const assets = Array.from({ length: 18 }, (_, i) => makeAsset(`a${i}`, `https://host${i}.example.com`));
    const endpoints = Array.from({ length: 26 }, (_, i) =>
      makeEndpoint(`e${i}`, `https://host0.example.com/p${i}`, `/p${i}`, i === 0 ? ["secret_body"] : [])
    );
    const findings = Array.from({ length: 20 }, (_, i) =>
      makeFinding(`f${i}`, `Issue ${i}`, `https://host0.example.com/p${i}`)
    );

    const layout = buildAttackGraphLayout("Big Engagement", assets, endpoints, findings, "");
    assert.equal(layout.totals.assets, 18);
    assert.equal(layout.shown.assets, 14);
    assert.equal(layout.totals.endpoints, 26);
    assert.equal(layout.shown.endpoints, 22);
    assert.equal(layout.totals.findings, 20);
    assert.equal(layout.shown.findings, 16);

    // Search matches endpoint body_params too
    const filtered = buildAttackGraphLayout("Big Engagement", assets, endpoints, findings, "secret_body");
    assert.equal(filtered.shown.endpoints, 1);
  });

  it("truncates long labels cleanly", () => {
    assert.equal(truncateText("short", 10), "short");
    assert.equal(truncateText("very-long-endpoint-path", 10), "very-long…");
  });
});
