import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseHeaders, parseJsonObject, parseKVLines, splitLines } from "../utils/parsing.ts";

describe("Parsing utilities for ScopeWizardModal, RepeaterPanel, and ApprovalModal", () => {
  it("splits newline and comma-separated allowlist lines cleanly", () => {
    assert.deepEqual(
      splitLines("http://127.0.0.1:3000, https://staging.example.com\n\n /logout "),
      ["http://127.0.0.1:3000", "https://staging.example.com", "/logout"]
    );
  });

  it("parses header and cookie key-value lines preserving colons/equals in values", () => {
    assert.deepEqual(
      parseHeaders("Authorization: Bearer a:b:c\nX-Custom:  hello \nMalformedLine\n:no-key"),
      {
        Authorization: "Bearer a:b:c",
        "X-Custom": "hello",
      }
    );

    assert.deepEqual(
      parseKVLines("session=abc==\nrole=admin\n=emptykey\n\n", "="),
      {
        session: "abc==",
        role: "admin",
      }
    );
  });

  it("validates JSON objects strictly for tool arguments and approval edits", () => {
    assert.deepEqual(parseJsonObject(""), { ok: true, value: {} });
    assert.deepEqual(parseJsonObject('{"mode": "differential_bola", "depth": 2}'), {
      ok: true,
      value: { mode: "differential_bola", depth: 2 },
    });

    const arrRes = parseJsonObject("[1, 2, 3]", "modified arguments");
    assert.equal(arrRes.ok, false);

    const nullRes = parseJsonObject("null", "modified arguments");
    assert.equal(nullRes.ok, false);

    const badRes = parseJsonObject("{bad json}", "modified arguments");
    assert.equal(badRes.ok, false);
  });
});
