export function splitLines(txt: string): string[] {
  return txt
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function parseKVLines(txt: string, sep: ":" | "="): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of txt.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const idx = line.indexOf(sep);
    if (idx > 0) {
      const key = line.slice(0, idx).trim();
      const val = line.slice(idx + 1).trim();
      if (key) {
        out[key] = val;
      }
    }
  }
  return out;
}

export function parseHeaders(raw: string): Record<string, string> {
  return parseKVLines(raw, ":");
}

export type JsonObjectParseResult =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; error: string };

export function parseJsonObject(raw: string, fieldLabel = "arguments"): JsonObjectParseResult {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { ok: true, value: {} };
  }
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, error: `Expected a JSON object for ${fieldLabel}.` };
    }
    return { ok: true, value: parsed as Record<string, unknown> };
  } catch {
    return { ok: false, error: `Invalid JSON in ${fieldLabel}.` };
  }
}
