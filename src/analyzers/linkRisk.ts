import { createHash } from "node:crypto";
import type { NormalizedArtifact } from "../lib/artifact.js";
import type { RuleMatch } from "./types.js";
import { lineRangeFromOffsets } from "./lineRange.js";

const SUSPICIOUS_HOSTS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "pastebin.com",
  "paste.ee",
  "0x0.st"
];

export function analyzeLinkRisk(artifact: NormalizedArtifact): RuleMatch[] {
  const matches: RuleMatch[] = [];
  for (const f of artifact.files) {
    const isText = f.path.endsWith(".md") || f.path.endsWith(".txt") || f.path.endsWith(".js") || f.path.endsWith(".ts") || f.path.endsWith(".py") || f.path.endsWith(".json");
    if (!isText) continue;
    const text = Buffer.from(f.bytes).toString("utf8");
    const re = /(https?:\/\/[^\s\)\]\"']+)/g;
    for (const m of text.matchAll(re)) {
      const url = m[0] || "";
      const start = m.index ?? 0;
      const end = start + url.length;
      const host = safeHost(url);
      const isRawIp = /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(host);
      if (!host) continue;
      if (SUSPICIOUS_HOSTS.includes(host) || isRawIp) {
        const lines = lineRangeFromOffsets(text, start, end);
        matches.push({
          rule_id: "LINK.SUSPICIOUS",
          evidence: { path: f.path, line_start: lines.line_start, line_end: lines.line_end, snippet: url },
          fingerprint: fingerprint("LINK.SUSPICIOUS", f.path, start, end, url)
        });
      }
    }
  }
  return matches;
}

function safeHost(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function fingerprint(rule_id: string, path: string, start: number, end: number, token: string): string {
  return createHash("sha256").update(`${rule_id}|${path}|${start}|${end}|${token}`).digest("hex");
}
