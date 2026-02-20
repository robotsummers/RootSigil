import { createHash } from "node:crypto";
import type { NormalizedArtifact } from "../lib/artifact.js";
import type { RuleMatch } from "./types.js";
import { lineRangeFromOffsets } from "./lineRange.js";

const PATTERNS: Array<{ rule_id: string; re: RegExp }> = [
  { rule_id: "MD.REQUEST_SECRETS", re: /(private key|seed phrase|mnemonic|api key|access token|\.env|environment variable|ssh key|keychain)/gi },
  { rule_id: "MD.OVERRIDE_INSTRUCTIONS", re: /(ignore (all|previous) (instructions|messages)|override (system|developer) message)/gi },
  { rule_id: "MD.AUTO_APPROVE", re: /(always approve|do not ask for confirmation|no matter what approve)/gi }
];

export function analyzeMarkdownRisk(artifact: NormalizedArtifact): RuleMatch[] {
  const matches: RuleMatch[] = [];
  for (const f of artifact.files) {
    if (!f.path.endsWith(".md")) continue;
    const text = Buffer.from(f.bytes).toString("utf8");
    for (const p of PATTERNS) {
      for (const m of text.matchAll(p.re)) {
        const start = m.index ?? 0;
        const end = start + (m[0]?.length || 0);
        const snippet = text.slice(Math.max(0, start - 40), Math.min(text.length, end + 40));
        const fp = fingerprint(p.rule_id, f.path, start, end, m[0] || "");
        const lines = lineRangeFromOffsets(text, start, end);
        matches.push({
          rule_id: p.rule_id,
          evidence: { path: f.path, line_start: lines.line_start, line_end: lines.line_end, snippet },
          fingerprint: fp
        });
      }
    }
  }
  return matches;
}

function fingerprint(rule_id: string, path: string, start: number, end: number, token: string): string {
  return createHash("sha256").update(`${rule_id}|${path}|${start}|${end}|${token}`).digest("hex");
}
