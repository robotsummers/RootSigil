import { createHash } from "node:crypto";
import type { NormalizedArtifact } from "../lib/artifact.js";
import type { RuleMatch } from "./types.js";
import { lineRangeFromOffsets } from "./lineRange.js";

const TOKENS: Array<{ rule_id: string; token: string }> = [
  { rule_id: "PY.EVAL_EXEC", token: "eval(" },
  { rule_id: "PY.EVAL_EXEC", token: "exec(" },
  { rule_id: "PY.SUBPROCESS", token: "subprocess" },
  { rule_id: "PY.SUBPROCESS", token: "os.system(" },
  { rule_id: "PY.PICKLE", token: "pickle.loads" },
  { rule_id: "PY.NET_EGRESS", token: "requests" },
  { rule_id: "PY.NET_EGRESS", token: "socket" }
];

export function analyzePythonRisk(artifact: NormalizedArtifact): RuleMatch[] {
  const matches: RuleMatch[] = [];
  for (const f of artifact.files) {
    if (!f.path.endsWith(".py")) continue;
    const text = Buffer.from(f.bytes).toString("utf8");
    for (const t of TOKENS) {
      let idx = 0;
      while (true) {
        const found = text.indexOf(t.token, idx);
        if (found === -1) break;
        const start = found;
        const end = found + t.token.length;
        const snippet = text.slice(Math.max(0, start - 40), Math.min(text.length, end + 40));
        const lines = lineRangeFromOffsets(text, start, end);
        matches.push({
          rule_id: t.rule_id,
          evidence: { path: f.path, line_start: lines.line_start, line_end: lines.line_end, snippet },
          fingerprint: fingerprint(t.rule_id, f.path, start, end, t.token)
        });
        idx = end;
      }
    }
  }
  return matches;
}

function fingerprint(rule_id: string, path: string, start: number, end: number, token: string): string {
  return createHash("sha256").update(`${rule_id}|${path}|${start}|${end}|${token}`).digest("hex");
}
