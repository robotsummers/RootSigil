import { createHash } from "node:crypto";
import type { NormalizedArtifact } from "../lib/artifact.js";
import type { RuleMatch } from "./types.js";

const RULES: Array<{ rule_id: string; test: (lineLower: string) => boolean }> = [
  {
    rule_id: "CMD.PIPE_TO_SHELL",
    test: (l) => (l.includes("curl ") || l.includes("wget ")) && (l.includes("| sh") || l.includes("|bash") || l.includes("| bash"))
  },
  { rule_id: "CMD.RM_RF", test: (l) => l.includes("rm -rf") },
  { rule_id: "CMD.SUDO", test: (l) => l.startsWith("sudo ") || l.includes(" sudo ") },
  {
    rule_id: "CMD.PERSISTENCE",
    test: (l) => l.includes("crontab") || l.includes("systemctl") || l.includes("launchctl") || l.includes("schtasks") || l.includes("reg add ")
  }
];

export function analyzeCommandRisk(artifact: NormalizedArtifact): RuleMatch[] {
  const matches: RuleMatch[] = [];
  for (const f of artifact.files) {
    const isText = f.path.endsWith(".md") || f.path.endsWith(".sh") || f.path.endsWith(".txt") || f.path.endsWith(".js") || f.path.endsWith(".ts") || f.path.endsWith(".py");
    if (!isText) continue;
    const text = Buffer.from(f.bytes).toString("utf8");
    const lines = text.split(/\r?\n/);
    let offset = 0;
    let lineNo = 1;
    for (const line of lines) {
      const lower = line.toLowerCase();
      for (const r of RULES) {
        if (!r.test(lower)) continue;
        const start = offset;
        const end = offset + line.length;
        const fp = fingerprint(r.rule_id, f.path, start, end, line);
        matches.push({
          rule_id: r.rule_id,
          evidence: { path: f.path, line_start: lineNo, line_end: lineNo, snippet: line.slice(0, 300) },
          fingerprint: fp
        });
      }
      offset += line.length + 1;
      lineNo += 1;
    }
  }
  return matches;
}

function fingerprint(rule_id: string, path: string, start: number, end: number, token: string): string {
  return createHash("sha256").update(`${rule_id}|${path}|${start}|${end}|${token}`).digest("hex");
}
