import { createHash } from "node:crypto";
import type { NormalizedArtifact } from "../lib/artifact.js";
import type { RuleMatch } from "./types.js";

export function analyzeDependencySurface(artifact: NormalizedArtifact): RuleMatch[] {
  const matches: RuleMatch[] = [];
  const pkg = artifact.files.find((f) => f.path === "package.json");
  if (!pkg) return matches;
  const text = Buffer.from(pkg.bytes).toString("utf8");
  try {
    const json = JSON.parse(text) as any;
    const scripts = json?.scripts && typeof json.scripts === "object" ? json.scripts : {};
    for (const key of Object.keys(scripts)) {
      if (!["preinstall", "install", "postinstall"].includes(key)) continue;
      const val = String(scripts[key]);
      const line = findLineOfKey(text, key);
      const fp = fingerprint("DEP.NPM_INSTALL_SCRIPTS", pkg.path, key, val);
      matches.push({
        rule_id: "DEP.NPM_INSTALL_SCRIPTS",
        evidence: { path: pkg.path, line_start: line, line_end: line, snippet: `${key}: ${val}` },
        fingerprint: fp
      });
    }
  } catch {
    // Ignore parse errors.
  }
  return matches;
}

function fingerprint(rule_id: string, path: string, key: string, val: string): string {
  return createHash("sha256").update(`${rule_id}|${path}|${key}|${val}`).digest("hex");
}

function findLineOfKey(text: string, key: string): number {
  const needle = `"${key}"`;
  const idx = text.indexOf(needle);
  if (idx < 0) return 1;
  let line = 1;
  for (let i = 0; i < idx; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}
