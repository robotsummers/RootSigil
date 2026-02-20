import type { NormalizedArtifact } from "./artifact.js";
import type { Policy } from "./policy.js";
import { analyzeMarkdownRisk } from "../analyzers/markdownRisk.js";
import { analyzeCommandRisk } from "../analyzers/commandRisk.js";
import { analyzeJsTsRisk } from "../analyzers/jsTsRisk.js";
import { analyzePythonRisk } from "../analyzers/pythonRisk.js";
import { analyzeDependencySurface } from "../analyzers/dependencySurface.js";
import { analyzeLinkRisk } from "../analyzers/linkRisk.js";
import type { RuleMatch } from "../analyzers/types.js";
import type { Finding } from "../db/types.js";
import { computeVerdict, matchesToFindings } from "./policy.js";

export type ScanOutput = {
  findings: Finding[];
  verdict: "pass" | "warn" | "fail";
  score: number;
  counts: Record<string, number>;
  matches: RuleMatch[];
};

export function runScan(scan_id: string, artifact: NormalizedArtifact, policy: Policy): ScanOutput {
  const matches = collectMatches(artifact);
  const findings = matchesToFindings(scan_id, matches, policy);
  const { verdict, score, counts } = computeVerdict(policy, findings);
  return { findings, verdict, score, counts, matches };
}

function collectMatches(artifact: NormalizedArtifact): RuleMatch[] {
  const all = [
    ...analyzeMarkdownRisk(artifact),
    ...analyzeCommandRisk(artifact),
    ...analyzeJsTsRisk(artifact),
    ...analyzePythonRisk(artifact),
    ...analyzeDependencySurface(artifact),
    ...analyzeLinkRisk(artifact)
  ];

  // Deduplicate by fingerprint
  const seen = new Set<string>();
  const out: RuleMatch[] = [];
  for (const m of all) {
    if (seen.has(m.fingerprint)) continue;
    seen.add(m.fingerprint);
    out.push(m);
  }
  return out;
}
