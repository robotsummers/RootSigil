import fs from "node:fs";
import { z } from "zod";
import type { RuleMatch } from "../analyzers/types.js";
import type { Finding, Verdict } from "../db/types.js";
import { v4 as uuidv4 } from "uuid";

const SeveritySchema = z.enum(["critical", "high", "medium", "low"]);
export type Severity = z.infer<typeof SeveritySchema>;

const RuleDefSchema = z.object({
  severity: SeveritySchema,
  category: z.string(),
  title: z.string(),
  description: z.string()
});

const PolicySchema = z.object({
  policy_version: z.string(),
  verdict_thresholds: z.object({
    fail_if_critical_greater_equal: z.number().int().nonnegative(),
    fail_if_high_greater_equal: z.number().int().nonnegative(),
    warn_if_high_greater_equal: z.number().int().nonnegative(),
    warn_if_medium_greater_equal: z.number().int().nonnegative()
  }),
  rules: z.record(z.string(), RuleDefSchema)
});

export type Policy = z.infer<typeof PolicySchema>;

export function loadPolicyFromFile(policyFile: string): Policy {
  const raw = fs.readFileSync(policyFile, "utf8");
  const j = JSON.parse(raw);
  const parsed = PolicySchema.safeParse(j);
  if (!parsed.success) throw new Error(`Invalid policy file: ${parsed.error.message}`);
  return parsed.data;
}

export function matchesToFindings(scan_id: string, matches: RuleMatch[], policy: Policy): Finding[] {
  const out: Finding[] = [];
  for (const m of matches) {
    const rule = policy.rules[m.rule_id];
    if (!rule) continue;
    out.push({
      finding_id: uuidv4(),
      scan_id,
      severity: rule.severity,
      category: rule.category,
      title: rule.title,
      description: rule.description,
      evidence: [m.evidence],
      recommendations: defaultRecommendations(m.rule_id),
      fingerprints: [m.fingerprint]
    });
  }
  return out;
}

export function computeVerdict(policy: Policy, findings: Finding[]): { verdict: Verdict; score: number; counts: Record<string, number> } {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) (counts as any)[f.severity] += 1;

  if (counts.critical >= policy.verdict_thresholds.fail_if_critical_greater_equal) return { verdict: "fail", score: 0, counts };
  if (counts.high >= policy.verdict_thresholds.fail_if_high_greater_equal) return { verdict: "fail", score: 10, counts };
  if (counts.high >= policy.verdict_thresholds.warn_if_high_greater_equal) return { verdict: "warn", score: 30, counts };
  if (counts.medium >= policy.verdict_thresholds.warn_if_medium_greater_equal) return { verdict: "warn", score: 60, counts };
  return { verdict: "pass", score: 90, counts };
}

function defaultRecommendations(ruleId: string): string[] {
  if (ruleId.startsWith("CMD.")) return ["Avoid recommending destructive or persistence-oriented shell commands.", "Prefer least-privilege commands and explicit confirmations."];
  if (ruleId.startsWith("JS.")) return ["Avoid dynamic code execution and process spawning in skills unless strictly necessary.", "Document all outbound network calls and destination hosts."];
  if (ruleId.startsWith("PY.")) return ["Avoid subprocess execution and unsafe deserialization.", "Document all outbound network calls and destination hosts."];
  if (ruleId.startsWith("MD.")) return ["Remove instructions that request secrets or attempt to override agent policies."];
  return ["Review the referenced snippet and reduce privilege or capability surface if possible."];
}
