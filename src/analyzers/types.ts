export type Severity = "critical" | "high" | "medium" | "low";

export type RuleMatchEvidence = {
  path: string;
  line_start: number;
  line_end: number;
  snippet: string;
};

export type RuleMatch = {
  rule_id: string;
  evidence: RuleMatchEvidence;
  fingerprint: string;
};
