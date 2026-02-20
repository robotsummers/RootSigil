export type ScanStatus = "queued" | "running" | "completed" | "failed";
export type Verdict = "pass" | "warn" | "fail";

export interface FindingEvidence {
  path: string;
  line_start: number;
  line_end: number;
  snippet: string;
}

export interface Finding {
  finding_id: string;
  scan_id: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  title: string;
  description: string;
  evidence: FindingEvidence[];
  recommendations: string[];
  fingerprints: string[];
}

export interface Scan {
  scan_id: string;
  status: ScanStatus;
  created_at: number;
  updated_at: number;
  artifact_type: "inline" | "zip" | "git";
  artifact_source: string;
  entrypoint: string;
  policy_version: string;
  artifact_root_sha256: string;
  manifest_json: string;
  verdict: Verdict | null;
  score: number | null;
  finding_counts: Record<string, number> | null;
  result_token_sha256: string;
  share_anonymized_artifact_for_research: boolean;
  error_code: string | null;
  error_message: string | null;
  artifact_storage_path: string | null;
}
