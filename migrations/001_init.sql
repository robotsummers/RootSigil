PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  artifact_type TEXT NOT NULL,
  artifact_source TEXT NOT NULL,
  entrypoint TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  artifact_root_sha256 TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  verdict TEXT,
  score INTEGER,
  finding_counts_json TEXT,
  result_token_sha256 TEXT NOT NULL,
  share_anonymized_artifact_for_research INTEGER NOT NULL DEFAULT 0,
  error_code TEXT,
  error_message TEXT,
  artifact_storage_path TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  recommendations_json TEXT NOT NULL,
  fingerprints_json TEXT NOT NULL,
  FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE TABLE IF NOT EXISTS attestations (
  attestation_id TEXT PRIMARY KEY,
  artifact_root_sha256 TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  verdict TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  document_json TEXT NOT NULL,
  signature_b64url TEXT NOT NULL,
  issuer_public_key_b64 TEXT NOT NULL,
  issuer_id TEXT NOT NULL,
  algorithm TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revocations (
  artifact_root_sha256 TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  revoked_at INTEGER NOT NULL,
  reason TEXT,
  PRIMARY KEY (artifact_root_sha256, issued_at)
);

CREATE TABLE IF NOT EXISTS idempotency_cache (
  payment_id TEXT PRIMARY KEY,
  request_hash_sha256 TEXT NOT NULL,
  response_status INTEGER NOT NULL,
  response_headers_json TEXT NOT NULL,
  response_body_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
