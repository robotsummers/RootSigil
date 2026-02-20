import { createHash } from "node:crypto";
import type { SqliteDb } from "./db.js";
import type { Finding, Scan, ScanStatus, Verdict } from "./types.js";

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

export function nowMs(): number {
  return Date.now();
}

export function createScan(db: SqliteDb, scan: Omit<Scan, "created_at" | "updated_at">): void {
  const t = nowMs();
  db.prepare(
    `INSERT INTO scans (scan_id,status,created_at,updated_at,artifact_type,artifact_source,entrypoint,policy_version,artifact_root_sha256,manifest_json,verdict,score,finding_counts_json,result_token_sha256,share_anonymized_artifact_for_research,error_code,error_message,artifact_storage_path)
     VALUES (@scan_id,@status,@created_at,@updated_at,@artifact_type,@artifact_source,@entrypoint,@policy_version,@artifact_root_sha256,@manifest_json,@verdict,@score,@finding_counts_json,@result_token_sha256,@share_anonymized_artifact_for_research,@error_code,@error_message,@artifact_storage_path)`
  ).run({
    ...scan,
    created_at: t,
    updated_at: t,
    finding_counts_json: scan.finding_counts ? JSON.stringify(scan.finding_counts) : null,
    share_anonymized_artifact_for_research: scan.share_anonymized_artifact_for_research ? 1 : 0
  });
}

export function updateScanStatus(db: SqliteDb, scan_id: string, status: ScanStatus): void {
  db.prepare(`UPDATE scans SET status=?, updated_at=? WHERE scan_id=?`).run(status, nowMs(), scan_id);
}

export function finishScan(
  db: SqliteDb,
  scan_id: string,
  result: {
    verdict: Verdict;
    score: number;
    finding_counts: Record<string, number>;
  }
): void {
  db.prepare(
    `UPDATE scans SET status='completed', updated_at=?, verdict=?, score=?, finding_counts_json=? WHERE scan_id=?`
  ).run(nowMs(), result.verdict, result.score, JSON.stringify(result.finding_counts), scan_id);
}

export function failScan(db: SqliteDb, scan_id: string, error_code: string, error_message: string): void {
  db.prepare(
    `UPDATE scans SET status='failed', updated_at=?, error_code=?, error_message=? WHERE scan_id=?`
  ).run(nowMs(), error_code, error_message, scan_id);
}

export function insertFindings(db: SqliteDb, findings: Finding[]): void {
  const stmt = db.prepare(
    `INSERT INTO findings (finding_id,scan_id,severity,category,title,description,evidence_json,recommendations_json,fingerprints_json)
     VALUES (@finding_id,@scan_id,@severity,@category,@title,@description,@evidence_json,@recommendations_json,@fingerprints_json)`
  );
  const tx = db.transaction((rows: Finding[]) => {
    for (const f of rows) {
      stmt.run({
        ...f,
        evidence_json: JSON.stringify(f.evidence),
        recommendations_json: JSON.stringify(f.recommendations),
        fingerprints_json: JSON.stringify(f.fingerprints)
      });
    }
  });
  tx(findings);
}

export function getScanById(db: SqliteDb, scan_id: string): Scan | null {
  const row = db.prepare(`SELECT * FROM scans WHERE scan_id=?`).get(scan_id) as any;
  if (!row) return null;
  return hydrateScan(row);
}

export function getScanByIdAndToken(db: SqliteDb, scan_id: string, token: string): Scan | null {
  const tokenHash = sha256Hex(token);
  const row = db.prepare(`SELECT * FROM scans WHERE scan_id=? AND result_token_sha256=?`).get(scan_id, tokenHash) as any;
  if (!row) return null;
  return hydrateScan(row);
}

export function getFindingsForScan(db: SqliteDb, scan_id: string): Finding[] {
  const rows = db.prepare(`SELECT * FROM findings WHERE scan_id=? ORDER BY severity DESC`).all(scan_id) as any[];
  return rows.map((r) => ({
    finding_id: r.finding_id,
    scan_id: r.scan_id,
    severity: r.severity,
    category: r.category,
    title: r.title,
    description: r.description,
    evidence: JSON.parse(r.evidence_json),
    recommendations: JSON.parse(r.recommendations_json),
    fingerprints: JSON.parse(r.fingerprints_json)
  }));
}

function hydrateScan(row: any): Scan {
  return {
    scan_id: row.scan_id,
    status: row.status,
    created_at: row.created_at,
    updated_at: row.updated_at,
    artifact_type: row.artifact_type,
    artifact_source: row.artifact_source,
    entrypoint: row.entrypoint,
    policy_version: row.policy_version,
    artifact_root_sha256: row.artifact_root_sha256,
    manifest_json: row.manifest_json,
    verdict: row.verdict,
    score: row.score,
    finding_counts: row.finding_counts_json ? JSON.parse(row.finding_counts_json) : null,
    result_token_sha256: row.result_token_sha256,
    share_anonymized_artifact_for_research: Boolean(row.share_anonymized_artifact_for_research),
    error_code: row.error_code,
    error_message: row.error_message,
    artifact_storage_path: row.artifact_storage_path
  };
}

export type CachedResponse = {
  request_hash_sha256: string;
  status: number;
  headers: Record<string, string>;
  body: unknown;
  created_at: number;
  expires_at: number;
};

export function getCachedResponse(db: SqliteDb, payment_id: string): CachedResponse | null {
  const row = db.prepare(`SELECT * FROM idempotency_cache WHERE payment_id=?`).get(payment_id) as any;
  if (!row) return null;
  if (nowMs() > row.expires_at) {
    db.prepare(`DELETE FROM idempotency_cache WHERE payment_id=?`).run(payment_id);
    return null;
  }
  return {
    request_hash_sha256: row.request_hash_sha256,
    status: row.response_status,
    headers: JSON.parse(row.response_headers_json),
    body: JSON.parse(row.response_body_json),
    created_at: row.created_at,
    expires_at: row.expires_at
  };
}

export function putCachedResponse(db: SqliteDb, payment_id: string, cached: CachedResponse): void {
  db.prepare(
    `INSERT OR REPLACE INTO idempotency_cache (payment_id,request_hash_sha256,response_status,response_headers_json,response_body_json,created_at,expires_at)
     VALUES (?,?,?,?,?,?,?)`
  ).run(
    payment_id,
    cached.request_hash_sha256,
    cached.status,
    JSON.stringify(cached.headers),
    JSON.stringify(cached.body),
    cached.created_at,
    cached.expires_at
  );
}

export type AttestationRow = {
  attestation_id: string;
  artifact_root_sha256: string;
  policy_version: string;
  verdict: string;
  issued_at: number;
  document_json: string;
  signature_b64url: string;
  issuer_public_key_b64: string;
  issuer_id: string;
  algorithm: string;
};

export function insertAttestation(db: SqliteDb, row: AttestationRow): void {
  db.prepare(
    `INSERT INTO attestations (attestation_id,artifact_root_sha256,policy_version,verdict,issued_at,document_json,signature_b64url,issuer_public_key_b64,issuer_id,algorithm)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).run(
    row.attestation_id,
    row.artifact_root_sha256,
    row.policy_version,
    row.verdict,
    row.issued_at,
    row.document_json,
    row.signature_b64url,
    row.issuer_public_key_b64,
    row.issuer_id,
    row.algorithm
  );
}

export function getLatestAttestationByRoot(db: SqliteDb, root_sha256: string): AttestationRow | null {
  const row = db
    .prepare(`SELECT * FROM attestations WHERE artifact_root_sha256=? ORDER BY issued_at DESC LIMIT 1`)
    .get(root_sha256) as any;
  return row || null;
}

export function getAttestationsByRoot(db: SqliteDb, root_sha256: string): AttestationRow[] {
  const rows = db
    .prepare(`SELECT * FROM attestations WHERE artifact_root_sha256=? ORDER BY issued_at DESC`)
    .all(root_sha256) as any[];
  return rows.map((row) => ({
    attestation_id: row.attestation_id,
    artifact_root_sha256: row.artifact_root_sha256,
    policy_version: row.policy_version,
    verdict: row.verdict,
    issued_at: row.issued_at,
    document_json: row.document_json,
    signature_b64url: row.signature_b64url,
    issuer_public_key_b64: row.issuer_public_key_b64,
    issuer_id: row.issuer_id,
    algorithm: row.algorithm
  }));
}

export type RevocationRow = {
  artifact_root_sha256: string;
  issued_at: number;
  revoked_at: number;
  reason: string | null;
};

export function isRevoked(db: SqliteDb, root_sha256: string, issued_at: number): boolean {
  const row = db
    .prepare(`SELECT 1 FROM revocations WHERE artifact_root_sha256=? AND issued_at=? LIMIT 1`)
    .get(root_sha256, issued_at) as any;
  return Boolean(row);
}

export function listRevocations(db: SqliteDb): RevocationRow[] {
  const rows = db
    .prepare(`SELECT artifact_root_sha256, issued_at, revoked_at, reason FROM revocations ORDER BY revoked_at DESC, artifact_root_sha256 ASC`)
    .all() as any[];
  return rows.map((r) => ({
    artifact_root_sha256: r.artifact_root_sha256,
    issued_at: r.issued_at,
    revoked_at: r.revoked_at,
    reason: r.reason ?? null
  }));
}

export type ExpiredArtifactRow = {
  scan_id: string;
  artifact_storage_path: string;
};

export function listExpiredArtifacts(db: SqliteDb, cutoff_created_at_ms: number): ExpiredArtifactRow[] {
  const rows = db
    .prepare(`SELECT scan_id, artifact_storage_path FROM scans WHERE artifact_storage_path IS NOT NULL AND created_at <= ?`)
    .all(cutoff_created_at_ms) as any[];
  return rows
    .filter((r) => typeof r.artifact_storage_path === "string" && r.artifact_storage_path.length > 0)
    .map((r) => ({
      scan_id: r.scan_id,
      artifact_storage_path: r.artifact_storage_path
    }));
}

export function clearArtifactStoragePath(db: SqliteDb, scan_id: string): void {
  db.prepare(`UPDATE scans SET artifact_storage_path=NULL, updated_at=? WHERE scan_id=?`).run(nowMs(), scan_id);
}
