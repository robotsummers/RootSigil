import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { openDb, type SqliteDb } from "../src/db/db.js";
import { cleanupExpiredArtifacts } from "../src/lib/retention.js";

type Fixture = {
  db: SqliteDb;
  tmpDir: string;
  artifactRoot: string;
};

const fixtures: Fixture[] = [];

afterEach(() => {
  while (fixtures.length > 0) {
    const f = fixtures.pop()!;
    f.db.close();
    fs.rmSync(f.tmpDir, { recursive: true, force: true });
  }
});

describe("artifact retention cleanup", () => {
  test("removes expired in-root artifacts and skips outside-root paths", () => {
    const fixture = createFixture();
    const now = Date.parse("2026-02-17T00:00:00.000Z");
    const retentionHours = 24;

    const expiredInRoot = path.join(fixture.artifactRoot, "scan-expired");
    const freshInRoot = path.join(fixture.artifactRoot, "scan-fresh");
    const expiredOutside = path.join(fixture.tmpDir, "outside", "scan-expired-outside");
    fs.mkdirSync(expiredInRoot, { recursive: true });
    fs.mkdirSync(freshInRoot, { recursive: true });
    fs.mkdirSync(expiredOutside, { recursive: true });

    insertScanRow({
      db: fixture.db,
      scanId: "scan-expired",
      createdAtMs: now - 48 * 60 * 60 * 1000,
      artifactStoragePath: expiredInRoot
    });
    insertScanRow({
      db: fixture.db,
      scanId: "scan-fresh",
      createdAtMs: now - 60 * 60 * 1000,
      artifactStoragePath: freshInRoot
    });
    insertScanRow({
      db: fixture.db,
      scanId: "scan-expired-outside",
      createdAtMs: now - 48 * 60 * 60 * 1000,
      artifactStoragePath: expiredOutside
    });

    const result = cleanupExpiredArtifacts({
      db: fixture.db,
      artifact_storage_dir: fixture.artifactRoot,
      artifact_retention_hours: retentionHours,
      now_ms: now
    });

    expect(result).toEqual({
      checked: 2,
      removed: 1,
      skipped_outside_root: 1
    });
    expect(fs.existsSync(expiredInRoot)).toBe(false);
    expect(fs.existsSync(freshInRoot)).toBe(true);
    expect(fs.existsSync(expiredOutside)).toBe(true);

    expect(getStoragePath(fixture.db, "scan-expired")).toBeNull();
    expect(getStoragePath(fixture.db, "scan-fresh")).toBe(freshInRoot);
    expect(getStoragePath(fixture.db, "scan-expired-outside")).toBe(expiredOutside);
  });

  test("clears DB pointer for expired artifacts even if directory is already missing", () => {
    const fixture = createFixture();
    const now = Date.parse("2026-02-17T00:00:00.000Z");
    const missingPath = path.join(fixture.artifactRoot, "scan-missing");

    insertScanRow({
      db: fixture.db,
      scanId: "scan-missing",
      createdAtMs: now - 48 * 60 * 60 * 1000,
      artifactStoragePath: missingPath
    });

    const result = cleanupExpiredArtifacts({
      db: fixture.db,
      artifact_storage_dir: fixture.artifactRoot,
      artifact_retention_hours: 24,
      now_ms: now
    });

    expect(result).toEqual({
      checked: 1,
      removed: 1,
      skipped_outside_root: 0
    });
    expect(getStoragePath(fixture.db, "scan-missing")).toBeNull();
  });
});

function createFixture(): Fixture {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-attestor-retention-"));
  const sqlitePath = path.join(tmpDir, "test.sqlite");
  const artifactRoot = path.join(tmpDir, "artifacts");
  fs.mkdirSync(artifactRoot, { recursive: true });

  const db = openDb(sqlitePath);
  db.exec(fs.readFileSync(path.join(process.cwd(), "migrations", "001_init.sql"), "utf8"));

  const fixture = { db, tmpDir, artifactRoot };
  fixtures.push(fixture);
  return fixture;
}

function insertScanRow(args: {
  db: SqliteDb;
  scanId: string;
  createdAtMs: number;
  artifactStoragePath: string;
}): void {
  args.db
    .prepare(
      `INSERT INTO scans (
        scan_id,status,created_at,updated_at,artifact_type,artifact_source,entrypoint,policy_version,artifact_root_sha256,manifest_json,verdict,score,finding_counts_json,result_token_sha256,share_anonymized_artifact_for_research,error_code,error_message,artifact_storage_path
      ) VALUES (
        @scan_id,@status,@created_at,@updated_at,@artifact_type,@artifact_source,@entrypoint,@policy_version,@artifact_root_sha256,@manifest_json,@verdict,@score,@finding_counts_json,@result_token_sha256,@share_anonymized_artifact_for_research,@error_code,@error_message,@artifact_storage_path
      )`
    )
    .run({
      scan_id: args.scanId,
      status: "completed",
      created_at: args.createdAtMs,
      updated_at: args.createdAtMs,
      artifact_type: "inline",
      artifact_source: "inline",
      entrypoint: "SKILL.md",
      policy_version: "2026-02-17.static.v1",
      artifact_root_sha256: "root",
      manifest_json: "[]",
      verdict: "pass",
      score: 100,
      finding_counts_json: "{\"critical\":0,\"high\":0,\"medium\":0,\"low\":0}",
      result_token_sha256: `token-${args.scanId}`,
      share_anonymized_artifact_for_research: 0,
      error_code: null,
      error_message: null,
      artifact_storage_path: args.artifactStoragePath
    });
}

function getStoragePath(db: SqliteDb, scanId: string): string | null {
  const row = db.prepare(`SELECT artifact_storage_path FROM scans WHERE scan_id=?`).get(scanId) as { artifact_storage_path: string | null } | undefined;
  return row?.artifact_storage_path ?? null;
}
