import fs from "node:fs";
import path from "node:path";
import type { SqliteDb } from "../db/db.js";
import { clearArtifactStoragePath, listExpiredArtifacts } from "../db/repo.js";

export type RetentionCleanupResult = {
  checked: number;
  removed: number;
  skipped_outside_root: number;
};

export function cleanupExpiredArtifacts(args: {
  db: SqliteDb;
  artifact_storage_dir: string;
  artifact_retention_hours: number;
  now_ms?: number;
}): RetentionCleanupResult {
  const nowMs = args.now_ms ?? Date.now();
  const cutoff = nowMs - args.artifact_retention_hours * 60 * 60 * 1000;
  const rows = listExpiredArtifacts(args.db, cutoff);

  const root = path.resolve(args.artifact_storage_dir);
  let removed = 0;
  let skipped = 0;

  for (const row of rows) {
    const target = path.resolve(row.artifact_storage_path);
    const withinRoot = target === root || target.startsWith(root + path.sep);
    if (!withinRoot) {
      skipped += 1;
      continue;
    }

    fs.rmSync(target, { recursive: true, force: true });
    clearArtifactStoragePath(args.db, row.scan_id);
    removed += 1;
  }

  return {
    checked: rows.length,
    removed,
    skipped_outside_root: skipped
  };
}
