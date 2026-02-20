import os from "node:os";
import type { AppConfig } from "../config.js";
import type { SqliteDb } from "../db/db.js";
import type { Scan } from "../db/types.js";
import {
  claimNextScan,
  deleteFindingsForScan,
  insertFindings,
  markScanCompleted,
  markScanFailed,
  nowMs,
  releaseExpiredLeases
} from "../db/repo.js";
import { loadArtifactFromDisk } from "../lib/artifact.js";
import type { Policy } from "../lib/policy.js";
import { redactText } from "../lib/redact.js";
import { cleanupExpiredArtifacts } from "../lib/retention.js";
import { runScan } from "../lib/scanner.js";

const RETENTION_CLEANUP_INTERVAL_MS = 10 * 60 * 1000;

export function startWorkerLoop(args: {
  config: AppConfig;
  db: SqliteDb;
  policy: Policy;
  worker_id?: string;
}): { stop: () => void } {
  const { config, db, policy } = args;
  const workerId = args.worker_id || `${os.hostname()}:${process.pid}`;
  const pollMs = config.WORKER_POLL_MS ?? 500;
  const leaseMs = config.WORKER_LEASE_MS ?? 120_000;
  const concurrency = Math.max(1, config.WORKER_CONCURRENCY ?? 2);
  let stopped = false;
  let nextRetentionCleanupAt = nowMs();

  const loop = async () => {
    while (!stopped) {
      const now = nowMs();
      releaseExpiredLeases(db, now);
      if (now >= nextRetentionCleanupAt) {
        const cleanup = cleanupExpiredArtifacts({
          db,
          artifact_storage_dir: config.ARTIFACT_STORAGE_DIR,
          artifact_retention_hours: config.ARTIFACT_RETENTION_HOURS,
          now_ms: now
        });
        if (cleanup.removed > 0 || cleanup.skipped_outside_root > 0) {
          console.log(
            `Artifact cleanup checked=${cleanup.checked} removed=${cleanup.removed} skipped_outside_root=${cleanup.skipped_outside_root}`
          );
        }
        nextRetentionCleanupAt = now + RETENTION_CLEANUP_INTERVAL_MS;
      }

      let processed = 0;
      for (let i = 0; i < concurrency && !stopped; i += 1) {
        const claimed = claimNextScan(db, {
          worker_id: workerId,
          now_ms: nowMs(),
          lease_ms: leaseMs
        });
        if (!claimed) break;
        console.log(`Worker claimed scan_id=${claimed.scan_id} attempt=${claimed.attempt_count}`);
        processed += 1;
        processClaimedScan({ db, policy, scan: claimed });
      }

      if (processed === 0) {
        await sleep(pollMs);
      }
    }
  };

  loop().catch((e: any) => {
    console.error(`Worker loop crashed: ${String(e?.message || e)}`);
    stopped = true;
  });

  return {
    stop: () => {
      stopped = true;
    }
  };
}

function processClaimedScan(args: { db: SqliteDb; policy: Policy; scan: Scan }): void {
  const { db, policy, scan } = args;
  const scanId = String(scan.scan_id);

  try {
    if (!scan.artifact_storage_path) {
      throw new Error("scan artifact storage path is missing");
    }
    const artifact = loadArtifactFromDisk({
      artifact_storage_path: scan.artifact_storage_path,
      manifest_json: scan.manifest_json,
      entrypoint: scan.entrypoint,
      expected_root_sha256: scan.artifact_root_sha256
    });

    const out = runScan(scanId, artifact, policy);
    for (const finding of out.findings) {
      for (const evidence of finding.evidence) {
        evidence.snippet = redactText(evidence.snippet);
      }
    }

    deleteFindingsForScan(db, scanId);
    insertFindings(db, out.findings);
    markScanCompleted(db, scanId, {
      now_ms: nowMs(),
      verdict: out.verdict,
      score: out.score,
      finding_counts: out.counts
    });
    console.log(`Worker completed scan_id=${scanId} verdict=${out.verdict}`);
  } catch (e: any) {
    markScanFailed(db, scanId, "SCAN_FAILED", String(e?.message || e), {
      now_ms: nowMs()
    });
    console.warn(`Worker failed scan_id=${scanId}: ${String(e?.message || e)}`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
