import { randomBytes } from "node:crypto";
import type { Router } from "express";
import express from "express";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import type { SqliteDb } from "../db/db.js";
import {
  createScan,
  deleteFindingsForScan,
  getFindingsForScan,
  getScanById,
  getScanByIdAndToken,
  insertFindings,
  markScanCompleted,
  markScanFailed,
  markScanRunning,
  sha256Hex,
  nowMs
} from "../db/repo.js";
import { normalizeGit, normalizeInline, normalizeZip, persistArtifactToDisk, type IntakeLimits, type NormalizedArtifact } from "../lib/artifact.js";
import type { Policy } from "../lib/policy.js";
import { redactText } from "../lib/redact.js";
import { runScan } from "../lib/scanner.js";
import { computeRequestHash, IdempotencyStore } from "../payment/idempotency.js";
import type { X402Context } from "../payment/x402.js";
import { v4 as uuidv4 } from "uuid";

const InlineInput = z
  .object({
    filename: z.string().optional(),
    content: z.string().min(1)
  })
  .strict();

const ZipInput = z
  .object({
    zip_b64: z.string().min(1),
    entrypoint: z.string().optional()
  })
  .strict();

const GitInput = z
  .object({
    repo_url: z.string().url(),
    ref: z.string().min(1),
    entrypoint: z.string().optional()
  })
  .strict();

const ScanCreateRequest = z
  .object({
    policy_version: z.string().optional(),
    share_anonymized_artifact_for_research: z.boolean().optional(),
    inline: InlineInput.optional(),
    zip: ZipInput.optional(),
    git: GitInput.optional()
  })
  .strict()
  .superRefine((v, ctx) => {
    const count = [v.inline, v.zip, v.git].filter(Boolean).length;
    if (count !== 1) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "exactly one of inline, zip, or git must be provided"
      });
    }
  });

export function buildScanRouter(args: {
  config: AppConfig;
  db: SqliteDb;
  policy: Policy;
  x402: { context: X402Context };
}): Router {
  const { config, db, policy, x402 } = args;
  const router = express.Router();
  const idem = new IdempotencyStore(db, config.IDEMPOTENCY_TTL_MS);
  const limits: IntakeLimits = {
    max_files: config.INTAKE_MAX_FILES,
    max_total_bytes: config.INTAKE_MAX_TOTAL_BYTES,
    max_single_file_bytes: config.INTAKE_MAX_SINGLE_FILE_BYTES
  };

  router.post("/scan", async (req, res) => {
    const parsed = ScanCreateRequest.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: { error_code: "BAD_REQUEST", message: parsed.error.message } });
    }

    const paymentId = x402.context.extractPaymentId(req.get("PAYMENT-SIGNATURE") || undefined);
    const requestHash = computeRequestHash(req.body);
    if (paymentId) {
      const cached = idem.get(paymentId);
      if (cached) {
        if (cached.request_hash_sha256 !== requestHash) {
          return res.status(409).json({ error: { error_code: "IDEMPOTENCY_CONFLICT", message: "payment identifier reused for different request" } });
        }
        return res.status(cached.status).set(cached.headers).json(cached.body);
      }
    }

    const policyVersion = parsed.data.policy_version || config.DEFAULT_POLICY_VERSION;
    if (policyVersion !== policy.policy_version) {
      return res.status(400).json({ error: { error_code: "UNKNOWN_POLICY", message: "unknown policy_version" } });
    }

    const scan_id = uuidv4();
    const result_token = base64url(randomBytes(32));

    let artifact: NormalizedArtifact;
    let artifactType: "inline" | "zip" | "git";
    let artifactSource: string;
    try {
      if (parsed.data.inline) {
        artifact = normalizeInline({ filename: parsed.data.inline.filename, content: parsed.data.inline.content }, limits);
        artifactType = "inline";
        artifactSource = parsed.data.inline.filename || "SKILL.md";
      } else if (parsed.data.zip) {
        artifact = normalizeZip({ zip_bytes_b64: parsed.data.zip.zip_b64, entrypoint: parsed.data.zip.entrypoint }, limits);
        artifactType = "zip";
        artifactSource = "zip";
      } else if (parsed.data.git) {
        artifact = normalizeGit({
          repo_url: parsed.data.git.repo_url,
          ref: parsed.data.git.ref,
          entrypoint: parsed.data.git.entrypoint
        }, limits, {
          allowed_hosts: config.GIT_ALLOWED_HOSTS ?? ["github.com"],
          timeout_ms: config.GIT_TIMEOUT_MS ?? 15_000
        });
        artifactType = "git";
        artifactSource = parsed.data.git.repo_url;
      } else {
        return res.status(400).json({ error: { error_code: "BAD_REQUEST", message: "missing artifact input" } });
      }
    } catch (e: any) {
      return res.status(400).json({ error: { error_code: "INTAKE_FAILED", message: String(e?.message || e) } });
    }

    const artifactDir = persistArtifactToDisk(config.ARTIFACT_STORAGE_DIR, scan_id, artifact);

    createScan(db, {
      scan_id,
      status: "queued",
      artifact_type: artifactType,
      artifact_source: artifactSource,
      entrypoint: artifact.entrypoint,
      policy_version: policyVersion,
      artifact_root_sha256: artifact.root_sha256,
      manifest_json: artifact.canonical_manifest_json,
      verdict: null,
      score: null,
      finding_counts: null,
      result_token_sha256: sha256Hex(result_token),
      share_anonymized_artifact_for_research: Boolean(parsed.data.share_anonymized_artifact_for_research),
      error_code: null,
      error_message: null,
      artifact_storage_path: artifactDir,
      lease_owner: null,
      lease_expires_at: null,
      attempt_count: 0,
      next_attempt_at: null,
      started_at: null,
      completed_at: null
    });

    const totalBytes = artifact.files.reduce((s, f) => s + f.bytes.byteLength, 0);
    const asyncMode = (config.SCAN_FORCE_ASYNC ?? false) || totalBytes > 2 * 1024 * 1024 || artifact.files.length > 500;

    if (asyncMode) {
      const body = { scan_id, status: "queued", result_token };
      if (paymentId) {
        idem.put(paymentId, requestHash, 202, { "content-type": "application/json" }, body);
      }
      return res.status(202).json(body);
    }

    try {
      markScanRunning(db, scan_id, {
        worker_id: "api-sync",
        now_ms: nowMs(),
        lease_ms: config.WORKER_LEASE_MS ?? 120_000
      });
      const out = runScan(scan_id, artifact, policy);
      for (const f of out.findings) {
        for (const ev of f.evidence) {
          ev.snippet = redactText(ev.snippet);
        }
      }

      deleteFindingsForScan(db, scan_id);
      insertFindings(db, out.findings);
      markScanCompleted(db, scan_id, {
        now_ms: nowMs(),
        verdict: out.verdict,
        score: out.score,
        finding_counts: out.counts
      });

      const completedScan = getScanById(db, scan_id);
      if (!completedScan || completedScan.score === null || !completedScan.finding_counts) {
        throw new Error("scan row missing completed fields");
      }

      const body = {
        scan_id,
        status: "completed",
        created_at: toIso(completedScan.created_at),
        updated_at: toIso(completedScan.updated_at),
        policy_version: policyVersion,
        artifact_root_sha256: artifact.root_sha256,
        verdict: out.verdict,
        score: out.score,
        finding_counts: out.counts,
        findings: out.findings.map((f) => ({
          finding_id: f.finding_id,
          severity: f.severity,
          category: f.category,
          title: f.title,
          description: f.description,
          evidence: f.evidence,
          recommendations: f.recommendations,
          fingerprints: f.fingerprints
        })),
        result_token
      };

      if (paymentId) {
        idem.put(paymentId, requestHash, 200, { "content-type": "application/json" }, body);
      }
      return res.status(200).json(body);
    } catch (e: any) {
      markScanFailed(db, scan_id, "SCAN_FAILED", String(e?.message || e), {
        now_ms: nowMs()
      });
      return res.status(500).json({ error: { error_code: "SCAN_FAILED", message: "scan failed" } });
    }
  });

  router.get("/scan/:scan_id", (req, res) => {
    const scan_id = req.params.scan_id;
    const token = String(req.query.token || "");
    if (!token) return res.status(401).json({ error: { error_code: "UNAUTHORIZED", message: "missing token" } });

    const scan = getScanByIdAndToken(db, scan_id, token);
    if (!scan) return res.status(404).json({ error: { error_code: "NOT_FOUND", message: "scan not found" } });

    if (scan.status === "completed") {
      const findings = getFindingsForScan(db, scan_id);
      return res.status(200).json({
        scan_id,
        status: scan.status,
        created_at: toIso(scan.created_at),
        updated_at: toIso(scan.updated_at),
        artifact_root_sha256: scan.artifact_root_sha256,
        policy_version: scan.policy_version,
        verdict: scan.verdict,
        score: scan.score,
        finding_counts: scan.finding_counts,
        findings: findings.map((f) => ({
          finding_id: f.finding_id,
          severity: f.severity,
          category: f.category,
          title: f.title,
          description: f.description,
          evidence: f.evidence,
          recommendations: f.recommendations,
          fingerprints: f.fingerprints
        }))
      });
    }

    return res.status(200).json({
      scan_id,
      status: scan.status,
      created_at: toIso(scan.created_at),
      updated_at: toIso(scan.updated_at),
      ...(scan.status === "failed"
        ? {
            error: {
              error_code: scan.error_code || "SCAN_FAILED",
              message: scan.error_message || "scan failed"
            }
          }
        : {})
    });
  });

  return router;
}

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function toIso(ms: number): string {
  return new Date(ms).toISOString();
}
