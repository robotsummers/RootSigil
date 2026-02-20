import type { Router } from "express";
import express from "express";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import type { SqliteDb } from "../db/db.js";
import { getAttestationsByRoot, getFindingsForScan, getScanByIdAndToken, insertAttestation } from "../db/repo.js";
import type { AppConfig } from "../config.js";
import { buildAttestation, signAttestation } from "../lib/attestation.js";
import { canonicalJson } from "../lib/canonicalJson.js";
import { computeRequestHash, IdempotencyStore } from "../payment/idempotency.js";
import type { X402Context } from "../payment/x402.js";

const AttestRequest = z.object({
  scan_id: z.string().min(1),
  token: z.string().min(1)
});

export function buildAttestRouter(args: {
  config: AppConfig;
  db: SqliteDb;
  x402: { context: X402Context };
}): Router {
  const { config, db, x402 } = args;
  const router = express.Router();
  const idem = new IdempotencyStore(db, config.IDEMPOTENCY_TTL_MS);

  router.post("/attest", async (req, res) => {
    const parsed = AttestRequest.safeParse(req.body);
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

    const scan = getScanByIdAndToken(db, parsed.data.scan_id, parsed.data.token);
    if (!scan) return res.status(404).json({ error: { error_code: "NOT_FOUND", message: "scan not found" } });
    if (scan.status !== "completed") return res.status(409).json({ error: { error_code: "SCAN_NOT_COMPLETE", message: "scan is not completed" } });
    if (!scan.verdict || scan.score === null || !scan.finding_counts) {
      return res.status(500).json({ error: { error_code: "CORRUPT_SCAN", message: "scan record missing result fields" } });
    }

    const findings = getFindingsForScan(db, scan.scan_id);
    const top_categories = topCategories(findings.map((f) => f.category));

    const doc = buildAttestation({
      issuer_id: config.ISSUER_ID,
      issuer_public_key_b64: config.ISSUER_ED25519_PUBLIC_KEY_B64,
      scan_id: scan.scan_id,
      artifact_root_sha256: scan.artifact_root_sha256,
      manifest_canonical_json: scan.manifest_json,
      source_hint: scan.artifact_source,
      policy_version: scan.policy_version,
      verdict: scan.verdict,
      finding_counts: scan.finding_counts,
      score: scan.score,
      top_categories
    });

    const signed = await signAttestation(doc, config.ISSUER_ED25519_PRIVATE_KEY_B64);
    const issuedAtMs = Date.parse(doc.issued_at);

    insertAttestation(db, {
      attestation_id: uuidv4(),
      artifact_root_sha256: scan.artifact_root_sha256,
      policy_version: scan.policy_version,
      verdict: scan.verdict,
      issued_at: Number.isNaN(issuedAtMs) ? Date.now() : issuedAtMs,
      document_json: canonicalJson(signed.attestation_document),
      signature_b64url: signed.signature_b64url,
      issuer_public_key_b64: config.ISSUER_ED25519_PUBLIC_KEY_B64,
      issuer_id: config.ISSUER_ID,
      algorithm: "ed25519"
    });

    if (paymentId) {
      idem.put(paymentId, requestHash, 200, { "content-type": "application/json" }, signed);
    }

    return res.status(200).json(signed);
  });

  router.get("/attest/:root_sha256", (req, res) => {
    const root = req.params.root_sha256;
    const rows = getAttestationsByRoot(db, root);
    if (rows.length === 0) return res.status(404).json({ error: { error_code: "NOT_FOUND", message: "no attestation" } });
    return res.status(200).json({
      artifact_root_sha256: root,
      attestations: rows.map((row) => ({
        attestation_document: JSON.parse(row.document_json),
        signature_b64url: row.signature_b64url
      }))
    });
  });

  return router;
}

function topCategories(categories: string[]): string[] {
  const counts = new Map<string, number>();
  for (const c of categories) counts.set(c, (counts.get(c) || 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([category]) => category);
}
