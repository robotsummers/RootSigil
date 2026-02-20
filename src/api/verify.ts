import type { Router } from "express";
import express from "express";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import type { SqliteDb } from "../db/db.js";
import { isRevoked } from "../db/repo.js";
import { verifyAttestation } from "../lib/attestation.js";
import { canonicalJson, sha256HexUtf8 } from "../lib/canonicalJson.js";

const VerifyRequest = z.object({
  attestation_document: z.object({}).passthrough(),
  signature_b64url: z.string().min(1),
  artifact_manifest: z
    .array(
      z
        .object({
          path: z.string(),
          sha256: z.string(),
          size_bytes: z.number().int().nonnegative()
        })
        .strict()
    )
    .optional()
});

export function buildVerifyRouter(args: { config: AppConfig; db: SqliteDb }): Router {
  const { config, db } = args;
  const router = express.Router();

  router.post("/verify", async (req, res) => {
    const parsed = VerifyRequest.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: { error_code: "BAD_REQUEST", message: parsed.error.message } });
    }
    const errors: string[] = [];
    const doc = parsed.data.attestation_document as Record<string, unknown>;
    const docIssuer = asObject(doc.issuer);
    const issuerPublicKey = typeof docIssuer?.public_key === "string" ? docIssuer.public_key : config.ISSUER_ED25519_PUBLIC_KEY_B64;

    let validSignature = false;
    try {
      validSignature = await verifyAttestation(
        {
          attestation_document: parsed.data.attestation_document as any,
          signature_b64url: parsed.data.signature_b64url
        },
        issuerPublicKey
      );
    } catch {
      validSignature = false;
    }
    if (!validSignature) errors.push("invalid signature");

    const artifactObj = asObject(doc.artifact);
    const docRoot = typeof artifactObj?.root_sha256 === "string" ? artifactObj.root_sha256 : null;
    let matchesArtifactHash = true;
    if (parsed.data.artifact_manifest) {
      if (!isSortedByPath(parsed.data.artifact_manifest)) {
        matchesArtifactHash = false;
        errors.push("artifact_manifest must be sorted by path");
      } else if (!docRoot) {
        matchesArtifactHash = false;
        errors.push("attestation_document.artifact.root_sha256 is missing");
      } else {
        const computedRoot = sha256HexUtf8(canonicalJson(parsed.data.artifact_manifest));
        matchesArtifactHash = computedRoot === docRoot;
        if (!matchesArtifactHash) errors.push("artifact manifest hash does not match attestation root");
      }
    }

    const issuedAt = parseDate(doc.issued_at)?.getTime() ?? null;
    const revoked = Boolean(docRoot && issuedAt !== null && isRevoked(db, docRoot, issuedAt));
    if (revoked) errors.push("attestation is revoked");

    const expiresAt = parseDate(doc.expires_at);
    if (expiresAt && expiresAt.getTime() <= Date.now()) {
      errors.push("attestation is expired");
    }

    return res.status(200).json({
      valid_signature: validSignature,
      matches_artifact_hash: matchesArtifactHash,
      revoked,
      errors
    });
  });

  return router;
}

function parseDate(s: unknown): Date | null {
  if (typeof s !== "string") return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

function asObject(v: unknown): Record<string, unknown> | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  return v as Record<string, unknown>;
}

function isSortedByPath(entries: Array<{ path: string }>): boolean {
  for (let i = 1; i < entries.length; i += 1) {
    if (entries[i - 1].path > entries[i].path) return false;
  }
  return true;
}
