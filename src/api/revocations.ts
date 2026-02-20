import type { Router } from "express";
import express from "express";
import { sha256 } from "@noble/hashes/sha256";
import { signAsync } from "@noble/ed25519";
import type { AppConfig } from "../config.js";
import type { SqliteDb } from "../db/db.js";
import { listRevocations } from "../db/repo.js";
import { canonicalJson } from "../lib/canonicalJson.js";

export function buildRevocationRouter(args: { config: AppConfig; db: SqliteDb }): Router {
  const { config, db } = args;
  const router = express.Router();

  router.get("/revocations", async (_req, res) => {
    const rows = listRevocations(db);
    const doc = {
      revocations_version: "1",
      issuer: {
        issuer_id: config.ISSUER_ID,
        public_key: config.ISSUER_ED25519_PUBLIC_KEY_B64,
        algorithm: "ed25519" as const
      },
      published_at: new Date().toISOString(),
      revocations: rows.map((r) => ({
        root_sha256: r.artifact_root_sha256,
        issued_at: new Date(r.issued_at).toISOString(),
        revoked_at: new Date(r.revoked_at).toISOString(),
        ...(r.reason ? { reason: r.reason } : {})
      }))
    };
    const canonical = canonicalJson(doc);
    const digest = sha256(new TextEncoder().encode(canonical));
    const sk = Buffer.from(config.ISSUER_ED25519_PRIVATE_KEY_B64, "base64");
    const sig = await signAsync(digest, sk);
    const signature_b64url = Buffer.from(sig)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");

    return res.status(200).json({ revocations_document: doc, signature_b64url });
  });

  return router;
}
