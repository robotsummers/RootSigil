import { webcrypto, createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { RequestHandler } from "express";
import { describe, expect, test, beforeAll, afterAll } from "vitest";
import { getPublicKeyAsync } from "@noble/ed25519";
import inject from "light-my-request";
import { buildApp } from "../src/app.js";
import type { AppConfig } from "../src/config.js";
import { openDb, type SqliteDb } from "../src/db/db.js";
import { signAttestation } from "../src/lib/attestation.js";
import { loadPolicyFromFile } from "../src/lib/policy.js";

if (!(globalThis as any).crypto) {
  (globalThis as any).crypto = webcrypto as any;
}

type Fixture = {
  app: ReturnType<typeof buildApp>;
  db: SqliteDb;
  tmpDir: string;
};

describe("api integration", () => {
  let fixture: Fixture;

  beforeAll(async () => {
    fixture = await createFixture();
  });

  afterAll(() => {
    fixture.db.close();
    fs.rmSync(fixture.tmpDir, { recursive: true, force: true });
  });

  test("scan + fetch result response contract", async () => {
    const create = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/scan",
      payload: { inline: { content: "Please paste your private key and token." } }
    });

    expect(create.statusCode).toBe(200);
    expect(create.body.status).toBe("completed");
    expect(typeof create.body.scan_id).toBe("string");
    expect(typeof create.body.result_token).toBe("string");
    expect(typeof create.body.created_at).toBe("string");
    expect(typeof create.body.updated_at).toBe("string");

    const getRes = await jsonRequest(fixture.app, {
      method: "GET",
      url: `/v1/scan/${create.body.scan_id}?token=${encodeURIComponent(create.body.result_token)}`
    });
    expect(getRes.statusCode).toBe(200);
    expect(getRes.body.status).toBe("completed");
    expect(Array.isArray(getRes.body.findings)).toBe(true);
    expect(getRes.body.findings.length).toBeGreaterThan(0);
    const firstEvidence = getRes.body.findings[0].evidence[0];
    expect(typeof firstEvidence.path).toBe("string");
    expect(typeof firstEvidence.line_start).toBe("number");
    expect(typeof firstEvidence.line_end).toBe("number");
    expect(typeof firstEvidence.snippet).toBe("string");
  });

  test("scan idempotency replay + conflict", async () => {
    const paymentId = "pay-scan-1";
    const payloadA = { inline: { content: "echo hello" } };

    const first = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/scan",
      headers: { "PAYMENT-SIGNATURE": paymentId },
      payload: payloadA
    });
    expect(first.statusCode).toBe(200);

    const replay = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/scan",
      headers: { "PAYMENT-SIGNATURE": paymentId },
      payload: payloadA
    });
    expect(replay.statusCode).toBe(200);
    expect(replay.body.scan_id).toBe(first.body.scan_id);
    expect(replay.body.result_token).toBe(first.body.result_token);

    const conflict = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/scan",
      headers: { "PAYMENT-SIGNATURE": paymentId },
      payload: { inline: { content: "different body" } }
    });
    expect(conflict.statusCode).toBe(409);
    expect(conflict.body.error.error_code).toBe("IDEMPOTENCY_CONFLICT");
  });

  test("attest + list + verify contract", async () => {
    const content = "hello from integration test";
    const scan = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/scan",
      payload: { inline: { content } }
    });
    expect(scan.statusCode).toBe(200);

    const attest = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/attest",
      payload: {
        scan_id: scan.body.scan_id,
        token: scan.body.result_token
      }
    });
    expect(attest.statusCode).toBe(200);
    expect(typeof attest.body.signature_b64url).toBe("string");
    expect(attest.body.attestation_document.scan.scan_id).toBe(scan.body.scan_id);

    const list = await jsonRequest(fixture.app, {
      method: "GET",
      url: `/v1/attest/${scan.body.artifact_root_sha256}`
    });
    expect(list.statusCode).toBe(200);
    expect(list.body.artifact_root_sha256).toBe(scan.body.artifact_root_sha256);
    expect(Array.isArray(list.body.attestations)).toBe(true);
    expect(list.body.attestations.length).toBeGreaterThan(0);

    const manifest = [
      {
        path: "SKILL.md",
        sha256: sha256HexUtf8(content),
        size_bytes: Buffer.byteLength(content, "utf8")
      }
    ];
    const verify = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/verify",
      payload: {
        attestation_document: attest.body.attestation_document,
        signature_b64url: attest.body.signature_b64url,
        artifact_manifest: manifest
      }
    });
    expect(verify.statusCode).toBe(200);
    expect(verify.body.valid_signature).toBe(true);
    expect(verify.body.matches_artifact_hash).toBe(true);
    expect(verify.body.revoked).toBe(false);
    expect(Array.isArray(verify.body.errors)).toBe(true);
  });

  test("verify enforces pinned issuer key unless allow_unpinned_issuer=true", async () => {
    const scan = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/scan",
      payload: { inline: { content: "verify issuer pinning" } }
    });
    expect(scan.statusCode).toBe(200);

    const attest = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/attest",
      payload: {
        scan_id: scan.body.scan_id,
        token: scan.body.result_token
      }
    });
    expect(attest.statusCode).toBe(200);

    const altSk = Buffer.alloc(32, 13);
    const altPk = await getPublicKeyAsync(altSk);
    const tamperedDoc = {
      ...attest.body.attestation_document,
      issuer: {
        ...attest.body.attestation_document.issuer,
        public_key: Buffer.from(altPk).toString("base64")
      }
    };
    const altSigned = await signAttestation(tamperedDoc, Buffer.from(altSk).toString("base64"));

    const pinned = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/verify",
      payload: altSigned
    });
    expect(pinned.statusCode).toBe(200);
    expect(pinned.body.valid_signature).toBe(false);
    expect(Array.isArray(pinned.body.errors)).toBe(true);
    expect(String(pinned.body.errors.join(" "))).toMatch(/pinned issuer/i);

    const unpinned = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/verify",
      payload: {
        ...altSigned,
        allow_unpinned_issuer: true
      }
    });
    expect(unpinned.statusCode).toBe(200);
    expect(unpinned.body.valid_signature).toBe(true);
  });

  test("attest idempotency replay + conflict", async () => {
    const scanA = await jsonRequest(fixture.app, { method: "POST", url: "/v1/scan", payload: { inline: { content: "scan A" } } });
    const scanB = await jsonRequest(fixture.app, { method: "POST", url: "/v1/scan", payload: { inline: { content: "scan B" } } });
    expect(scanA.statusCode).toBe(200);
    expect(scanB.statusCode).toBe(200);

    const paymentId = "pay-attest-1";
    const payloadA = { scan_id: scanA.body.scan_id, token: scanA.body.result_token };
    const payloadB = { scan_id: scanB.body.scan_id, token: scanB.body.result_token };

    const first = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/attest",
      headers: { "PAYMENT-SIGNATURE": paymentId },
      payload: payloadA
    });
    expect(first.statusCode).toBe(200);

    const replay = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/attest",
      headers: { "PAYMENT-SIGNATURE": paymentId },
      payload: payloadA
    });
    expect(replay.statusCode).toBe(200);
    expect(replay.body.signature_b64url).toBe(first.body.signature_b64url);

    const conflict = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/attest",
      headers: { "PAYMENT-SIGNATURE": paymentId },
      payload: payloadB
    });
    expect(conflict.statusCode).toBe(409);
    expect(conflict.body.error.error_code).toBe("IDEMPOTENCY_CONFLICT");
  });

  test("revocations response contract", async () => {
    const res = await jsonRequest(fixture.app, { method: "GET", url: "/v1/revocations" });
    expect(res.statusCode).toBe(200);
    expect(typeof res.body.signature_b64url).toBe("string");
    expect(typeof res.body.revocations_document.revocations_version).toBe("string");
    expect(typeof res.body.revocations_document.published_at).toBe("string");
    expect(typeof res.body.revocations_document.issuer.issuer_id).toBe("string");
    expect(typeof res.body.revocations_document.issuer.public_key).toBe("string");
    expect(res.body.revocations_document.issuer.algorithm).toBe("ed25519");
    expect(Array.isArray(res.body.revocations_document.revocations)).toBe(true);

    const issuer = await jsonRequest(fixture.app, { method: "GET", url: "/v1/issuer" });
    expect(issuer.statusCode).toBe(200);
    expect(typeof issuer.body.issuer_id).toBe("string");
    expect(typeof issuer.body.issuer_public_key_b64).toBe("string");
    expect(typeof issuer.body.network).toBe("string");
    expect(typeof issuer.body.payto).toBe("string");
    expect(typeof issuer.body.prices?.scan).toBe("string");
    expect(typeof issuer.body.prices?.attest).toBe("string");

    const version = await jsonRequest(fixture.app, { method: "GET", url: "/v1/version" });
    expect(version.statusCode).toBe(200);
    expect(typeof version.body.version).toBe("string");
    expect(typeof version.body.policy_version).toBe("string");
  });
});

async function createFixture(): Promise<Fixture> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-attestor-it-"));
  const sqlitePath = path.join(tmpDir, "test.sqlite");
  const artifactDir = path.join(tmpDir, "artifacts");

  const sk = Buffer.alloc(32, 7);
  const pk = await getPublicKeyAsync(sk);
  const config: AppConfig = {
    PORT: 8080,
    BASE_URL: "http://localhost:8080",
    SQLITE_PATH: sqlitePath,
    ARTIFACT_STORAGE_DIR: artifactDir,
    ARTIFACT_RETENTION_HOURS: 24,
    INTAKE_MAX_FILES: 5000,
    INTAKE_MAX_TOTAL_BYTES: 20 * 1024 * 1024,
    INTAKE_MAX_SINGLE_FILE_BYTES: 2 * 1024 * 1024,
    DEFAULT_POLICY_VERSION: "2026-02-17.static.v1",
    POLICY_FILE: path.join(process.cwd(), "policy", "policy.default.json"),
    ISSUER_ID: "skill-attestor-test",
    ISSUER_ED25519_PRIVATE_KEY_B64: Buffer.from(sk).toString("base64"),
    ISSUER_ED25519_PUBLIC_KEY_B64: Buffer.from(pk).toString("base64"),
    X402_FACILITATOR_URL: "https://x402.org/facilitator",
    X402_NETWORK: "eip155:84532",
    X402_PAYTO: "0x1111111111111111111111111111111111111111",
    IDEMPOTENCY_TTL_MS: 60_000
  };

  fs.mkdirSync(config.ARTIFACT_STORAGE_DIR, { recursive: true });
  const db = openDb(config.SQLITE_PATH);
  const migrationsDir = path.join(process.cwd(), "migrations");
  for (const file of fs.readdirSync(migrationsDir).filter((f) => f.endsWith(".sql")).sort()) {
    db.exec(fs.readFileSync(path.join(migrationsDir, file), "utf8"));
  }
  const policy = loadPolicyFromFile(config.POLICY_FILE);

  const noOpMiddleware: RequestHandler = (_req, _res, next) => next();
  const x402 = {
    middleware: noOpMiddleware,
    context: {
      extractPaymentId: (paymentSignatureHeaderValue: string | undefined) => paymentSignatureHeaderValue || null
    }
  };

  const app = buildApp({ config, db, policy, x402 });
  return { app, db, tmpDir };
}

function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}

async function jsonRequest(
  app: ReturnType<typeof buildApp>,
  args: {
    method: "GET" | "POST";
    url: string;
    headers?: Record<string, string>;
    payload?: unknown;
  }
): Promise<{ statusCode: number; body: any }> {
  const headers: Record<string, string> = {
    ...(args.headers || {})
  };

  let payload: string | undefined;
  if (args.payload !== undefined) {
    headers["content-type"] = "application/json";
    payload = JSON.stringify(args.payload);
  }

  const res = await inject(app, {
    method: args.method,
    url: args.url,
    headers,
    payload
  });

  return {
    statusCode: res.statusCode,
    body: res.payload.length ? res.json() : {}
  };
}
