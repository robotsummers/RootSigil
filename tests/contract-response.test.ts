import { webcrypto, createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { RequestHandler } from "express";
import { afterEach, describe, expect, test } from "vitest";
import { getPublicKeyAsync } from "@noble/ed25519";
import inject from "light-my-request";
import { buildApp } from "../src/app.js";
import type { AppConfig } from "../src/config.js";
import { openDb, type SqliteDb } from "../src/db/db.js";
import { loadPolicyFromFile } from "../src/lib/policy.js";

if (!(globalThis as any).crypto) {
  (globalThis as any).crypto = webcrypto as any;
}

type Fixture = {
  app: ReturnType<typeof buildApp>;
  db: SqliteDb;
  tmpDir: string;
};

const fixtures: Fixture[] = [];

afterEach(() => {
  while (fixtures.length > 0) {
    const fixture = fixtures.pop()!;
    fixture.db.close();
    fs.rmSync(fixture.tmpDir, { recursive: true, force: true });
  }
});

describe("response contracts", () => {
  test("scan create/get response shapes", async () => {
    const fixture = await createFixture();
    const create = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/scan",
      payload: { inline: { content: "never commit API tokens" } }
    });

    expect(create.statusCode).toBe(200);
    expectExactKeys(create.body, [
      "scan_id",
      "status",
      "created_at",
      "updated_at",
      "policy_version",
      "artifact_root_sha256",
      "verdict",
      "score",
      "finding_counts",
      "findings",
      "result_token"
    ]);
    expect(create.body.status).toBe("completed");
    expectExactKeys(create.body.finding_counts, ["critical", "high", "medium", "low"]);
    expect(Array.isArray(create.body.findings)).toBe(true);
    if (create.body.findings.length > 0) {
      expectExactKeys(create.body.findings[0], [
        "finding_id",
        "severity",
        "category",
        "title",
        "description",
        "evidence",
        "recommendations",
        "fingerprints"
      ]);
      expect(Array.isArray(create.body.findings[0].evidence)).toBe(true);
      if (create.body.findings[0].evidence.length > 0) {
        expectExactKeys(create.body.findings[0].evidence[0], ["path", "line_start", "line_end", "snippet"]);
      }
    }

    const getRes = await jsonRequest(fixture.app, {
      method: "GET",
      url: `/v1/scan/${create.body.scan_id}?token=${encodeURIComponent(create.body.result_token)}`
    });
    expect(getRes.statusCode).toBe(200);
    expectExactKeys(getRes.body, [
      "scan_id",
      "status",
      "created_at",
      "updated_at",
      "artifact_root_sha256",
      "policy_version",
      "verdict",
      "score",
      "finding_counts",
      "findings"
    ]);
  });

  test("attestation list and verify response shapes", async () => {
    const fixture = await createFixture();
    const content = "contract test content";

    const scan = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/scan",
      payload: { inline: { content } }
    });
    expect(scan.statusCode).toBe(200);

    const attest = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/attest",
      payload: { scan_id: scan.body.scan_id, token: scan.body.result_token }
    });
    expect(attest.statusCode).toBe(200);
    expectExactKeys(attest.body, ["attestation_document", "signature_b64url"]);

    const list = await jsonRequest(fixture.app, {
      method: "GET",
      url: `/v1/attest/${scan.body.artifact_root_sha256}`
    });
    expect(list.statusCode).toBe(200);
    expectExactKeys(list.body, ["artifact_root_sha256", "attestations"]);
    expect(Array.isArray(list.body.attestations)).toBe(true);
    expect(list.body.attestations.length).toBeGreaterThan(0);
    expectExactKeys(list.body.attestations[0], ["attestation_document", "signature_b64url"]);

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
    expectExactKeys(verify.body, ["valid_signature", "matches_artifact_hash", "revoked", "errors"]);
  });

  test("revocations response shape", async () => {
    const fixture = await createFixture();
    const res = await jsonRequest(fixture.app, {
      method: "GET",
      url: "/v1/revocations"
    });

    expect(res.statusCode).toBe(200);
    expectExactKeys(res.body, ["revocations_document", "signature_b64url"]);
    expectExactKeys(res.body.revocations_document, ["revocations_version", "issuer", "published_at", "revocations"]);
    expectExactKeys(res.body.revocations_document.issuer, ["issuer_id", "public_key", "algorithm"]);
  });
});

function expectExactKeys(value: unknown, expectedKeys: string[]): void {
  expect(value).toBeTruthy();
  expect(typeof value).toBe("object");
  expect(Array.isArray(value)).toBe(false);
  expect(Object.keys(value as Record<string, unknown>).sort()).toEqual([...expectedKeys].sort());
}

async function createFixture(): Promise<Fixture> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-attestor-contract-"));
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
      extractPaymentId: (_paymentSignatureHeaderValue: string | undefined) => null
    }
  };

  const app = buildApp({ config, db, policy, x402 });
  const fixture = { app, db, tmpDir };
  fixtures.push(fixture);
  return fixture;
}

function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}

async function jsonRequest(
  app: ReturnType<typeof buildApp>,
  args: {
    method: "GET" | "POST";
    url: string;
    payload?: unknown;
  }
): Promise<{ statusCode: number; body: any }> {
  const headers: Record<string, string> = {};
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
