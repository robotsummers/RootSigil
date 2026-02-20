import { webcrypto } from "node:crypto";
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
import { claimNextScan, createScan } from "../src/db/repo.js";
import { loadPolicyFromFile } from "../src/lib/policy.js";
import { startWorkerLoop } from "../src/worker/scan-worker.js";

if (!(globalThis as any).crypto) {
  (globalThis as any).crypto = webcrypto as any;
}

type Fixture = {
  app: ReturnType<typeof buildApp>;
  db: SqliteDb;
  tmpDir: string;
  config: AppConfig;
};

const fixtures: Fixture[] = [];

afterEach(() => {
  while (fixtures.length > 0) {
    const fixture = fixtures.pop()!;
    fixture.db.close();
    fs.rmSync(fixture.tmpDir, { recursive: true, force: true });
  }
});

describe("queue and worker loop", () => {
  test("returns 202 when SCAN_FORCE_ASYNC=true and worker completes queued scans", async () => {
    const fixture = await createFixture({ forceAsync: true });
    const worker = startWorkerLoop({
      config: fixture.config,
      db: fixture.db,
      policy: loadPolicyFromFile(path.join(process.cwd(), "policy", "policy.default.json"))
    });

    const created = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/scan",
      payload: {
        inline: {
          filename: "SKILL.md",
          content: "Never commit production secrets"
        }
      }
    });
    expect(created.statusCode).toBe(202);
    expect(created.body.status).toBe("queued");
    expect(typeof created.body.scan_id).toBe("string");
    expect(typeof created.body.result_token).toBe("string");

    const completed = await waitForCompletion(fixture.app, created.body.scan_id, created.body.result_token, 2000);
    expect(completed.statusCode).toBe(200);
    expect(completed.body.status).toBe("completed");
    expect(typeof completed.body.verdict).toBe("string");
    expect(Array.isArray(completed.body.findings)).toBe(true);

    worker.stop();
  });

  test("reclaims running scans after lease expiration", async () => {
    const fixture = await createFixture({ forceAsync: true });

    createScan(fixture.db, {
      scan_id: "scan-reclaim",
      status: "queued",
      artifact_type: "inline",
      artifact_source: "inline",
      entrypoint: "SKILL.md",
      policy_version: "2026-02-17.static.v1",
      artifact_root_sha256: "root",
      manifest_json: "[]",
      verdict: null,
      score: null,
      finding_counts: null,
      result_token_sha256: "token",
      share_anonymized_artifact_for_research: false,
      error_code: null,
      error_message: null,
      artifact_storage_path: null
    });

    const first = claimNextScan(fixture.db, {
      worker_id: "worker-a",
      now_ms: 1_000,
      lease_ms: 1_000
    });
    expect(first?.scan_id).toBe("scan-reclaim");
    expect(first?.status).toBe("running");
    expect(first?.attempt_count).toBe(1);
    expect(first?.lease_owner).toBe("worker-a");

    const beforeExpiry = claimNextScan(fixture.db, {
      worker_id: "worker-b",
      now_ms: 1_500,
      lease_ms: 1_000
    });
    expect(beforeExpiry).toBeNull();

    const afterExpiry = claimNextScan(fixture.db, {
      worker_id: "worker-b",
      now_ms: 2_100,
      lease_ms: 1_000
    });
    expect(afterExpiry?.scan_id).toBe("scan-reclaim");
    expect(afterExpiry?.attempt_count).toBe(2);
    expect(afterExpiry?.lease_owner).toBe("worker-b");
  });
});

async function createFixture(args: { forceAsync: boolean }): Promise<Fixture> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-attestor-worker-it-"));
  const sqlitePath = path.join(tmpDir, "test.sqlite");
  const artifactDir = path.join(tmpDir, "artifacts");
  const config = await buildConfig(sqlitePath, artifactDir, args.forceAsync);

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
  const fixture = { app, db, tmpDir, config };
  fixtures.push(fixture);
  return fixture;
}

async function buildConfig(sqlitePath: string, artifactDir: string, forceAsync: boolean): Promise<AppConfig> {
  const sk = Buffer.alloc(32, 7);
  const pk = await getPublicKeyAsync(sk);
  return {
    PORT: 8080,
    BASE_URL: "http://localhost:8080",
    SQLITE_PATH: sqlitePath,
    ARTIFACT_STORAGE_DIR: artifactDir,
    ARTIFACT_RETENTION_HOURS: 24,
    INTAKE_MAX_FILES: 5000,
    INTAKE_MAX_TOTAL_BYTES: 20 * 1024 * 1024,
    INTAKE_MAX_SINGLE_FILE_BYTES: 2 * 1024 * 1024,
    HTTP_JSON_BODY_LIMIT_BYTES: 40 * 1024 * 1024,
    DEFAULT_POLICY_VERSION: "2026-02-17.static.v1",
    POLICY_FILE: path.join(process.cwd(), "policy", "policy.default.json"),
    ISSUER_ID: "rootsigil-test",
    ISSUER_ED25519_PRIVATE_KEY_B64: Buffer.from(sk).toString("base64"),
    ISSUER_ED25519_PUBLIC_KEY_B64: Buffer.from(pk).toString("base64"),
    TRUST_PROXY: false,
    RATE_LIMIT_WINDOW_MS: 60_000,
    RATE_LIMIT_MAX: 5000,
    GIT_ALLOWED_HOSTS: ["github.com", "example.com"],
    GIT_TIMEOUT_MS: 15_000,
    SCAN_FORCE_ASYNC: forceAsync,
    WORKER_POLL_MS: 25,
    WORKER_LEASE_MS: 1_000,
    WORKER_CONCURRENCY: 1,
    ROOTSIGIL_ROLE: "all",
    X402_ENABLED: false,
    X402_PAYWALL_SCAN: false,
    X402_PAYWALL_ATTEST: false,
    X402_PRICE_SCAN: "$0.01",
    X402_PRICE_ATTEST: "$0.01",
    X402_FACILITATOR_MODE: "testnet_url",
    X402_FACILITATOR_URL: "https://x402.org/facilitator",
    X402_NETWORK: "eip155:84532",
    X402_ASSET: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    X402_PAYTO: "0x1111111111111111111111111111111111111111",
    IDEMPOTENCY_TTL_MS: 60_000,
    VERSION: "test"
  };
}

async function waitForCompletion(
  app: ReturnType<typeof buildApp>,
  scanId: string,
  token: string,
  timeoutMs: number
): Promise<{ statusCode: number; body: any }> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const status = await jsonRequest(app, {
      method: "GET",
      url: `/v1/scan/${scanId}?token=${encodeURIComponent(token)}`
    });
    if (status.body?.status === "completed" || status.body?.status === "failed") {
      return status;
    }
    await sleep(25);
  }
  throw new Error("timed out waiting for queued scan completion");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function jsonRequest(
  app: ReturnType<typeof buildApp>,
  args:
    | {
        method: "POST";
        url: string;
        payload: unknown;
      }
    | {
        method: "GET";
        url: string;
      }
): Promise<{ statusCode: number; body: any }> {
  const headers: Record<string, string> = {};
  let payload: string | undefined;

  if (args.method === "POST") {
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
