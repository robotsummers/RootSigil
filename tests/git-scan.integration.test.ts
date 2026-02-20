import { webcrypto } from "node:crypto";
import { execFileSync } from "node:child_process";
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
  previousRewriteEnv: string | undefined;
};

const fixtures: Fixture[] = [];

afterEach(() => {
  while (fixtures.length > 0) {
    const fixture = fixtures.pop()!;
    fixture.db.close();
    if (fixture.previousRewriteEnv === undefined) {
      delete process.env.SKILL_ATTESTOR_TEST_GIT_REWRITE_JSON;
    } else {
      process.env.SKILL_ATTESTOR_TEST_GIT_REWRITE_JSON = fixture.previousRewriteEnv;
    }
    fs.rmSync(fixture.tmpDir, { recursive: true, force: true });
  }
});

describe("git scan integration", () => {
  test("scans git input from local fixture repo via test rewrite map", async () => {
    const fixture = await createFixture({ maxSingleFileBytes: 2 * 1024 * 1024 });
    const repoDir = createGitRepo(fixture.tmpDir, {
      "SKILL.md": "Do not commit API tokens.\n\n```bash\necho test\n```",
      "docs/README.md": "fixture docs"
    });

    const repoUrl = "https://example.com/fixture-repo.git";
    process.env.SKILL_ATTESTOR_TEST_GIT_REWRITE_JSON = JSON.stringify({ [repoUrl]: repoDir });

    const res = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/scan",
      payload: {
        git: {
          repo_url: repoUrl,
          ref: "HEAD",
          entrypoint: "SKILL.md"
        }
      }
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe("completed");
    expect(typeof res.body.scan_id).toBe("string");
    expect(typeof res.body.result_token).toBe("string");
    expect(typeof res.body.artifact_root_sha256).toBe("string");
  });

  test("rejects oversized git files using configured intake limits", async () => {
    const fixture = await createFixture({ maxSingleFileBytes: 64 });
    const repoDir = createGitRepo(fixture.tmpDir, {
      "SKILL.md": "x".repeat(512)
    });

    const repoUrl = "https://example.com/fixture-oversized.git";
    process.env.SKILL_ATTESTOR_TEST_GIT_REWRITE_JSON = JSON.stringify({ [repoUrl]: repoDir });

    const res = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/scan",
      payload: {
        git: {
          repo_url: repoUrl,
          ref: "HEAD",
          entrypoint: "SKILL.md"
        }
      }
    });

    expect(res.statusCode).toBe(400);
    expect(res.body.error?.error_code).toBe("INTAKE_FAILED");
    expect(String(res.body.error?.message || "")).toMatch(/oversized/i);
  });
});

async function createFixture(args: { maxSingleFileBytes: number }): Promise<Fixture> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-attestor-git-it-"));
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
    INTAKE_MAX_SINGLE_FILE_BYTES: args.maxSingleFileBytes,
    DEFAULT_POLICY_VERSION: "2026-02-17.static.v1",
    POLICY_FILE: path.join(process.cwd(), "policy", "policy.default.json"),
    ISSUER_ID: "skill-attestor-test",
    ISSUER_ED25519_PRIVATE_KEY_B64: Buffer.from(sk).toString("base64"),
    ISSUER_ED25519_PUBLIC_KEY_B64: Buffer.from(pk).toString("base64"),
    X402_FACILITATOR_URL: "https://x402.org/facilitator",
    X402_NETWORK: "eip155:84532",
    X402_PAYTO: "0x1111111111111111111111111111111111111111",
    GIT_ALLOWED_HOSTS: ["example.com", "github.com"],
    GIT_TIMEOUT_MS: 15_000,
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
  const fixture = {
    app,
    db,
    tmpDir,
    previousRewriteEnv: process.env.SKILL_ATTESTOR_TEST_GIT_REWRITE_JSON
  };
  fixtures.push(fixture);
  return fixture;
}

function createGitRepo(baseTmpDir: string, files: Record<string, string>): string {
  const repoDir = path.join(baseTmpDir, `repo-${Math.random().toString(36).slice(2)}`);
  fs.mkdirSync(repoDir, { recursive: true });

  for (const [relativePath, content] of Object.entries(files)) {
    const fullPath = path.join(repoDir, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, "utf8");
  }

  runGit(repoDir, ["init"]);
  runGit(repoDir, ["config", "user.name", "Test User"]);
  runGit(repoDir, ["config", "user.email", "test@example.com"]);
  runGit(repoDir, ["add", "."]);
  runGit(repoDir, ["commit", "-m", "fixture commit"]);
  return repoDir;
}

function runGit(cwd: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0" }
  }).toString("utf8");
}

async function jsonRequest(
  app: ReturnType<typeof buildApp>,
  args: {
    method: "POST";
    url: string;
    payload: unknown;
  }
): Promise<{ statusCode: number; body: any }> {
  const res = await inject(app, {
    method: args.method,
    url: args.url,
    headers: { "content-type": "application/json" },
    payload: JSON.stringify(args.payload)
  });
  return {
    statusCode: res.statusCode,
    body: res.payload.length ? res.json() : {}
  };
}
