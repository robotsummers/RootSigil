import { webcrypto, createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { RequestHandler } from "express";
import { afterEach, describe, expect, test } from "vitest";
import { getPublicKeyAsync } from "@noble/ed25519";
import inject from "light-my-request";
import YAML from "yaml";
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
  config: AppConfig;
};

type OpenApiDoc = {
  paths: Record<string, Record<string, { responses: Record<string, ResponseObject> }>>;
};

type ResponseObject = {
  content?: Record<string, { schema?: unknown }>;
};

type SchemaObject = {
  $ref?: string;
  oneOf?: unknown[];
  type?: string;
  enum?: unknown[];
  properties?: Record<string, unknown>;
  required?: string[];
  additionalProperties?: boolean | unknown;
  items?: unknown;
};

const fixtures: Fixture[] = [];

afterEach(() => {
  while (fixtures.length > 0) {
    const fixture = fixtures.pop()!;
    fixture.db.close();
    fs.rmSync(fixture.tmpDir, { recursive: true, force: true });
  }
});

describe("openapi conformance", () => {
  test("runtime JSON responses conform to declared OpenAPI schemas", async () => {
    const doc = loadOpenApiDoc();
    const fixture = await createFixture();

    const scanCreate = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/scan",
      payload: { inline: { content: "do not expose private keys" } }
    });
    expect(scanCreate.statusCode).toBe(200);
    assertConforms(scanCreate.body, getResponseSchema(doc, "/v1/scan", "post", 200), doc);

    const scanGet = await jsonRequest(fixture.app, {
      method: "GET",
      url: `/v1/scan/${scanCreate.body.scan_id}?token=${encodeURIComponent(scanCreate.body.result_token)}`
    });
    expect(scanGet.statusCode).toBe(200);
    assertConforms(scanGet.body, getResponseSchema(doc, "/v1/scan/{scan_id}", "get", 200), doc);

    const attest = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/attest",
      payload: { scan_id: scanCreate.body.scan_id, token: scanCreate.body.result_token }
    });
    expect(attest.statusCode).toBe(200);
    assertConforms(attest.body, getResponseSchema(doc, "/v1/attest", "post", 200), doc);

    const attestList = await jsonRequest(fixture.app, {
      method: "GET",
      url: `/v1/attest/${scanCreate.body.artifact_root_sha256}`
    });
    expect(attestList.statusCode).toBe(200);
    assertConforms(attestList.body, getResponseSchema(doc, "/v1/attest/{root_sha256}", "get", 200), doc);

    const verify = await jsonRequest(fixture.app, {
      method: "POST",
      url: "/v1/verify",
      payload: {
        attestation_document: attest.body.attestation_document,
        signature_b64url: attest.body.signature_b64url,
        artifact_manifest: [
          {
            path: "SKILL.md",
            sha256: sha256HexUtf8("do not expose private keys"),
            size_bytes: Buffer.byteLength("do not expose private keys", "utf8")
          }
        ]
      }
    });
    expect(verify.statusCode).toBe(200);
    assertConforms(verify.body, getResponseSchema(doc, "/v1/verify", "post", 200), doc);

    const policy = await jsonRequest(fixture.app, {
      method: "GET",
      url: `/v1/policies/${fixture.config.DEFAULT_POLICY_VERSION}`
    });
    expect(policy.statusCode).toBe(200);
    assertConforms(policy.body, getResponseSchema(doc, "/v1/policies/{policy_version}", "get", 200), doc);

    const revocations = await jsonRequest(fixture.app, {
      method: "GET",
      url: "/v1/revocations"
    });
    expect(revocations.statusCode).toBe(200);
    assertConforms(revocations.body, getResponseSchema(doc, "/v1/revocations", "get", 200), doc);
  });
});

function loadOpenApiDoc(): OpenApiDoc {
  const raw = fs.readFileSync(path.join(process.cwd(), "openapi", "skill-attestor.openapi.yaml"), "utf8");
  return YAML.parse(raw) as OpenApiDoc;
}

function getResponseSchema(doc: OpenApiDoc, apiPath: string, method: "get" | "post", statusCode: number): unknown {
  const operation = doc.paths[apiPath]?.[method];
  if (!operation) throw new Error(`OpenAPI operation not found for ${method.toUpperCase()} ${apiPath}`);

  const response = operation.responses[String(statusCode)];
  if (!response) throw new Error(`OpenAPI response ${statusCode} not found for ${method.toUpperCase()} ${apiPath}`);

  const schema = response.content?.["application/json"]?.schema;
  if (!schema) throw new Error(`OpenAPI schema missing for ${method.toUpperCase()} ${apiPath} ${statusCode}`);
  return schema;
}

function assertConforms(value: unknown, schema: unknown, doc: OpenApiDoc): void {
  const errors = validateAgainstSchema(value, schema, doc, "$");
  if (errors.length > 0) {
    throw new Error(`OpenAPI schema mismatch:\n${errors.join("\n")}`);
  }
}

function validateAgainstSchema(value: unknown, schema: unknown, doc: OpenApiDoc, at: string): string[] {
  const s = asSchema(schema);

  if (typeof s.$ref === "string") {
    return validateAgainstSchema(value, resolveRef(doc, s.$ref), doc, at);
  }

  if (Array.isArray(s.oneOf) && s.oneOf.length > 0) {
    const branchErrors = s.oneOf.map((branch) => validateAgainstSchema(value, branch, doc, at));
    if (branchErrors.some((errs) => errs.length === 0)) return [];
    return [`${at}: does not match any oneOf branch`];
  }

  if (Array.isArray(s.enum) && s.enum.length > 0) {
    const found = s.enum.some((candidate) => Object.is(candidate, value));
    if (!found) return [`${at}: expected enum ${JSON.stringify(s.enum)}, got ${JSON.stringify(value)}`];
  }

  const schemaType = inferType(s);
  if (!schemaType) return [];

  if (schemaType === "object") {
    if (!isPlainObject(value)) return [`${at}: expected object, got ${describeValue(value)}`];

    const required = Array.isArray(s.required) ? s.required : [];
    for (const key of required) {
      if (!(key in value)) return [`${at}: missing required key "${key}"`];
    }

    const properties = isPlainObject(s.properties) ? s.properties : {};
    for (const [key, propSchema] of Object.entries(properties)) {
      if (key in value) {
        const childErrors = validateAgainstSchema((value as Record<string, unknown>)[key], propSchema, doc, `${at}.${key}`);
        if (childErrors.length > 0) return childErrors;
      }
    }

    if (s.additionalProperties === false) {
      const allowed = new Set(Object.keys(properties));
      for (const key of Object.keys(value)) {
        if (!allowed.has(key)) return [`${at}: unexpected key "${key}"`];
      }
    }
    return [];
  }

  if (schemaType === "array") {
    if (!Array.isArray(value)) return [`${at}: expected array, got ${describeValue(value)}`];
    if (!("items" in s)) return [];
    for (let i = 0; i < value.length; i += 1) {
      const childErrors = validateAgainstSchema(value[i], s.items, doc, `${at}[${i}]`);
      if (childErrors.length > 0) return childErrors;
    }
    return [];
  }

  if (schemaType === "string") {
    return typeof value === "string" ? [] : [`${at}: expected string, got ${describeValue(value)}`];
  }
  if (schemaType === "integer") {
    return Number.isInteger(value) ? [] : [`${at}: expected integer, got ${describeValue(value)}`];
  }
  if (schemaType === "number") {
    return typeof value === "number" && Number.isFinite(value) ? [] : [`${at}: expected number, got ${describeValue(value)}`];
  }
  if (schemaType === "boolean") {
    return typeof value === "boolean" ? [] : [`${at}: expected boolean, got ${describeValue(value)}`];
  }

  return [];
}

function resolveRef(doc: OpenApiDoc, ref: string): unknown {
  if (!ref.startsWith("#/")) {
    throw new Error(`Unsupported $ref: ${ref}`);
  }
  const parts = ref
    .slice(2)
    .split("/")
    .map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));

  let current: unknown = doc as unknown;
  for (const part of parts) {
    if (!isPlainObject(current) || !(part in current)) {
      throw new Error(`Unable to resolve $ref: ${ref}`);
    }
    current = current[part];
  }
  return current;
}

function asSchema(value: unknown): SchemaObject {
  if (!isPlainObject(value)) return {};
  return value as SchemaObject;
}

function inferType(schema: SchemaObject): string | null {
  if (typeof schema.type === "string") return schema.type;
  if (isPlainObject(schema.properties) || Array.isArray(schema.required)) return "object";
  if ("items" in schema) return "array";
  return null;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function describeValue(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

async function createFixture(): Promise<Fixture> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-attestor-openapi-"));
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
  db.exec(fs.readFileSync(path.join(process.cwd(), "migrations", "001_init.sql"), "utf8"));
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
