import type { AppConfig } from "../src/config.js";
import { buildX402 } from "../src/payment/x402.js";
import { describe, expect, test } from "vitest";

describe("x402 configuration toggles", () => {
  test("X402_ENABLED=false returns pass-through middleware and null payment ids", () => {
    const config = baseConfig({
      X402_ENABLED: false
    });
    const x402 = buildX402(config);

    let nextCalled = false;
    x402.middleware({} as any, {} as any, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(true);
    expect(x402.context.extractPaymentId("eyJ0ZXN0IjoidGVzdCJ9")).toBeNull();
  });

  test("enabled x402 with both paywalls off is pass-through", () => {
    const config = baseConfig({
      X402_ENABLED: true,
      X402_PAYWALL_SCAN: false,
      X402_PAYWALL_ATTEST: false
    });
    const x402 = buildX402(config);

    let nextCalled = false;
    x402.middleware({} as any, {} as any, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(true);
  });
});

function baseConfig(overrides: Partial<AppConfig>): AppConfig {
  return {
    PORT: 8080,
    BASE_URL: "http://localhost:8080",
    SQLITE_PATH: "./test.sqlite",
    ARTIFACT_STORAGE_DIR: "./.artifacts-test",
    ARTIFACT_RETENTION_HOURS: 24,
    INTAKE_MAX_FILES: 5000,
    INTAKE_MAX_TOTAL_BYTES: 20 * 1024 * 1024,
    INTAKE_MAX_SINGLE_FILE_BYTES: 2 * 1024 * 1024,
    HTTP_JSON_BODY_LIMIT_BYTES: 40 * 1024 * 1024,
    DEFAULT_POLICY_VERSION: "2026-02-17.static.v1",
    POLICY_FILE: "./policy/policy.default.json",
    ISSUER_ID: "rootsigil-test",
    ISSUER_ED25519_PRIVATE_KEY_B64: "test-private",
    ISSUER_ED25519_PUBLIC_KEY_B64: "test-public",
    TRUST_PROXY: false,
    RATE_LIMIT_WINDOW_MS: 60_000,
    RATE_LIMIT_MAX: 120,
    GIT_ALLOWED_HOSTS: ["github.com"],
    GIT_TIMEOUT_MS: 15_000,
    SCAN_FORCE_ASYNC: false,
    WORKER_POLL_MS: 500,
    WORKER_LEASE_MS: 120_000,
    WORKER_CONCURRENCY: 2,
    ROOTSIGIL_ROLE: "api",
    X402_ENABLED: true,
    X402_PAYWALL_SCAN: true,
    X402_PAYWALL_ATTEST: true,
    X402_PRICE_SCAN: "$0.01",
    X402_PRICE_ATTEST: "$0.01",
    X402_FACILITATOR_MODE: "testnet_url",
    X402_FACILITATOR_URL: "https://x402.org/facilitator",
    X402_NETWORK: "eip155:84532",
    X402_ASSET: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    X402_PAYTO: "0x1111111111111111111111111111111111111111",
    IDEMPOTENCY_TTL_MS: 60_000,
    VERSION: "test",
    ...overrides
  };
}
