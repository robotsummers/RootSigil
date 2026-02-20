import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const BASE_MAINNET_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

const BooleanFromEnv = z.preprocess((value) => {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true" || normalized === "1" || normalized === "yes" || normalized === "on") return true;
    if (normalized === "false" || normalized === "0" || normalized === "no" || normalized === "off") return false;
  }
  return value;
}, z.boolean());

function resolveDefaultVersion(): string {
  if (process.env.npm_package_version) {
    return process.env.npm_package_version;
  }
  try {
    const thisFile = fileURLToPath(import.meta.url);
    const packageJsonPath = path.resolve(path.dirname(thisFile), "../package.json");
    const raw = fs.readFileSync(packageJsonPath, "utf8");
    const parsed = JSON.parse(raw);
    return typeof parsed?.version === "string" ? parsed.version : "dev";
  } catch {
    return "dev";
  }
}

function inferDefaultAsset(network: string): string | null {
  if (network === "eip155:84532") {
    return BASE_SEPOLIA_USDC;
  }
  if (network === "eip155:8453") {
    return BASE_MAINNET_USDC;
  }
  return null;
}

const EnvSchema = z.object({
  PORT: z.coerce.number().int().positive().default(8080),
  BASE_URL: z.string().url().default("http://localhost:8080"),

  SQLITE_PATH: z.string().default("./rootsigil.sqlite"),
  ARTIFACT_STORAGE_DIR: z.string().default("./.artifacts"),
  ARTIFACT_RETENTION_HOURS: z.coerce.number().positive().default(24),
  INTAKE_MAX_FILES: z.coerce.number().int().positive().default(5000),
  INTAKE_MAX_TOTAL_BYTES: z.coerce.number().int().positive().default(20 * 1024 * 1024),
  INTAKE_MAX_SINGLE_FILE_BYTES: z.coerce.number().int().positive().default(2 * 1024 * 1024),
  HTTP_JSON_BODY_LIMIT_BYTES: z.coerce.number().int().positive().default(40 * 1024 * 1024),

  DEFAULT_POLICY_VERSION: z.string().default("2026-02-17.static.v1"),
  POLICY_FILE: z.string().default("./policy/policy.default.json"),

  ISSUER_ID: z.string().default("rootsigil-local"),
  ISSUER_ED25519_PRIVATE_KEY_B64: z.string(),
  ISSUER_ED25519_PUBLIC_KEY_B64: z.string(),

  TRUST_PROXY: BooleanFromEnv.default(false),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(120),

  GIT_ALLOWED_HOSTS: z.string().default("github.com"),
  GIT_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),

  SCAN_FORCE_ASYNC: BooleanFromEnv.default(false),
  WORKER_POLL_MS: z.coerce.number().int().positive().default(500),
  WORKER_LEASE_MS: z.coerce.number().int().positive().default(120_000),
  WORKER_CONCURRENCY: z.coerce.number().int().positive().default(2),
  ROOTSIGIL_ROLE: z.enum(["api", "worker", "all"]).default("api"),

  X402_ENABLED: BooleanFromEnv.default(true),
  X402_PAYWALL_SCAN: BooleanFromEnv.default(true),
  X402_PAYWALL_ATTEST: BooleanFromEnv.default(true),
  X402_PRICE_SCAN: z.string().default("$0.01"),
  X402_PRICE_ATTEST: z.string().default("$0.01"),
  X402_FACILITATOR_MODE: z.enum(["testnet_url", "cdp_mainnet"]).default("testnet_url"),
  X402_FACILITATOR_URL: z.string().url().default("https://x402.org/facilitator"),
  X402_NETWORK: z.string().default("eip155:84532"),
  X402_ASSET: z.string().optional(),
  X402_PAYTO: z.string(),

  IDEMPOTENCY_TTL_MS: z.coerce.number().int().positive().default(60 * 60 * 1000),
  VERSION: z.string().default(resolveDefaultVersion())
});

type ParsedEnv = z.infer<typeof EnvSchema>;

export type AppConfig = Omit<ParsedEnv, "GIT_ALLOWED_HOSTS" | "X402_ASSET"> & {
  GIT_ALLOWED_HOSTS: string[];
  X402_ASSET: string;
};

export function loadConfig(env: NodeJS.ProcessEnv): AppConfig {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    throw new Error(`Invalid environment: ${parsed.error.message}`);
  }

  const allowedHosts = parsed.data.GIT_ALLOWED_HOSTS.split(",")
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);
  if (allowedHosts.length === 0) {
    throw new Error("Invalid environment: GIT_ALLOWED_HOSTS must include at least one host");
  }

  const inferredAsset = inferDefaultAsset(parsed.data.X402_NETWORK);
  const configuredAsset = parsed.data.X402_ASSET?.trim();
  const x402Asset = configuredAsset || inferredAsset;
  if (!x402Asset) {
    throw new Error(`Invalid environment: X402_ASSET must be set when X402_NETWORK=${parsed.data.X402_NETWORK}`);
  }

  return {
    ...parsed.data,
    GIT_ALLOWED_HOSTS: allowedHosts,
    X402_ASSET: x402Asset
  };
}
