import { z } from "zod";

const EnvSchema = z.object({
  PORT: z.coerce.number().int().positive().default(8080),
  BASE_URL: z.string().url().default("http://localhost:8080"),

  SQLITE_PATH: z.string().default("./skill_attestor.sqlite"),
  ARTIFACT_STORAGE_DIR: z.string().default("./.artifacts"),
  ARTIFACT_RETENTION_HOURS: z.coerce.number().positive().default(24),
  INTAKE_MAX_FILES: z.coerce.number().int().positive().default(5000),
  INTAKE_MAX_TOTAL_BYTES: z.coerce.number().int().positive().default(20 * 1024 * 1024),
  INTAKE_MAX_SINGLE_FILE_BYTES: z.coerce.number().int().positive().default(2 * 1024 * 1024),

  DEFAULT_POLICY_VERSION: z.string().default("2026-02-17.static.v1"),
  POLICY_FILE: z.string().default("./policy/policy.default.json"),

  ISSUER_ID: z.string().default("skill-attestor-local"),
  ISSUER_ED25519_PRIVATE_KEY_B64: z.string(),
  ISSUER_ED25519_PUBLIC_KEY_B64: z.string(),

  X402_FACILITATOR_URL: z.string().url().default("https://x402.org/facilitator"),
  X402_NETWORK: z.string().default("eip155:84532"),
  X402_PAYTO: z.string(),
  IDEMPOTENCY_TTL_MS: z.coerce.number().int().positive().default(60 * 60 * 1000)
});

export type AppConfig = z.infer<typeof EnvSchema>;

export function loadConfig(env: NodeJS.ProcessEnv): AppConfig {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    throw new Error(`Invalid environment: ${parsed.error.message}`);
  }
  return parsed.data;
}
