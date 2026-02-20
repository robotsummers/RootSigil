import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { RequestHandler } from "express";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import swaggerUi from "swagger-ui-express";
import YAML from "yaml";
import type { AppConfig } from "./config.js";
import type { SqliteDb } from "./db/db.js";
import type { Policy } from "./lib/policy.js";
import { buildScanRouter } from "./api/scan.js";
import { buildAttestRouter } from "./api/attest.js";
import { buildVerifyRouter } from "./api/verify.js";
import { buildPolicyRouter } from "./api/policy.js";
import { buildRevocationRouter } from "./api/revocations.js";
import { buildIdempotencyPrecheckMiddleware } from "./payment/idempotency.js";
import type { X402Context } from "./payment/x402.js";

export type X402AppDeps = {
  middleware: RequestHandler;
  context: X402Context;
};

export function buildApp(args: {
  config: AppConfig;
  db: SqliteDb;
  policy: Policy;
  x402: X402AppDeps;
}) {
  const { config, db, policy, x402 } = args;
  const app = express();

  app.use(helmet());
  app.use(cors());
  app.use(express.json({ limit: "5mb" }));

  const moduleDir = path.dirname(fileURLToPath(import.meta.url));
  const openapiYaml = fs.readFileSync(path.join(moduleDir, "../openapi/skill-attestor.openapi.yaml"), "utf8");
  const openapiObj = YAML.parse(openapiYaml);
  app.get("/openapi.json", (_req, res) => res.json(openapiObj));
  app.use("/docs", swaggerUi.serve, swaggerUi.setup(openapiObj));

  app.use(buildIdempotencyPrecheckMiddleware({ db, x402 }));
  app.use(x402.middleware);

  app.use("/v1", buildScanRouter({ config, db, policy, x402 }));
  app.use("/v1", buildAttestRouter({ config, db, x402 }));
  app.use("/v1", buildVerifyRouter({ config, db }));
  app.use("/v1", buildPolicyRouter({ policy }));
  app.use("/v1", buildRevocationRouter({ config, db }));

  app.get("/healthz", (_req, res) => res.json({ ok: true }));

  return app;
}
