import type { Router } from "express";
import express from "express";
import type { AppConfig } from "../config.js";
import type { Policy } from "../lib/policy.js";

export function buildMetaRouter(args: { config: AppConfig; policy: Policy }): Router {
  const { config, policy } = args;
  const router = express.Router();

  router.get("/issuer", (_req, res) => {
    return res.status(200).json({
      issuer_id: config.ISSUER_ID,
      issuer_public_key_b64: config.ISSUER_ED25519_PUBLIC_KEY_B64,
      network: config.X402_NETWORK,
      payto: config.X402_PAYTO,
      prices: {
        scan: config.X402_PRICE_SCAN ?? "$0.01",
        attest: config.X402_PRICE_ATTEST ?? "$0.01"
      }
    });
  });

  router.get("/version", (_req, res) => {
    return res.status(200).json({
      version: config.VERSION ?? "dev",
      policy_version: policy.policy_version
    });
  });

  return router;
}
