import type { Router } from "express";
import express from "express";
import type { Policy } from "../lib/policy.js";

export function buildPolicyRouter(args: { policy: Policy }): Router {
  const { policy } = args;
  const router = express.Router();

  router.get("/policies/:policy_version", (req, res) => {
    const v = req.params.policy_version;
    if (v !== policy.policy_version) {
      return res.status(404).json({ error: { error_code: "NOT_FOUND", message: "policy not found" } });
    }
    return res.status(200).json(policy);
  });

  return router;
}
