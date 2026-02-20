import type { RequestHandler } from "express";
import type { SqliteDb } from "../db/db.js";
import { getCachedResponse, putCachedResponse, type CachedResponse, nowMs, sha256Hex } from "../db/repo.js";
import { canonicalJson } from "../lib/canonicalJson.js";
import type { X402Context } from "./x402.js";

export class IdempotencyStore {
  constructor(private readonly db: SqliteDb, private readonly ttlMs: number) {}

  get(paymentId: string): CachedResponse | null {
    return getCachedResponse(this.db, paymentId);
  }

  put(paymentId: string, request_hash_sha256: string, status: number, headers: Record<string, string>, body: unknown): void {
    const t = nowMs();
    putCachedResponse(this.db, paymentId, {
      request_hash_sha256,
      status,
      headers,
      body,
      created_at: t,
      expires_at: t + this.ttlMs
    });
  }
}

export function computeRequestHash(requestBody: unknown): string {
  return sha256Hex(canonicalJson(requestBody ?? null));
}

export function buildIdempotencyPrecheckMiddleware(args: {
  db: SqliteDb;
  x402: { context: X402Context };
}): RequestHandler {
  const { db, x402 } = args;

  return (req, res, next) => {
    const routeKey = `${req.method.toUpperCase()} ${req.path}`;
    if (routeKey !== "POST /v1/scan" && routeKey !== "POST /v1/attest") return next();

    const paymentId = x402.context.extractPaymentId(req.get("PAYMENT-SIGNATURE") || undefined);
    if (!paymentId) return next();

    const cached = getCachedResponse(db, paymentId);
    if (!cached) return next();

    const requestHash = computeRequestHash(req.body);
    if (cached.request_hash_sha256 !== requestHash) {
      return res.status(409).json({
        error: {
          error_code: "IDEMPOTENCY_CONFLICT",
          message: "payment identifier reused for different request"
        }
      });
    }

    return res.status(cached.status).set(cached.headers).json(cached.body);
  };
}
