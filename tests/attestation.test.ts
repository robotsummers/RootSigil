import { webcrypto } from "node:crypto";
if (!(globalThis as any).crypto) { (globalThis as any).crypto = webcrypto as any; }

import { describe, expect, test } from "vitest";
import { getPublicKeyAsync } from "@noble/ed25519";
import { buildAttestation, signAttestation, verifyAttestation } from "../src/lib/attestation.js";

describe("attestation", () => {
  test("sign + verify", async () => {
    const sk = Buffer.alloc(32, 1);
    const pk = await getPublicKeyAsync(sk);

    const doc = buildAttestation({
      issuer_id: "issuer",
      issuer_public_key_b64: Buffer.from(pk).toString("base64"),
      scan_id: "11111111-1111-1111-1111-111111111111",
      artifact_root_sha256: "a".repeat(64),
      manifest_canonical_json: "[]",
      policy_version: "2026-02-17.static.v1",
      verdict: "pass",
      finding_counts: { low: 0, medium: 0, high: 0, critical: 0 },
      score: 90,
      top_categories: [],
      issued_at: new Date("2026-02-17T00:00:00.000Z"),
      ttl_days: 1
    });

    expect(doc.scan.scan_id).toBe("11111111-1111-1111-1111-111111111111");
    expect(doc.scan.score).toBe(90);
    expect(doc.scan.finding_counts).toEqual({ low: 0, medium: 0, high: 0, critical: 0 });
    expect(doc.summary.top_categories).toEqual([]);

    const signed1 = await signAttestation(doc, Buffer.from(sk).toString("base64"));
    const signed2 = await signAttestation(doc, Buffer.from(sk).toString("base64"));

    expect(signed1.signature_b64url).toBe(signed2.signature_b64url);
    expect(await verifyAttestation(signed1, Buffer.from(pk).toString("base64"))).toBe(true);
  });
});
