import { sha256 } from "@noble/hashes/sha256";
import { signAsync, verifyAsync } from "@noble/ed25519";
import { canonicalJson } from "./canonicalJson.js";

export type AttestationDoc = {
  attestation_version: string;
  issuer: {
    issuer_id: string;
    public_key: string; // base64
    algorithm: "ed25519";
  };
  issued_at: string;
  expires_at: string;
  artifact: {
    root_sha256: string;
    manifest_sha256: string;
    source_hint?: string;
  };
  scan: {
    scan_id: string;
    policy_version: string;
    verdict: "pass" | "warn" | "fail";
    score: number;
    finding_counts: Record<string, number>;
  };
  summary: {
    top_categories: string[];
    notes?: string;
  };
};

export type SignedAttestation = {
  attestation_document: AttestationDoc;
  signature_b64url: string;
};

export function buildAttestation(args: {
  issuer_id: string;
  issuer_public_key_b64: string;
  scan_id: string;
  artifact_root_sha256: string;
  manifest_canonical_json: string;
  source_hint?: string;
  policy_version: string;
  verdict: "pass" | "warn" | "fail";
  finding_counts: Record<string, number>;
  score: number;
  top_categories: string[];
  notes?: string;
  issued_at?: Date;
  ttl_days?: number;
}): AttestationDoc {
  const issued = args.issued_at || new Date();
  const ttlDays = args.ttl_days ?? 90;
  const expires = new Date(issued.getTime() + ttlDays * 24 * 60 * 60 * 1000);
  const manifestSha256 = Buffer.from(sha256(new TextEncoder().encode(args.manifest_canonical_json))).toString("hex");

  return {
    attestation_version: "1",
    issuer: {
      issuer_id: args.issuer_id,
      public_key: args.issuer_public_key_b64,
      algorithm: "ed25519"
    },
    issued_at: issued.toISOString(),
    expires_at: expires.toISOString(),
    artifact: {
      root_sha256: args.artifact_root_sha256,
      manifest_sha256: manifestSha256,
      ...(args.source_hint ? { source_hint: args.source_hint } : {})
    },
    scan: {
      scan_id: args.scan_id,
      policy_version: args.policy_version,
      verdict: args.verdict,
      score: args.score,
      finding_counts: args.finding_counts
    },
    summary: {
      top_categories: args.top_categories,
      ...(args.notes ? { notes: args.notes } : {})
    }
  };
}

export async function signAttestation(doc: AttestationDoc, issuerPrivateKeyB64: string): Promise<SignedAttestation> {
  const canonical = canonicalJson(doc);
  const digest = sha256(new TextEncoder().encode(canonical));
  const sk = Buffer.from(issuerPrivateKeyB64, "base64");
  const sig = await signAsync(digest, sk);
  return {
    attestation_document: doc,
    signature_b64url: b64url(sig)
  };
}

export async function verifyAttestation(signed: SignedAttestation, issuerPublicKeyB64: string): Promise<boolean> {
  const canonical = canonicalJson(signed.attestation_document);
  const digest = sha256(new TextEncoder().encode(canonical));
  const pk = Buffer.from(issuerPublicKeyB64, "base64");
  const sig = unb64url(signed.signature_b64url);
  return verifyAsync(sig, digest, pk);
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function unb64url(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  return new Uint8Array(Buffer.from(b64, "base64"));
}
