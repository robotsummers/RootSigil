# RootSigil

RootSigil scans artifacts against a versioned security policy and produces signed attestations that can be verified later.

## Contract

- OpenAPI contract: `openapi/skill-attestor.openapi.yaml`

## Core capabilities

- Intake artifacts from:
  - inline text
  - base64 zip archives
  - git repos (`https` + `ref`)
- Normalize files and compute deterministic artifact root hashes.
- Run static analyzers and return structured findings with verdicts (`pass|warn|fail`).
- Issue Ed25519-signed attestations bound to artifact hash + policy version + verdict.
- Verify attestations offline-compatible and check revocation status.
- Publish a signed revocation document.

## API

- `POST /v1/scan` (x402-paid): create a scan (`202` queued when async mode is enabled).
- `GET /v1/scan/{scan_id}?token=...`: fetch status/result via capability token.
- `POST /v1/attest` (x402-paid): issue attestation for a completed scan.
- `GET /v1/attest/{root_sha256}`: list attestations for an artifact root hash.
- `POST /v1/verify`: verify signature/hash/revocation for an attestation.
- `GET /v1/issuer`: discover issuer + payment metadata.
- `GET /v1/version`: discover service and policy version.
- `GET /v1/policies/{policy_version}`: fetch active policy metadata.
- `GET /v1/revocations`: fetch signed revocation list.
- `GET /openapi.json`: machine-readable OpenAPI.
- `GET /docs`: Swagger UI.

## Determinism and hashing

- Manifest entries are `{path, sha256, size_bytes}` sorted by path.
- Artifact root hash is `sha256(canonical_json(manifest))`.
- Attestation signature input is `sha256(canonical_json(attestation_document))`.

## Security model

RootSigil treats all artifacts as hostile input.

- Static analysis only (no execution of untrusted artifact code).
- Path traversal and absolute paths are rejected.
- Zip intake rejects unsupported/non-regular entry types and enforces size/count limits.
- Git intake enforces `https` URLs, blocks submodules/symlinks, and enforces size/count limits.
- Evidence snippets are redacted for secret-like values before returning results.

## x402 and idempotency

Paid endpoints use x402 headers:

- `PAYMENT-REQUIRED`
- `PAYMENT-SIGNATURE`
- `PAYMENT-RESPONSE`

Payment identifiers are idempotent:

- same identifier + same request hash => replay cached response
- same identifier + different request hash => `409 IDEMPOTENCY_CONFLICT`

## Production (Base mainnet)

RootSigil supports CDP-backed x402 settlement on Base mainnet:

- network: `eip155:8453`
- facilitator mode: `X402_FACILITATOR_MODE=cdp_mainnet`
- required keys: `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET`
- production receiver: `0x4525d5E422dD75b8e062565EA28E9efe19eE5Dae`

Use `docker-compose.prod.yml`, `Dockerfile`, and `Caddyfile` in this repo for Docker + Caddy deployment.

## Local development

Prereqs:

- Node.js `>=20`

Setup:

```bash
npm install
cp .env.example .env
npm run gen:keypair
npm run migrate
```

Run:

```bash
npm run dev
```

Production-like local stack:

```bash
docker compose -f docker-compose.prod.yml up --build
```

Checks:

```bash
npm run lint
npm run typecheck
npm test
```

## Required configuration

See `.env.example`. Critical vars:

- `ISSUER_ED25519_PRIVATE_KEY_B64`
- `ISSUER_ED25519_PUBLIC_KEY_B64`
- `X402_PAYTO`

Useful intake/retention controls:

- `ARTIFACT_RETENTION_HOURS`
- `INTAKE_MAX_FILES`
- `INTAKE_MAX_TOTAL_BYTES`
- `INTAKE_MAX_SINGLE_FILE_BYTES`

## Project layout

- `src/`: service implementation (API, analyzers, payment, storage logic)
- `openapi/`: API contract
- `policy/`: policy definitions
- `migrations/`: SQLite schema
- `tests/`: unit + integration + conformance tests
- `.github/`: CI, templates, repo automation config

## Current release

- `v0.1.0`: `CHANGELOG.md`
