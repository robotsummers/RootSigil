# RootSigil Buyer Example (x402)

This is a minimal Node client that pays x402-protected RootSigil endpoints automatically.

It uses:
- `@x402/fetch` to automatically handle 402 responses and retry with `PAYMENT-SIGNATURE`
- `@x402/evm` Exact scheme client registration
- `viem` to create a signer from an EVM private key

## Safety

Use a testnet wallet (Base Sepolia) first.

Do not put a mainnet private key into CI or a shared machine until you have an operational story you trust.

## Setup

```bash
npm ci
cp .env.example .env
# edit .env and set BUYER_PRIVATE_KEY
```

Environment variables:

- `ROOTSIGIL_URL` (default: `http://localhost:8080`)
- `BUYER_PRIVATE_KEY` (required)
- `NETWORK` (optional, default: `eip155:84532` for Base Sepolia)

## Scan (inline)

```bash
node index.mjs scan --inline ./sample/SKILL.md
```

## Scan (zip)

Create a zip:

```bash
cd sample
zip -r sample.zip SKILL.md
cd ..
node index.mjs scan --zip ./sample/sample.zip
```

## Poll result

The scan command prints `scan_id` and `result_token`.
You can poll:

```bash
node index.mjs poll --scan-id <scan_id> --token <result_token>
```

## Attest

```bash
node index.mjs attest --scan-id <scan_id> --token <result_token>
```

## Verify

```bash
node index.mjs verify --attestation-file ./attestation.json
```
