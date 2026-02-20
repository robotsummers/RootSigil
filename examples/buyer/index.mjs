import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import dotenv from "dotenv";
import { x402Client, wrapFetchWithPayment, x402HTTPClient } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

dotenv.config();

function usage(msg) {
  if (msg) console.error(msg);
  console.error(`\nUsage:
  node index.mjs scan --inline <path> [--wait]
  node index.mjs scan --zip <path> [--entrypoint <path>] [--wait]
  node index.mjs poll --scan-id <id> --token <token>
  node index.mjs attest --scan-id <id> --token <token> [--out <file>]
  node index.mjs verify --attestation-file <file>
`);
  process.exit(msg ? 1 : 0);
}

function getArg(name) {
  const i = process.argv.indexOf(name);
  if (i === -1) return null;
  return process.argv[i + 1] ?? null;
}
function hasFlag(name) {
  return process.argv.includes(name);
}

const cmd = process.argv[2];
if (!cmd) usage();

const ROOTSIGIL_URL = (process.env.ROOTSIGIL_URL || "http://localhost:8080").replace(/\/$/, "");
const NETWORK = process.env.NETWORK || "eip155:84532";
const pkRaw = process.env.BUYER_PRIVATE_KEY;
if (!pkRaw) usage("Missing BUYER_PRIVATE_KEY in environment.");

const pk = pkRaw.startsWith("0x") ? pkRaw : `0x${pkRaw}`;
const signer = privateKeyToAccount(pk);

const client = new x402Client();
registerExactEvmScheme(client, { signer, networks: [NETWORK] });

const fetchWithPayment = wrapFetchWithPayment(fetch, client);
const httpClient = new x402HTTPClient(client);

const DEFAULT_TIMEOUT_MS = Number(process.env.TIMEOUT_MS || "60000");
async function fetchJson(url, init) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
  try {
    const res = await fetchWithPayment(url, { ...init, signal: controller.signal });
    const text = await res.text();
    const contentType = res.headers.get("content-type") || "";
    const body = contentType.includes("application/json") && text ? JSON.parse(text) : text;
    let payment = null;
    try {
      payment = httpClient.getPaymentSettleResponse((name) => res.headers.get(name));
    } catch {
      // ignore
    }
    return { res, body, payment };
  } finally {
    clearTimeout(t);
  }
}

async function cmdScan() {
  const inlinePath = getArg("--inline");
  const zipPath = getArg("--zip");
  const entrypoint = getArg("--entrypoint") || undefined;
  const wait = hasFlag("--wait");

  if (!!inlinePath === !!zipPath) usage("Provide exactly one of --inline or --zip.");

  let payload;
  if (inlinePath) {
    const content = fs.readFileSync(inlinePath, "utf8");
    payload = {
      inline: {
        filename: path.basename(inlinePath),
        content,
      },
    };
  } else {
    const zipBytes = fs.readFileSync(zipPath);
    payload = {
      zip: {
        zip_b64: Buffer.from(zipBytes).toString("base64"),
        ...(entrypoint ? { entrypoint } : {}),
      },
    };
  }

  const { res, body, payment } = await fetchJson(`${ROOTSIGIL_URL}/v1/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });

  console.log(JSON.stringify({ status: res.status, body, payment }, null, 2));

  if (res.status !== 200 && res.status !== 202) process.exit(1);

  const scan_id = body.scan_id;
  const token = body.result_token;
  if (wait && scan_id && token) {
    await waitForCompletion(scan_id, token);
  }
}

async function cmdPoll() {
  const scan_id = getArg("--scan-id");
  const token = getArg("--token");
  if (!scan_id || !token) usage("Missing --scan-id or --token.");

  const { res, body } = await fetchJson(`${ROOTSIGIL_URL}/v1/scan/${encodeURIComponent(scan_id)}?token=${encodeURIComponent(token)}`, {
    method: "GET",
  });
  console.log(JSON.stringify({ status: res.status, body }, null, 2));
  if (!res.ok) process.exit(1);
}

async function waitForCompletion(scan_id, token) {
  const pollMs = Number(getArg("--poll-ms") || "1000");
  const deadlineMs = Date.now() + 5 * 60 * 1000;

  while (true) {
    const { res, body } = await fetchJson(`${ROOTSIGIL_URL}/v1/scan/${encodeURIComponent(scan_id)}?token=${encodeURIComponent(token)}`, {
      method: "GET",
    });
    if (!res.ok) {
      console.error("poll failed:", res.status, body);
      process.exit(1);
    }
    const status = body.status;
    if (status === "completed" || status === "failed") {
      console.log(JSON.stringify({ scan_id, status, body }, null, 2));
      if (status === "failed") process.exit(2);
      return;
    }
    if (Date.now() > deadlineMs) {
      console.error("poll timeout");
      process.exit(3);
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

async function cmdAttest() {
  const scan_id = getArg("--scan-id");
  const token = getArg("--token");
  const outFile = getArg("--out") || null;
  if (!scan_id || !token) usage("Missing --scan-id or --token.");

  const payload = { scan_id, token };
  const { res, body, payment } = await fetchJson(`${ROOTSIGIL_URL}/v1/attest`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });

  console.log(JSON.stringify({ status: res.status, body, payment }, null, 2));
  if (!res.ok) process.exit(1);

  if (outFile) {
    fs.writeFileSync(outFile, JSON.stringify(body, null, 2));
    console.error(`wrote ${outFile}`);
  }
}

async function cmdVerify() {
  const attFile = getArg("--attestation-file");
  if (!attFile) usage("Missing --attestation-file.");
  const data = JSON.parse(fs.readFileSync(attFile, "utf8"));
  // data must have attestation_document + signature_b64url
  const { res, body } = await fetchJson(`${ROOTSIGIL_URL}/v1/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      attestation_document: data.attestation_document,
      signature_b64url: data.signature_b64url,
    }),
  });
  console.log(JSON.stringify({ status: res.status, body }, null, 2));
  if (!res.ok) process.exit(1);
}

if (cmd === "scan") {
  await cmdScan();
} else if (cmd === "poll") {
  await cmdPoll();
} else if (cmd === "attest") {
  await cmdAttest();
} else if (cmd === "verify") {
  await cmdVerify();
} else {
  usage(`Unknown command: ${cmd}`);
}
