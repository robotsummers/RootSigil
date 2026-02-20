import type { RequestHandler } from "express";
import { paymentMiddleware } from "@x402/express";
import { HTTPFacilitatorClient, x402ResourceServer } from "@x402/core/server";
import { registerExactEvmScheme } from "@x402/evm/exact/server";
import { declarePaymentIdentifierExtension, PAYMENT_IDENTIFIER, extractPaymentIdentifier } from "@x402/extensions/payment-identifier";
import { bazaarResourceServerExtension, declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { facilitator as cdpMainnetFacilitator } from "@coinbase/x402";
import type { AppConfig } from "../config.js";

export type X402Context = {
  extractPaymentId: (paymentSignatureHeaderValue: string | undefined) => string | null;
};

export function buildX402(config: AppConfig): { middleware: RequestHandler; context: X402Context } {
  const context: X402Context = {
    extractPaymentId: (paymentSignatureHeaderValue) => {
      if (!config.X402_ENABLED) return null;
      if (!paymentSignatureHeaderValue) return null;
      try {
        const json = JSON.parse(Buffer.from(paymentSignatureHeaderValue, "base64").toString("utf8"));
        return extractPaymentIdentifier(json) || null;
      } catch {
        return null;
      }
    }
  };

  if (!config.X402_ENABLED) {
    const passthrough: RequestHandler = (_req, _res, next) => next();
    return { middleware: passthrough, context };
  }

  const facilitatorClient =
    config.X402_FACILITATOR_MODE === "cdp_mainnet"
      ? new HTTPFacilitatorClient(cdpMainnetFacilitator)
      : new HTTPFacilitatorClient({ url: config.X402_FACILITATOR_URL });
  const server = new x402ResourceServer(facilitatorClient).registerExtension(bazaarResourceServerExtension);
  registerExactEvmScheme(server);

  const accepts = (price: string) => ({
    scheme: "exact",
    price,
    network: config.X402_NETWORK,
    payTo: config.X402_PAYTO,
    ...(config.X402_ASSET ? { asset: config.X402_ASSET } : {})
  });

  const routes: Record<string, any> = {};
  if (config.X402_PAYWALL_SCAN) {
    routes["POST /v1/scan"] = {
      accepts: [accepts(config.X402_PRICE_SCAN)],
      description: "Create a scan for an artifact",
      mimeType: "application/json",
      extensions: {
        [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(false),
        ...declareDiscoveryExtension({
          input: {
            inline: {
              filename: "SKILL.md",
              content: "Do not commit plaintext secrets."
            }
          },
          inputSchema: {
            type: "object",
            properties: {
              inline: {
                type: "object",
                properties: {
                  filename: { type: "string" },
                  content: { type: "string" }
                },
                required: ["content"]
              },
              zip: {
                type: "object",
                properties: {
                  zip_b64: { type: "string" },
                  entrypoint: { type: "string" }
                },
                required: ["zip_b64"]
              },
              git: {
                type: "object",
                properties: {
                  repo_url: { type: "string", format: "uri" },
                  ref: { type: "string" },
                  entrypoint: { type: "string" }
                },
                required: ["repo_url", "ref"]
              },
              policy_version: { type: "string" }
            },
            oneOf: [{ required: ["inline"] }, { required: ["zip"] }, { required: ["git"] }]
          },
          bodyType: "json",
          output: {
            example: {
              scan_id: "2ad640d5-e9a6-4f89-909a-ad5b729f2201",
              status: "queued",
              result_token: "capability-token"
            },
            schema: {
              type: "object",
              properties: {
                scan_id: { type: "string" },
                status: { type: "string", enum: ["queued"] },
                result_token: { type: "string" }
              },
              required: ["scan_id", "status", "result_token"]
            }
          }
        })
      }
    };
  }

  if (config.X402_PAYWALL_ATTEST) {
    routes["POST /v1/attest"] = {
      accepts: [accepts(config.X402_PRICE_ATTEST)],
      description: "Issue an attestation for a completed scan",
      mimeType: "application/json",
      extensions: {
        [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(false),
        ...declareDiscoveryExtension({
          input: {
            scan_id: "2ad640d5-e9a6-4f89-909a-ad5b729f2201",
            token: "capability-token"
          },
          inputSchema: {
            type: "object",
            properties: {
              scan_id: { type: "string" },
              token: { type: "string" }
            },
            required: ["scan_id", "token"]
          },
          bodyType: "json",
          output: {
            example: {
              attestation_document: {
                artifact_root_sha256: "example-root",
                policy_version: "2026-02-17.static.v1",
                verdict: "pass"
              },
              signature_b64url: "base64url-signature"
            },
            schema: {
              type: "object",
              properties: {
                attestation_document: { type: "object" },
                signature_b64url: { type: "string" }
              },
              required: ["attestation_document", "signature_b64url"]
            }
          }
        })
      }
    };
  }

  const middleware: RequestHandler =
    Object.keys(routes).length === 0 ? (_req, _res, next) => next() : paymentMiddleware(routes, server);

  return { middleware, context };
}
