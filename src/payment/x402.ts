import type { RequestHandler } from "express";
import { paymentMiddleware } from "@x402/express";
import { HTTPFacilitatorClient, x402ResourceServer } from "@x402/core/server";
import { registerExactEvmScheme } from "@x402/evm/exact/server";
import { declarePaymentIdentifierExtension, PAYMENT_IDENTIFIER, extractPaymentIdentifier } from "@x402/extensions/payment-identifier";
import type { AppConfig } from "../config.js";

export type X402Context = {
  extractPaymentId: (paymentSignatureHeaderValue: string | undefined) => string | null;
};

export function buildX402(config: AppConfig): { middleware: RequestHandler; context: X402Context } {
  const facilitatorClient = new HTTPFacilitatorClient({ url: config.X402_FACILITATOR_URL });
  const server = new x402ResourceServer(facilitatorClient);
  registerExactEvmScheme(server);

  // Route config keys MUST match method + space + path.
  const routes: any = {
    "POST /v1/scan": {
      accepts: [
        {
          scheme: "exact",
          price: "$0.01",
          network: config.X402_NETWORK,
          payTo: config.X402_PAYTO
        }
      ],
      description: "Scan a skill bundle",
      mimeType: "application/json",
      extensions: {
        [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(false)
      }
    },
    "POST /v1/attest": {
      accepts: [
        {
          scheme: "exact",
          price: "$0.01",
          network: config.X402_NETWORK,
          payTo: config.X402_PAYTO
        }
      ],
      description: "Issue an attestation for an artifact root hash",
      mimeType: "application/json",
      extensions: {
        [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(false)
      }
    }
  };

  // Request replay short-circuit is handled by app middleware before x402.
  const middleware = paymentMiddleware(routes, server);

  const context: X402Context = {
    extractPaymentId: (paymentSignatureHeaderValue) => {
      if (!paymentSignatureHeaderValue) return null;
      try {
        const json = JSON.parse(Buffer.from(paymentSignatureHeaderValue, "base64").toString("utf8"));
        return extractPaymentIdentifier(json) || null;
      } catch {
        return null;
      }
    }
  };

  return { middleware, context };
}
