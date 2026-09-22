import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import {
  X402_PAYMENT_REQUIRED_HEADER,
  X402_PAYMENT_RESPONSE_HEADER,
  X402_PAYMENT_SIGNATURE_HEADER,
  encodePaymentRequired,
  encodePaymentResponse,
  type PaymentRequiredV2,
  type PaymentRequirements,
} from "../../../packages/x402/src/index.js";

export type { PaymentRequirements };

/**
 * Minimal x402 resource server.
 *
 * Speaks the real protocol — 402 with `accepts`, then a `PAYMENT-SIGNATURE`
 * header carrying base64(JSON(paymentPayload)) — and settles through the real
 * facilitator, so "the payment succeeded" in the demo is a fact about the
 * network, not a simulation.
 *
 * What it deliberately does NOT do is vouch for its own content. That is the
 * gap AegisProof exists to cover, and a seller that could vouch for itself
 * would defeat the point of the demo.
 */

export interface SellerConfig {
  readonly name: string;
  readonly port: number;
  readonly resourcePath: string;
  readonly requirements: PaymentRequirements;
  readonly facilitatorUrl: string;
  /** What this seller actually returns once paid. */
  readonly body: () => { readonly contentType: string; readonly payload: unknown };
}

export interface SellerHandle {
  readonly server: Server;
  readonly url: string;
  close(): Promise<void>;
}

interface FacilitatorResult {
  readonly ok: boolean;
  readonly body: unknown;
}

async function callFacilitator(
  url: string,
  path: string,
  body: unknown,
): Promise<FacilitatorResult> {
  try {
    const response = await fetch(`${url}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await response.text();
    let parsed: unknown = text;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      /* keep raw text so a non-JSON failure stays legible */
    }
    return { ok: response.ok, body: parsed };
  } catch (error: unknown) {
    return { ok: false, body: { error: error instanceof Error ? error.message : String(error) } };
  }
}

function json(response: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...extra,
  });
  response.end(JSON.stringify(body));
}

function decodePaymentHeader(raw: string | undefined): unknown | undefined {
  if (raw === undefined || raw.length === 0) return undefined;
  try {
    return JSON.parse(Buffer.from(raw, "base64").toString("utf8")) as unknown;
  } catch {
    return undefined;
  }
}

export function startSeller(config: SellerConfig): Promise<SellerHandle> {
  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    void (async (): Promise<void> => {
      const url = new URL(request.url ?? "/", `http://localhost:${config.port}`);
      if (request.method !== "GET" || url.pathname !== config.resourcePath) {
        json(response, 404, { error: "not found" });
        return;
      }

      const header = request.headers[X402_PAYMENT_SIGNATURE_HEADER];
      const paymentPayload = decodePaymentHeader(Array.isArray(header) ? header[0] : header);

      if (paymentPayload === undefined) {
        const required: PaymentRequiredV2 = {
          x402Version: 2,
          error: "payment required",
          resource: {
            url: `http://localhost:${config.port}${config.resourcePath}`,
            mimeType: "application/json",
          },
          accepts: [config.requirements],
        };
        // Spec: requirements travel in the Payment-Required header. The body
        // repeats them for clients that only read bodies.
        json(response, 402, required, {
          [X402_PAYMENT_REQUIRED_HEADER]: encodePaymentRequired(required),
        });
        return;
      }

      const envelope = {
        x402Version: 2,
        paymentPayload,
        paymentRequirements: config.requirements,
      };

      const verified = await callFacilitator(config.facilitatorUrl, "/verify", envelope);
      const isValid = (verified.body as { isValid?: boolean } | undefined)?.isValid === true;
      if (!isValid) {
        json(response, 402, { error: "payment did not verify", detail: verified.body });
        return;
      }

      const settled = await callFacilitator(config.facilitatorUrl, "/settle", envelope);
      const settleBody = settled.body as { success?: boolean; transaction?: string } | undefined;
      if (settleBody?.success !== true) {
        json(response, 402, { error: "settlement failed", detail: settled.body });
        return;
      }

      const { contentType, payload } = config.body();
      response.writeHead(200, {
        "content-type": contentType,
        "cache-control": "no-store",
        [X402_PAYMENT_RESPONSE_HEADER]: encodePaymentResponse(settleBody),
      });
      response.end(typeof payload === "string" ? payload : JSON.stringify(payload));
    })().catch(() => {
      json(response, 500, { error: "seller failure" });
    });
  });

  return new Promise<SellerHandle>((resolve) => {
    server.listen(config.port, "127.0.0.1", () => {
      resolve({
        server,
        url: `http://127.0.0.1:${config.port}${config.resourcePath}`,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
          }),
      });
    });
  });
}
