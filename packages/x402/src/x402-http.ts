/**
 * x402 HTTP wire format.
 *
 * Extracted while interoperating with a third-party seller, which exposed three
 * places our own implementation had drifted from the spec:
 *
 *   - the settlement header is `PAYMENT-RESPONSE`, not `X-PAYMENT-RESPONSE`
 *   - a 402 carries its requirements in a `Payment-Required` header (base64 of
 *     the JSON body), which is what the SDK helpers read
 *   - `extra` is the seller's, not ours: it can carry arbitrary fields the
 *     seller's own verification depends on, so it must be forwarded verbatim
 *
 * Everything parsed here is untrusted seller input and is validated as such.
 */

export const X402_PAYMENT_REQUIRED_HEADER = "payment-required";
export const X402_PAYMENT_SIGNATURE_HEADER = "payment-signature";
export const X402_PAYMENT_RESPONSE_HEADER = "payment-response";
/** What our own server emitted before the spec name was adopted. */
export const X402_LEGACY_PAYMENT_RESPONSE_HEADER = "x-payment-response";

/** Reads one header by lowercase name. Works for `Headers` and node dicts. */
export type HeaderReader = (name: string) => string | null | undefined;

export interface PaymentRequirements {
  readonly scheme: string;
  readonly network: string;
  readonly asset: string;
  readonly amount: string;
  readonly payTo: string;
  readonly maxTimeoutSeconds: number;
  /**
   * The seller's own terms. Opaque to us on purpose: forward it unchanged or
   * the seller's verification fails on fields we never knew about.
   */
  readonly extra: Readonly<Record<string, unknown>>;
}

export interface PaymentRequiredV2 {
  readonly x402Version: number;
  readonly error?: string;
  readonly resource?: {
    readonly url?: string;
    readonly description?: string;
    readonly mimeType?: string;
  };
  readonly accepts: readonly PaymentRequirements[];
}

export class X402ProtocolError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.name = "X402ProtocolError";
    this.code = code;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeBase64Json(raw: string): unknown {
  let text: string;
  try {
    text = Buffer.from(raw, "base64").toString("utf8");
  } catch {
    throw new X402ProtocolError("MALFORMED_HEADER", "Header is not valid base64.");
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new X402ProtocolError("MALFORMED_HEADER", "Header does not decode to JSON.");
  }
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new X402ProtocolError("MALFORMED_REQUIREMENTS", `${field} must be a non-empty string.`);
  }
  return value;
}

/** Atomic amounts are decimal integer strings; a float here is a protocol error. */
function requireAtomic(value: unknown, field: string): string {
  const raw = requireString(value, field);
  if (!/^[0-9]+$/.test(raw)) {
    throw new X402ProtocolError("MALFORMED_REQUIREMENTS", `${field} must be a decimal integer string.`);
  }
  return raw;
}

function parseRequirements(value: unknown): PaymentRequirements {
  if (!isRecord(value)) {
    throw new X402ProtocolError("MALFORMED_REQUIREMENTS", "An accepts entry must be an object.");
  }
  const timeout = value["maxTimeoutSeconds"];
  if (typeof timeout !== "number" || !Number.isFinite(timeout) || timeout <= 0) {
    throw new X402ProtocolError("MALFORMED_REQUIREMENTS", "maxTimeoutSeconds must be a positive number.");
  }
  const extra = value["extra"];
  if (extra !== undefined && !isRecord(extra)) {
    throw new X402ProtocolError("MALFORMED_REQUIREMENTS", "extra must be an object when present.");
  }

  return Object.freeze({
    scheme: requireString(value["scheme"], "scheme"),
    network: requireString(value["network"], "network"),
    asset: requireString(value["asset"], "asset"),
    amount: requireAtomic(value["amount"], "amount"),
    payTo: requireString(value["payTo"], "payTo"),
    maxTimeoutSeconds: timeout,
    // Frozen, never rebuilt. See the note on PaymentRequirements.extra.
    extra: Object.freeze({ ...(extra ?? {}) }),
  });
}

function parsePaymentRequiredValue(value: unknown): PaymentRequiredV2 {
  if (!isRecord(value)) {
    throw new X402ProtocolError("MALFORMED_402", "Payment-required payload must be an object.");
  }
  const version = value["x402Version"];
  if (typeof version !== "number") {
    throw new X402ProtocolError("MALFORMED_402", "x402Version must be a number.");
  }
  const accepts = value["accepts"];
  if (!Array.isArray(accepts) || accepts.length === 0) {
    throw new X402ProtocolError("NO_ACCEPTS", "A 402 must carry at least one accepts entry.");
  }
  const resource = isRecord(value["resource"]) ? value["resource"] : undefined;

  return Object.freeze({
    x402Version: version,
    ...(typeof value["error"] === "string" ? { error: value["error"] } : {}),
    ...(resource === undefined
      ? {}
      : {
          resource: Object.freeze({
            ...(typeof resource["url"] === "string" ? { url: resource["url"] } : {}),
            ...(typeof resource["description"] === "string"
              ? { description: resource["description"] }
              : {}),
            ...(typeof resource["mimeType"] === "string" ? { mimeType: resource["mimeType"] } : {}),
          }),
        }),
    accepts: Object.freeze(accepts.map(parseRequirements)),
  });
}

/**
 * Read a 402's requirements.
 *
 * The header is authoritative because that is what the spec and the SDK use;
 * the body is accepted as a fallback so servers that only populate one of the
 * two still work.
 */
export function parsePaymentRequired(headers: HeaderReader, body?: unknown): PaymentRequiredV2 {
  const header = headers(X402_PAYMENT_REQUIRED_HEADER);
  if (typeof header === "string" && header.length > 0) {
    return parsePaymentRequiredValue(decodeBase64Json(header));
  }
  if (body !== undefined) {
    return parsePaymentRequiredValue(body);
  }
  throw new X402ProtocolError(
    "NO_PAYMENT_REQUIRED",
    `Response carried neither a ${X402_PAYMENT_REQUIRED_HEADER} header nor a usable body.`,
  );
}

/** Pick the offer we can actually pay, and hand it back untouched. */
export function selectAccepts(
  required: PaymentRequiredV2,
  want: { readonly scheme: string; readonly network: string },
): PaymentRequirements {
  const match = required.accepts.find(
    (entry) => entry.scheme === want.scheme && entry.network === want.network,
  );
  if (match === undefined) {
    const offered = required.accepts.map((e) => `${e.scheme}/${e.network}`).join(", ");
    throw new X402ProtocolError(
      "UNSUPPORTED_OFFER",
      `Seller offers [${offered}]; we need ${want.scheme}/${want.network}.`,
    );
  }
  return match;
}

export function encodePaymentSignature(payload: unknown): Readonly<Record<string, string>> {
  return Object.freeze({
    [X402_PAYMENT_SIGNATURE_HEADER]: Buffer.from(JSON.stringify(payload), "utf8").toString("base64"),
  });
}

export interface SettlementResponse {
  readonly success?: boolean;
  readonly transaction?: string;
  readonly network?: string;
  readonly payer?: string;
}

/**
 * Read the settlement a seller reports. Accepts the legacy header too, so a
 * silent `undefined` never masquerades as "the seller did not settle".
 */
export function decodePaymentResponse(headers: HeaderReader): SettlementResponse | undefined {
  const raw =
    headers(X402_PAYMENT_RESPONSE_HEADER) ?? headers(X402_LEGACY_PAYMENT_RESPONSE_HEADER);
  if (typeof raw !== "string" || raw.length === 0) return undefined;
  try {
    const decoded = decodeBase64Json(raw);
    return isRecord(decoded) ? (decoded as SettlementResponse) : undefined;
  } catch {
    return undefined;
  }
}

export function encodePaymentRequired(payload: PaymentRequiredV2): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

export function encodePaymentResponse(settlement: SettlementResponse): string {
  return Buffer.from(JSON.stringify(settlement), "utf8").toString("base64");
}
