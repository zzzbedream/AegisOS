import type { PurchaseCommitmentV1 } from "../../proof/src/index.js";

/**
 * The agent/signer boundary.
 *
 * The x402 quickstart builds its signer inside the client with
 * `createEd25519Signer(STELLAR_PRIVATE_KEY, …)`, which puts the key in the
 * same process that reads attacker-controlled content. Everything here exists
 * to move that key somewhere the agent cannot reach.
 *
 * Requests are a closed union of *typed operations*, never "here is a blob,
 * sign it". The agent cannot widen what it is asking for.
 */

export const SIGNER_PROTOCOL_VERSION = "aegisos.signer-ipc.v1";

export interface SignerRequestBase {
  readonly protocol: typeof SIGNER_PROTOCOL_VERSION;
  readonly id: string;
}

export interface GetAddressRequest extends SignerRequestBase {
  readonly kind: "get_address";
}

/**
 * Sign one x402 authorization entry.
 *
 * The commitment travels with the request so the signer can decide for itself
 * whether the entry is the payment the buyer actually committed to — rather
 * than trusting an amount the agent asserts.
 */
export interface SignAuthEntryRequest extends SignerRequestBase {
  readonly kind: "sign_auth_entry";
  readonly authEntryXdr: string;
  readonly networkPassphrase?: string;
  readonly address?: string;
  readonly commitment: PurchaseCommitmentV1;
}

/**
 * Ask the commitment authority to sign an on-chain commitment. The authority
 * signs only what its launch-time policy allows (approved sellers, ceiling,
 * window); the paying account is taken from the signer config, never from
 * the request.
 */
export interface SignOnChainCommitmentRequest extends SignerRequestBase {
  readonly kind: "sign_onchain_commitment";
  readonly commitment: {
    readonly commitmentHash: string;
    readonly seller: string;
    readonly asset: string;
    /** Decimal string, atomic units. */
    readonly maxAmount: string;
    /** Decimal string, unix seconds. */
    readonly expiresAt: string;
  };
}

export type SignerRequest = GetAddressRequest | SignAuthEntryRequest | SignOnChainCommitmentRequest;

export interface SignerOkResponse {
  readonly protocol: typeof SIGNER_PROTOCOL_VERSION;
  readonly id: string;
  readonly kind: "ok";
  readonly value: string;
}

export interface SignerDeniedResponse {
  readonly protocol: typeof SIGNER_PROTOCOL_VERSION;
  readonly id: string;
  readonly kind: "denied";
  readonly code: SignerDenialCode;
  readonly message: string;
}

export type SignerResponse = SignerOkResponse | SignerDeniedResponse;

export type SignerDenialCode =
  | "MALFORMED_REQUEST"
  | "UNKNOWN_OPERATION"
  | "COMMITMENT_KEY_UNTRUSTED"
  | "COMMITMENT_SIGNATURE_INVALID"
  | "COMMITMENT_EXPIRED"
  | "SELLER_NOT_ALLOWED"
  | "NETWORK_NOT_ALLOWED"
  | "ASSET_NOT_ALLOWED"
  | "AMOUNT_EXCEEDS_COMMITMENT"
  | "AUTH_ENTRY_UNDECODABLE"
  | "AUTH_ENTRY_MISMATCH"
  | "KEY_MATERIAL_IN_REQUEST"
  | "AUTHORITY_NOT_CONFIGURED"
  | "COMMITMENT_POLICY_DENIED"
  | "SIGNING_FAILED";

export class SignerDeniedError extends Error {
  public readonly code: SignerDenialCode;

  public constructor(code: SignerDenialCode, message: string) {
    super(message);
    this.name = "SignerDeniedError";
    this.code = code;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Key material must never cross this boundary. It is the agent that is
 * untrusted here, so a request carrying a secret is rejected outright rather
 * than merely ignored.
 */
const KEY_MATERIAL = /privatekey|private_key|secretkey|secret_key|seed|mnemonic|passphrase_secret/i;

export function assertNoKeyMaterial(value: unknown, depth = 0): void {
  if (depth > 8 || !isRecord(value)) return;
  for (const key of Object.keys(value)) {
    if (KEY_MATERIAL.test(key)) {
      throw new SignerDeniedError(
        "KEY_MATERIAL_IN_REQUEST",
        `Request carries key-like field "${key}"; the signer never accepts one.`,
      );
    }
    assertNoKeyMaterial(value[key], depth + 1);
  }
}

export function parseSignerRequest(value: unknown): SignerRequest {
  if (!isRecord(value) || value["protocol"] !== SIGNER_PROTOCOL_VERSION) {
    throw new SignerDeniedError("MALFORMED_REQUEST", "Unrecognised signer protocol.");
  }
  if (typeof value["id"] !== "string" || value["id"].length === 0) {
    throw new SignerDeniedError("MALFORMED_REQUEST", "Request id is required.");
  }
  assertNoKeyMaterial(value);

  const kind = value["kind"];
  if (kind === "get_address") {
    return { protocol: SIGNER_PROTOCOL_VERSION, id: value["id"], kind: "get_address" };
  }
  if (kind === "sign_auth_entry") {
    if (typeof value["authEntryXdr"] !== "string") {
      throw new SignerDeniedError("MALFORMED_REQUEST", "authEntryXdr must be a string.");
    }
    if (!isRecord(value["commitment"])) {
      throw new SignerDeniedError("MALFORMED_REQUEST", "A purchase commitment is required.");
    }
    return {
      protocol: SIGNER_PROTOCOL_VERSION,
      id: value["id"],
      kind: "sign_auth_entry",
      authEntryXdr: value["authEntryXdr"],
      ...(typeof value["networkPassphrase"] === "string"
        ? { networkPassphrase: value["networkPassphrase"] }
        : {}),
      ...(typeof value["address"] === "string" ? { address: value["address"] } : {}),
      commitment: value["commitment"] as unknown as PurchaseCommitmentV1,
    };
  }
  if (kind === "sign_onchain_commitment") {
    const c = value["commitment"];
    if (!isRecord(c)) {
      throw new SignerDeniedError("MALFORMED_REQUEST", "An on-chain commitment is required.");
    }
    const text = (field: string, pattern: RegExp): string => {
      const v = c[field];
      if (typeof v !== "string" || !pattern.test(v)) {
        throw new SignerDeniedError("MALFORMED_REQUEST", `commitment.${field} is malformed.`);
      }
      return v;
    };
    return {
      protocol: SIGNER_PROTOCOL_VERSION,
      id: value["id"],
      kind: "sign_onchain_commitment",
      commitment: {
        commitmentHash: text("commitmentHash", /^[a-f0-9]{64}$/),
        seller: text("seller", /^[GC][A-Z2-7]{55}$/),
        asset: text("asset", /^C[A-Z2-7]{55}$/),
        maxAmount: text("maxAmount", /^[1-9][0-9]{0,37}$/),
        expiresAt: text("expiresAt", /^[1-9][0-9]{0,19}$/),
      },
    };
  }
  throw new SignerDeniedError("UNKNOWN_OPERATION", `Unsupported signer operation: ${String(kind)}`);
}
