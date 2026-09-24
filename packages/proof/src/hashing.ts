import { sha256Canonical, sha256Hex } from "../../core/src/index.js";
import type { ContentCanonicalization } from "./types.js";

/**
 * Domain separation. Without it, the hash of a receipt could be replayed as
 * the hash of a commitment, because both are just "sha256 of some object".
 */
export const PROOF_DOMAINS = {
  purchaseCommitment: "aegisproof:purchase-commitment:v1",
  sellerOffer: "aegisproof:seller-offer:v1",
  deliveryReceipt: "aegisproof:delivery-receipt:v1",
  payment: "aegisproof:payment:v1",
  paymentBinding: "aegisproof:payment-binding:v1",
  batchLeaf: "aegisproof:batch-leaf:v1",
} as const;

export type ProofDomain = (typeof PROOF_DOMAINS)[keyof typeof PROOF_DOMAINS];

/** Bare lowercase 64-hex. The single internal representation. */
export type Sha256Hex = string;

const SHA256_HEX = /^[a-f0-9]{64}$/;
const PREFIXED_SHA256 = /^sha256:[a-f0-9]{64}$/;

export class ContentHashError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.name = "ContentHashError";
    this.code = code;
  }
}

export function isSha256Hex(value: unknown): value is Sha256Hex {
  return typeof value === "string" && SHA256_HEX.test(value);
}

export function assertSha256Hex(value: unknown, label: string): asserts value is Sha256Hex {
  if (!isSha256Hex(value)) {
    throw new ContentHashError("INVALID_HASH_FORMAT", `${label} must be bare lowercase 64-hex.`);
  }
}

/**
 * Edge adapters. The signer package speaks `sha256:<hex>`; core and this
 * package speak bare hex, and their validators reject each other's format.
 * Translate exactly once, at the boundary — never accept both inside.
 */
export function toPrefixedSha256(hash: Sha256Hex): `sha256:${string}` {
  assertSha256Hex(hash, "hash");
  return `sha256:${hash}`;
}

export function fromPrefixedSha256(value: string): Sha256Hex {
  if (!PREFIXED_SHA256.test(value)) {
    throw new ContentHashError("INVALID_HASH_FORMAT", "Expected sha256:<64-hex>.");
  }
  return value.slice("sha256:".length);
}

/** Hash a domain-separated object. Always use this, never a bare sha256. */
export function hashInDomain(domain: ProofDomain, payload: unknown): Sha256Hex {
  return sha256Canonical({ domain, payload });
}

/**
 * Bind a payment to its rail. A bare transaction hash is ambiguous across
 * schemes and networks, so the identifier carries its own context.
 */
export function computePaymentHash(input: {
  readonly scheme: string;
  readonly network: string;
  readonly payer: string;
  readonly payee: string;
  readonly transactionRef: string;
  readonly paymentRequirementsHash: string;
}): Sha256Hex {
  return hashInDomain(PROOF_DOMAINS.payment, input);
}

/** Ties the pre-payment commitment to the settled payment. */
export function computePaymentBindingHash(input: {
  readonly commitmentHash: Sha256Hex;
  readonly paymentHash: Sha256Hex;
  readonly network: string;
  readonly assetId: string;
  readonly sellerId: string;
}): Sha256Hex {
  assertSha256Hex(input.commitmentHash, "commitmentHash");
  assertSha256Hex(input.paymentHash, "paymentHash");
  return hashInDomain(PROOF_DOMAINS.paymentBinding, input);
}

export interface DeliveredContentHash {
  readonly contentHash: Sha256Hex;
  readonly contentBytes: number;
  readonly canonicalization: ContentCanonicalization;
}

/**
 * Hash what actually arrived.
 *
 * The canonicalization is an explicit input rather than a guess, because the
 * receipt has to state which claim it is making. Volatile HTTP metadata
 * (headers, timing) is never part of the hash — only the body.
 */
export function hashDeliveredContent(input: {
  readonly bodyBytes: Uint8Array;
  readonly canonicalization: ContentCanonicalization;
}): DeliveredContentHash {
  const bytes = input.bodyBytes;
  const contentBytes = bytes.byteLength;

  if (input.canonicalization === "json-canonical-v1") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      throw new ContentHashError("UNPARSEABLE_JSON", "Body is not valid UTF-8 JSON.");
    }
    // Core's canonicalizer rejects cycles, class instances and non-finite
    // numbers; a body that trips it is malformed, not merely risky.
    try {
      return {
        contentHash: sha256Canonical(parsed),
        contentBytes,
        canonicalization: input.canonicalization,
      };
    } catch {
      throw new ContentHashError("NON_CANONICAL_JSON", "Body is not canonicalizable JSON.");
    }
  }

  if (input.canonicalization === "utf8-bytes-v1") {
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new ContentHashError("INVALID_UTF8", "Body is not valid UTF-8.");
    }
  }

  return {
    contentHash: sha256Hex(bytes),
    contentBytes,
    canonicalization: input.canonicalization,
  };
}

/** Short, pattern-safe reference to a value that must not appear verbatim. */
export function shortHash(value: unknown): string {
  return sha256Canonical(value).slice(0, 16);
}
