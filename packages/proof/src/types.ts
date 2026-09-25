import type { DetachedSignatureV1 } from "../../core/src/index.js";

/**
 * Canonical seller identity. A bare string would let `seller-good`,
 * `seller_good`, a URL and a Stellar account fragment one seller's history
 * into four, which is both a reputation bypass and a reputation forgery.
 */
export type SellerId = `stellar:${string}`;

export type DeliveryVerdict = "OK" | "TAINTED" | "MISMATCH" | "NOT_DELIVERED";

/**
 * How much the buyer can prove about the seller's side of the exchange.
 *
 * T1 — the seller signed an offer before payment, so a breach is attributable.
 * T2 — the seller never promised anything in a verifiable way. The buyer can
 *      still detect injection and mismatch against its own commitment and cut
 *      the cascade; it simply cannot prove the seller broke a promise.
 *
 * T2 is the default in the open world and already delivers the invariant.
 */
export type AssuranceTier = "T1" | "T2";

/**
 * How the delivered bytes were reduced to a hash. Recorded on the receipt
 * because "the hash of this JSON" and "the hash of these bytes" are different
 * claims, and a verifier must know which one was made.
 */
export type ContentCanonicalization = "json-canonical-v1" | "utf8-bytes-v1" | "raw-bytes-v1";

/**
 * Minimal structural shape of a content-risk signal.
 *
 * Deliberately `kind: string` so the plugin layer's richer `MemoryRiskSignal`
 * is assignable without this package depending on a framework adapter.
 */
export interface ContentRiskSignalV1 {
  readonly kind: string;
  readonly score: number;
  readonly evidence: string;
}

/** Injected risk assessor. Keeps `proof` independent of any agent framework. */
export type ContentRiskAssessor = (
  content: string,
) => { readonly taintScore: number; readonly signals: readonly ContentRiskSignalV1[] };

/**
 * What the buyer declares it is about to purchase, signed BEFORE paying.
 * Without this there is nothing to compare the delivery against.
 */
export interface PurchaseCommitmentV1 {
  readonly version: "1";
  readonly id: string;
  readonly resourceUrl: string;
  readonly sellerId: SellerId;
  readonly expectedContentType: string;
  readonly expectedMinContentBytes?: number;
  readonly expectedMaxContentBytes?: number;
  readonly allowEmptyBody?: boolean;
  readonly responseDeadlineMs?: number;
  readonly maxAmountAtomic: string;
  readonly assetId: string;
  readonly committedAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly signature: DetachedSignatureV1;
}

/**
 * T1 only. The seller commits to a specific content (or delivery manifest)
 * before the buyer pays. This is what makes a breach attributable.
 */
export interface SellerOfferV1 {
  readonly version: "1";
  readonly sellerId: SellerId;
  readonly resource: string;
  readonly requestHash: string;
  readonly commitmentHash: string;
  readonly paymentRequirementsHash: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly signature: DetachedSignatureV1;
}

export interface DeliveryAssessmentV1 {
  readonly verdict: DeliveryVerdict;
  readonly contentHash: string;
  readonly contentBytes: number;
  readonly contentCanonicalization: ContentCanonicalization;
  readonly observedContentType?: string;
  readonly taintScore: number;
  readonly riskSignals: readonly ContentRiskSignalV1[];
  readonly assuranceTier: AssuranceTier;
  /** Machine-readable, pattern-safe codes. Never free-form seller text. */
  readonly reasons: readonly string[];
}

/**
 * The buyer's signed attestation about one delivery.
 *
 * `attesterRole` exists because a buyer signature is NOT evidence that the
 * seller delivered correctly — it is evidence of what the buyer received and
 * concluded. Conflating the two is the easiest way to overclaim.
 */
export interface DeliveryReceiptV1 {
  readonly version: "1";
  readonly commitmentHash: string;
  readonly paymentHash: string;
  readonly sellerId: SellerId;
  readonly contentHash: string;
  readonly contentBytes: number;
  readonly contentCanonicalization: ContentCanonicalization;
  readonly receivedAt: string;
  readonly verdict: DeliveryVerdict;
  readonly riskSignals: readonly ContentRiskSignalV1[];
  readonly taintScore: number;
  readonly reasons: readonly string[];
  readonly assuranceTier: AssuranceTier;
  readonly attesterId: string;
  readonly attesterRole: "buyer" | "seller";
  readonly signature: DetachedSignatureV1;
}

/** Mirrors the on-chain aggregate. Counts of attestations, not of truth. */
export interface SellerScoreV1 {
  readonly version: "1";
  readonly sellerId: SellerId;
  readonly ok: number;
  readonly tainted: number;
  readonly mismatch: number;
  readonly notDelivered: number;
  readonly disputed: number;
  readonly total: number;
  /**
   * OK deliveries asserted through anchored batches. Kept apart from `ok`: a
   * batch count is the buyer's word, not one record per delivery.
   */
  readonly batchedOk?: number;
  /**
   * Verdicts anchored through ranges: each bound to a payment the buyer's
   * AegisOS account notarized, counted once, none omitted.
   */
  readonly verified?: {
    readonly ok: number;
    readonly tainted: number;
    readonly mismatch: number;
    readonly notDelivered: number;
  };
  readonly asOf?: string;
}

/**
 * The composition surface. A spend rail reads `tainted` and denies; it does
 * not need to understand delivery semantics.
 */
export interface TrustVerdictV1 {
  readonly version: "1";
  readonly sellerId: SellerId;
  readonly sellerScore: SellerScoreV1;
  readonly deliveryVerdict: DeliveryVerdict;
  readonly tainted: boolean;
  readonly assuranceTier: AssuranceTier;
  readonly receiptHash: string;
  readonly evaluatedAt: string;
}
