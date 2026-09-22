import { DEFAULT_TAINT_THRESHOLD } from "./assess.js";
import { hashDeliveryReceipt } from "./records.js";
import type {
  DeliveryReceiptV1,
  SellerId,
  SellerScoreV1,
  TrustVerdictV1,
} from "./types.js";

export function emptySellerScore(sellerId: SellerId): SellerScoreV1 {
  return Object.freeze({
    version: "1" as const,
    sellerId,
    ok: 0,
    tainted: 0,
    mismatch: 0,
    notDelivered: 0,
    disputed: 0,
    total: 0,
  });
}

export interface TrustVerdictOptions {
  readonly taintThreshold?: number;
  readonly evaluatedAt: string;
}

/**
 * Collapse a delivery into the one boolean a spend rail needs.
 *
 * `tainted` is deliberately broader than `verdict === "TAINTED"`: a mismatch
 * or a non-delivery is also unfit to justify a downstream payment. The point
 * is not "was this content malicious" but "may this content become authority".
 */
export function toTrustVerdict(
  receipt: DeliveryReceiptV1,
  sellerScore: SellerScoreV1,
  options: TrustVerdictOptions,
): TrustVerdictV1 {
  const threshold = options.taintThreshold ?? DEFAULT_TAINT_THRESHOLD;
  const tainted =
    receipt.verdict !== "OK" ||
    receipt.taintScore >= threshold ||
    sellerScore.mismatch > 0 ||
    sellerScore.notDelivered > 0;

  return Object.freeze({
    version: "1" as const,
    sellerId: receipt.sellerId,
    sellerScore,
    deliveryVerdict: receipt.verdict,
    tainted,
    assuranceTier: receipt.assuranceTier,
    receiptHash: hashDeliveryReceipt(receipt),
    evaluatedAt: options.evaluatedAt,
  });
}

export interface AbstentionPolicy {
  readonly maxMismatch?: number;
  readonly maxTainted?: number;
  readonly maxNotDelivered?: number;
  readonly minTotalBeforeTrusting?: number;
  readonly requireTier?: "T1";
}

/**
 * Whether to buy from this seller AT ALL — a separate question from whether a
 * delivery already received may authorize spending.
 *
 * Kept out of the protocol on purpose: one bad delivery should not blacklist a
 * seller forever, and where that line sits is the operator's call, not ours.
 * The on-chain score is also trivially grief-able, so it must never be the
 * sole input to a hard block.
 */
export function shouldAbstainFromPurchase(
  score: SellerScoreV1,
  policy: AbstentionPolicy = {},
): { readonly abstain: boolean; readonly reasons: readonly string[] } {
  const reasons: string[] = [];

  if (policy.maxMismatch !== undefined && score.mismatch > policy.maxMismatch) {
    reasons.push("SELLER_MISMATCH_HISTORY");
  }
  if (policy.maxTainted !== undefined && score.tainted > policy.maxTainted) {
    reasons.push("SELLER_TAINTED_HISTORY");
  }
  if (policy.maxNotDelivered !== undefined && score.notDelivered > policy.maxNotDelivered) {
    reasons.push("SELLER_NON_DELIVERY_HISTORY");
  }
  if (policy.minTotalBeforeTrusting !== undefined && score.total < policy.minTotalBeforeTrusting) {
    reasons.push("SELLER_HISTORY_TOO_THIN");
  }

  return Object.freeze({ abstain: reasons.length > 0, reasons: Object.freeze([...new Set(reasons)]) });
}
