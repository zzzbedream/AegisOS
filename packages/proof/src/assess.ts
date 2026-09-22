import {
  ContentHashError,
  hashDeliveredContent,
  type Sha256Hex,
} from "./hashing.js";
import { isSellerId } from "./ids.js";
import { verifySellerOffer } from "./records.js";
import type {
  AssuranceTier,
  ContentCanonicalization,
  ContentRiskAssessor,
  ContentRiskSignalV1,
  DeliveryAssessmentV1,
  DeliveryVerdict,
  PurchaseCommitmentV1,
  SellerOfferV1,
} from "./types.js";

export const DEFAULT_TAINT_THRESHOLD = 60;

/** What the buyer actually observed coming back from the resource server. */
export interface DeliveryObservationV1 {
  readonly responseReceived: boolean;
  readonly bodyBytes: Uint8Array;
  readonly contentType?: string;
  readonly sellerId: unknown;
  readonly receivedAt: string;
  readonly elapsedMs?: number;
  /** Override the canonicalization inferred from the content type. */
  readonly canonicalization?: ContentCanonicalization;
}

export interface AssessDeliveryOptions {
  readonly assessRisk: ContentRiskAssessor;
  readonly taintThreshold?: number;
  /** Present only in T1, where the seller signed an offer before payment. */
  readonly sellerOffer?: SellerOfferV1;
  readonly sellerPublicKey?: string;
}

function essenceOf(contentType: string | undefined): string {
  if (contentType === undefined) return "";
  const head = contentType.split(";")[0];
  return (head ?? "").trim().toLowerCase();
}

function canonicalizationFor(contentType: string | undefined): ContentCanonicalization {
  const essence = essenceOf(contentType);
  if (essence === "application/json" || essence.endsWith("+json")) return "json-canonical-v1";
  if (essence.startsWith("text/")) return "utf8-bytes-v1";
  return "raw-bytes-v1";
}

interface HashOutcome {
  readonly contentHash: Sha256Hex;
  readonly contentBytes: number;
  readonly canonicalization: ContentCanonicalization;
  readonly hashFailure?: string;
}

/**
 * Always produce a hash, even for malformed bodies: the receipt is evidence,
 * and evidence that vanishes when the seller misbehaves is useless. A body
 * that cannot be canonicalized still gets hashed as raw bytes, and the failure
 * becomes a mismatch reason.
 */
function hashWithFallback(
  observation: DeliveryObservationV1,
  preferred: ContentCanonicalization,
): HashOutcome {
  try {
    return hashDeliveredContent({ bodyBytes: observation.bodyBytes, canonicalization: preferred });
  } catch (error: unknown) {
    const raw = hashDeliveredContent({
      bodyBytes: observation.bodyBytes,
      canonicalization: "raw-bytes-v1",
    });
    const code = error instanceof ContentHashError ? error.code : "UNHASHABLE_CONTENT";
    return { ...raw, hashFailure: code };
  }
}

/**
 * Deterministic. No model call: a classifier here would add a dependency,
 * nondeterminism, and a second place for the attacker's text to be read.
 *
 * Precedence is strict — NOT_DELIVERED beats MISMATCH beats TAINTED — so an
 * empty body carrying injection text is reported as a non-delivery, and an
 * HTML page where JSON was promised is a mismatch even if it also injects.
 */
export function assessDelivery(
  commitment: PurchaseCommitmentV1,
  observation: DeliveryObservationV1,
  options: AssessDeliveryOptions,
): DeliveryAssessmentV1 {
  const threshold = options.taintThreshold ?? DEFAULT_TAINT_THRESHOLD;
  const assuranceTier: AssuranceTier = options.sellerOffer === undefined ? "T2" : "T1";
  const preferred =
    observation.canonicalization ?? canonicalizationFor(observation.contentType ?? commitment.expectedContentType);

  const hashed = hashWithFallback(observation, preferred);
  const reasons: string[] = [];

  const finish = (verdict: DeliveryVerdict, taintScore: number, signals: readonly ContentRiskSignalV1[]): DeliveryAssessmentV1 =>
    Object.freeze({
      verdict,
      contentHash: hashed.contentHash,
      contentBytes: hashed.contentBytes,
      contentCanonicalization: hashed.canonicalization,
      ...(observation.contentType === undefined ? {} : { observedContentType: observation.contentType }),
      taintScore,
      riskSignals: Object.freeze([...signals]),
      assuranceTier,
      reasons: Object.freeze([...new Set(reasons)]),
    });

  // 1. NOT_DELIVERED — nothing usable came back.
  if (!observation.responseReceived) {
    reasons.push("NO_RESPONSE");
    return finish("NOT_DELIVERED", 0, []);
  }
  if (
    commitment.responseDeadlineMs !== undefined &&
    observation.elapsedMs !== undefined &&
    observation.elapsedMs > commitment.responseDeadlineMs
  ) {
    reasons.push("DEADLINE_EXCEEDED");
    return finish("NOT_DELIVERED", 0, []);
  }
  if (hashed.contentBytes === 0 && commitment.allowEmptyBody !== true) {
    reasons.push("EMPTY_BODY");
    return finish("NOT_DELIVERED", 0, []);
  }

  // 2. MISMATCH — it arrived, but it is not what was committed to.
  if (!isSellerId(observation.sellerId) || observation.sellerId !== commitment.sellerId) {
    reasons.push("SELLER_MISMATCH");
  }
  if (hashed.hashFailure !== undefined) {
    reasons.push(hashed.hashFailure);
  }
  const expected = essenceOf(commitment.expectedContentType);
  const observed = essenceOf(observation.contentType);
  if (expected !== "" && observed !== "" && expected !== observed) {
    reasons.push("CONTENT_TYPE_MISMATCH");
  }
  if (
    commitment.expectedMinContentBytes !== undefined &&
    hashed.contentBytes < commitment.expectedMinContentBytes
  ) {
    reasons.push("CONTENT_TOO_SMALL");
  }
  if (
    commitment.expectedMaxContentBytes !== undefined &&
    hashed.contentBytes > commitment.expectedMaxContentBytes
  ) {
    reasons.push("CONTENT_TOO_LARGE");
  }

  // T1 only: the seller promised a specific content up front.
  if (options.sellerOffer !== undefined) {
    const offer = options.sellerOffer;
    if (options.sellerPublicKey === undefined || !verifySellerOffer(offer, options.sellerPublicKey)) {
      reasons.push("OFFER_SIGNATURE_INVALID");
    } else if (offer.commitmentHash !== hashed.contentHash) {
      reasons.push("OFFER_CONTENT_MISMATCH");
    }
  }

  if (reasons.length > 0) {
    return finish("MISMATCH", 0, []);
  }

  // 3. TAINTED — structurally correct, but the text is trying to steer the agent.
  let text = "";
  try {
    text = new TextDecoder("utf-8", { fatal: false }).decode(observation.bodyBytes);
  } catch {
    text = "";
  }
  const risk = options.assessRisk(text);
  if (risk.taintScore >= threshold) {
    reasons.push("RISK_THRESHOLD_EXCEEDED");
    return finish("TAINTED", risk.taintScore, risk.signals);
  }

  // 4. OK.
  return finish("OK", risk.taintScore, risk.signals);
}
