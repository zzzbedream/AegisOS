import type { SigningIdentityV1 } from "../../core/src/index.js";
import { assessDelivery, type AssessDeliveryOptions, type DeliveryObservationV1 } from "./assess.js";
import { hashPurchaseCommitment, createDeliveryReceipt } from "./records.js";
import type {
  DeliveryAssessmentV1,
  DeliveryReceiptV1,
  PurchaseCommitmentV1,
  SellerId,
} from "./types.js";

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

/**
 * Structural view of the memory gateway. Declared here rather than imported so
 * this package never depends on an agent-framework adapter.
 */
export interface MemoryGatewayLike<TEnvelope> {
  ingest(input: {
    readonly id?: string;
    readonly content: string;
    readonly provenance: {
      readonly source: "tool";
      readonly sourceRef: string;
      readonly actorId?: string;
      readonly receivedAt?: string;
    };
    readonly metadata?: Readonly<Record<string, JsonValue>>;
  }): TEnvelope;
}

export type DeliveryAdmission = "ADMITTED" | "QUARANTINED" | "REJECTED";

export interface AdmitDeliveryResult<TEnvelope> {
  readonly admission: DeliveryAdmission;
  readonly assessment: DeliveryAssessmentV1;
  readonly receipt: DeliveryReceiptV1;
  /** Absent when the delivery was rejected outright and never stored. */
  readonly envelope?: TEnvelope;
}

export interface AdmitDeliveryOptions<TEnvelope> extends AssessDeliveryOptions {
  readonly gateway: MemoryGatewayLike<TEnvelope>;
  readonly paymentHash: string;
  readonly attesterId: string;
  readonly signer: SigningIdentityV1;
  readonly memoryId?: string;
}

/**
 * The single path from a paid response into agent context.
 *
 * Every delivery produces a signed receipt — including the ones that are
 * refused — because the receipt is the evidence that the block happened.
 * What varies is whether the content is allowed to reach the store:
 *
 *   OK            → admitted; still external content, never authority
 *   TAINTED       → stored, and the gateway quarantines it because the verdict
 *                   IS taint >= threshold, so the two agree by construction
 *   MISMATCH      → NOT stored. The gateway decides quarantine from its own
 *                   taint score, so a low-taint mismatch would be stored as
 *                   AVAILABLE and become readable context — the receipt and the
 *                   content hash are the evidence, and that is enough.
 *   NOT_DELIVERED → nothing usable arrived, so nothing is stored at all
 *
 * The MISMATCH rule is not an optimisation. An earlier version ingested it and
 * reported `QUARANTINED` from the verdict while the gateway had it AVAILABLE;
 * the corpus caught the disagreement by measuring what `retrieve()` returned
 * instead of trusting the returned admission.
 *
 * Deliberately not optional: if a caller could skip this and hand a body
 * straight to the gateway, the invariant would hold only by convention.
 */
export function admitDelivery<TEnvelope>(
  commitment: PurchaseCommitmentV1,
  observation: DeliveryObservationV1,
  options: AdmitDeliveryOptions<TEnvelope>,
): AdmitDeliveryResult<TEnvelope> {
  const assessment = assessDelivery(commitment, observation, options);

  const receipt = createDeliveryReceipt(
    {
      version: "1",
      commitmentHash: hashPurchaseCommitment(commitment),
      paymentHash: options.paymentHash,
      sellerId: commitment.sellerId,
      contentHash: assessment.contentHash,
      contentBytes: assessment.contentBytes,
      contentCanonicalization: assessment.contentCanonicalization,
      receivedAt: observation.receivedAt,
      verdict: assessment.verdict,
      riskSignals: assessment.riskSignals,
      taintScore: assessment.taintScore,
      reasons: assessment.reasons,
      assuranceTier: assessment.assuranceTier,
      attesterId: options.attesterId,
      attesterRole: "buyer",
    },
    options.signer,
  );

  // Only a verdict the gateway will agree with reaches the store. For OK the
  // gateway marks it AVAILABLE; for TAINTED it quarantines, because the verdict
  // is defined by the same threshold the gateway uses.
  if (assessment.verdict === "NOT_DELIVERED" || assessment.verdict === "MISMATCH") {
    return Object.freeze({ admission: "REJECTED" as const, assessment, receipt });
  }

  const text = new TextDecoder("utf-8", { fatal: false }).decode(observation.bodyBytes);
  const envelope = options.gateway.ingest({
    ...(options.memoryId === undefined ? {} : { id: options.memoryId }),
    content: text,
    provenance: { source: "tool", sourceRef: options.paymentHash, receivedAt: observation.receivedAt },
    metadata: deliveryMetadata(receipt, commitment.sellerId),
  });

  return Object.freeze({
    admission: assessment.verdict === "OK" ? ("ADMITTED" as const) : ("QUARANTINED" as const),
    assessment,
    receipt,
    envelope,
  });
}

/**
 * `verifiedDeliveryBinding` is the flag downstream policy keys on. It is true
 * only for a clean verdict — not merely "we have a receipt", since a receipt
 * exists for refused deliveries too.
 */
export function deliveryMetadata(
  receipt: DeliveryReceiptV1,
  sellerId: SellerId,
): Readonly<Record<string, JsonValue>> {
  return Object.freeze({
    aegisProofVersion: "1",
    sellerId,
    commitmentHash: receipt.commitmentHash,
    paymentHash: receipt.paymentHash,
    contentHash: receipt.contentHash,
    deliveryVerdict: receipt.verdict,
    assuranceTier: receipt.assuranceTier,
    verifiedDeliveryBinding: receipt.verdict === "OK",
    attesterRole: receipt.attesterRole,
  });
}
