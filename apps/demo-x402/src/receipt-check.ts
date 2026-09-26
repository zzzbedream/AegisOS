import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  accountFromSellerId,
  rootFromProof,
  batchLeafForReceipt,
  verifyDeliveryReceipt,
  type DeliveryReceiptV1,
  type MerkleProofV1,
} from "../../../packages/proof/src/index.js";
import {
  rangeLeafHash,
  type AnchoredBatchV1,
  type AnchoredDeliveryV1,
  type RangeRecordV1,
} from "../../../packages/x402/src/index.js";
import type { PaymentNotarization } from "./agent.js";
import type { PublishedAttesterV1 } from "./attester.js";
import type { ReclaimProofV1 } from "./content-proof.js";

export const RECEIPTS_DIR = ".aegis/receipts";

/** Where a receipt was anchored. The contract must be one we published. */
export type AnchorRefV1 =
  | { readonly mode: "individual"; readonly contractId: string; readonly tx?: string }
  | {
      readonly mode: "batch";
      readonly contractId: string;
      readonly root: string;
      readonly proof: MerkleProofV1;
      readonly tx?: string;
    };

/** Where the receipt's payment was anchored as part of an account range. */
export interface RangeRefV1 {
  readonly contractId: string;
  readonly account: string;
  readonly fromSeq: string;
  readonly toSeq: string;
  readonly root: string;
  readonly proof: MerkleProofV1;
  readonly tx?: string;
}

export interface ReceiptFileV1 {
  readonly version: "1";
  readonly receipt: DeliveryReceiptV1;
  readonly anchor?: AnchorRefV1;
  /** Smart-account mode: the account's own record of this payment. */
  readonly notarization?: PaymentNotarization;
  /** Smart-account mode: the account range this payment was counted in. */
  readonly range?: RangeRefV1;
  /** Guarantee D: an attestor's proof that the seller served this content over TLS. */
  readonly contentProof?: ContentProofRefV1;
}

export interface ContentProofRefV1 {
  readonly kind: "reclaim-zkfetch-v1";
  readonly proof: ReclaimProofV1;
}

/** Which on-chain record proves that a receipt was anchored. */
export type AnchorRoute = "individual" | "batch" | "range" | "search";

export function anchorRoute(file: Pick<ReceiptFileV1, "anchor" | "notarization" | "range">): AnchorRoute {
  if (file.anchor !== undefined) return file.anchor.mode;
  // A range proves anchoring only with the notarization the registry recomputed.
  if (file.range !== undefined && file.notarization !== undefined) return "range";
  // Legacy receipts carry no reference: search every published contract.
  return "search";
}

export interface ReceiptCheck {
  readonly name: string;
  readonly pass: boolean;
  readonly detail: string;
}

/** Accept the envelope, or a bare receipt as written before batching. */
export function readReceiptFile(raw: unknown): ReceiptFileV1 {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("Receipt file must hold a JSON object.");
  }
  const record = raw as Record<string, unknown>;
  if (typeof record["receipt"] === "object" && record["receipt"] !== null) {
    return raw as ReceiptFileV1;
  }
  return { version: "1", receipt: raw as DeliveryReceiptV1 };
}

/**
 * Signature checks: what a third party can establish with the published key
 * alone. A valid receipt proves the buyer environment attested to it — it
 * does not prove the verdict is true or that the seller misbehaved.
 */
export function signatureChecks(
  receipt: DeliveryReceiptV1,
  published: PublishedAttesterV1,
): readonly ReceiptCheck[] {
  const keyMatches = receipt.signature.keyId === published.keyId;
  const signatureHolds = keyMatches && verifyDeliveryReceipt(receipt, published.publicKey);
  return [
    {
      name: "signed by the published attester",
      pass: keyMatches,
      detail: keyMatches
        ? published.keyId
        : `receipt keyId ${receipt.signature.keyId} ≠ published ${published.keyId}`,
    },
    {
      name: "signature verifies",
      pass: signatureHolds,
      detail: signatureHolds ? "ed25519 over the canonical receipt" : "signature does not verify",
    },
  ];
}

function matches(name: string, ours: string, onChain: string): ReceiptCheck {
  return {
    name,
    pass: ours === onChain,
    detail: ours === onChain ? onChain : `receipt ${ours} ≠ chain ${onChain}`,
  };
}

/** Compare a receipt with the record `get_delivery` returned for it. */
export function individualChecks(
  receipt: DeliveryReceiptV1,
  anchored: AnchoredDeliveryV1,
): readonly ReceiptCheck[] {
  return [
    matches("on-chain payment hash matches", receipt.paymentHash, anchored.paymentHash),
    matches("on-chain commitment hash matches", receipt.commitmentHash, anchored.commitmentHash),
    matches("on-chain content hash matches", receipt.contentHash, anchored.contentHash),
    matches("on-chain verdict matches", receipt.verdict, anchored.verdict),
    matches("on-chain seller matches", accountFromSellerId(receipt.sellerId), anchored.seller),
  ];
}

/**
 * Prove a batched receipt against the root `get_batch` returned.
 *
 * The leaf is recomputed from the receipt, and the root from the path; the
 * root written in the file is never trusted, only compared.
 */
export function batchChecks(
  receipt: DeliveryReceiptV1,
  proof: MerkleProofV1,
  batch: AnchoredBatchV1,
): readonly ReceiptCheck[] {
  let computedRoot = "";
  try {
    computedRoot = rootFromProof(batchLeafForReceipt(receipt), proof.steps);
  } catch (error: unknown) {
    computedRoot = `error: ${error instanceof Error ? error.message : String(error)}`;
  }
  const attesterAccount = receipt.attesterId.startsWith("buyer:")
    ? receipt.attesterId.slice("buyer:".length)
    : receipt.attesterId;
  return [
    {
      name: "only an OK receipt can be batched",
      pass: receipt.verdict === "OK",
      detail: receipt.verdict,
    },
    matches("inclusion proof reaches the on-chain root", computedRoot, batch.root),
    matches("on-chain batch seller matches", accountFromSellerId(receipt.sellerId), batch.seller),
    matches("on-chain batch buyer matches the attester", attesterAccount, batch.buyer),
  ];
}

/**
 * Prove the receipt was counted in an account range. The leaf is rebuilt from
 * the notarized payment (seq, commitment, seller, amount) and the receipt
 * (content hash, verdict); the root comes from `get_range`, never the file.
 */
export function rangeChecks(
  receipt: DeliveryReceiptV1,
  notarization: PaymentNotarization,
  ref: RangeRefV1,
  record: RangeRecordV1,
): readonly ReceiptCheck[] {
  const seq = BigInt(notarization.seq);
  let computed = "";
  try {
    computed = rootFromProof(
      rangeLeafHash({
        seq,
        commitmentHash: notarization.commitmentHash,
        seller: notarization.seller,
        amount: BigInt(notarization.amount),
        contentHash: receipt.contentHash,
        verdict: receipt.verdict,
      }),
      ref.proof.steps,
    );
  } catch (error: unknown) {
    computed = `error: ${error instanceof Error ? error.message : String(error)}`;
  }
  return [
    matches("range belongs to the paying account", notarization.account, record.account),
    {
      name: "payment falls inside the anchored range",
      pass: seq >= record.fromSeq && seq <= record.toSeq,
      detail: `seq ${seq.toString()} in ${record.fromSeq.toString()}..${record.toSeq.toString()}`,
    },
    matches("receipt proves into the range root the registry computed", computed, record.root),
  ];
}

/** Keep the receipt where a verifier can be pointed at it. Public data only. */
export function saveReceipt(
  receipt: DeliveryReceiptV1,
  extras: {
    readonly anchor?: AnchorRefV1;
    readonly notarization?: PaymentNotarization;
    readonly range?: RangeRefV1;
    readonly contentProof?: ContentProofRefV1;
  } = {},
  dir: string = RECEIPTS_DIR,
): string {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${receipt.paymentHash}.json`);
  const file: ReceiptFileV1 = {
    version: "1",
    receipt,
    ...(extras.anchor === undefined ? {} : { anchor: extras.anchor }),
    ...(extras.notarization === undefined ? {} : { notarization: extras.notarization }),
    ...(extras.range === undefined ? {} : { range: extras.range }),
    ...(extras.contentProof === undefined ? {} : { contentProof: extras.contentProof }),
  };
  writeFileSync(path, `${JSON.stringify(file, null, 2)}\n`, "utf8");
  return path;
}
