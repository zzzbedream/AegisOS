import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  accountFromSellerId,
  verifyDeliveryReceipt,
  type DeliveryReceiptV1,
} from "../../../packages/proof/src/index.js";
import type { AnchoredDeliveryV1 } from "../../../packages/x402/src/index.js";
import type { PublishedAttesterV1 } from "./attester.js";

export const RECEIPTS_DIR = ".aegis/receipts";

export interface ReceiptCheck {
  readonly name: string;
  readonly pass: boolean;
  readonly detail: string;
}

/**
 * What a third party can establish about a receipt with public inputs only:
 * the published attester key and, optionally, the on-chain record.
 *
 * Deliberately says nothing about whether the verdict is TRUE. A valid receipt
 * proves the buyer's environment attested to it, and that the chain holds the
 * same hashes; it does not prove the seller misbehaved.
 */
export function checkReceipt(
  receipt: DeliveryReceiptV1,
  published: PublishedAttesterV1,
  anchored?: AnchoredDeliveryV1,
): readonly ReceiptCheck[] {
  const checks: ReceiptCheck[] = [];

  const keyMatches = receipt.signature.keyId === published.keyId;
  checks.push({
    name: "signed by the published attester",
    pass: keyMatches,
    detail: keyMatches
      ? published.keyId
      : `receipt keyId ${receipt.signature.keyId} ≠ published ${published.keyId}`,
  });

  const signatureHolds = keyMatches && verifyDeliveryReceipt(receipt, published.publicKey);
  checks.push({
    name: "signature verifies",
    pass: signatureHolds,
    detail: signatureHolds ? "ed25519 over the canonical receipt" : "signature does not verify",
  });

  if (anchored === undefined) return checks;

  const pairs: readonly (readonly [string, string, string])[] = [
    ["payment hash", receipt.paymentHash, anchored.paymentHash],
    ["commitment hash", receipt.commitmentHash, anchored.commitmentHash],
    ["content hash", receipt.contentHash, anchored.contentHash],
    ["verdict", receipt.verdict, anchored.verdict],
    ["seller", accountFromSellerId(receipt.sellerId), anchored.seller],
  ];
  for (const [name, ours, onChain] of pairs) {
    checks.push({
      name: `on-chain ${name} matches`,
      pass: ours === onChain,
      detail: ours === onChain ? onChain : `receipt ${ours} ≠ chain ${onChain}`,
    });
  }
  return checks;
}

/** Keep the receipt where a verifier can be pointed at it. Public data only. */
export function saveReceipt(receipt: DeliveryReceiptV1, dir: string = RECEIPTS_DIR): string {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${receipt.paymentHash}.json`);
  writeFileSync(path, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  return path;
}
