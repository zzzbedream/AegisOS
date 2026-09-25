import type { FlushedBatch } from "../../../packages/x402/src/index.js";
import type { PaymentNotarization, PurchaseOutcome } from "./agent.js";
import { appendPaymentLog } from "./notarization.js";
import { saveReceipt } from "./receipt-check.js";

const EXPLORER = "https://stellar.expert/explorer/testnet/tx/";

/**
 * Save a receipt anchored on its own right away. A receipt still waiting in a
 * batch is saved when its batch is flushed, because only then does it have a
 * Merkle proof to carry.
 */
export function saveIndividualReceipt(outcome: PurchaseOutcome, contractId: string): string | undefined {
  if (outcome.notarization !== undefined) appendPaymentLog(outcome.notarization);
  if (outcome.anchorPending === true) {
    if (outcome.notarization !== undefined) pendingNotarizations.set(outcome.admission.receipt.paymentHash, outcome.notarization);
    return undefined;
  }
  const receipt = outcome.admission.receipt;
  return saveReceipt(receipt, {
    ...(outcome.anchorTx === undefined ? {} : { anchor: { mode: "individual" as const, contractId, tx: outcome.anchorTx } }),
    ...(outcome.notarization === undefined ? {} : { notarization: outcome.notarization }),
  });
}

/** Notarizations of receipts waiting in a batch, saved with them on flush. */
const pendingNotarizations = new Map<string, PaymentNotarization>();

/** One line for the console. */
export function describeNotarization(n: PaymentNotarization): string {
  return `seq ${n.seq} en la cuenta ${n.account.slice(0, 8)}… · cadena ${n.consistent ? "consistente" : "NO consistente"}`;
}

/** Print each flushed batch and save its receipts with their inclusion proofs. */
export function reportFlushedBatches(
  batches: readonly FlushedBatch[],
  contractId: string,
): readonly string[] {
  const saved: string[] = [];
  for (const batch of batches) {
    console.log(`  lote             : ${String(batch.count)} compra(s) OK → 1 transacción`);
    console.log(`  raíz Merkle      : ${batch.root}`);
    if (batch.anchorTx !== undefined) {
      console.log(`  anclado on-chain : ${EXPLORER}${batch.anchorTx}`);
      for (const { receipt, proof } of batch.entries) {
        const notarization = pendingNotarizations.get(receipt.paymentHash);
        pendingNotarizations.delete(receipt.paymentHash);
        saved.push(
          saveReceipt(receipt, {
            anchor: { mode: "batch", contractId, root: batch.root, proof, tx: batch.anchorTx },
            ...(notarization === undefined ? {} : { notarization }),
          }),
        );
      }
    } else {
      console.log(`  anclaje falló    : ${batch.anchorError ?? "desconocido"} (quedan pendientes)`);
    }
  }
  for (const path of saved) console.log(`  receipt          : ${path}`);
  return saved;
}
