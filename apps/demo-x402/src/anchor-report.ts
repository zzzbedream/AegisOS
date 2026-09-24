import type { FlushedBatch } from "../../../packages/x402/src/index.js";
import type { PurchaseOutcome } from "./agent.js";
import { saveReceipt } from "./receipt-check.js";

const EXPLORER = "https://stellar.expert/explorer/testnet/tx/";

/**
 * Save a receipt anchored on its own right away. A receipt still waiting in a
 * batch is saved when its batch is flushed, because only then does it have a
 * Merkle proof to carry.
 */
export function saveIndividualReceipt(outcome: PurchaseOutcome, contractId: string): string | undefined {
  if (outcome.anchorPending === true) return undefined;
  const receipt = outcome.admission.receipt;
  return outcome.anchorTx === undefined
    ? saveReceipt(receipt)
    : saveReceipt(receipt, { mode: "individual", contractId, tx: outcome.anchorTx });
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
        saved.push(
          saveReceipt(receipt, { mode: "batch", contractId, root: batch.root, proof, tx: batch.anchorTx }),
        );
      }
    } else {
      console.log(`  anclaje falló    : ${batch.anchorError ?? "desconocido"} (quedan pendientes)`);
    }
  }
  for (const path of saved) console.log(`  receipt          : ${path}`);
  return saved;
}
