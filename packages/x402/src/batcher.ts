import type { Keypair } from "@stellar/stellar-sdk";

import {
  MAX_BATCH_LEAVES,
  batchLeafForReceipt,
  merkleProof,
  merkleRoot,
  type DeliveryReceiptV1,
  type MerkleProofV1,
  type SellerId,
} from "../../proof/src/index.js";
import type { AegisAnchorClient } from "./anchor-client.js";

export interface BatchedReceipt {
  readonly receipt: DeliveryReceiptV1;
  readonly proof: MerkleProofV1;
}

export interface FlushedBatch {
  readonly sellerId: SellerId;
  readonly root: string;
  readonly count: number;
  readonly entries: readonly BatchedReceipt[];
  readonly anchorTx?: string;
  /** Set when the anchor failed; the entries are handed back, not dropped. */
  readonly anchorError?: string;
}

/**
 * Collects OK receipts and anchors them as one Merkle root per seller.
 *
 * Only OK receipts are accepted: an exception has to be visible per payment
 * and at once, so it is anchored on its own and never waits in a batch.
 * Anchoring stays evidence, not enforcement — every verdict was already
 * applied locally before a receipt reaches here.
 */
export class ReceiptBatcher {
  #pending: ReadonlyMap<SellerId, readonly DeliveryReceiptV1[]> = new Map();

  public add(receipt: DeliveryReceiptV1): void {
    // Computes the leaf, which also rejects anything but OK.
    batchLeafForReceipt(receipt);
    const current = this.#pending.get(receipt.sellerId) ?? [];
    this.#pending = new Map([...this.#pending, [receipt.sellerId, [...current, receipt]]]);
  }

  public get pendingCount(): number {
    let count = 0;
    for (const receipts of this.#pending.values()) count += receipts.length;
    return count;
  }

  /**
   * Build and anchor every pending batch. Receipts whose anchor fails stay
   * pending so a later flush can retry them.
   */
  public async flush(client: AegisAnchorClient, buyer: Keypair): Promise<readonly FlushedBatch[]> {
    const pending = this.#pending;
    this.#pending = new Map();

    const flushed: FlushedBatch[] = [];
    let retry: ReadonlyMap<SellerId, readonly DeliveryReceiptV1[]> = new Map();

    for (const [sellerId, receipts] of pending) {
      for (let start = 0; start < receipts.length; start += MAX_BATCH_LEAVES) {
        const chunk = receipts.slice(start, start + MAX_BATCH_LEAVES);
        const leaves = chunk.map(batchLeafForReceipt);
        const root = merkleRoot(leaves);
        const entries = chunk.map((receipt, index) => ({ receipt, proof: merkleProof(leaves, index) }));
        try {
          const anchored = await client.anchorBatch({ sellerId, root, count: chunk.length }, buyer);
          flushed.push({ sellerId, root, count: chunk.length, entries, anchorTx: anchored.transactionHash });
        } catch (error: unknown) {
          const anchorError = error instanceof Error ? error.message : String(error);
          flushed.push({ sellerId, root, count: chunk.length, entries, anchorError });
          retry = new Map([...retry, [sellerId, [...(retry.get(sellerId) ?? []), ...chunk]]]);
        }
      }
    }

    for (const [sellerId, receipts] of retry) {
      this.#pending = new Map([
        ...this.#pending,
        [sellerId, [...receipts, ...(this.#pending.get(sellerId) ?? [])]],
      ]);
    }
    return flushed;
  }
}
