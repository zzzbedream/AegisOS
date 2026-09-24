import { createHash } from "node:crypto";

import { assertSha256Hex, hashInDomain, PROOF_DOMAINS, type Sha256Hex } from "./hashing.js";
import { hashDeliveryReceipt } from "./records.js";
import type { DeliveryReceiptV1 } from "./types.js";

/**
 * Batched anchoring.
 *
 * Anchoring each micropayment on Soroban costs more than the payment itself,
 * so OK receipts are committed as one Merkle root per (buyer, seller) batch.
 * A receipt's inclusion is then proven off-chain against the anchored root.
 *
 * Two classic pitfalls are designed out:
 *   - Second preimage: leaves and inner nodes hash under different one-byte
 *     prefixes (0x00 / 0x01), so an inner node can never pass as a leaf.
 *   - Duplicated last leaf (Bitcoin CVE-2012-2459): an odd node is promoted to
 *     the next level unchanged instead of being paired with itself, so two
 *     different leaf lists cannot share a root.
 */

export const MAX_BATCH_LEAVES = 1_024;

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

export interface MerkleStep {
  readonly sibling: Sha256Hex;
  /** Where the sibling sits relative to the running hash. */
  readonly side: "left" | "right";
}

export interface MerkleProofV1 {
  readonly version: "1";
  readonly leaf: Sha256Hex;
  readonly index: number;
  readonly leafCount: number;
  readonly steps: readonly MerkleStep[];
  readonly root: Sha256Hex;
}

export class MerkleError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.name = "MerkleError";
    this.code = code;
  }
}

function sha256(...parts: readonly Buffer[]): Sha256Hex {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest("hex");
}

function hex(value: Sha256Hex): Buffer {
  return Buffer.from(value, "hex");
}

function hashNode(left: Sha256Hex, right: Sha256Hex): Sha256Hex {
  return sha256(NODE_PREFIX, hex(left), hex(right));
}

/**
 * The leaf for one receipt. It binds the whole signed receipt (through its
 * domain-separated hash) plus the fields the contract would have stored had
 * the receipt been anchored on its own, so a verifier can check them directly.
 */
export function batchLeafForReceipt(receipt: DeliveryReceiptV1): Sha256Hex {
  if (receipt.verdict !== "OK") {
    throw new MerkleError(
      "NOT_BATCHABLE",
      `Only OK receipts are batched; ${receipt.verdict} must be anchored individually.`,
    );
  }
  const body = hashInDomain(PROOF_DOMAINS.batchLeaf, {
    receiptHash: hashDeliveryReceipt(receipt),
    paymentHash: receipt.paymentHash,
    commitmentHash: receipt.commitmentHash,
    contentHash: receipt.contentHash,
    sellerId: receipt.sellerId,
    verdict: receipt.verdict,
  });
  return sha256(LEAF_PREFIX, hex(body));
}

function assertLeaves(leaves: readonly Sha256Hex[]): void {
  if (leaves.length === 0) {
    throw new MerkleError("EMPTY_BATCH", "A batch needs at least one leaf.");
  }
  if (leaves.length > MAX_BATCH_LEAVES) {
    throw new MerkleError("BATCH_TOO_LARGE", `A batch holds at most ${String(MAX_BATCH_LEAVES)} leaves.`);
  }
  leaves.forEach((leaf, i) => assertSha256Hex(leaf, `leaves[${String(i)}]`));
  if (new Set(leaves).size !== leaves.length) {
    throw new MerkleError("DUPLICATE_LEAF", "The same receipt appears twice in one batch.");
  }
}

/** Every level of the tree, leaves first, root last. */
function levels(leaves: readonly Sha256Hex[]): readonly (readonly Sha256Hex[])[] {
  const all: Sha256Hex[][] = [[...leaves]];
  let current: readonly Sha256Hex[] = leaves;
  while (current.length > 1) {
    const next: Sha256Hex[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i] as Sha256Hex;
      const right = current[i + 1];
      next.push(right === undefined ? left : hashNode(left, right));
    }
    all.push(next);
    current = next;
  }
  return all;
}

export function merkleRoot(leaves: readonly Sha256Hex[]): Sha256Hex {
  assertLeaves(leaves);
  const tree = levels(leaves);
  return (tree[tree.length - 1] as readonly Sha256Hex[])[0] as Sha256Hex;
}

export function merkleProof(leaves: readonly Sha256Hex[], index: number): MerkleProofV1 {
  assertLeaves(leaves);
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new MerkleError("BAD_INDEX", `Leaf index ${String(index)} is out of range.`);
  }
  const tree = levels(leaves);
  const steps: MerkleStep[] = [];
  let position = index;
  for (let depth = 0; depth < tree.length - 1; depth += 1) {
    const level = tree[depth] as readonly Sha256Hex[];
    const isRight = position % 2 === 1;
    const sibling = level[isRight ? position - 1 : position + 1];
    // A promoted odd node has no sibling at this level: no step.
    if (sibling !== undefined) {
      steps.push({ sibling, side: isRight ? "left" : "right" });
    }
    position = Math.floor(position / 2);
  }
  return Object.freeze({
    version: "1",
    leaf: leaves[index] as Sha256Hex,
    index,
    leafCount: leaves.length,
    steps: Object.freeze(steps),
    root: merkleRoot(leaves),
  });
}

/** Recompute the root from a leaf and its path. Pure; no trust in `proof.root`. */
export function rootFromProof(leaf: Sha256Hex, steps: readonly MerkleStep[]): Sha256Hex {
  assertSha256Hex(leaf, "leaf");
  return steps.reduce((running, step) => {
    assertSha256Hex(step.sibling, "sibling");
    return step.side === "left" ? hashNode(step.sibling, running) : hashNode(running, step.sibling);
  }, leaf);
}

/**
 * True when `receipt` is included under `root`. The leaf is recomputed from
 * the receipt itself — a proof carrying someone else's leaf does not help.
 */
export function verifyReceiptInclusion(
  receipt: DeliveryReceiptV1,
  proof: Pick<MerkleProofV1, "steps">,
  root: Sha256Hex,
): boolean {
  try {
    return rootFromProof(batchLeafForReceipt(receipt), proof.steps) === root;
  } catch {
    return false;
  }
}
