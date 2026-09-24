import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { generateEd25519KeyPair } from "../../core/src/index.js";
import {
  MAX_BATCH_LEAVES,
  MerkleError,
  batchLeafForReceipt,
  createDeliveryReceipt,
  merkleProof,
  merkleRoot,
  rootFromProof,
  verifyReceiptInclusion,
  type DeliveryReceiptV1,
  type DeliveryVerdict,
} from "../src/index.js";

const attester = generateEd25519KeyPair();
const SELLER = "stellar:GDARKECJYS4TXQ3AZOOKA4HCQ5AEJEPZBKQAUXQSDOCO5EEZ76F377WJ" as const;

function h(seed: string): string {
  return createHash("sha256").update(seed).digest("hex");
}

function receipt(n: number, verdict: DeliveryVerdict = "OK"): DeliveryReceiptV1 {
  return createDeliveryReceipt(
    {
      version: "1",
      commitmentHash: h(`commitment:${String(n)}`),
      paymentHash: h(`payment:${String(n)}`),
      sellerId: SELLER,
      contentHash: h(`content:${String(n)}`),
      contentBytes: 64,
      contentCanonicalization: "json-canonical-v1",
      receivedAt: "2027-05-10T12:00:00.000Z",
      verdict,
      riskSignals: [],
      taintScore: verdict === "OK" ? 35 : 90,
      reasons: [],
      assuranceTier: "T2",
      attesterId: "buyer:test",
      attesterRole: "buyer",
    },
    attester,
  );
}

function leaves(count: number): readonly string[] {
  return Array.from({ length: count }, (_, i) => h(`leaf:${String(i)}`));
}

test("a single-leaf tree has the leaf as its root and an empty path", () => {
  const [leaf] = leaves(1);
  assert.equal(merkleRoot([leaf as string]), leaf);
  assert.deepEqual(merkleProof([leaf as string], 0).steps, []);
});

test("every leaf proves into the root, for balanced and odd trees alike", () => {
  for (const size of [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33]) {
    const list = leaves(size);
    const root = merkleRoot(list);
    list.forEach((leaf, index) => {
      const proof = merkleProof(list, index);
      assert.equal(rootFromProof(leaf, proof.steps), root, `size ${String(size)} index ${String(index)}`);
    });
  }
});

test("a full batch of the maximum size still proves in about log2(n) steps", () => {
  const list = leaves(MAX_BATCH_LEAVES);
  const proof = merkleProof(list, 777);
  assert.equal(proof.steps.length, 10);
  assert.equal(rootFromProof(list[777] as string, proof.steps), merkleRoot(list));
});

test("a tampered sibling or a flipped side breaks the proof", () => {
  const list = leaves(8);
  const root = merkleRoot(list);
  const proof = merkleProof(list, 3);

  const tampered = proof.steps.map((step, i) => (i === 1 ? { ...step, sibling: h("evil") } : step));
  assert.notEqual(rootFromProof(list[3] as string, tampered), root);

  const flipped = proof.steps.map((step, i) =>
    i === 0 ? { ...step, side: step.side === "left" ? ("right" as const) : ("left" as const) } : step,
  );
  assert.notEqual(rootFromProof(list[3] as string, flipped), root);
});

test("an odd node is promoted, not duplicated: [a,b,c] and [a,b,c,c] differ (CVE-2012-2459)", () => {
  const [a, b, c] = leaves(3) as [string, string, string];
  // The Bitcoin construction pairs c with itself; ours must not coincide.
  const node = (l: string, r: string): string =>
    createHash("sha256").update(Buffer.from([0x01])).update(Buffer.from(l, "hex")).update(Buffer.from(r, "hex")).digest("hex");
  const bitcoinStyle = node(node(a, b), node(c, c));
  assert.notEqual(merkleRoot([a, b, c]), bitcoinStyle);
  assert.equal(merkleRoot([a, b, c]), node(node(a, b), c));
});

test("empty, oversized and duplicated batches are refused", () => {
  assert.throws(() => merkleRoot([]), (e: unknown) => e instanceof MerkleError && e.code === "EMPTY_BATCH");
  assert.throws(
    () => merkleRoot(leaves(MAX_BATCH_LEAVES + 1)),
    (e: unknown) => e instanceof MerkleError && e.code === "BATCH_TOO_LARGE",
  );
  const [a, b] = leaves(2) as [string, string];
  assert.throws(() => merkleRoot([a, b, a]), (e: unknown) => e instanceof MerkleError && e.code === "DUPLICATE_LEAF");
  assert.throws(() => merkleProof([a, b], 2), (e: unknown) => e instanceof MerkleError && e.code === "BAD_INDEX");
});

test("only OK receipts can be batched; exceptions stay individual", () => {
  assert.throws(
    () => batchLeafForReceipt(receipt(1, "TAINTED")),
    (e: unknown) => e instanceof MerkleError && e.code === "NOT_BATCHABLE",
  );
});

test("a receipt proves its inclusion; an edited or foreign receipt does not", () => {
  const batch = [receipt(1), receipt(2), receipt(3)];
  const list = batch.map(batchLeafForReceipt);
  const root = merkleRoot(list);
  const proof = merkleProof(list, 1);

  assert.equal(verifyReceiptInclusion(batch[1] as DeliveryReceiptV1, proof, root), true);

  const edited = { ...(batch[1] as DeliveryReceiptV1), contentHash: h("swapped") };
  assert.equal(verifyReceiptInclusion(edited, proof, root), false);
  assert.equal(verifyReceiptInclusion(receipt(9), proof, root), false);
  // Exceptions never verify as batched, even with a valid-looking path.
  assert.equal(verifyReceiptInclusion(receipt(2, "TAINTED"), proof, root), false);
});

test("a receipt leaf can never equal an inner node", () => {
  const list = [receipt(1), receipt(2)].map(batchLeafForReceipt);
  const inner = merkleRoot(list);
  // Claiming the inner node as a leaf needs a receipt whose 0x00-prefixed hash
  // equals a 0x01-prefixed one. Checked here for the obvious candidates.
  assert.ok(!list.includes(inner));
});
