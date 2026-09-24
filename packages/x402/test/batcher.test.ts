import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { Keypair } from "@stellar/stellar-sdk";
import { generateEd25519KeyPair } from "../../core/src/index.js";
import {
  MerkleError,
  createDeliveryReceipt,
  sellerIdFromAccount,
  verifyReceiptInclusion,
  type DeliveryVerdict,
  type SellerId,
} from "../../proof/src/index.js";
import { ReceiptBatcher, type AegisAnchorClient } from "../src/index.js";

const attester = generateEd25519KeyPair();
const buyer = Keypair.random();
const sellerA = sellerIdFromAccount(Keypair.random().publicKey());
const sellerB = sellerIdFromAccount(Keypair.random().publicKey());

function h(seed: string): string {
  return createHash("sha256").update(seed).digest("hex");
}

function receipt(n: number, sellerId: SellerId, verdict: DeliveryVerdict = "OK") {
  return createDeliveryReceipt(
    {
      version: "1",
      commitmentHash: h(`c:${String(n)}`),
      paymentHash: h(`p:${String(n)}`),
      sellerId,
      contentHash: h(`x:${String(n)}`),
      contentBytes: 10,
      contentCanonicalization: "json-canonical-v1",
      receivedAt: "2027-05-10T12:00:00.000Z",
      verdict,
      riskSignals: [],
      taintScore: 35,
      reasons: [],
      assuranceTier: "T2",
      attesterId: `buyer:${buyer.publicKey()}`,
      attesterRole: "buyer",
    },
    attester,
  );
}

interface Call {
  readonly sellerId: SellerId;
  readonly root: string;
  readonly count: number;
}

/** Only `anchorBatch` is used by the batcher; no network is reached. */
function fakeClient(fail = false): { client: AegisAnchorClient; calls: Call[] } {
  const calls: Call[] = [];
  const client = {
    async anchorBatch(input: Call) {
      calls.push(input);
      if (fail) throw new Error("rpc down");
      return { transactionHash: h(`tx:${input.root}`), explorerUrl: "" };
    },
  } as unknown as AegisAnchorClient;
  return { client, calls };
}

test("exceptions are refused: they are anchored on their own, never batched", () => {
  const batcher = new ReceiptBatcher();
  assert.throws(
    () => batcher.add(receipt(1, sellerA, "TAINTED")),
    (e: unknown) => e instanceof MerkleError && e.code === "NOT_BATCHABLE",
  );
  assert.equal(batcher.pendingCount, 0);
});

test("one transaction per seller, and every receipt proves into its root", async () => {
  const batcher = new ReceiptBatcher();
  [1, 2, 3].forEach((n) => batcher.add(receipt(n, sellerA)));
  [4, 5].forEach((n) => batcher.add(receipt(n, sellerB)));
  const { client, calls } = fakeClient();

  const flushed = await batcher.flush(client, buyer);

  assert.equal(calls.length, 2);
  assert.deepEqual(flushed.map((b) => [b.sellerId, b.count]), [[sellerA, 3], [sellerB, 2]]);
  for (const batch of flushed) {
    assert.ok(batch.anchorTx !== undefined);
    for (const { receipt: r, proof } of batch.entries) {
      assert.ok(verifyReceiptInclusion(r, proof, batch.root));
    }
  }
  assert.equal(batcher.pendingCount, 0);
});

test("a failed anchor keeps its receipts pending instead of dropping them", async () => {
  const batcher = new ReceiptBatcher();
  [1, 2].forEach((n) => batcher.add(receipt(n, sellerA)));

  const failed = await batcher.flush(fakeClient(true).client, buyer);
  assert.equal(failed[0]?.anchorError, "rpc down");
  assert.equal(batcher.pendingCount, 2);

  const retried = await batcher.flush(fakeClient().client, buyer);
  assert.equal(retried[0]?.count, 2);
  assert.equal(batcher.pendingCount, 0);
});

test("more receipts than one batch holds are split across transactions", async () => {
  const batcher = new ReceiptBatcher();
  for (let n = 0; n < 1_030; n += 1) batcher.add(receipt(n, sellerA));
  const { client, calls } = fakeClient();

  await batcher.flush(client, buyer);

  assert.deepEqual(calls.map((c) => c.count), [1_024, 6]);
});
