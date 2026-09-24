import assert from "node:assert/strict";
import test from "node:test";

import { Keypair } from "@stellar/stellar-sdk";
import { generateEd25519KeyPair } from "../../core/src/index.js";
import {
  createDeliveryReceipt,
  sellerIdFromAccount,
  type DeliveryReceiptV1,
  type DeliveryVerdict,
} from "../../proof/src/index.js";
import {
  AegisAnchorClient,
  AnchorClientError,
  decodeBatchRecord,
  decodeDeliveryRecord,
} from "../src/index.js";

// A real deployed id, so construction is realistic; no test here reaches the
// network — every assertion is about validation that happens BEFORE submit.
const CONTRACT_ID = "CBG2DFZBHC3MEBN4UIVIVVNZX4YGI6TMRVRIK3TD4CVFKHMIKDXIJXZV";

const buyer = Keypair.random();
const seller = Keypair.random();
const attester = generateEd25519KeyPair("key:attester");

function receipt(overrides: Partial<DeliveryReceiptV1> = {}): DeliveryReceiptV1 {
  return createDeliveryReceipt(
    {
      version: "1",
      commitmentHash: "a".repeat(64),
      paymentHash: "b".repeat(64),
      sellerId: sellerIdFromAccount(seller.publicKey()),
      contentHash: "c".repeat(64),
      contentBytes: 64,
      contentCanonicalization: "json-canonical-v1",
      receivedAt: "2027-05-10T12:00:00.000Z",
      verdict: "TAINTED" as DeliveryVerdict,
      riskSignals: [],
      taintScore: 92,
      reasons: ["RISK_THRESHOLD_EXCEEDED"],
      assuranceTier: "T2",
      attesterId: "buyer:test",
      attesterRole: "buyer",
      ...overrides,
    },
    attester,
  );
}

function client(): AegisAnchorClient {
  return new AegisAnchorClient({ contractId: CONTRACT_ID });
}

test("a zero hash is refused locally instead of burning a transaction", async () => {
  // The contract rejects zero hashes. Learning that on-chain costs a fee and
  // returns an opaque Error(Contract, #2).
  await assert.rejects(
    () => client().anchorDelivery(receipt({ contentHash: "0".repeat(64) }), buyer),
    (error: unknown) => error instanceof AnchorClientError && error.code === "ZERO_HASH",
  );
});

// Hash format is enforced one layer earlier: a receipt carrying a malformed
// hash cannot be constructed at all. The anchor client's own check is the
// second line, reachable only for a receipt built by other means — which is why
// the zero-hash case above still matters: "0"*64 is valid hex, so it passes the
// receipt and is caught here.
test("a malformed hash cannot even be put into a receipt", () => {
  assert.throws(() => receipt({ paymentHash: "NOTHEX" }), /64-hex/);
});

test("an uppercase hash is refused: the internal format is bare lowercase hex", () => {
  assert.throws(() => receipt({ commitmentHash: "A".repeat(64) }), /64-hex/);
});

test("self-dealing is refused locally", async () => {
  const selfReceipt = receipt({ sellerId: sellerIdFromAccount(buyer.publicKey()) });

  await assert.rejects(
    () => client().anchorDelivery(selfReceipt, buyer),
    (error: unknown) => error instanceof AnchorClientError && error.code === "SELF_DEALING",
  );
});

test("a non-stellar seller id is refused before anything is built", async () => {
  const bad = { ...receipt(), sellerId: "seller-good" } as unknown as DeliveryReceiptV1;

  await assert.rejects(() => client().anchorDelivery(bad, buyer));
});

// ------------------------------------------------------------ get_delivery

function nativeRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    buyer: buyer.publicKey(),
    seller: seller.publicKey(),
    payment_hash: Buffer.from("b".repeat(64), "hex"),
    commitment_hash: Buffer.from("a".repeat(64), "hex"),
    content_hash: Buffer.from("c".repeat(64), "hex"),
    verdict: ["Tainted"],
    anchored_at: 1_790_000_000n,
    ...overrides,
  };
}

test("a missing delivery decodes as undefined, the contract None", () => {
  assert.equal(decodeDeliveryRecord(undefined), undefined);
  assert.equal(decodeDeliveryRecord(null), undefined);
});

test("an anchored record decodes into our own formats", () => {
  assert.deepEqual(decodeDeliveryRecord(nativeRecord()), {
    buyer: buyer.publicKey(),
    seller: seller.publicKey(),
    paymentHash: "b".repeat(64),
    commitmentHash: "a".repeat(64),
    contentHash: "c".repeat(64),
    verdict: "TAINTED",
    anchoredAt: 1_790_000_000,
  });
});

test("a record with an unknown verdict or a short hash is refused, not guessed", () => {
  assert.throws(() => decodeDeliveryRecord(nativeRecord({ verdict: ["Maybe"] })), AnchorClientError);
  assert.throws(
    () => decodeDeliveryRecord(nativeRecord({ content_hash: Buffer.alloc(31) })),
    AnchorClientError,
  );
});

// ------------------------------------------------------------- batches

test("a batch record decodes into our own formats", () => {
  assert.deepEqual(
    decodeBatchRecord({
      buyer: buyer.publicKey(),
      seller: seller.publicKey(),
      root: Buffer.from("d".repeat(64), "hex"),
      count: 12,
      anchored_at: 1_790_000_000n,
    }),
    { buyer: buyer.publicKey(), seller: seller.publicKey(), root: "d".repeat(64), count: 12, anchoredAt: 1_790_000_000 },
  );
  assert.equal(decodeBatchRecord(undefined), undefined);
  assert.throws(
    () => decodeBatchRecord({ buyer: buyer.publicKey(), seller: seller.publicKey(), root: Buffer.alloc(32, 1), count: 0 }),
    AnchorClientError,
  );
});

test("a batch that is empty, oversized or self-dealing is refused before any network call", async () => {
  const client = new AegisAnchorClient({ contractId: CONTRACT_ID });
  const sellerId = sellerIdFromAccount(seller.publicKey());
  const root = "d".repeat(64);
  for (const count of [0, 1_025, 1.5]) {
    await assert.rejects(
      () => client.anchorBatch({ sellerId, root, count }, buyer),
      (e: unknown) => e instanceof AnchorClientError && e.code === "BAD_BATCH_COUNT",
    );
  }
  await assert.rejects(
    () => client.anchorBatch({ sellerId: sellerIdFromAccount(buyer.publicKey()), root, count: 1 }, buyer),
    (e: unknown) => e instanceof AnchorClientError && e.code === "SELF_DEALING",
  );
});
