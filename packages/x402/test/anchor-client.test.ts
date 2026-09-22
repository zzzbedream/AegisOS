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
import { AegisAnchorClient, AnchorClientError } from "../src/index.js";

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
