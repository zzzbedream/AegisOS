import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Keypair, StrKey } from "@stellar/stellar-sdk";

import { generateEd25519KeyPair } from "../../../packages/core/src/index.js";
import { createDeliveryReceipt, merkleRoot, sellerIdFromAccount, type DeliveryVerdict } from "../../../packages/proof/src/index.js";
import { paymentChainLink, rangeLeafHash } from "../../../packages/x402/src/index.js";
import { appendPaymentLog } from "../src/notarization.js";
import { buildPendingRange } from "../src/range.js";
import { saveReceipt } from "../src/receipt-check.js";

const account = StrKey.encodeContract(randomBytes(32));
const seller = Keypair.random().publicKey();
const attester = generateEd25519KeyPair();

function scratch(t: { after: (fn: () => void) => void }) {
  const root = mkdtempSync(join(tmpdir(), "aegis-range-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { receipts: join(root, "receipts"), log: join(root, "log") };
}

/** Notarize `count` payments into the log; save receipts for `withReceipt`. */
function payments(
  dirs: { receipts: string; log: string },
  count: number,
  withReceipt: (seq: number) => boolean,
  verdict: (seq: number) => DeliveryVerdict = () => "OK",
): void {
  let head = "00".repeat(32);
  for (let seq = 1; seq <= count; seq += 1) {
    const commitmentHash = randomBytes(32).toString("hex");
    const next = paymentChainLink({ previous: head, seq: BigInt(seq), commitmentHash, seller, amount: 10_000n });
    const notarization = {
      account, seq: String(seq), previousHead: head, chainHead: next, commitmentHash, seller, amount: "10000", consistent: true,
    };
    appendPaymentLog(notarization, dirs.log);
    head = next;
    if (!withReceipt(seq)) continue;
    const receipt = createDeliveryReceipt(
      {
        version: "1",
        commitmentHash,
        paymentHash: randomBytes(32).toString("hex"),
        sellerId: sellerIdFromAccount(seller),
        contentHash: randomBytes(32).toString("hex"),
        contentBytes: 1,
        contentCanonicalization: "raw-bytes-v1",
        receivedAt: "2027-05-10T12:00:00.000Z",
        verdict: verdict(seq),
        riskSignals: [],
        taintScore: 35,
        reasons: [],
        assuranceTier: "T2",
        attesterId: `buyer:${account}`,
        attesterRole: "buyer",
      },
      attester,
    );
    saveReceipt(receipt, { notarization }, dirs.receipts);
  }
}

test("everything after the checkpoint becomes leaves, in seq order, with their verdicts", (t) => {
  const dirs = scratch(t);
  payments(dirs, 3, () => true, (seq) => (seq === 2 ? "TAINTED" : "OK"));
  const range = buildPendingRange(account, 0n, 3n, dirs);

  assert.ok(range !== undefined);
  assert.equal(range.fromSeq, 1n);
  assert.deepEqual(range.leaves.map((l) => [l.seq, l.verdict]), [[1n, "OK"], [2n, "TAINTED"], [3n, "OK"]]);
  assert.equal(range.tail.length, 0);
  assert.equal(range.leafHashes[1], rangeLeafHash(range.leaves[1] as Parameters<typeof rangeLeafHash>[0]));
  assert.match(merkleRoot([...range.leafHashes]), /^[a-f0-9]{64}$/);
});

test("the range starts right after the checkpoint", (t) => {
  const dirs = scratch(t);
  payments(dirs, 4, () => true);
  const range = buildPendingRange(account, 2n, 4n, dirs);
  assert.deepEqual(range?.leaves.map((l) => l.seq), [3n, 4n]);
  assert.equal(buildPendingRange(account, 4n, 4n, dirs), undefined, "nothing pending");
});

test("a payment without a receipt ends the leaves; it and the rest ride in the tail", (t) => {
  const dirs = scratch(t);
  payments(dirs, 4, (seq) => seq !== 3);
  const range = buildPendingRange(account, 0n, 4n, dirs);
  assert.deepEqual(range?.leaves.map((l) => l.seq), [1n, 2n]);
  assert.equal(range?.tail.length, 2, "seq 3 and 4 are verified but not counted yet");
});

test("no receipt for the first pending payment means no range at all", (t) => {
  const dirs = scratch(t);
  payments(dirs, 2, (seq) => seq !== 1);
  assert.throws(() => buildPendingRange(account, 0n, 2n, dirs), /No receipt for payment seq 1/);
});

test("a log missing payments is refused rather than guessed", (t) => {
  const dirs = scratch(t);
  payments(dirs, 2, () => true);
  assert.throws(() => buildPendingRange(account, 0n, 3n, dirs), /has 2 of the 3 payments/);
});
