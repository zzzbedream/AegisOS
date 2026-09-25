import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Keypair, StrKey } from "@stellar/stellar-sdk";
import { randomBytes } from "node:crypto";

import { generateEd25519KeyPair } from "../../../packages/core/src/index.js";
import { createDeliveryReceipt, sellerIdFromAccount } from "../../../packages/proof/src/index.js";
import { paymentChainLink } from "../../../packages/x402/src/index.js";
import type { PaymentNotarization } from "../src/agent.js";
import {
  appendPaymentLog,
  notarizationChecks,
  readPaymentLog,
  replayPaymentLog,
  type PaymentLogEntry,
} from "../src/notarization.js";

const ZERO = "00".repeat(32);
const account = StrKey.encodeContract(randomBytes(32));
const seller = Keypair.random().publicKey();

function chain(count: number): PaymentLogEntry[] {
  const entries: PaymentLogEntry[] = [];
  let head = ZERO;
  for (let i = 1; i <= count; i += 1) {
    const commitmentHash = String(i % 10).repeat(64);
    const next = paymentChainLink({ previous: head, seq: BigInt(i), commitmentHash, seller, amount: 10_000n });
    entries.push({ seq: String(i), previousHead: head, chainHead: next, commitmentHash, seller, amount: "10000" });
    head = next;
  }
  return entries;
}

test("an honest log replays to the head, link by link", () => {
  const log = chain(4);
  const replay = replayPaymentLog(log);
  assert.equal(replay.ok, true);
  assert.equal(replay.seq, 4n);
  assert.equal(replay.head, log[3]?.chainHead);
});

test("a dropped payment is a gap", () => {
  const log = chain(3);
  const replay = replayPaymentLog([log[0] as PaymentLogEntry, log[2] as PaymentLogEntry]);
  assert.equal(replay.ok, false);
  assert.match(replay.error ?? "", /gap/);
});

test("an edited amount, seller or commitment breaks the chain", () => {
  for (const edit of [{ amount: "10001" }, { seller: Keypair.random().publicKey() }, { commitmentHash: "f".repeat(64) }]) {
    const log = chain(3);
    const tampered = log.map((e, i) => (i === 1 ? { ...e, ...edit } : e));
    assert.equal(replayPaymentLog(tampered).ok, false, JSON.stringify(edit));
  }
});

test("the log is appended in seq order and de-duplicated", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "aegis-log-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const [one, two] = chain(2) as [PaymentLogEntry, PaymentLogEntry];
  appendPaymentLog({ ...two, account, consistent: true }, dir);
  appendPaymentLog({ ...one, account, consistent: true }, dir);
  appendPaymentLog({ ...one, account, consistent: true }, dir);
  assert.deepEqual(readPaymentLog(account, dir).map((e) => e.seq), ["1", "2"]);
});

test("a receipt verifies only when its payment is a link of a chain that reaches the on-chain head", () => {
  const log = chain(2);
  const second = log[1] as PaymentLogEntry;
  const receipt = createDeliveryReceipt(
    {
      version: "1",
      commitmentHash: second.commitmentHash,
      paymentHash: "b".repeat(64),
      sellerId: sellerIdFromAccount(seller),
      contentHash: "c".repeat(64),
      contentBytes: 1,
      contentCanonicalization: "raw-bytes-v1",
      receivedAt: "2027-05-10T12:00:00.000Z",
      verdict: "OK",
      riskSignals: [],
      taintScore: 35,
      reasons: [],
      assuranceTier: "T2",
      attesterId: `buyer:${account}`,
      attesterRole: "buyer",
    },
    generateEd25519KeyPair(),
  );
  const n: PaymentNotarization = { ...second, account, consistent: true };
  const evidence = {
    deployedWasm: "a".repeat(64),
    publishedWasm: "a".repeat(64),
    log,
    onChainHead: { seq: 2n, chainHead: second.chainHead },
  };
  assert.ok(notarizationChecks(receipt, n, evidence).every((c) => c.pass));

  const wrongWasm = notarizationChecks(receipt, n, { ...evidence, deployedWasm: "b".repeat(64) });
  assert.equal(wrongWasm.find((c) => c.name.startsWith("account runs"))?.pass, false);

  // The chain moved on (a third payment the log does not show): the replay no
  // longer lands on the head, so the log is incomplete and the check fails.
  const stale = notarizationChecks(receipt, n, { ...evidence, onChainHead: { seq: 3n, chainHead: "e".repeat(64) } });
  assert.equal(stale.find((c) => c.name.startsWith("payment log"))?.pass, false);
});
