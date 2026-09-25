import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Keypair } from "@stellar/stellar-sdk";

import { generateEd25519KeyPair } from "../../../packages/core/src/index.js";
import {
  batchLeafForReceipt,
  createDeliveryReceipt,
  merkleProof,
  merkleRoot,
  sellerIdFromAccount,
  type DeliveryVerdict,
} from "../../../packages/proof/src/index.js";
import type { AnchoredBatchV1, AnchoredDeliveryV1 } from "../../../packages/x402/src/index.js";
import {
  AttesterError,
  attesterPath,
  initAttester,
  loadAttester,
  publishedFrom,
  readPublishedAttester,
} from "../src/attester.js";
import {
  batchChecks,
  individualChecks,
  readReceiptFile,
  saveReceipt,
  signatureChecks,
} from "../src/receipt-check.js";

function scratch(t: { after: (fn: () => void) => void }): string {
  const dir = mkdtempSync(join(tmpdir(), "aegis-attester-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test("the attester is created once and loads back as the same key", (t) => {
  const path = join(scratch(t), "nested", "attester.json");

  const { keyPair, published } = initAttester(path);
  const loaded = loadAttester(path);

  assert.equal(loaded.publicKey, keyPair.publicKey);
  assert.equal(published.publicKey, keyPair.publicKey);
  assert.ok(!JSON.stringify(published).includes(keyPair.privateKey), "published half carries no secret");
  if (process.platform !== "win32") {
    assert.equal(statSync(path).mode & 0o777, 0o600);
  }
});

test("initialising twice is refused: rotating would orphan every old receipt", (t) => {
  const path = join(scratch(t), "attester.json");
  initAttester(path);
  assert.throws(() => initAttester(path), AttesterError);
});

test("a missing attester says how to create one", (t) => {
  assert.throws(() => loadAttester(join(scratch(t), "absent.json")), /attester:init/);
});

test("a file pairing our private key with a foreign public key is refused", (t) => {
  const path = join(scratch(t), "attester.json");
  const ours = generateEd25519KeyPair();
  const theirs = generateEd25519KeyPair();
  writeFileSync(path, JSON.stringify({ ...ours, publicKey: theirs.publicKey }));
  assert.throws(() => loadAttester(path), /does not match privateKey/);
});

test("a file whose keyId does not derive from its key is refused", (t) => {
  const path = join(scratch(t), "attester.json");
  writeFileSync(
    path,
    JSON.stringify({ ...generateEd25519KeyPair(), keyId: "ed25519:000000000000000000000000" }),
  );
  assert.throws(() => loadAttester(path), /keyId does not match/);
});

test("the attester path comes from the environment, with a gitignored default", () => {
  assert.equal(attesterPath({}), ".aegis/attester.json");
  assert.equal(
    attesterPath({ AEGIS_ATTESTER_SECRET_FILE: "/run/secrets/attester" }),
    "/run/secrets/attester",
  );
});

test("the published attester is read from the deployments file, or reported absent", () => {
  const published = publishedFrom(generateEd25519KeyPair());
  assert.deepEqual(readPublishedAttester({ contracts: {}, attester: published }), published);
  assert.equal(readPublishedAttester({ contracts: {} }), undefined);
  assert.equal(readPublishedAttester(null), undefined);
});

// ------------------------------------------------------ third-party check

const seller = Keypair.random();
const buyer = Keypair.random();
const attester = generateEd25519KeyPair();
const published = publishedFrom(attester);

function receipt(payment = "b", verdict: DeliveryVerdict = "TAINTED") {
  return createDeliveryReceipt(
    {
      version: "1",
      commitmentHash: "a".repeat(64),
      paymentHash: payment.repeat(64),
      sellerId: sellerIdFromAccount(seller.publicKey()),
      contentHash: "c".repeat(64),
      contentBytes: 64,
      contentCanonicalization: "json-canonical-v1",
      receivedAt: "2027-05-10T12:00:00.000Z",
      verdict,
      riskSignals: [],
      taintScore: verdict === "OK" ? 35 : 92,
      reasons: ["RISK_THRESHOLD_EXCEEDED"],
      assuranceTier: "T2",
      attesterId: `buyer:${buyer.publicKey()}`,
      attesterRole: "buyer",
    },
    attester,
  );
}

function anchored(overrides: Partial<AnchoredDeliveryV1> = {}): AnchoredDeliveryV1 {
  return {
    buyer: buyer.publicKey(),
    seller: seller.publicKey(),
    paymentHash: "b".repeat(64),
    commitmentHash: "a".repeat(64),
    contentHash: "c".repeat(64),
    verdict: "TAINTED",
    anchoredAt: 1_790_000_000,
    ...overrides,
  };
}

const allPass = (checks: readonly { pass: boolean }[]): boolean => checks.every((c) => c.pass);

test("a receipt verifies against the published key and the anchored record", () => {
  const r = receipt();
  assert.ok(allPass(signatureChecks(r, published)));
  assert.ok(allPass(individualChecks(r, anchored())));
});

test("a receipt signed by an unpublished key fails even though its signature is valid", () => {
  const other = publishedFrom(generateEd25519KeyPair());
  assert.ok(signatureChecks(receipt(), other).every((c) => !c.pass));
});

test("a receipt edited after signing fails the signature check", () => {
  const edited = { ...receipt(), verdict: "OK" as const };
  const signature = signatureChecks(edited, published).find((c) => c.name === "signature verifies");
  assert.equal(signature?.pass, false);
});

test("a receipt whose content hash differs from the chain is caught", () => {
  const content = individualChecks(receipt(), anchored({ contentHash: "d".repeat(64) })).find(
    (c) => c.name === "on-chain content hash matches",
  );
  assert.equal(content?.pass, false);
});

// ------------------------------------------------------------- batches

function batchOf(receipts: ReturnType<typeof receipt>[]) {
  const leaves = receipts.map(batchLeafForReceipt);
  const root = merkleRoot(leaves);
  const record: AnchoredBatchV1 = {
    buyer: buyer.publicKey(),
    seller: seller.publicKey(),
    root,
    count: receipts.length,
    anchoredAt: 1_790_000_000,
  };
  return { leaves, root, record };
}

test("a batched receipt proves its inclusion under the anchored root", () => {
  const receipts = ["1", "2", "3"].map((p) => receipt(p, "OK"));
  const { leaves, record } = batchOf(receipts);
  const checks = batchChecks(receipts[2] as ReturnType<typeof receipt>, merkleProof(leaves, 2), record);
  assert.ok(allPass(checks), JSON.stringify(checks.filter((c) => !c.pass)));
});

test("a batched receipt fails against a root that is not the anchored one", () => {
  const receipts = ["1", "2"].map((p) => receipt(p, "OK"));
  const { leaves, record } = batchOf(receipts);
  const other = { ...record, root: "e".repeat(64) };
  const inclusion = batchChecks(receipts[0] as ReturnType<typeof receipt>, merkleProof(leaves, 0), other).find(
    (c) => c.name === "inclusion proof reaches the on-chain root",
  );
  assert.equal(inclusion?.pass, false);
});

test("a receipt from another buyer cannot borrow someone else's batch", () => {
  const receipts = ["1", "2"].map((p) => receipt(p, "OK"));
  const { leaves, record } = batchOf(receipts);
  const foreign = { ...record, buyer: Keypair.random().publicKey() };
  const buyerCheck = batchChecks(receipts[0] as ReturnType<typeof receipt>, merkleProof(leaves, 0), foreign).find(
    (c) => c.name === "on-chain batch buyer matches the attester",
  );
  assert.equal(buyerCheck?.pass, false);
});

test("receipts are saved with their anchor and read back; bare legacy files still load", (t) => {
  const dir = scratch(t);
  const saved = receipt();
  const path = saveReceipt(saved, { anchor: { mode: "individual", contractId: "CTEST", tx: "f".repeat(64) } }, dir);
  assert.ok(path.endsWith(`${"b".repeat(64)}.json`));

  const file = readReceiptFile(JSON.parse(readFileSync(path, "utf8")) as unknown);
  assert.deepEqual(JSON.parse(JSON.stringify(file.receipt)), JSON.parse(JSON.stringify(saved)));
  assert.equal(file.anchor?.mode, "individual");

  const legacy = readReceiptFile(JSON.parse(JSON.stringify(saved)) as unknown);
  assert.equal(legacy.anchor, undefined);
  assert.equal(legacy.receipt.paymentHash, saved.paymentHash);
});
