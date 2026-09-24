import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Keypair } from "@stellar/stellar-sdk";

import { generateEd25519KeyPair } from "../../../packages/core/src/index.js";
import { createDeliveryReceipt, sellerIdFromAccount } from "../../../packages/proof/src/index.js";
import type { AnchoredDeliveryV1 } from "../../../packages/x402/src/index.js";
import {
  AttesterError,
  attesterPath,
  initAttester,
  loadAttester,
  publishedFrom,
  readPublishedAttester,
} from "../src/attester.js";
import { checkReceipt, saveReceipt } from "../src/receipt-check.js";

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

function receipt() {
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
      verdict: "TAINTED",
      riskSignals: [],
      taintScore: 92,
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

test("a receipt verifies against the published key and the anchored record", () => {
  const checks = checkReceipt(receipt(), published, anchored());
  assert.ok(checks.every((c) => c.pass), JSON.stringify(checks.filter((c) => !c.pass)));
  assert.equal(checks.length, 7);
});

test("a receipt signed by an unpublished key fails even though its signature is valid", () => {
  const other = publishedFrom(generateEd25519KeyPair());
  const checks = checkReceipt(receipt(), other);
  assert.ok(checks.every((c) => !c.pass));
});

test("a receipt edited after signing fails the signature check", () => {
  const edited = { ...receipt(), verdict: "OK" as const };
  const signature = checkReceipt(edited, published).find((c) => c.name === "signature verifies");
  assert.equal(signature?.pass, false);
});

test("a receipt whose content hash differs from the chain is caught", () => {
  const checks = checkReceipt(receipt(), published, anchored({ contentHash: "d".repeat(64) }));
  const content = checks.find((c) => c.name === "on-chain content hash matches");
  assert.equal(content?.pass, false);
});

test("receipts are saved under their payment hash, as public data", (t) => {
  const dir = scratch(t);
  const saved = receipt();
  const path = saveReceipt(saved, dir);
  assert.ok(path.endsWith(`${"b".repeat(64)}.json`));
  assert.deepEqual(JSON.parse(readFileSync(path, "utf8")), JSON.parse(JSON.stringify(saved)));
});
