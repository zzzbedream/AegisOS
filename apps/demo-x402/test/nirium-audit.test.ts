import assert from "node:assert/strict";
import test from "node:test";

import { Keypair } from "@stellar/stellar-sdk";

import { auditMessage, buildAnchorRequest, sha256Hex, verifyAnchorFile, type NiriumAnchorFileV1 } from "../src/nirium-audit.js";

const signer = Keypair.random();
const receiptBytes = Buffer.from('{"version":"1","receipt":{"verdict":"OK"}}\n');

function anchorFile(bytes: Uint8Array, key = signer): NiriumAnchorFileV1 {
  const request = buildAnchorRequest({ receiptBytes: bytes, signer: key, tag: "niriumtober", txHash: "6c".repeat(32) });
  return {
    version: "1",
    node: "https://nirium-agent.fly.dev/api/audit/log",
    receiptFile: "receipt.json",
    receiptSha256: request.hash,
    request,
    response: { cid: "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku" },
  };
}

test("signs the Nirium domain message over the receipt file's sha-256", () => {
  const request = buildAnchorRequest({ receiptBytes, signer, tag: "niriumtober" });

  assert.equal(request.hash, sha256Hex(receiptBytes));
  assert.equal(auditMessage(request.hash).toString(), `nirium-audit-v1:${request.hash}`);
  assert.ok(signer.verify(auditMessage(request.hash), Buffer.from(request.agent.signature, "base64")));
  assert.equal(request.agent.key, signer.publicKey());
  assert.equal("txHash" in request, false);
});

test("rejects a hash that is not lowercase sha-256 hex", () => {
  assert.throws(() => auditMessage("sha-256:abc"), /Not a lowercase sha-256 hex/);
});

test("an anchor file verifies against the exact receipt bytes", () => {
  const checks = verifyAnchorFile(anchorFile(receiptBytes), receiptBytes);

  assert.deepEqual(checks.map((c) => c.pass), [true, true, true]);
});

test("a changed receipt no longer matches its anchor", () => {
  const changed = Buffer.from(receiptBytes.toString().replace("OK", "TAINTED"));

  const [hashCheck] = verifyAnchorFile(anchorFile(receiptBytes), changed);

  assert.equal(hashCheck?.pass, false);
});

test("a signature by another key is rejected", () => {
  const file = anchorFile(receiptBytes);
  const forged: NiriumAnchorFileV1 = { ...file, request: { ...file.request, agent: { ...file.request.agent, key: Keypair.random().publicKey() } } };

  const [, signatureCheck] = verifyAnchorFile(forged, receiptBytes);

  assert.equal(signatureCheck?.pass, false);
});
