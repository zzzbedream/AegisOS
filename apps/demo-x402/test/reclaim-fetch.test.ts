import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { contentProofChecks, provenResponse, type ReclaimProofV1 } from "../src/content-proof.js";
import { reclaimPaidFetch, type ZkFetcher } from "../src/reclaim-fetch.js";
import { readReceiptFile, saveReceipt } from "../src/receipt-check.js";

const credentials = { appId: "0x" + "1".repeat(40), appSecret: "0x" + "2".repeat(64) };
const paymentHeaders = { "PAYMENT-SIGNATURE": "eyJzaWduZWQiOiJwYXltZW50In0=" };
const commitmentHash = "ab".repeat(32);

/** Records what zkFetch was asked, and answers with a canned proven response. */
function fakeClient(captured: string | undefined): ZkFetcher & { calls: unknown[][] } {
  const calls: unknown[][] = [];
  return {
    calls,
    async zkFetch(...args: unknown[]) {
      calls.push(args);
      if (captured === undefined) return undefined;
      return {
        identifier: "0x00",
        claimData: {
          provider: "http", parameters: "{}", owner: "0x00", timestampS: 0, epoch: 1, identifier: "0x00",
          context: JSON.stringify({ contextMessage: commitmentHash, extractedParameters: { body: captured } }),
        },
        signatures: [],
        witnesses: [],
      };
    },
  };
}

const ok = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nPayment-Response: eyJ0eCI6MX0=\r\n\r\n{"quote":1}';

test("the payment signature travels only in the private headers, and the proof names the commitment", async () => {
  const client = fakeClient(ok);
  await reclaimPaidFetch(credentials, client)("https://seller.example/x", paymentHeaders, commitmentHash);

  assert.equal(client.calls.length, 1, "one call");
  const [url, publicOptions, secretOptions, retries] = client.calls[0] as [string, unknown, { headers: unknown }, number];
  assert.equal(url, "https://seller.example/x");
  assert.equal(retries, 1, "never resend a payment");
  assert.deepEqual(secretOptions.headers, paymentHeaders);
  assert.ok(!JSON.stringify(publicOptions).includes("PAYMENT-SIGNATURE"), "public options never see the payment");
  assert.equal((publicOptions as { context: { contextMessage: string } }).context.contextMessage, commitmentHash);
});

test("the agent receives the body without headers, the proven headers, and the proof", async () => {
  const response = await reclaimPaidFetch(credentials, fakeClient(ok))("https://s", paymentHeaders, commitmentHash);
  assert.equal(response.ok, true);
  assert.equal(new TextDecoder().decode(response.body), '{"quote":1}');
  assert.equal(response.header("payment-response"), "eyJ0eCI6MX0=");
  assert.equal(response.header("content-type"), "application/json");
  assert.equal(response.contentProof?.kind, "reclaim-zkfetch-v1");
});

test("a proven error is reported as not ok, and a missing proof is an error", async () => {
  const refused = await reclaimPaidFetch(credentials, fakeClient("HTTP/1.1 402 Payment Required\r\n\r\n{}"))(
    "https://s", paymentHeaders, commitmentHash,
  );
  assert.equal(refused.ok, false);
  await assert.rejects(reclaimPaidFetch(credentials, fakeClient(undefined))("https://s", paymentHeaders, commitmentHash), /no proof/);
});

test("the real paid Bazaar proof verifies, and the seller itself acknowledges our payment in it", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("./fixtures/reclaim-bazaar-paid-proof.json", import.meta.url), "utf8"),
  ) as {
    receipt: { commitmentHash: string; contentHash: string; contentCanonicalization: "json-canonical-v1" };
    settlementTx: string;
    payer: string;
    proof: ReclaimProofV1;
  };
  const deployments = JSON.parse(
    readFileSync(new URL("../../../contracts/deployments/testnet.json", import.meta.url), "utf8"),
  ) as { reclaim: { witnesses: string[] } };

  const checks = contentProofChecks(fixture.proof, {
    commitmentHash: fixture.receipt.commitmentHash,
    contentHash: fixture.receipt.contentHash,
    canonicalization: fixture.receipt.contentCanonicalization,
    trustedWitnesses: deployments.reclaim.witnesses,
  });
  assert.deepEqual(checks.filter((c) => !c.pass).map((c) => c.name), []);

  // The seller's PAYMENT-RESPONSE is inside the signed response: its own word,
  // over TLS, that this account paid in this transaction.
  const header = provenResponse(fixture.proof)?.header("payment-response") ?? "";
  const settlement = JSON.parse(Buffer.from(header, "base64").toString("utf8")) as {
    success: boolean; payer: string; transaction: string;
  };
  assert.deepEqual(
    { success: settlement.success, payer: settlement.payer, transaction: settlement.transaction },
    { success: true, payer: fixture.payer, transaction: fixture.settlementTx },
  );
});

test("a receipt file keeps its content proof through save and read", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "aegis-proof-file-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const fixture = JSON.parse(
    readFileSync(new URL("./fixtures/reclaim-bazaar-paid-proof.json", import.meta.url), "utf8"),
  ) as { proof: ReclaimProofV1 };
  const receipt = { paymentHash: "cd".repeat(32) } as Parameters<typeof saveReceipt>[0];

  const path = saveReceipt(receipt, { contentProof: { kind: "reclaim-zkfetch-v1", proof: fixture.proof } }, dir);
  const file = readReceiptFile(JSON.parse(readFileSync(path, "utf8")) as unknown);
  assert.equal(file.contentProof?.proof.identifier, fixture.proof.identifier);
});
