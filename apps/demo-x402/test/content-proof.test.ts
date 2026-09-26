import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { getIdentifierFromClaimInfo } from "@reclaimprotocol/attestor-core";
import { Wallet } from "ethers";

import { claimIdentifier, contentProofChecks, type ReclaimProofV1 } from "../src/content-proof.js";

const witness = Wallet.createRandom();
const stranger = Wallet.createRandom();
const commitmentHash = "ab".repeat(32);
const body = '{"network_passphrase":"Test SDF Network ; September 2015"}';
const contentHash = createHash("sha256").update(body, "utf8").digest("hex");

/** A proof shaped like zkFetch's, signed the way a Reclaim attestor signs. */
async function proofSignedBy(signer: Wallet, overrides: { body?: string; message?: string } = {}): Promise<ReclaimProofV1> {
  const claim = {
    provider: "http",
    parameters: JSON.stringify({ method: "GET", url: "https://horizon-testnet.stellar.org/" }),
    context: JSON.stringify({
      contextAddress: "0x0000000000000000000000000000000000000000",
      contextMessage: overrides.message ?? commitmentHash,
      extractedParameters: { body: overrides.body ?? body },
      providerHash: "0x01",
    }),
    owner: "0x00000000000000000000000000000000000000aa",
    timestampS: 1_790_000_000,
    epoch: 1,
  };
  const identifier = claimIdentifier(claim);
  const signData = [identifier, claim.owner.toLowerCase(), String(claim.timestampS), String(claim.epoch)].join("\n");
  return {
    identifier,
    claimData: { ...claim, identifier },
    signatures: [await signer.signMessage(signData)],
    witnesses: [{ id: signer.address.toLowerCase(), url: "wss://attestor.example" }],
    extractedParameterValues: { body: overrides.body ?? body },
  };
}

const expected = { commitmentHash, contentHash, canonicalization: "raw-bytes-v1" as const, trustedWitnesses: [witness.address] };
const failing = (checks: ReturnType<typeof contentProofChecks>) => checks.filter((c) => !c.pass).map((c) => c.name);

test("the claim identifier matches Reclaim's own computation", async () => {
  const proof = await proofSignedBy(witness);
  const { provider, parameters, context } = proof.claimData;
  assert.equal(claimIdentifier({ provider, parameters, context }), getIdentifierFromClaimInfo({ provider, parameters, context }));
});

test("a proof from a pinned witness, over our commitment and the receipt's content, verifies", async () => {
  assert.deepEqual(failing(contentProofChecks(await proofSignedBy(witness), expected)), []);
});

test("a witness we did not pin proves nothing, even with a valid signature", async () => {
  assert.deepEqual(failing(contentProofChecks(await proofSignedBy(stranger), expected)), ["signed by a pinned Reclaim witness"]);
});

test("a proof of different content does not back this receipt", async () => {
  const proof = await proofSignedBy(witness, { body: '{"network_passphrase":"Public Global Stellar Network"}' });
  assert.deepEqual(failing(contentProofChecks(proof, expected)), ["proven body is the receipt's content"]);
});

test("a proof made for another commitment cannot be reused", async () => {
  const proof = await proofSignedBy(witness, { message: "cd".repeat(32) });
  assert.deepEqual(failing(contentProofChecks(proof, expected)), ["proof is bound to this commitment"]);
});

test("a real zkFetch proof verifies against the witness published in deployments", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("./fixtures/reclaim-horizon-proof.json", import.meta.url), "utf8"),
  ) as { commitmentHash: string; proof: ReclaimProofV1 };
  const deployments = JSON.parse(
    readFileSync(new URL("../../../contracts/deployments/testnet.json", import.meta.url), "utf8"),
  ) as { reclaim: { witnesses: string[] } };
  const context = JSON.parse(fixture.proof.claimData.context) as { extractedParameters: { body: string } };
  const real = {
    commitmentHash: fixture.commitmentHash,
    contentHash: createHash("sha256").update(context.extractedParameters.body, "utf8").digest("hex"),
    canonicalization: "raw-bytes-v1" as const,
    trustedWitnesses: deployments.reclaim.witnesses,
  };
  assert.deepEqual(failing(contentProofChecks(fixture.proof, real)), []);

  const edited = { ...context, extractedParameters: { body: context.extractedParameters.body.replace("Test SDF", "Evil") } };
  const tampered = { ...fixture.proof, claimData: { ...fixture.proof.claimData, context: JSON.stringify(edited) } };
  assert.deepEqual(failing(contentProofChecks(tampered, real)), [
    "claim identifier recomputes",
    "signed by a pinned Reclaim witness",
    "proven body is the receipt's content",
  ]);
  assert.deepEqual(failing(contentProofChecks(fixture.proof, { ...real, commitmentHash: "00".repeat(32) })), [
    "proof is bound to this commitment",
  ]);
});

test("editing the claim after signing breaks the identifier and the signature", async () => {
  const proof = await proofSignedBy(witness);
  const edited = { ...proof, claimData: { ...proof.claimData, parameters: proof.claimData.parameters.replace("horizon", "evil") } };
  assert.ok(failing(contentProofChecks(edited, expected)).includes("claim identifier recomputes"));
  // The extracted value shown outside the signed context is ignored, not trusted.
  const swapped = { ...proof, extractedParameterValues: { body: "anything" } };
  assert.deepEqual(failing(contentProofChecks(swapped, expected)), []);
});
