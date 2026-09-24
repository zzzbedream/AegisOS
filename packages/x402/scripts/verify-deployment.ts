/**
 * Deployment gate: prove the deployed aegis-proof contract works end to end.
 *
 *   AEGIS_BUYER_SECRET=S... AEGIS_SELLER_ACCOUNT=G... npm run verify:deployment
 *
 * Anchors a fresh TAINTED attestation, reads it back with get_delivery, checks
 * the seller aggregate moved by exactly one, and confirms the same payment hash
 * cannot be anchored twice. Replaces the Git Bash script, which failed under
 * WSL; this needs only Node and the TS client the demos already use.
 *
 * Re-runnable: hashes derive from a nonce, so runs never collide.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { Keypair } from "@stellar/stellar-sdk";
import { generateEd25519KeyPair } from "../../core/src/index.js";
import { createDeliveryReceipt, sellerIdFromAccount } from "../../proof/src/index.js";
import { AegisAnchorClient } from "../src/index.js";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`Missing ${name}.`);
  return value;
}

function hex32(seed: string): string {
  return createHash("sha256").update(seed).digest("hex");
}

let failures = 0;
function check(step: string, pass: boolean, detail: string): void {
  if (!pass) failures += 1;
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${step} — ${detail}`);
}

async function main(): Promise<void> {
  const deployments = JSON.parse(
    readFileSync(new URL("../../../contracts/deployments/testnet.json", import.meta.url), "utf8"),
  ) as { rpcUrl?: string; contracts: Record<string, { contractId: string }> };
  const contractId = deployments.contracts["aegis-proof"]?.contractId;
  if (contractId === undefined) throw new Error("aegis-proof contract id not found.");

  const buyer = Keypair.fromSecret(requireEnv("AEGIS_BUYER_SECRET"));
  const sellerAccount = requireEnv("AEGIS_SELLER_ACCOUNT");
  const sellerId = sellerIdFromAccount(sellerAccount);
  const nonce = process.argv[2] ?? String(Date.now());
  const client = new AegisAnchorClient({
    contractId,
    ...(deployments.rpcUrl === undefined ? {} : { rpcUrl: deployments.rpcUrl }),
  });

  const receipt = createDeliveryReceipt(
    {
      version: "1",
      commitmentHash: hex32(`verify:commitment:${nonce}`),
      paymentHash: hex32(`verify:payment:${nonce}`),
      sellerId,
      contentHash: hex32(`verify:content:${nonce}`),
      contentBytes: 1,
      contentCanonicalization: "raw-bytes-v1",
      receivedAt: new Date().toISOString(),
      verdict: "TAINTED",
      riskSignals: [],
      taintScore: 90,
      reasons: ["RISK_THRESHOLD_EXCEEDED"],
      assuranceTier: "T2",
      attesterId: `buyer:${buyer.publicKey()}`,
      attesterRole: "buyer",
    },
    // The contract never sees this signature; an ephemeral key is enough here.
    generateEd25519KeyPair(),
  );

  console.log(`contrato : ${contractId}`);
  console.log(`comprador: ${buyer.publicKey()}`);
  console.log(`vendedor : ${sellerAccount}`);
  console.log(`pago     : ${receipt.paymentHash}`);

  const before = await client.sellerScore(sellerId, buyer);

  const anchored = await client.anchorDelivery(receipt, buyer);
  check("1/4 anchor_delivery", true, anchored.explorerUrl);

  const record = await client.getDelivery(receipt.paymentHash, buyer.publicKey());
  check(
    "2/4 get_delivery",
    record !== undefined &&
      record.contentHash === receipt.contentHash &&
      record.commitmentHash === receipt.commitmentHash &&
      record.verdict === "TAINTED" &&
      record.buyer === buyer.publicKey() &&
      record.anchoredAt > 0,
    record === undefined ? "no record returned" : `verdict ${record.verdict}, ledger time ${String(record.anchoredAt)}`,
  );

  const after = await client.sellerScore(sellerId, buyer);
  check(
    "3/4 seller_score",
    after.tainted === before.tainted + 1 && after.total === before.total + 1,
    `tainted ${String(before.tainted)}→${String(after.tainted)}, total ${String(before.total)}→${String(after.total)}`,
  );

  let duplicateRejected = false;
  let reason = "the duplicate was accepted: history is rewritable";
  try {
    await client.anchorDelivery({ ...receipt, verdict: "OK" }, buyer);
  } catch (error: unknown) {
    duplicateRejected = true;
    reason = (error instanceof Error ? error.message : String(error)).split("\n")[0] ?? "rejected";
  }
  check("4/4 duplicate payment hash rejected", duplicateRejected, reason.slice(0, 120));

  console.log(failures === 0 ? `PASS: contrato ${contractId} verificado en testnet` : `${String(failures)} comprobación(es) fallaron`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
