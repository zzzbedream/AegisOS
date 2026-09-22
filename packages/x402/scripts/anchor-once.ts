/**
 * Anchor one delivery attestation from TypeScript and read the seller aggregate back.
 *
 * Proves the off-chain proof layer reaches the on-chain anchor without a CLI
 * step in between, which is what lets the demo be a single command.
 *
 *   AEGIS_BUYER_SECRET=... AEGIS_SELLER_ACCOUNT=G... \
 *   npx tsx packages/x402/scripts/anchor-once.ts [OK|TAINTED|MISMATCH|NOT_DELIVERED]
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

import { Keypair } from "@stellar/stellar-sdk";
import { generateEd25519KeyPair } from "../../core/src/index.js";
import {
  createDeliveryReceipt,
  sellerIdFromAccount,
  type DeliveryVerdict,
} from "../../proof/src/index.js";
import { AegisAnchorClient } from "../src/index.js";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`Missing ${name}.`);
  return value;
}

const VERDICTS: readonly DeliveryVerdict[] = ["OK", "TAINTED", "MISMATCH", "NOT_DELIVERED"];

function parseVerdict(raw: string | undefined): DeliveryVerdict {
  if (raw === undefined) return "TAINTED";
  const upper = raw.toUpperCase() as DeliveryVerdict;
  if (!VERDICTS.includes(upper)) {
    throw new Error(`Verdict must be one of ${VERDICTS.join(", ")}.`);
  }
  return upper;
}

function hex32(seed: string): string {
  return createHash("sha256").update(seed).digest("hex");
}

async function main(): Promise<void> {
  const deployments = JSON.parse(
    readFileSync(new URL("../../../contracts/deployments/testnet.json", import.meta.url), "utf8"),
  ) as { contracts: Record<string, { contractId: string }> };
  const contractId = deployments.contracts["aegis-proof"]?.contractId;
  if (contractId === undefined) throw new Error("aegis-proof contract id not found.");

  const buyer = Keypair.fromSecret(requireEnv("AEGIS_BUYER_SECRET"));
  const sellerId = sellerIdFromAccount(requireEnv("AEGIS_SELLER_ACCOUNT"));
  const verdict = parseVerdict(process.argv[2]);
  const nonce = String(Date.now());

  const receipt = createDeliveryReceipt(
    {
      version: "1",
      commitmentHash: hex32(`commitment:${nonce}`),
      paymentHash: hex32(`payment:${nonce}`),
      sellerId,
      contentHash: hex32(`content:${nonce}`),
      contentBytes: 128,
      contentCanonicalization: "json-canonical-v1",
      receivedAt: new Date().toISOString(),
      verdict,
      riskSignals: [],
      taintScore: verdict === "TAINTED" ? 92 : 12,
      reasons: verdict === "TAINTED" ? ["RISK_THRESHOLD_EXCEEDED"] : [],
      assuranceTier: "T2",
      attesterId: `buyer:${buyer.publicKey()}`,
      attesterRole: "buyer",
    },
    generateEd25519KeyPair("key:buyer-attester"),
  );

  console.log(`contract : ${contractId}`);
  console.log(`buyer    : ${buyer.publicKey()}`);
  console.log(`seller   : ${sellerId}`);
  console.log(`verdict  : ${verdict}`);
  console.log(`payment  : ${receipt.paymentHash}`);

  const client = new AegisAnchorClient({ contractId });

  console.log("\nanchoring…");
  const anchored = await client.anchorDelivery(receipt, buyer);
  console.log(`  ANCHORED  ${anchored.explorerUrl}`);

  console.log("\nreading seller_score…");
  const score = await client.sellerScore(sellerId, buyer);
  console.log(`  ${JSON.stringify(score)}`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? `${error.name}: ${error.message}` : error);
  process.exitCode = 1;
});
