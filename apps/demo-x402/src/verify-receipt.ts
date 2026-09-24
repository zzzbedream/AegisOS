/**
 * Verify a delivery receipt the way a third party would: public inputs only.
 *
 *   npm run verify:receipt -- .aegis/receipts/<paymentHash>.json
 *
 * Checks the signature against the attester key published next to the contract
 * ID, then compares the receipt with the record anchored on Soroban. Needs no
 * secret; set AEGIS_SKIP_CHAIN=1 to check the signature offline.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import type { DeliveryReceiptV1 } from "../../../packages/proof/src/index.js";
import { AegisAnchorClient, type AnchoredDeliveryV1 } from "../../../packages/x402/src/index.js";
import { readPublishedAttester } from "./attester.js";
import { describeErrorChain } from "./error-chain.js";
import { checkReceipt } from "./receipt-check.js";

const DEPLOYMENTS = fileURLToPath(
  new URL("../../../contracts/deployments/testnet.json", import.meta.url),
);
const SKIP_CHAIN = process.env["AEGIS_SKIP_CHAIN"] === "1";

interface Deployments {
  readonly rpcUrl?: string;
  readonly contracts: Record<string, { readonly contractId: string; readonly deployer?: string }>;
}

async function main(): Promise<void> {
  const file = process.argv[2];
  if (file === undefined || file.length === 0) {
    throw new Error("Usage: npm run verify:receipt -- <receipt.json>");
  }
  const receipt = JSON.parse(readFileSync(file, "utf8")) as DeliveryReceiptV1;
  const deploymentsRaw = JSON.parse(readFileSync(DEPLOYMENTS, "utf8")) as unknown;
  const published = readPublishedAttester(deploymentsRaw);
  if (published === undefined) {
    throw new Error("No attester published in contracts/deployments/testnet.json. Run: npm run attester:init");
  }
  const deployments = deploymentsRaw as Deployments;
  const contract = deployments.contracts["aegis-proof"];

  let anchored: AnchoredDeliveryV1 | undefined;
  let chainNote = "omitido (AEGIS_SKIP_CHAIN=1)";
  if (!SKIP_CHAIN && contract !== undefined && contract.deployer !== undefined) {
    const client = new AegisAnchorClient({
      contractId: contract.contractId,
      ...(deployments.rpcUrl === undefined ? {} : { rpcUrl: deployments.rpcUrl }),
    });
    // Any existing account can be the simulation source; the deployer is public.
    anchored = await client.getDelivery(receipt.paymentHash, contract.deployer);
    chainNote = anchored === undefined ? "NO hay registro anclado para este pago" : `anclado en ledger time ${String(anchored.anchoredAt)}`;
  }

  const checks = checkReceipt(receipt, published, anchored);
  console.log("AegisProof · verificación de receipt con datos públicos");
  console.log(`  receipt  : ${file}`);
  console.log(`  veredicto: ${receipt.verdict} (atestación del comprador, no prueba contra el vendedor)`);
  console.log(`  cadena   : ${chainNote}`);
  for (const check of checks) {
    console.log(`  ${check.pass ? "PASS" : "FAIL"}  ${check.name} — ${check.detail}`);
  }
  const anchoredMissing = !SKIP_CHAIN && anchored === undefined;
  const ok = checks.every((check) => check.pass) && !anchoredMissing;
  console.log(ok ? "Receipt verificado." : "El receipt NO verifica.");
  process.exitCode = ok ? 0 : 1;
}

main().catch((error: unknown) => {
  console.error(describeErrorChain(error));
  process.exitCode = 1;
});
