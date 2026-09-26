/**
 * Check the landing's links against Stellar testnet itself:
 *
 *   npm run landing:check
 *
 * Every transaction linked on site/index.html must exist and have succeeded,
 * and every contract linked must be deployed. Reads public data only.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { rpc } from "@stellar/stellar-sdk";
import { TESTNET_RPC_URL, deployedWasmHash } from "../../../packages/x402/src/index.js";
import { describeErrorChain } from "./error-chain.js";

const HORIZON = "https://horizon-testnet.stellar.org";
const html = readFileSync(fileURLToPath(new URL("../../../site/index.html", import.meta.url)), "utf8");

async function main(): Promise<void> {
  const txs = [...new Set([...html.matchAll(/explorer\/testnet\/tx\/([0-9a-f]{64})/g)].map((m) => m[1] as string))];
  const contracts = [
    ...new Set([...html.matchAll(/explorer\/testnet\/contract\/(C[A-Z2-7]{55})/g)].map((m) => m[1] as string)),
  ];
  const server = new rpc.Server(TESTNET_RPC_URL);
  let failures = 0;

  for (const hash of txs) {
    const response = await fetch(`${HORIZON}/transactions/${hash}`);
    const body = response.ok ? ((await response.json()) as { successful?: boolean; created_at?: string }) : undefined;
    const pass = body?.successful === true;
    if (!pass) failures += 1;
    console.log(`  ${pass ? "PASS" : "FAIL"}  tx ${hash.slice(0, 12)}… ${pass ? `successful · ${body?.created_at ?? ""}` : `HTTP ${String(response.status)}`}`);
  }
  for (const id of contracts) {
    let detail: string;
    let pass: boolean;
    try {
      detail = `wasm ${(await deployedWasmHash(server, id)).slice(0, 16)}…`;
      pass = true;
    } catch (error: unknown) {
      detail = error instanceof Error ? error.message : String(error);
      pass = false;
    }
    if (!pass) failures += 1;
    console.log(`  ${pass ? "PASS" : "FAIL"}  contract ${id.slice(0, 8)}… ${detail}`);
  }
  console.log(failures === 0 ? `Landing: ${String(txs.length)} tx y ${String(contracts.length)} contratos verificados en testnet.` : `${String(failures)} enlace(s) fallaron.`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((error: unknown) => {
  console.error(describeErrorChain(error));
  process.exitCode = 1;
});
