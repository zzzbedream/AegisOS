/**
 * Anchor an AegisOS receipt file in Nirium Audit Trail (testnet), or verify that anchor:
 *
 *   AEGIS_BUYER_SECRET=... npm run nirium:anchor -- <receipt.json> [settlement tx]
 *   npm run nirium:anchor -- --verify <receipt.json>
 *
 * Writes `nirium-anchor.json` next to the receipt. Verifying reads the receipt bytes, the
 * anchor file and the record Nirium pinned to IPFS; it needs no key.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

import { Keypair } from "@stellar/stellar-sdk";
import { describeErrorChain } from "./error-chain.js";
import { NIRIUM_TESTNET_URL, buildAnchorRequest, sha256Hex, verifyAnchorFile, type NiriumAnchorFileV1 } from "./nirium-audit.js";

const TAG = "niriumtober";
const IPFS_GATEWAY = "https://ipfs.io/ipfs/";

function anchorPath(receiptPath: string): string {
  return join(dirname(receiptPath), "nirium-anchor.json");
}

async function anchor(receiptPath: string, txHash: string | undefined): Promise<void> {
  const secret = process.env["AEGIS_BUYER_SECRET"];
  if (secret === undefined || secret === "") throw new Error("AEGIS_BUYER_SECRET is required to sign the attestation.");
  const receiptBytes = readFileSync(receiptPath);
  const request = buildAnchorRequest({ receiptBytes, signer: Keypair.fromSecret(secret), tag: TAG, ...(txHash === undefined ? {} : { txHash }) });

  const response = await fetch(`${NIRIUM_TESTNET_URL}/api/audit/log`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
  });
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok || typeof body["cid"] !== "string") {
    throw new Error(`Nirium refused the anchor [${String(response.status)}]: ${JSON.stringify(body)}`);
  }
  const file: NiriumAnchorFileV1 = {
    version: "1",
    node: `${NIRIUM_TESTNET_URL}/api/audit/log`,
    receiptFile: basename(receiptPath),
    receiptSha256: request.hash,
    request,
    response: body as unknown as NiriumAnchorFileV1["response"],
  };
  writeFileSync(anchorPath(receiptPath), `${JSON.stringify(file, null, 2)}\n`);
  console.log(`  CID       : ${file.response.cid}`);
  console.log(`  attested  : ${request.agent.key}`);
  console.log(`  receipt   : sha-256 ${request.hash}`);
  console.log(`  saved     : ${anchorPath(receiptPath)}`);
}

async function verify(receiptPath: string): Promise<boolean> {
  const receiptBytes = readFileSync(receiptPath);
  const file = JSON.parse(readFileSync(anchorPath(receiptPath), "utf8")) as NiriumAnchorFileV1;
  const checks = [...verifyAnchorFile(file, receiptBytes)];

  // The pinned record must name the same hash; IPFS content is addressed by the CID itself.
  const pinnedUrl = file.response.gatewayUrl ?? `${IPFS_GATEWAY}${file.response.cid}`;
  let pinned = "";
  try {
    const response = await fetch(pinnedUrl, { signal: AbortSignal.timeout(30_000) });
    pinned = response.ok ? await response.text() : `HTTP ${String(response.status)}`;
  } catch (error) {
    pinned = describeErrorChain(error);
  }
  checks.push({ name: "IPFS record names this receipt's hash", pass: pinned.includes(sha256Hex(receiptBytes)), detail: pinnedUrl });

  for (const check of checks) console.log(`  ${check.pass ? "PASS" : "FAIL"}  ${check.name} — ${check.detail}`);
  return checks.every((check) => check.pass);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args[0] === "--verify" && args[1] !== undefined) {
    if (!(await verify(args[1]))) process.exitCode = 1;
    else console.log("Anclaje en Nirium verificado.");
    return;
  }
  if (args[0] === undefined) throw new Error("Usage: nirium:anchor -- <receipt.json> [settlement tx] | --verify <receipt.json>");
  await anchor(args[0], args[1]);
}

main().catch((error: unknown) => {
  console.error(describeErrorChain(error));
  process.exitCode = 1;
});
