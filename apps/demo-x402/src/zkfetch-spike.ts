/**
 * Spike S3: can a Reclaim zkFetch proof bind a response body to its origin?
 *
 *   npx tsx --env-file=.env apps/demo-x402/src/zkfetch-spike.ts [url]
 *
 * Fetches `url` through a Reclaim attestor, captures the whole body in the
 * signed claim, binds a commitment hash through the claim context, and saves
 * the proof to .aegis/zkfetch-spike.json for offline verification tests.
 * Credentials come from .env and are never printed.
 */
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";

import { ReclaimClient } from "@reclaimprotocol/zk-fetch";

const DEFAULT_URL = "https://horizon-testnet.stellar.org/";
const OUT = ".aegis/zkfetch-spike.json";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`Missing ${name} (set it in .env).`);
  return value;
}

async function main(): Promise<void> {
  const url = process.argv[2] ?? DEFAULT_URL;
  const commitmentHash = createHash("sha256").update(`spike:${Date.now()}`).digest("hex");
  const client = new ReclaimClient(requireEnv("AEGIS_RECLAIM_APP_ID"), requireEnv("AEGIS_RECLAIM_APP_SECRET"));

  console.log(`url        : ${url}`);
  const started = Date.now();
  const proof = await client.zkFetch(
    url,
    {
      method: "GET",
      context: { contextAddress: "0x0000000000000000000000000000000000000000", contextMessage: commitmentHash },
    },
    { responseMatches: [{ type: "regex", value: "(?<body>[\\s\\S]*)" }] },
  );
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  if (proof === undefined) throw new Error(`zkFetch returned no proof after ${seconds}s.`);

  const body = String((proof.extractedParameterValues as { body?: unknown }).body ?? "");
  mkdirSync(".aegis", { recursive: true });
  writeFileSync(OUT, `${JSON.stringify({ url, commitmentHash, proof }, null, 2)}\n`, "utf8");

  console.log(`tiempo     : ${seconds} s`);
  console.log(`witnesses  : ${proof.witnesses.map((w) => `${w.id} ${w.url}`).join(", ")}`);
  console.log(`firmas     : ${String(proof.signatures.length)}`);
  console.log(`identifier : ${proof.identifier}`);
  console.log(`cuerpo     : ${String(body.length)} bytes, sha256 ${createHash("sha256").update(body, "utf8").digest("hex")}`);
  console.log(`context    : ${proof.claimData.context.slice(0, 160)}…`);
  console.log(`guardado   : ${OUT}`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? `${error.name}: ${error.message}` : String(error));
  process.exitCode = 1;
});
