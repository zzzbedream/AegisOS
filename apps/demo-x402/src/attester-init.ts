/**
 * Create the buyer attester once and publish its public key.
 *
 *   npm run attester:init
 *
 * Writes the key pair to AEGIS_ATTESTER_SECRET_FILE (default .aegis/attester.json,
 * gitignored) and adds ONLY the public half to contracts/deployments/testnet.json.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { attesterPath, initAttester } from "./attester.js";

const DEPLOYMENTS = fileURLToPath(
  new URL("../../../contracts/deployments/testnet.json", import.meta.url),
);

function main(): void {
  const path = attesterPath();
  const { published } = initAttester(path);

  const deployments = JSON.parse(readFileSync(DEPLOYMENTS, "utf8")) as Record<string, unknown>;
  writeFileSync(DEPLOYMENTS, `${JSON.stringify({ ...deployments, attester: published }, null, 2)}\n`, "utf8");

  console.log(`attester creado     : ${path} (privado, gitignored)`);
  console.log(`clave publicada en  : contracts/deployments/testnet.json`);
  console.log(`keyId               : ${published.keyId}`);
}

try {
  main();
} catch (error: unknown) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
