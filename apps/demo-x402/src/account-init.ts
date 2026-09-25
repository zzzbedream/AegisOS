/**
 * Create the AegisOS smart account the demos pay from.
 *
 *   AEGIS_BUYER_SECRET=S... npm run account:init
 *
 * - commitment authority key: .aegis/authority.json (lives only in the signer
 *   process at run time; the agent never loads it)
 * - owner key (recovery):     .aegis/owner.json
 * - session key:              the buyer key, which also pays fees
 *
 * The account is created by the published registry's factory, which deploys
 * only the account wasm it was constructed with — that is what lets the
 * registry, and any verifier, trust the account's notarization. Then keeps it
 * alive, funds it with USDC, and publishes the PUBLIC parts.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Contract, Keypair, nativeToScVal, rpc } from "@stellar/stellar-sdk";
import {
  AegisAnchorClient,
  extendAccountTtl,
  rawFromSpki,
  submitSorobanOperation,
} from "../../../packages/x402/src/index.js";
import { initAttester, loadAttester } from "./attester.js";
import { describeErrorChain } from "./error-chain.js";
import { ACCOUNT_FILE, AUTHORITY_FILE, OWNER_FILE } from "./smart-account-config.js";

const USDC_SAC = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const PASSPHRASE = "Test SDF Network ; September 2015";
const RPC_URL = "https://soroban-testnet.stellar.org";
const DEPLOYMENTS = fileURLToPath(new URL("../../../contracts/deployments/testnet.json", import.meta.url));
const FUND_ATOMIC = BigInt(process.env["AEGIS_ACCOUNT_FUND_ATOMIC"] ?? "5000000");

function keyFile(path: string) {
  return existsSync(path) ? loadAttester(path) : initAttester(path).keyPair;
}

async function main(): Promise<void> {
  if (existsSync(ACCOUNT_FILE)) {
    throw new Error(`${ACCOUNT_FILE} already exists. Move it aside to create a new account.`);
  }
  const secret = process.env["AEGIS_BUYER_SECRET"];
  if (secret === undefined || secret.length === 0) throw new Error("Missing AEGIS_BUYER_SECRET.");
  const session = Keypair.fromSecret(secret);
  const server = new rpc.Server(RPC_URL);
  const deployments = JSON.parse(readFileSync(DEPLOYMENTS, "utf8")) as Record<string, unknown> & {
    contracts: Record<string, { contractId: string; accountWasmHash?: string }>;
  };
  const registry = deployments.contracts["aegis-proof"];
  if (registry?.accountWasmHash === undefined) {
    throw new Error("The published registry has no account factory (needs aegis-proof v3).");
  }

  const authority = keyFile(AUTHORITY_FILE);
  const owner = keyFile(OWNER_FILE);

  const client = new AegisAnchorClient({ contractId: registry.contractId });
  const { address, transactionHash } = await client.createAccount(
    {
      owner: rawFromSpki(owner.publicKey),
      authority: rawFromSpki(authority.publicKey),
      session: session.rawPublicKey(),
    },
    [USDC_SAC],
    session,
  );
  await extendAccountTtl(server, PASSPHRASE, session, address);
  await submitSorobanOperation({
    server,
    passphrase: PASSPHRASE,
    source: session,
    operation: new Contract(USDC_SAC).call(
      "transfer",
      nativeToScVal(session.publicKey(), { type: "address" }),
      nativeToScVal(address, { type: "address" }),
      nativeToScVal(FUND_ATOMIC, { type: "i128" }),
    ),
  });

  writeFileSync(ACCOUNT_FILE, `${JSON.stringify({ address, createdAt: new Date().toISOString() }, null, 2)}\n`, "utf8");
  writeFileSync(
    DEPLOYMENTS,
    `${JSON.stringify(
      {
        ...deployments,
        account: {
          address,
          wasmHash: registry.accountWasmHash,
          registry: registry.contractId,
          session: session.publicKey(),
          authority: { keyId: authority.keyId, publicKey: authority.publicKey },
          createTx: transactionHash,
        },
      },
      null,
      2,
    )}\n`,
    "utf8",
  );

  console.log(`cuenta         : ${address}`);
  console.log(`creada por     : registro ${registry.contractId} (factory)`);
  console.log(`wasm           : ${registry.accountWasmHash}`);
  console.log(`fondeada con   : ${(Number(FUND_ATOMIC) / 1e7).toFixed(7)} USDC`);
  console.log(`autoridad      : ${authority.keyId} (${AUTHORITY_FILE}, solo para el proceso signer)`);
  console.log(`create         : https://stellar.expert/explorer/testnet/tx/${transactionHash}`);
}

main().catch((error: unknown) => {
  console.error(describeErrorChain(error));
  process.exitCode = 1;
});
