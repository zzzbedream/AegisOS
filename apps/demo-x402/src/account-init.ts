/**
 * Create the AegisOS smart account the demos pay from.
 *
 *   AEGIS_BUYER_SECRET=S... npm run account:init
 *
 * - commitment authority key: .aegis/authority.json (lives only in the signer
 *   process at run time; the agent never loads it)
 * - owner key (recovery):     .aegis/owner.json
 * - session key:              the buyer key, which also pays fees
 * Then deploys the account pointing at the published registry, keeps it
 * alive, funds it with USDC, and publishes the PUBLIC parts to
 * contracts/deployments/testnet.json.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Contract, Keypair, nativeToScVal, rpc } from "@stellar/stellar-sdk";
import {
  deployAccount,
  extendAccountTtl,
  rawFromSpki,
  submitSorobanOperation,
  uploadWasm,
} from "../../../packages/x402/src/index.js";
import { initAttester, loadAttester } from "./attester.js";
import { describeErrorChain } from "./error-chain.js";
import { ACCOUNT_FILE, AUTHORITY_FILE, OWNER_FILE } from "./smart-account-config.js";

const USDC_SAC = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const PASSPHRASE = "Test SDF Network ; September 2015";
const RPC_URL = "https://soroban-testnet.stellar.org";
const WASM = fileURLToPath(new URL("../../../contracts/target/wasm32v1-none/release/aegis_account.wasm", import.meta.url));
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
    contracts: Record<string, { contractId: string }>;
    accountWasm?: { wasmHash: string };
  };
  const registry = deployments.contracts["aegis-proof"]?.contractId;
  if (registry === undefined) throw new Error("No aegis-proof registry published.");

  const authority = keyFile(AUTHORITY_FILE);
  const owner = keyFile(OWNER_FILE);

  let wasmHash: string;
  let wasmBytes: number | undefined;
  if (existsSync(WASM)) {
    const wasm = readFileSync(WASM);
    wasmHash = await uploadWasm(server, PASSPHRASE, session, wasm);
    wasmBytes = wasm.length;
  } else if (deployments.accountWasm !== undefined) {
    wasmHash = deployments.accountWasm.wasmHash;
  } else {
    throw new Error("No account wasm: run `stellar contract build` in contracts/ first.");
  }

  const { address, transactionHash } = await deployAccount(server, PASSPHRASE, session, wasmHash, {
    owner: rawFromSpki(owner.publicKey),
    authority: rawFromSpki(authority.publicKey),
    session: session.rawPublicKey(),
    allowedAssets: [USDC_SAC],
    registry,
  });
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
  const published = {
    ...deployments,
    ...(wasmBytes === undefined ? {} : { accountWasm: { wasmHash, wasmBytes, deployedAt: new Date().toISOString().slice(0, 10) } }),
    account: {
      address,
      wasmHash,
      registry,
      session: session.publicKey(),
      authority: { keyId: authority.keyId, publicKey: authority.publicKey },
      deployTx: transactionHash,
    },
  };
  writeFileSync(DEPLOYMENTS, `${JSON.stringify(published, null, 2)}\n`, "utf8");

  console.log(`cuenta         : ${address}`);
  console.log(`wasm           : ${wasmHash}`);
  console.log(`registro       : ${registry}`);
  console.log(`fondeada con   : ${(Number(FUND_ATOMIC) / 1e7).toFixed(7)} USDC`);
  console.log(`autoridad      : ${authority.keyId} (${AUTHORITY_FILE}, solo para el proceso signer)`);
  console.log(`publicado en   : contracts/deployments/testnet.json`);
  console.log(`deploy         : https://stellar.expert/explorer/testnet/tx/${transactionHash}`);
}

main().catch((error: unknown) => {
  console.error(describeErrorChain(error));
  process.exitCode = 1;
});
