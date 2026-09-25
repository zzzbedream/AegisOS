/**
 * Spike S2 diagnostics: where does a smart-account payment's fee go?
 * Builds the same payment as spike-smart-account.ts and prints the simulated
 * resources instead of submitting anything. Costs nothing.
 */
import { createHash, createPrivateKey, randomBytes, sign } from "node:crypto";
import { readFileSync } from "node:fs";

import { Keypair, rpc, Transaction } from "@stellar/stellar-sdk";
import { buildSmartAccountPayment, onChainCommitmentDigest } from "../src/index.js";

const USDC_SAC = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const PASSPHRASE = "Test SDF Network ; September 2015";
const RPC_URL = "https://soroban-testnet.stellar.org";

async function main(): Promise<void> {
  const session = Keypair.fromSecret(process.env["AEGIS_BUYER_SECRET"] ?? "");
  const seller = process.env["AEGIS_SELLER_ACCOUNT"] ?? "";
  const account = process.env["AEGIS_ACCOUNT"] ?? "";
  const attester = JSON.parse(readFileSync(".aegis/attester.json", "utf8")) as { privateKey: string };
  const commitment = {
    commitmentHash: createHash("sha256").update(randomBytes(32)).digest("hex"),
    seller, asset: USDC_SAC, maxAmount: 10_000n,
    expiresAt: BigInt(Math.floor(Date.now() / 1000) + 600),
  };
  const key = createPrivateKey({ key: Buffer.from(attester.privateKey, "base64url"), format: "der", type: "pkcs8" });
  const { transaction } = await buildSmartAccountPayment({
    account, payTo: seller, asset: USDC_SAC, amount: 10_000n, maxTimeoutSeconds: 120, commitment,
    authoritySignature: sign(null, onChainCommitmentDigest(account, commitment), key),
    signAuthPreimage: async (preimage) => Buffer.from(session.sign(createHash("sha256").update(Buffer.from(preimage, "base64")).digest())),
    rpcUrl: RPC_URL, networkPassphrase: PASSPHRASE,
  });

  const server = new rpc.Server(RPC_URL);
  const tx = new Transaction(transaction, PASSPHRASE);
  const sim = await server.simulateTransaction(tx);
  if (!rpc.Api.isSimulationSuccess(sim)) throw new Error(JSON.stringify(sim));
  const data = sim.transactionData.build();
  const res = data.resources();
  const fp = res.footprint();
  console.log(`minResourceFee : ${sim.minResourceFee}`);
  console.log(`instructions   : ${String(res.instructions())}`);
  console.log(`diskReadBytes  : ${String(res.diskReadBytes())}  writeBytes: ${String(res.writeBytes())}`);
  console.log(`resourceFee    : ${data.resourceFee().toString()}`);
  console.log(`footprint RO   : ${String(fp.readOnly().length)}  RW: ${String(fp.readWrite().length)}`);
  for (const k of fp.readWrite()) console.log(`  RW ${k.switch().name} ${k.switch().name === "contractData" ? k.contractData().durability().name + " " + k.contractData().key().switch().name : ""}`);
  for (const k of fp.readOnly()) console.log(`  RO ${k.switch().name}`);
  console.log(`cost           : ${JSON.stringify(sim.cost)}`);
  console.log(`stateChanges   : ${String(sim.stateChanges?.length ?? 0)}`);
}

main().catch((e: unknown) => { console.error(e); process.exitCode = 1; });
