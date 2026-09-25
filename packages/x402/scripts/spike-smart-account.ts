/**
 * Spike S1/S2: can an AegisOS smart account pay x402 through a public
 * facilitator, and does the payment stay under its fee ceiling?
 *
 *   AEGIS_BUYER_SECRET=S... AEGIS_SELLER_ACCOUNT=G... AEGIS_ACCOUNT=C... \
 *   npx tsx packages/x402/scripts/spike-smart-account.ts [facilitatorUrl]
 *
 * Also proves, for free, that a commitment signed by the wrong authority is
 * refused by the account in simulation, before any facilitator is involved.
 */
import { createHash, createPrivateKey, randomBytes, sign } from "node:crypto";
import { readFileSync } from "node:fs";

import { Keypair } from "@stellar/stellar-sdk";
import { generateEd25519KeyPair } from "../../core/src/index.js";
import { buildSmartAccountPayment, onChainCommitmentDigest, type OnChainCommitmentV1 } from "../src/index.js";

const USDC_SAC = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const NETWORK = "stellar:testnet";
const PASSPHRASE = "Test SDF Network ; September 2015";
const RPC_URL = "https://soroban-testnet.stellar.org";
const FACILITATOR = process.argv[2] ?? "https://www.x402.org/facilitator";
const AMOUNT = 10_000n;
const FEE_CEILING_STROOPS = 50_000;

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`Missing ${name}.`);
  return value;
}

function signWith(privateKeyPkcs8: string, message: Buffer): Buffer {
  const key = createPrivateKey({ key: Buffer.from(privateKeyPkcs8, "base64url"), format: "der", type: "pkcs8" });
  return sign(null, message, key);
}

async function post(path: string, body: unknown): Promise<{ status: number; json: unknown }> {
  const response = await fetch(`${FACILITATOR}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body, (_k, v: unknown) => (typeof v === "bigint" ? v.toString() : v)),
  });
  return { status: response.status, json: (await response.json().catch(() => null)) as unknown };
}

async function main(): Promise<void> {
  const session = Keypair.fromSecret(requireEnv("AEGIS_BUYER_SECRET"));
  const seller = requireEnv("AEGIS_SELLER_ACCOUNT");
  const account = requireEnv("AEGIS_ACCOUNT");
  const attester = JSON.parse(readFileSync(".aegis/attester.json", "utf8")) as { privateKey: string };

  const supported = (await (await fetch(`${FACILITATOR}/supported`)).json()) as {
    kinds?: { scheme?: string; network?: string; extra?: Record<string, unknown> }[];
  };
  const kind = (supported.kinds ?? []).find((k) => k.scheme === "exact" && k.network === NETWORK);
  if (kind === undefined) throw new Error(`Facilitator does not support exact/${NETWORK}.`);

  const commitment: OnChainCommitmentV1 = {
    commitmentHash: createHash("sha256").update(randomBytes(32)).digest("hex"),
    seller,
    asset: USDC_SAC,
    maxAmount: AMOUNT,
    expiresAt: BigInt(Math.floor(Date.now() / 1000) + 600),
  };
  const digest = onChainCommitmentDigest(commitment);
  const base = {
    account, payTo: seller, asset: USDC_SAC, amount: AMOUNT, maxTimeoutSeconds: 120, commitment,
    signPayload: async (payload: Buffer) => Buffer.from(session.sign(payload)),
    rpcUrl: RPC_URL, networkPassphrase: PASSPHRASE,
  };

  console.log(`cuenta      : ${account}`);
  console.log(`facilitator : ${FACILITATOR}`);

  // ---- free: the wrong authority is refused by the account itself
  const rogue = generateEd25519KeyPair();
  try {
    await buildSmartAccountPayment({ ...base, authoritySignature: signWith(rogue.privateKey, digest) });
    console.log("FAIL  commitment firmado por un agente: la cuenta lo ACEPTÓ");
    process.exitCode = 1;
  } catch (error: unknown) {
    console.log(`PASS  commitment firmado por un agente: rechazado on-chain en simulación (${(error instanceof Error ? error.message : String(error)).slice(0, 90)}…)`);
  }

  // ---- the real payment
  const payload = await buildSmartAccountPayment({ ...base, authoritySignature: signWith(attester.privateKey, digest) });
  const requirements = {
    scheme: "exact", network: NETWORK, asset: USDC_SAC, amount: AMOUNT.toString(),
    payTo: seller, maxTimeoutSeconds: 120, extra: { ...(kind.extra ?? {}) },
  };
  const paymentPayload = { x402Version: 2, accepted: requirements, payload };

  const verify = await post("/verify", { x402Version: 2, paymentPayload, paymentRequirements: requirements });
  console.log(`verify      : ${String(verify.status)} ${JSON.stringify(verify.json).slice(0, 300)}`);
  if ((verify.json as { isValid?: boolean } | null)?.isValid !== true) {
    process.exitCode = 1;
    return;
  }
  const settle = await post("/settle", { x402Version: 2, paymentPayload, paymentRequirements: requirements });
  console.log(`settle      : ${String(settle.status)} ${JSON.stringify(settle.json).slice(0, 300)}`);
  const tx = (settle.json as { transaction?: string } | null)?.transaction;
  if (tx === undefined) {
    process.exitCode = 1;
    return;
  }
  console.log(`LIQUIDADO   : https://stellar.expert/explorer/testnet/tx/${tx}`);

  await new Promise((resolve) => setTimeout(resolve, 3000));
  const horizon = (await (await fetch(`https://horizon-testnet.stellar.org/transactions/${tx}`)).json()) as { fee_charged?: string };
  const fee = Number(horizon.fee_charged ?? NaN);
  console.log(`fee cobrado : ${String(fee)} stroops (tope del facilitator ${String(FEE_CEILING_STROOPS)}) → ${fee <= FEE_CEILING_STROOPS ? "PASS" : "FAIL"}`);
  console.log(`commitment  : ${commitment.commitmentHash}`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
