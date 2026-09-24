/**
 * Make one real x402 payment on Stellar testnet, signed by the isolated signer.
 *
 * The point is not that a payment works — it is that the process holding the
 * key is not the process asking for the payment, and the key never crosses
 * between them.
 *
 *   AEGIS_BUYER_SECRET_FILE=... npx tsx packages/x402/scripts/pay-once.ts
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { ExactStellarScheme } from "@x402/stellar/exact/client";
import { generateEd25519KeyPair } from "../../core/src/index.js";
import { createPurchaseCommitment, sellerIdFromAccount } from "../../proof/src/index.js";
import { createRemoteSigner, forkSigner } from "../src/index.js";

const USDC_SAC = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const TESTNET_PASSPHRASE = "Test SDF Network ; September 2015";
const NETWORK = "stellar:testnet";
const RPC_URL = "https://soroban-testnet.stellar.org";
const FACILITATOR = process.env["AEGIS_FACILITATOR_URL"] ?? "https://www.x402.org/facilitator";

const BUYER_SECRET = requireEnv("AEGIS_BUYER_SECRET");
const SELLER_ACCOUNT = requireEnv("AEGIS_SELLER_ACCOUNT");
const AMOUNT_ATOMIC = process.env["AEGIS_AMOUNT_ATOMIC"] ?? "100000"; // 0.01 USDC

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`Missing ${name}.`);
  }
  return value;
}

async function post(path: string, body: unknown): Promise<{ status: number; json: unknown }> {
  const response = await fetch(`${FACILITATOR}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let json: unknown = text;
  try {
    json = JSON.parse(text) as unknown;
  } catch {
    /* keep the raw text so a non-JSON failure is still legible */
  }
  return { status: response.status, json };
}

async function main(): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "aegis-pay-"));
  const secretFile = join(dir, "buyer.secret");
  writeFileSync(secretFile, BUYER_SECRET, "utf8");

  const buyerIdentity = generateEd25519KeyPair("key:buyer-commitment");

  const forked = await forkSigner({
    modulePath: fileURLToPath(new URL("../src/signer-process.ts", import.meta.url)),
    secretFile,
    network: NETWORK,
    allowedAssets: { "stellar:USDC": USDC_SAC },
    allowedNetworkPassphrases: [TESTNET_PASSPHRASE],
    trustedCommitmentKeys: { [buyerIdentity.keyId]: buyerIdentity.publicKey },
    execArgv: ["--import", "tsx"],
    onAudit: (line) => process.stderr.write(`[signer] ${line}\n`),
  });

  try {
    console.log(`signer process pid : ${String(forked.pid)} (agent pid ${process.pid})`);
    console.log(`signer address     : ${forked.address}`);
    console.log(`seller             : ${SELLER_ACCOUNT}`);
    console.log(`amount (atomic)    : ${AMOUNT_ATOMIC}`);

    const now = new Date();
    const commitment = createPurchaseCommitment(
      {
        version: "1",
        id: `commitment:${now.getTime()}`,
        resourceUrl: "https://seller.example/market-data",
        sellerId: sellerIdFromAccount(SELLER_ACCOUNT),
        expectedContentType: "application/json",
        maxAmountAtomic: AMOUNT_ATOMIC,
        assetId: "stellar:USDC",
        committedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + 900_000).toISOString(),
        nonce: `nonce:${now.getTime()}`,
      },
      buyerIdentity,
    );

    const signer = await createRemoteSigner({
      transport: forked,
      commitment,
    });

    // Take `extra` from what the facilitator advertises rather than guessing:
    // the Exact scheme refuses to build a payload unless the network's own
    // terms (fee sponsorship, for instance) are carried through verbatim.
    const supported = await (await fetch(`${FACILITATOR}/supported`)).json() as {
      kinds?: { scheme?: string; network?: string; extra?: Record<string, unknown> }[];
    };
    const kind = (supported.kinds ?? []).find(
      (entry) => entry.scheme === "exact" && entry.network === NETWORK,
    );
    if (kind === undefined) {
      throw new Error(`Facilitator does not support exact/${NETWORK}.`);
    }
    console.log(`facilitator terms  : ${JSON.stringify(kind.extra ?? {})}`);

    const paymentRequirements = {
      scheme: "exact",
      network: NETWORK,
      asset: USDC_SAC,
      amount: AMOUNT_ATOMIC,
      payTo: SELLER_ACCOUNT,
      maxTimeoutSeconds: 120,
      extra: { ...(kind.extra ?? {}) },
    };

    const scheme = new ExactStellarScheme(signer, { url: RPC_URL });
    console.log("\nbuilding payment payload (signed by the isolated process)…");
    const created = await scheme.createPaymentPayload(2, paymentRequirements as never);

    const paymentPayload = {
      x402Version: created.x402Version,
      accepted: paymentRequirements,
      payload: created.payload,
    };

    console.log("verifying with facilitator…");
    const verify = await post("/verify", {
      x402Version: 2,
      paymentPayload,
      paymentRequirements,
    });
    console.log(`  status ${verify.status}: ${JSON.stringify(verify.json).slice(0, 400)}`);

    const verified = verify.json as { isValid?: boolean };
    if (verified.isValid !== true) {
      console.log("\nnot settling: facilitator did not validate the payment.");
      return;
    }

    console.log("settling…");
    const settle = await post("/settle", {
      x402Version: 2,
      paymentPayload,
      paymentRequirements,
    });
    console.log(`  status ${settle.status}: ${JSON.stringify(settle.json).slice(0, 600)}`);

    const settled = settle.json as { success?: boolean; transaction?: string };
    if (settled.success === true && settled.transaction !== undefined) {
      console.log(
        `\nSETTLED  https://stellar.expert/explorer/testnet/tx/${settled.transaction}`,
      );
    }
  } finally {
    await forked.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
