import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { Address, Keypair, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { generateEd25519KeyPair } from "../../core/src/index.js";
import { createPurchaseCommitment, sellerIdFromAccount } from "../../proof/src/index.js";
import { createRemoteSigner, forkSigner, type ForkedSigner } from "../src/index.js";

const USDC_TESTNET = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const TESTNET_PASSPHRASE = "Test SDF Network ; September 2015";

const signerKeypair = Keypair.random();
const sellerKeypair = Keypair.random();
const attackerKeypair = Keypair.random();
const buyerIdentity = generateEd25519KeyPair("key:buyer");
const SELLER_ID = sellerIdFromAccount(sellerKeypair.publicKey());

const SIGNER_MODULE = fileURLToPath(new URL("../src/signer-process.ts", import.meta.url));

function transferXdr(to: string, amount = 10000n): string {
  const contractFn = new xdr.InvokeContractArgs({
    contractAddress: new Address(USDC_TESTNET).toScAddress(),
    functionName: "transfer",
    args: [
      new Address(signerKeypair.publicKey()).toScVal(),
      new Address(to).toScVal(),
      nativeToScVal(amount, { type: "i128" }),
    ],
  });
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: new Address(signerKeypair.publicKey()).toScAddress(),
        nonce: xdr.Int64.fromString("1"),
        signatureExpirationLedger: 100000,
        signature: xdr.ScVal.scvVoid(),
      }),
    ),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(contractFn),
      subInvocations: [],
    }),
  }).toXDR("base64");
}

function commitment() {
  const now = new Date();
  return createPurchaseCommitment(
    {
      version: "1",
      id: "commitment:fork",
      resourceUrl: "https://seller.example/market-data",
      sellerId: SELLER_ID,
      expectedContentType: "application/json",
      maxAmountAtomic: "100000",
      assetId: "stellar:USDC",
      committedAt: new Date(now.getTime() - 60_000).toISOString(),
      expiresAt: new Date(now.getTime() + 900_000).toISOString(),
      nonce: "nonce:fork-1",
    },
    buyerIdentity,
  );
}

test("the signer runs in its own process and the agent never holds the key", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "aegis-signer-"));
  const secretFile = join(dir, "signer.secret");
  writeFileSync(secretFile, signerKeypair.secret(), "utf8");

  const audit: string[] = [];
  let forked: ForkedSigner | undefined;

  t.after(async () => {
    await forked?.close();
    rmSync(dir, { recursive: true, force: true });
  });

  forked = await forkSigner({
    modulePath: SIGNER_MODULE,
    // The parent hands over a PATH, never the secret itself.
    secretFile,
    network: "stellar:testnet",
    allowedAssets: { "stellar:USDC": USDC_TESTNET },
    allowedNetworkPassphrases: [TESTNET_PASSPHRASE],
    trustedCommitmentKeys: { [buyerIdentity.keyId]: buyerIdentity.publicKey },
    execArgv: ["--import", "tsx"],
    onAudit: (line) => audit.push(line),
  });

  assert.equal(forked.address, signerKeypair.publicKey());
  assert.notEqual(forked.pid, process.pid);

  // The claim, made checkable: the agent's own environment does not carry the
  // key, only the path to it.
  const parentEnv = JSON.stringify(process.env);
  assert.ok(!parentEnv.includes(signerKeypair.secret()));

  const signer = await createRemoteSigner({
    transport: forked,
    commitment: commitment(),
  });

  const ok = await signer.signAuthEntry(transferXdr(sellerKeypair.publicKey()), {
    networkPassphrase: TESTNET_PASSPHRASE,
  });
  assert.ok(ok.signedAuthEntry.length > 0);

  await assert.rejects(
    () =>
      signer.signAuthEntry(transferXdr(attackerKeypair.publicKey()), {
        networkPassphrase: TESTNET_PASSPHRASE,
      }),
    /SELLER_NOT_ALLOWED|not the committed seller/,
  );

  // The denial is auditable from the parent without the reply ever carrying it.
  assert.ok(audit.join("\n").includes("SELLER_NOT_ALLOWED"));
});
