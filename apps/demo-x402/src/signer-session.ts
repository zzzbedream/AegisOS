import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import type { Keypair } from "@stellar/stellar-sdk";

import type { Ed25519KeyPairV1 } from "../../../packages/core/src/index.js";
import { forkSigner, type ForkedSigner } from "../../../packages/x402/src/index.js";
import type { SmartAccountSetup } from "./smart-account-config.js";

export const USDC_SAC = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
export const TESTNET_PASSPHRASE = "Test SDF Network ; September 2015";

export interface SignerSession {
  readonly signer: ForkedSigner;
  close(): Promise<void>;
}

/**
 * Fork the isolated signer. The buyer key reaches it through a temp file and never
 * stays in this process's context. In smart-account mode the owner's policy (which
 * sellers, what ceiling) is fixed here, at launch, and cannot be changed by the agent.
 */
export async function openSignerSession(input: {
  readonly buyer: Keypair;
  readonly attester: Ed25519KeyPairV1;
  readonly smart: SmartAccountSetup | undefined;
  readonly allowedSellers: readonly string[];
  readonly maxAmountAtomic: string;
}): Promise<SignerSession> {
  const dir = mkdtempSync(join(tmpdir(), "aegis-signer-"));
  const secretFile = join(dir, "buyer.secret");
  writeFileSync(secretFile, input.buyer.secret(), "utf8");
  try {
    const signer = await forkSigner({
      modulePath: fileURLToPath(new URL("../../../packages/x402/src/signer-process.ts", import.meta.url)),
      secretFile,
      network: "stellar:testnet",
      allowedAssets: { "stellar:USDC": USDC_SAC },
      allowedNetworkPassphrases: [TESTNET_PASSPHRASE],
      trustedCommitmentKeys: { [input.attester.keyId]: input.attester.publicKey },
      ...(input.smart === undefined
        ? {}
        : {
            payerAddress: input.smart.address,
            authority: {
              secretFile: input.smart.authoritySecretFile,
              policy: { allowedSellers: [...input.allowedSellers], maxAmountAtomic: input.maxAmountAtomic },
            },
          }),
      execArgv: ["--import", "tsx"],
    });
    return {
      signer,
      close: async () => {
        await signer.close?.();
        rmSync(dir, { recursive: true, force: true });
      },
    };
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
}
