import { createPrivateKey, sign } from "node:crypto";

import { SignerDeniedError } from "./protocol.js";
import { onChainCommitmentDigest, type OnChainCommitmentV1 } from "./smart-account.js";

/**
 * The commitment authority.
 *
 * The AegisOS account pays only under a commitment this key signed. So this
 * key must never live in the agent's process: if it did, a compromised agent
 * would sign a commitment to the attacker and the account would honour it. It
 * lives in the isolated signer process, and signs only what its policy — fixed
 * when the process starts — allows.
 *
 * The policy is deliberately narrow: which sellers, how much per commitment,
 * how long a commitment may stay open. Budgets over time belong to the spend
 * rail, not here.
 */

export interface AuthorityPolicy {
  /** Seller accounts (`G…`/`C…`) the owner approved. */
  readonly allowedSellers: readonly string[];
  /** Ceiling for a single commitment, in atomic units. */
  readonly maxAmountAtomic: string;
  /** Longest a commitment may stay payable. Must not exceed the account's. */
  readonly maxWindowSeconds?: number;
}

export interface AuthorityConfig {
  /** base64url PKCS#8 DER of the authority's ed25519 key. */
  readonly privateKey: string;
  /** The account these commitments pay from; bound into every digest. */
  readonly account: string;
  readonly allowedAssetContracts: readonly string[];
  readonly policy: AuthorityPolicy;
  readonly now: () => Date;
}

/** Mirrors `MAX_COMMITMENT_WINDOW_SECS` in the account contract. */
export const ACCOUNT_MAX_WINDOW_SECONDS = 3_600;

function deny(message: string): never {
  throw new SignerDeniedError("COMMITMENT_POLICY_DENIED", message);
}

export function authorizeOnChainCommitment(
  config: AuthorityConfig,
  commitment: OnChainCommitmentV1,
): Buffer {
  if (!config.policy.allowedSellers.includes(commitment.seller)) {
    deny("Seller is not on the owner's approved list.");
  }
  if (!config.allowedAssetContracts.includes(commitment.asset)) {
    deny("Asset is not allowed for this account.");
  }
  const ceiling = BigInt(config.policy.maxAmountAtomic);
  if (commitment.maxAmount <= 0n || commitment.maxAmount > ceiling) {
    deny(`Commitment ceiling must be between 1 and ${config.policy.maxAmountAtomic}.`);
  }
  const window = Math.min(
    config.policy.maxWindowSeconds ?? ACCOUNT_MAX_WINDOW_SECONDS,
    ACCOUNT_MAX_WINDOW_SECONDS,
  );
  const now = BigInt(Math.floor(config.now().getTime() / 1000));
  if (commitment.expiresAt <= now) deny("Commitment is already expired.");
  if (commitment.expiresAt - now > BigInt(window)) {
    deny(`Commitment may stay open at most ${String(window)} seconds.`);
  }

  const key = createPrivateKey({
    key: Buffer.from(config.privateKey, "base64url"),
    format: "der",
    type: "pkcs8",
  });
  return sign(null, onChainCommitmentDigest(config.account, commitment), key);
}
