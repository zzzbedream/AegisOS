import { Address, scValToNative, xdr } from "@stellar/stellar-sdk";
import {
  accountFromSellerId,
  verifyPurchaseCommitment,
  type PurchaseCommitmentV1,
} from "../../proof/src/index.js";
import { SignerDeniedError } from "./protocol.js";

/** Only a plain SEP-41 transfer is signable. Anything else is out of scope. */
const ALLOWED_FUNCTION = "transfer";

export interface SignerGuardConfig {
  /** Asset id → contract address, e.g. "stellar:USDC" → "CBIELTK6…". */
  readonly allowedAssets: Readonly<Record<string, string>>;
  readonly allowedNetworkPassphrases: readonly string[];
  /** The signer's own account; a transfer must debit this and nothing else. */
  readonly signerAddress: string;
  readonly now: () => Date;
}

export interface DecodedTransfer {
  readonly functionName: string;
  readonly tokenContract: string;
  readonly from: string;
  readonly to: string;
  readonly amountAtomic: string;
  readonly subInvocationCount: number;
}

/**
 * Read an authorization entry without trusting anything the agent said about
 * it. This is the whole point of the split: the signer forms its own view of
 * what it is being asked to authorize.
 */
/**
 * What the SEP-43 signer is actually handed.
 *
 * `authorizeEntry` in stellar-sdk does not pass the SorobanAuthorizationEntry
 * itself — it builds a `HashIdPreimage` (CAP-71 adds the address-bound
 * variant) and asks the signer to sign that. The invocation lives inside, so
 * the guard can still see the real transfer; it just has to unwrap first.
 * A raw entry is still accepted so the guard works for callers that pass one.
 */
function extractInvocation(authEntryXdr: string): xdr.SorobanAuthorizedInvocation {
  try {
    const preimage = xdr.HashIdPreimage.fromXDR(authEntryXdr, "base64");
    const arm = preimage.switch().name;
    if (arm === "envelopeTypeSorobanAuthorization") {
      return preimage.sorobanAuthorization().invocation();
    }
    if (arm === "envelopeTypeSorobanAuthorizationWithAddress") {
      return preimage.sorobanAuthorizationWithAddress().invocation();
    }
    throw new SignerDeniedError(
      "AUTH_ENTRY_MISMATCH",
      `Signing payload is a ${arm} preimage, not an authorization.`,
    );
  } catch (error: unknown) {
    if (error instanceof SignerDeniedError) throw error;
    // Not a preimage; fall through to the raw-entry form.
  }

  try {
    return xdr.SorobanAuthorizationEntry.fromXDR(authEntryXdr, "base64").rootInvocation();
  } catch {
    throw new SignerDeniedError(
      "AUTH_ENTRY_UNDECODABLE",
      "Signing payload is neither an authorization preimage nor an authorization entry.",
    );
  }
}

export function decodeTransferAuthEntry(authEntryXdr: string): DecodedTransfer {
  const invocation = extractInvocation(authEntryXdr);

  try {
    const contractFn = invocation.function().contractFn();
    const args = contractFn.args();

    if (args.length !== 3) {
      throw new SignerDeniedError(
        "AUTH_ENTRY_MISMATCH",
        `Expected a 3-argument transfer, found ${args.length} arguments.`,
      );
    }

    const [fromArg, toArg, amountArg] = args;
    if (fromArg === undefined || toArg === undefined || amountArg === undefined) {
      throw new SignerDeniedError("AUTH_ENTRY_MISMATCH", "Transfer arguments are incomplete.");
    }

    return {
      functionName: contractFn.functionName().toString(),
      tokenContract: Address.fromScAddress(contractFn.contractAddress()).toString(),
      from: String(scValToNative(fromArg)),
      to: String(scValToNative(toArg)),
      amountAtomic: String(scValToNative(amountArg)),
      subInvocationCount: invocation.subInvocations().length,
    };
  } catch (error: unknown) {
    if (error instanceof SignerDeniedError) throw error;
    throw new SignerDeniedError(
      "AUTH_ENTRY_UNDECODABLE",
      "Authorization entry is not a readable contract invocation.",
    );
  }
}

/**
 * Decide whether this entry is the payment the buyer committed to.
 *
 * Fail-closed throughout: every branch that cannot be positively verified
 * denies. A guard that shrugs and signs when it cannot parse the request is
 * worse than no guard, because it looks like one.
 */
export function assertSignableTransfer(
  authEntryXdr: string,
  commitment: PurchaseCommitmentV1,
  buyerPublicKey: string,
  config: SignerGuardConfig,
  networkPassphrase?: string,
): DecodedTransfer {
  // 1. The commitment must be authentic. An agent that fabricates a commitment
  //    to justify a payment gets nowhere.
  if (!verifyPurchaseCommitment(commitment, buyerPublicKey)) {
    throw new SignerDeniedError(
      "COMMITMENT_SIGNATURE_INVALID",
      "Purchase commitment does not verify under the buyer key.",
    );
  }

  const now = config.now().getTime();
  if (Number.isNaN(Date.parse(commitment.expiresAt)) || now > Date.parse(commitment.expiresAt)) {
    throw new SignerDeniedError("COMMITMENT_EXPIRED", "Purchase commitment has expired.");
  }

  if (
    networkPassphrase !== undefined &&
    !config.allowedNetworkPassphrases.includes(networkPassphrase)
  ) {
    throw new SignerDeniedError("NETWORK_NOT_ALLOWED", "Network is not allowed for this signer.");
  }

  const expectedToken = config.allowedAssets[commitment.assetId];
  if (expectedToken === undefined) {
    throw new SignerDeniedError(
      "ASSET_NOT_ALLOWED",
      `Asset ${commitment.assetId} is not allowed for this signer.`,
    );
  }

  const decoded = decodeTransferAuthEntry(authEntryXdr);

  if (decoded.functionName !== ALLOWED_FUNCTION) {
    throw new SignerDeniedError(
      "AUTH_ENTRY_MISMATCH",
      `Only ${ALLOWED_FUNCTION} may be authorized; found ${decoded.functionName}.`,
    );
  }
  // Sub-invocations turn a payment into an arbitrary call graph.
  if (decoded.subInvocationCount !== 0) {
    throw new SignerDeniedError(
      "AUTH_ENTRY_MISMATCH",
      "Authorization entry carries sub-invocations.",
    );
  }
  if (decoded.tokenContract !== expectedToken) {
    throw new SignerDeniedError("ASSET_NOT_ALLOWED", "Transfer is for an unexpected token.");
  }
  if (decoded.from !== config.signerAddress) {
    throw new SignerDeniedError(
      "AUTH_ENTRY_MISMATCH",
      "Transfer does not debit this signer's account.",
    );
  }

  // This is the check that stops a poisoned agent redirecting funds: the
  // destination must be the seller the buyer committed to, not whatever
  // address the content suggested.
  const expectedSeller = accountFromSellerId(commitment.sellerId);
  if (decoded.to !== expectedSeller) {
    throw new SignerDeniedError(
      "SELLER_NOT_ALLOWED",
      "Transfer destination is not the committed seller.",
    );
  }

  let amount: bigint;
  let ceiling: bigint;
  try {
    amount = BigInt(decoded.amountAtomic);
    ceiling = BigInt(commitment.maxAmountAtomic);
  } catch {
    throw new SignerDeniedError("AUTH_ENTRY_MISMATCH", "Transfer amount is not an integer.");
  }
  if (amount <= 0n) {
    throw new SignerDeniedError("AUTH_ENTRY_MISMATCH", "Transfer amount must be positive.");
  }
  if (amount > ceiling) {
    throw new SignerDeniedError(
      "AMOUNT_EXCEEDS_COMMITMENT",
      `Transfer of ${decoded.amountAtomic} exceeds the committed ceiling ${commitment.maxAmountAtomic}.`,
    );
  }

  return decoded;
}
