import { createHash } from "node:crypto";

import {
  Address,
  authorizeEntry,
  contract,
  nativeToScVal,
  rpc,
  xdr,
} from "@stellar/stellar-sdk";

/**
 * Paying x402 from an AegisOS smart account (`contracts/aegis-account`).
 *
 * The stock `ExactStellarScheme` client cannot pay from a contract account: it
 * wraps the SEP-43 signature as raw bytes and the SDK then treats the payer as
 * an ed25519 `G…` key. The SDK does accept a ready-made `signatureScVal`, so
 * this builds the same one-operation `transfer` transaction the facilitator
 * expects, with the account's own signature format.
 */

export const ONCHAIN_COMMITMENT_DOMAIN = "aegisos:onchain-commitment:v1";
export const PAYMENT_CHAIN_DOMAIN = "aegisos:payment-chain:v1";

const ESTIMATED_LEDGER_SECONDS = 5;

/** Mirrors `OnChainCommitment` in the account contract. */
export interface OnChainCommitmentV1 {
  /** Bare 64-hex: the off-chain purchase commitment hash. */
  readonly commitmentHash: string;
  readonly seller: string;
  readonly asset: string;
  readonly maxAmount: bigint;
  /** Unix seconds, compared with the ledger timestamp. */
  readonly expiresAt: bigint;
}

function i128Be(value: bigint): Buffer {
  const out = Buffer.alloc(16);
  out.writeBigInt64BE(value >> 64n, 0);
  out.writeBigUInt64BE(value & 0xffff_ffff_ffff_ffffn, 8);
  return out;
}

function u64Be(value: bigint): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(value, 0);
  return out;
}

function addressXdr(value: string): Buffer {
  return new Address(value).toScVal().toXDR();
}

function hashBytes(hex: string, label: string): Buffer {
  if (!/^[a-f0-9]{64}$/.test(hex)) throw new Error(`${label} must be bare lowercase 64-hex.`);
  return Buffer.from(hex, "hex");
}

/**
 * What the commitment authority signs. Same byte layout as the contract's
 * `commitment_digest`; `packages/x402/test/smart-account.test.ts` pins both to
 * the vector the Rust test prints.
 */
export function onChainCommitmentDigest(c: OnChainCommitmentV1): Buffer {
  return createHash("sha256")
    .update(Buffer.from(ONCHAIN_COMMITMENT_DOMAIN, "ascii"))
    .update(hashBytes(c.commitmentHash, "commitmentHash"))
    .update(addressXdr(c.seller))
    .update(addressXdr(c.asset))
    .update(i128Be(c.maxAmount))
    .update(u64Be(c.expiresAt))
    .digest();
}

/** The contract's `chain_link`, so a verifier can replay the payment chain. */
export function paymentChainLink(input: {
  readonly previous: string;
  readonly seq: bigint;
  readonly commitmentHash: string;
  readonly seller: string;
  readonly amount: bigint;
}): string {
  return createHash("sha256")
    .update(Buffer.from(PAYMENT_CHAIN_DOMAIN, "ascii"))
    .update(hashBytes(input.previous, "previous"))
    .update(u64Be(input.seq))
    .update(hashBytes(input.commitmentHash, "commitmentHash"))
    .update(addressXdr(input.seller))
    .update(i128Be(input.amount))
    .digest("hex");
}

function field(key: string, val: xdr.ScVal): xdr.ScMapEntry {
  return new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val });
}

/** `AegisAuth::Payment(PaymentAuth)` as the contract decodes it. Map keys sorted. */
export function paymentAuthScVal(input: {
  readonly commitment: OnChainCommitmentV1;
  readonly authoritySignature: Buffer;
  readonly sessionSignature: Buffer;
}): xdr.ScVal {
  const c = input.commitment;
  const commitment = xdr.ScVal.scvMap([
    field("asset", new Address(c.asset).toScVal()),
    field("commitment_hash", xdr.ScVal.scvBytes(hashBytes(c.commitmentHash, "commitmentHash"))),
    field("expires_at", nativeToScVal(c.expiresAt, { type: "u64" })),
    field("max_amount", nativeToScVal(c.maxAmount, { type: "i128" })),
    field("seller", new Address(c.seller).toScVal()),
  ]);
  const payment = xdr.ScVal.scvMap([
    field("authority_sig", xdr.ScVal.scvBytes(input.authoritySignature)),
    field("commitment", commitment),
    field("session_sig", xdr.ScVal.scvBytes(input.sessionSignature)),
  ]);
  return xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Payment"), payment]);
}

export interface SmartAccountPaymentInput {
  /** The paying account, `C…`. */
  readonly account: string;
  readonly payTo: string;
  readonly asset: string;
  readonly amount: bigint;
  readonly maxTimeoutSeconds: number;
  readonly commitment: OnChainCommitmentV1;
  /** Commitment authority's ed25519 signature over `onChainCommitmentDigest`. */
  readonly authoritySignature: Buffer;
  /**
   * Session signer: signs the 32-byte Soroban signature payload. In AegisOS
   * this is the isolated signer; it never sees the account's owner key.
   */
  readonly signPayload: (payload: Buffer) => Promise<Buffer>;
  readonly rpcUrl: string;
  readonly networkPassphrase: string;
}

/** Build the x402 `exact` payload `{ transaction }` for a smart-account payer. */
export async function buildSmartAccountPayment(
  input: SmartAccountPaymentInput,
): Promise<{ readonly transaction: string }> {
  const server = new rpc.Server(input.rpcUrl);
  const latest = await server.getLatestLedger();
  const maxLedger = latest.sequence + Math.ceil(input.maxTimeoutSeconds / ESTIMATED_LEDGER_SECONDS);

  const tx = await contract.AssembledTransaction.build({
    contractId: input.asset,
    method: "transfer",
    args: [
      nativeToScVal(input.account, { type: "address" }),
      nativeToScVal(input.payTo, { type: "address" }),
      nativeToScVal(input.amount, { type: "i128" }),
    ],
    networkPassphrase: input.networkPassphrase,
    rpcUrl: input.rpcUrl,
    parseResultXdr: (result: xdr.ScVal) => result,
  });
  const missing = tx.needsNonInvokerSigningBy();
  if (missing.length !== 1 || missing[0] !== input.account) {
    throw new Error(`Expected to sign only as ${input.account}, got [${missing.join(", ")}].`);
  }

  await tx.signAuthEntries({
    address: input.account,
    expiration: maxLedger,
    authorizeEntry: (entry, _unused, validUntil, passphrase) =>
      authorizeEntry(
        entry,
        async (preimage: xdr.HashIdPreimage) => {
          const payload = createHash("sha256").update(preimage.toXDR()).digest();
          const sessionSignature = await input.signPayload(payload);
          return {
            signatureScVal: paymentAuthScVal({
              commitment: input.commitment,
              authoritySignature: input.authoritySignature,
              sessionSignature,
            }),
          } as never;
        },
        validUntil,
        passphrase,
      ),
  });

  // Enforcing simulation: runs the account's __check_auth, so the footprint
  // includes what it writes, and a refusal surfaces here, before any facilitator.
  await tx.simulate();
  if (tx.simulation !== undefined && rpc.Api.isSimulationError(tx.simulation)) {
    throw new Error(`Smart-account payment refused in simulation: ${tx.simulation.error}`);
  }
  return { transaction: tx.built!.toXDR() };
}
