import {
  signCanonical,
  verifyCanonical,
  type SigningIdentityV1,
} from "../../core/src/index.js";
import { PROOF_DOMAINS, assertSha256Hex, hashInDomain, type Sha256Hex } from "./hashing.js";
import { assertSellerId } from "./ids.js";
import type {
  DeliveryReceiptV1,
  PurchaseCommitmentV1,
  SellerOfferV1,
} from "./types.js";

export class ProofRecordError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.name = "ProofRecordError";
    this.code = code;
  }
}

type Unsigned<T> = Omit<T, "signature">;

export type UnsignedPurchaseCommitmentV1 = Unsigned<PurchaseCommitmentV1>;
export type UnsignedSellerOfferV1 = Unsigned<SellerOfferV1>;
export type UnsignedDeliveryReceiptV1 = Unsigned<DeliveryReceiptV1>;

function signable<T extends { readonly signature: unknown }>(record: T): Unsigned<T> {
  const copy: Record<string, unknown> = { ...record };
  delete copy["signature"];
  return copy as Unsigned<T>;
}

// ---------------------------------------------------------------- commitment

export function purchaseCommitmentSignable(
  commitment: PurchaseCommitmentV1,
): UnsignedPurchaseCommitmentV1 {
  return signable(commitment);
}

export function hashPurchaseCommitment(commitment: PurchaseCommitmentV1): Sha256Hex {
  return hashInDomain(PROOF_DOMAINS.purchaseCommitment, purchaseCommitmentSignable(commitment));
}

export function createPurchaseCommitment(
  input: UnsignedPurchaseCommitmentV1,
  signer: SigningIdentityV1,
): PurchaseCommitmentV1 {
  assertSellerId(input.sellerId);
  if (Date.parse(input.expiresAt) <= Date.parse(input.committedAt)) {
    throw new ProofRecordError("BAD_WINDOW", "Commitment must expire after it is committed.");
  }
  const signature = signCanonical(
    { domain: PROOF_DOMAINS.purchaseCommitment, payload: input },
    signer,
  );
  return Object.freeze({ ...input, signature });
}

export function verifyPurchaseCommitment(
  commitment: PurchaseCommitmentV1,
  publicKey: string,
): boolean {
  try {
    assertSellerId(commitment.sellerId);
    return verifyCanonical(
      { domain: PROOF_DOMAINS.purchaseCommitment, payload: purchaseCommitmentSignable(commitment) },
      commitment.signature,
      publicKey,
    );
  } catch {
    return false;
  }
}

// --------------------------------------------------------------- seller offer

export function sellerOfferSignable(offer: SellerOfferV1): UnsignedSellerOfferV1 {
  return signable(offer);
}

export function hashSellerOffer(offer: SellerOfferV1): Sha256Hex {
  return hashInDomain(PROOF_DOMAINS.sellerOffer, sellerOfferSignable(offer));
}

export function createSellerOffer(
  input: UnsignedSellerOfferV1,
  signer: SigningIdentityV1,
): SellerOfferV1 {
  assertSellerId(input.sellerId);
  assertSha256Hex(input.commitmentHash, "commitmentHash");
  const signature = signCanonical({ domain: PROOF_DOMAINS.sellerOffer, payload: input }, signer);
  return Object.freeze({ ...input, signature });
}

export function verifySellerOffer(offer: SellerOfferV1, publicKey: string): boolean {
  try {
    assertSellerId(offer.sellerId);
    return verifyCanonical(
      { domain: PROOF_DOMAINS.sellerOffer, payload: sellerOfferSignable(offer) },
      offer.signature,
      publicKey,
    );
  } catch {
    return false;
  }
}

// ------------------------------------------------------------------- receipt

export function deliveryReceiptSignable(receipt: DeliveryReceiptV1): UnsignedDeliveryReceiptV1 {
  return signable(receipt);
}

export function hashDeliveryReceipt(receipt: DeliveryReceiptV1): Sha256Hex {
  return hashInDomain(PROOF_DOMAINS.deliveryReceipt, deliveryReceiptSignable(receipt));
}

/**
 * The MVP receipt is signed by the buyer, which is why `attesterRole` is
 * explicit and defaults to nothing. A buyer signature attests to what the
 * buyer received and concluded — it is not proof the seller performed.
 */
export function createDeliveryReceipt(
  input: UnsignedDeliveryReceiptV1,
  signer: SigningIdentityV1,
): DeliveryReceiptV1 {
  assertSellerId(input.sellerId);
  assertSha256Hex(input.commitmentHash, "commitmentHash");
  assertSha256Hex(input.paymentHash, "paymentHash");
  assertSha256Hex(input.contentHash, "contentHash");
  const signature = signCanonical(
    { domain: PROOF_DOMAINS.deliveryReceipt, payload: input },
    signer,
  );
  return Object.freeze({ ...input, signature });
}

export function verifyDeliveryReceipt(receipt: DeliveryReceiptV1, publicKey: string): boolean {
  try {
    assertSellerId(receipt.sellerId);
    assertSha256Hex(receipt.contentHash, "contentHash");
    return verifyCanonical(
      { domain: PROOF_DOMAINS.deliveryReceipt, payload: deliveryReceiptSignable(receipt) },
      receipt.signature,
      publicKey,
    );
  } catch {
    return false;
  }
}
