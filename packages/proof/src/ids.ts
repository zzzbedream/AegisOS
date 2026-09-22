import type { SellerId } from "./types.js";

/** Stellar public keys are 56 chars of base32 starting with G. */
const STELLAR_ACCOUNT = /^G[A-Z2-7]{55}$/;

export class SellerIdError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "SellerIdError";
  }
}

export function isSellerId(value: unknown): value is SellerId {
  if (typeof value !== "string" || !value.startsWith("stellar:")) return false;
  return STELLAR_ACCOUNT.test(value.slice("stellar:".length));
}

export function assertSellerId(value: unknown, label = "sellerId"): asserts value is SellerId {
  if (!isSellerId(value)) {
    throw new SellerIdError(`${label} must be stellar:<G...> with a valid account id.`);
  }
}

export function sellerIdFromAccount(account: string): SellerId {
  const candidate = `stellar:${account}`;
  assertSellerId(candidate);
  return candidate;
}

export function accountFromSellerId(sellerId: SellerId): string {
  assertSellerId(sellerId);
  return sellerId.slice("stellar:".length);
}

/**
 * Identity must agree across the 402 response, the commitment, the receipt and
 * the on-chain record. Anything else lets one seller present as several.
 */
export function assertSameSeller(
  values: readonly { readonly label: string; readonly sellerId: unknown }[],
): SellerId {
  if (values.length === 0) {
    throw new SellerIdError("No seller identity supplied.");
  }
  const first = values[0];
  if (first === undefined) {
    throw new SellerIdError("No seller identity supplied.");
  }
  assertSellerId(first.sellerId, first.label);
  for (const entry of values.slice(1)) {
    assertSellerId(entry.sellerId, entry.label);
    if (entry.sellerId !== first.sellerId) {
      throw new SellerIdError(
        `Seller identity disagrees between ${first.label} and ${entry.label}.`,
      );
    }
  }
  return first.sellerId;
}
