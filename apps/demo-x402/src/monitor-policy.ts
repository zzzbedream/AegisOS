/**
 * Delivery monitor: which sellers to buy from now, and what the public feed says.
 *
 * The monitor buys from real x402 sellers on a schedule and publishes, per seller,
 * whether each paid call delivered what was charged for. Buying from someone's service
 * on a schedule is load on their service, so consent is a hard rule: a seller is
 * checked only if it is ours (`self`) or its operator agreed (`granted:<date>`), and
 * only within the pace and price it set. `pending` and anything else never runs.
 */

export type Consent = "self" | `granted:${string}` | "pending";

export interface MonitoredSeller {
  readonly id: string;
  readonly name: string;
  readonly url: string;
  readonly consent: Consent;
  /** Who agreed and where, for `granted:` (e.g. "Nirium team, X DM 2026-11-03"). */
  readonly consentNote?: string;
  readonly enabled: boolean;
  /** Minimum hours between two paid checks of this seller. */
  readonly minIntervalHours: number;
  readonly maxChecksPerDay: number;
  /** Refuse to pay if the seller's 402 asks for more than this. */
  readonly maxPriceAtomic: string;
}

export interface MonitorCheckV1 {
  readonly version: "1";
  readonly sellerId: string;
  readonly checkedAt: string;
  readonly url: string;
  readonly priceAtomic?: string;
  /** "OK" | "TAINTED" | "MISMATCH" | "NOT_DELIVERED", or "ERROR" when no verdict was reached. */
  readonly verdict: string;
  readonly settlementTx?: string;
  /** True when a Reclaim proof of origin verified against the pinned witness. */
  readonly contentProven?: boolean;
  readonly receiptFile?: string;
  readonly error?: string;
}

export interface SellerFeedEntry {
  readonly id: string;
  readonly name: string;
  readonly url: string;
  readonly consent: Consent;
  readonly checks: number;
  readonly delivered: number;
  readonly proven: number;
  readonly lastCheckedAt?: string;
  readonly lastVerdict?: string;
  readonly lastSettlementTx?: string;
  readonly lastReceiptFile?: string;
}

export interface DeliveryFeedV1 {
  readonly version: "1";
  readonly network: "stellar:testnet";
  readonly generatedAt: string;
  readonly sellers: readonly SellerFeedEntry[];
}

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

export function hasConsent(consent: string): boolean {
  return consent === "self" || /^granted:\d{4}-\d{2}-\d{2}$/.test(consent);
}

/** Sellers due for a paid check at `now`, honoring consent, pace and the run's budget. */
export function dueSellers(
  sellers: readonly MonitoredSeller[],
  history: readonly MonitorCheckV1[],
  now: Date,
  maxChecksPerRun: number,
): readonly MonitoredSeller[] {
  const due = sellers.filter((seller) => {
    if (!seller.enabled || !hasConsent(seller.consent)) return false;
    const mine = history.filter((check) => check.sellerId === seller.id).map((check) => Date.parse(check.checkedAt));
    const last = Math.max(Number.NEGATIVE_INFINITY, ...mine);
    if (now.getTime() - last < seller.minIntervalHours * HOUR_MS) return false;
    const today = mine.filter((at) => now.getTime() - at < DAY_MS).length;
    return today < seller.maxChecksPerDay;
  });
  return due.slice(0, Math.max(0, maxChecksPerRun));
}

/** A seller's 402 is acceptable only at or below its agreed price ceiling. */
export function priceWithinCap(seller: MonitoredSeller, priceAtomic: string): boolean {
  return /^\d+$/.test(priceAtomic) && BigInt(priceAtomic) > 0n && BigInt(priceAtomic) <= BigInt(seller.maxPriceAtomic);
}

export function buildFeed(sellers: readonly MonitoredSeller[], history: readonly MonitorCheckV1[], now: Date): DeliveryFeedV1 {
  const entries = sellers
    .filter((seller) => hasConsent(seller.consent))
    .map((seller): SellerFeedEntry => {
      const mine = history
        .filter((check) => check.sellerId === seller.id)
        .sort((a, b) => Date.parse(a.checkedAt) - Date.parse(b.checkedAt));
      const last = mine.at(-1);
      return {
        id: seller.id,
        name: seller.name,
        url: seller.url,
        consent: seller.consent,
        checks: mine.length,
        delivered: mine.filter((check) => check.verdict === "OK" && check.settlementTx !== undefined).length,
        proven: mine.filter((check) => check.contentProven === true).length,
        ...(last === undefined
          ? {}
          : {
              lastCheckedAt: last.checkedAt,
              lastVerdict: last.verdict,
              ...(last.settlementTx === undefined ? {} : { lastSettlementTx: last.settlementTx }),
              ...(last.receiptFile === undefined ? {} : { lastReceiptFile: last.receiptFile }),
            }),
      };
    });
  return { version: "1", network: "stellar:testnet", generatedAt: now.toISOString(), sellers: entries };
}
