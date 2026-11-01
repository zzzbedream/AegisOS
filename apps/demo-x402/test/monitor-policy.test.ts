import assert from "node:assert/strict";
import test from "node:test";

import {
  buildFeed,
  dueSellers,
  hasConsent,
  priceWithinCap,
  type MonitorCheckV1,
  type MonitoredSeller,
} from "../src/monitor-policy.js";

const now = new Date("2026-11-02T12:00:00Z");

function seller(id: string, overrides: Partial<MonitoredSeller> = {}): MonitoredSeller {
  return {
    id, name: id, url: `https://${id}.example/x402`, consent: "self", enabled: true,
    minIntervalHours: 6, maxChecksPerDay: 2, maxPriceAtomic: "200000", ...overrides,
  };
}

function check(sellerId: string, hoursAgo: number, overrides: Partial<MonitorCheckV1> = {}): MonitorCheckV1 {
  return {
    version: "1", sellerId, url: `https://${sellerId}.example/x402`, verdict: "OK", settlementTx: "ab".repeat(32),
    checkedAt: new Date(now.getTime() - hoursAgo * 3_600_000).toISOString(), ...overrides,
  };
}

test("only our own sellers and dated grants count as consent", () => {
  assert.equal(hasConsent("self"), true);
  assert.equal(hasConsent("granted:2026-11-03"), true);
  assert.equal(hasConsent("pending"), false);
  assert.equal(hasConsent("granted:"), false);
  assert.equal(hasConsent("granted:yes"), false);
});

test("never buys from a seller without consent, even when enabled", () => {
  const due = dueSellers([seller("nirium", { consent: "pending" }), seller("ours")], [], now, 10);

  assert.deepEqual(due.map((s) => s.id), ["ours"]);
});

test("respects disabled sellers, the minimum interval and the daily cap", () => {
  const sellers = [seller("off", { enabled: false }), seller("recent"), seller("capped", { minIntervalHours: 1 }), seller("ready")];
  const history = [check("recent", 2), check("capped", 3), check("capped", 5), check("ready", 7)];

  assert.deepEqual(dueSellers(sellers, history, now, 10).map((s) => s.id), ["ready"]);
});

test("caps how many paid checks one run makes", () => {
  const sellers = [seller("a"), seller("b"), seller("c")];

  assert.deepEqual(dueSellers(sellers, [], now, 2).map((s) => s.id), ["a", "b"]);
  assert.deepEqual(dueSellers(sellers, [], now, 0), []);
});

test("refuses a 402 above the agreed price, or a malformed one", () => {
  const s = seller("a", { maxPriceAtomic: "200000" });

  assert.equal(priceWithinCap(s, "200000"), true);
  assert.equal(priceWithinCap(s, "200001"), false);
  assert.equal(priceWithinCap(s, "0"), false);
  assert.equal(priceWithinCap(s, "1e6"), false);
});

test("the feed counts delivered and proven checks and shows the latest one", () => {
  const history = [
    check("a", 30, { contentProven: true }),
    check("a", 10, { verdict: "NOT_DELIVERED", settlementTx: "cd".repeat(32), receiptFile: "docs/delivery/a/2.json" }),
    check("a", 20, { verdict: "ERROR", error: "timeout" }),
  ];

  const feed = buildFeed([seller("a"), seller("silent", { consent: "pending" })], history, now);

  assert.equal(feed.sellers.length, 1);
  assert.deepEqual(feed.sellers[0], {
    id: "a", name: "a", url: "https://a.example/x402", consent: "self",
    checks: 3, delivered: 1, proven: 1,
    lastCheckedAt: history[1]?.checkedAt, lastVerdict: "NOT_DELIVERED",
    lastSettlementTx: "cd".repeat(32), lastReceiptFile: "docs/delivery/a/2.json",
  });
});
