import assert from "node:assert/strict";
import test from "node:test";

import { assessMemoryRisk } from "../../../packages/plugin-eliza/src/index.js";
import { honestMarketData, poisonedMarketData } from "../src/catalog.js";
import { startSeller, type SellerHandle } from "../src/resource-server.js";

const requirements = {
  scheme: "exact",
  network: "stellar:testnet",
  asset: "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
  amount: "100000",
  payTo: "GDARKECJYS4TXQ3AZOOKA4HCQ5AEJEPZBKQAUXQSDOCO5EEZ76F377WJ",
  maxTimeoutSeconds: 120,
  extra: { areFeesSponsored: true },
};

async function withSeller(
  port: number,
  body: () => { readonly contentType: string; readonly payload: unknown },
  run: (handle: SellerHandle) => Promise<void>,
): Promise<void> {
  const handle = await startSeller({
    name: "test-seller",
    port,
    resourcePath: "/market-data",
    requirements,
    // Never reached: these tests stop at the 402, before any facilitator call.
    facilitatorUrl: "http://127.0.0.1:1",
    body,
  });
  try {
    await run(handle);
  } finally {
    await handle.close();
  }
}

test("an unpaid request gets a 402 carrying the payment requirements", async () => {
  await withSeller(4591, honestMarketData, async (handle) => {
    const response = await fetch(handle.url);

    assert.equal(response.status, 402);
    const body = (await response.json()) as { x402Version?: number; accepts?: unknown[] };
    assert.equal(body.x402Version, 2);
    assert.equal(body.accepts?.length, 1);
    assert.deepEqual(body.accepts?.[0], requirements);
  });
});

test("the 402 never leaks the content behind the paywall", async () => {
  await withSeller(4592, poisonedMarketData, async (handle) => {
    const text = await (await fetch(handle.url)).text();

    assert.ok(!text.includes("GATTACKER7X"));
    assert.ok(!text.includes("Nota del sistema"));
  });
});

test("an unknown path is not a paywall", async () => {
  await withSeller(4593, honestMarketData, async (handle) => {
    const response = await fetch(new URL("/not-a-resource", handle.url));
    assert.equal(response.status, 404);
  });
});

test("a malformed payment header is treated as no payment, not as a bypass", async () => {
  await withSeller(4594, honestMarketData, async (handle) => {
    const response = await fetch(handle.url, { headers: { "payment-signature": "%%%not-base64%%%" } });
    assert.equal(response.status, 402);
  });
});

// The demo's whole argument rests on this payload actually tripping the
// detector; if the corpus drifts, the demo silently becomes theatre.
test("the poisoned payload really does cross the quarantine threshold", () => {
  const body = JSON.stringify(poisonedMarketData().payload);
  const risk = assessMemoryRisk(body, "tool");

  assert.ok(risk.taintScore >= 60, `expected >= 60, got ${String(risk.taintScore)}`);
  assert.ok(risk.signals.length > 0);
});

test("the honest payload stays below the threshold", () => {
  const body = JSON.stringify(honestMarketData().payload);
  const risk = assessMemoryRisk(body, "tool");

  assert.ok(risk.taintScore < 60);
  assert.equal(risk.signals.length, 0);
});
