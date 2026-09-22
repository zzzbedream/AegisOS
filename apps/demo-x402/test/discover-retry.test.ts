import assert from "node:assert/strict";
import test from "node:test";

import { Keypair } from "@stellar/stellar-sdk";

import { generateEd25519KeyPair } from "../../../packages/core/src/index.js";
import type { ForkedSigner } from "../../../packages/x402/src/index.js";
import { DemoAgent } from "../src/agent.js";

/** Port 9 (discard): never dialed — fetch is mocked below, so this runs offline. */
const OFFER_URL = "http://127.0.0.1:9/market-data";

const requirements = {
  scheme: "exact",
  network: "stellar:testnet",
  asset: "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
  amount: "100000",
  payTo: "GDARKECJYS4TXQ3AZOOKA4HCQ5AEJEPZBKQAUXQSDOCO5EEZ76F377WJ",
  maxTimeoutSeconds: 120,
  extra: { areFeesSponsored: true },
};

/**
 * discover() never touches the signer, the buyer key or the RPC, so the
 * collaboration it does not use is stubbed rather than forked.
 */
function makeAgent(): DemoAgent {
  return new DemoAgent({
    signer: { address: "GSTUB", pid: undefined } as unknown as ForkedSigner,
    buyer: Keypair.random(),
    attester: generateEd25519KeyPair("key:test-attester"),
    buyerPublicKey: "GTEST",
    rpcUrl: "http://127.0.0.1:1",
  });
}

function offer402(): Response {
  return new Response(JSON.stringify({ x402Version: 2, accepts: [requirements] }), {
    status: 402,
    headers: { "content-type": "application/json" },
  });
}

/**
 * Replace global fetch with a script and hand the call log back to `run`.
 * Restored in finally so a failing assertion cannot leak into the next test.
 */
async function withMockedFetch(
  respond: (attempt: number) => Promise<Response>,
  run: (calls: readonly string[]) => Promise<void>,
): Promise<void> {
  const original = globalThis.fetch;
  const calls: string[] = [];
  globalThis.fetch = (async (input: unknown): Promise<Response> => {
    calls.push(String(input));
    return respond(calls.length);
  }) as typeof fetch;
  try {
    await run(calls);
  } finally {
    globalThis.fetch = original;
  }
}

test("discover makes exactly one request when the seller answers on the first try", async () => {
  await withMockedFetch(
    async () => offer402(),
    async (calls) => {
      const offer = await makeAgent().discover(OFFER_URL);

      assert.equal(calls.length, 1, "a clean exchange must not trigger a second request");
      assert.equal(calls[0], OFFER_URL);
      assert.equal(offer.requirements.amount, requirements.amount);
    },
  );
});

test("discover survives a transport failure once by retrying exactly one time", async () => {
  await withMockedFetch(
    async (attempt) => {
      if (attempt === 1) throw new TypeError("fetch failed");
      return offer402();
    },
    async (calls) => {
      const offer = await makeAgent().discover(OFFER_URL);

      assert.equal(calls.length, 2, "one transport failure means one retry, no more");
      assert.equal(offer.requirements.amount, requirements.amount);
    },
  );
});

test("discover surfaces the URL and the original transport error when the retry also fails", async () => {
  const first = new TypeError("fetch failed");
  const second = new TypeError("read ECONNRESET");
  await withMockedFetch(
    async (attempt) => {
      throw attempt === 1 ? first : second;
    },
    async (calls) => {
      const error = await makeAgent()
        .discover(OFFER_URL)
        .then(
          () => undefined,
          (thrown: unknown) => thrown as Error,
        );

      assert.ok(error, "a double transport failure must reject");
      assert.match(error.message, /http:\/\/127\.0\.0\.1:9\/market-data/, "the message names the URL");
      assert.match(error.message, /ECONNRESET/, "the retry's failure is not discarded");
      assert.match(error.message, /fetch failed/, "the first failure is not discarded");
      assert.equal(error.cause, first, "cause preserves the original transport error");
      assert.equal(calls.length, 2, "the failure happened after the single retry");
    },
  );
});

test("discover does not retry when the seller did answer, even with an error status", async () => {
  await withMockedFetch(
    async () => new Response("upstream unhappy", { status: 503 }),
    async (calls) => {
      const error = await makeAgent()
        .discover(OFFER_URL)
        .then(
          () => undefined,
          (thrown: unknown) => thrown as Error,
        );

      assert.ok(error, "a non-402 must still reject");
      assert.match(error.message, /Expected 402/, "the current error keeps its wording");
      assert.equal(calls.length, 1, "a response is not a transport failure: no retry");
    },
  );
});
