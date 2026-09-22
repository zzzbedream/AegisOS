import assert from "node:assert/strict";
import test from "node:test";

import {
  X402ProtocolError,
  X402_PAYMENT_REQUIRED_HEADER,
  decodePaymentResponse,
  encodePaymentRequired,
  encodePaymentResponse,
  encodePaymentSignature,
  parsePaymentRequired,
  selectAccepts,
  type HeaderReader,
} from "../src/index.js";

/**
 * The `Payment-Required` header returned by Stellar Bazaar x402
 * (bazaar.browns.studio) for its Swap Risk Quote sandbox, captured verbatim on
 * 2026-09-22. A third party's real wire output — the most honest fixture there
 * is for a parser that must work against services we do not control.
 */
const BAZAAR_PAYMENT_REQUIRED =
  "eyJ4NDAyVmVyc2lvbiI6MiwiZXJyb3IiOiJQYXltZW50IHJlcXVpcmVkIiwicmVzb3VyY2UiOnsidXJsIjoiaHR0cHM6Ly9iYXphYXIuYnJvd25zLnN0dWRpby9hcGkveDQwMi9zd2FwLXJpc2s/cGFpcj1YTE0lMkZVU0RDJmFtb3VudD0yNTAwJnNpZGU9YnV5IiwiZGVzY3JpcHRpb24iOiJEZXRlcm1pbmlzdGljIHJlYWQtb25seSBTd2FwIFJpc2sgUXVvdGU7IGluZm9ybWF0aW9uYWwgb25seS4iLCJtaW1lVHlwZSI6ImFwcGxpY2F0aW9uL2pzb24ifSwiYWNjZXB0cyI6W3sic2NoZW1lIjoiZXhhY3QiLCJuZXR3b3JrIjoic3RlbGxhcjp0ZXN0bmV0IiwicGF5VG8iOiJHRFZSMktESzVEU01OWVpKS05JU1VJT0JEQzZGWkszWFpPSVFXU1M3S0w0QlJNRDVCTVc2Uk1DUSIsImFzc2V0IjoiQ0JJRUxUSzZZQlpKVTVVUDJXV1FFVUNZS0xQVTZBVU5aMkJRNFdXRkVJRTNVU0NJSE1YUURBTUEiLCJhbW91bnQiOiIxMDAwMCIsIm1heFRpbWVvdXRTZWNvbmRzIjo2MCwiZXh0cmEiOnsiYXJlRmVlc1Nwb25zb3JlZCI6dHJ1ZSwicmVzb3VyY2VVcmwiOiJodHRwczovL2JhemFhci5icm93bnMuc3R1ZGlvL2FwaS94NDAyL3N3YXAtcmlzaz9wYWlyPVhMTSUyRlVTREMmYW1vdW50PTI1MDAmc2lkZT1idXkiLCJtZXRob2QiOiJHRVQiLCJyb3V0ZSI6Ii9hcGkveDQwMi9zd2FwLXJpc2siLCJpbnB1dEhhc2giOiJXRXhOTDFWVFJFTjhNalV3TUh4aWRYayJ9fV19";

const BAZAAR_PAY_TO = "GDVR2KDK5DSMNYZJKNISUIOBDC6FZK3XZOIQWSS7KL4BRMD5BMW6RMCQ";
const USDC_SAC = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

function headersOf(map: Record<string, string>): HeaderReader {
  const lower = Object.fromEntries(Object.entries(map).map(([k, v]) => [k.toLowerCase(), v]));
  return (name) => lower[name.toLowerCase()];
}

const noHeaders: HeaderReader = () => undefined;

// ---------------------------------------------------------- a real seller

test("parses a real third-party 402 from its Payment-Required header", () => {
  const required = parsePaymentRequired(headersOf({ "Payment-Required": BAZAAR_PAYMENT_REQUIRED }));

  assert.equal(required.x402Version, 2);
  assert.equal(required.accepts.length, 1);
  const offer = required.accepts[0];
  assert.equal(offer?.scheme, "exact");
  assert.equal(offer?.network, "stellar:testnet");
  assert.equal(offer?.payTo, BAZAAR_PAY_TO);
  assert.equal(offer?.asset, USDC_SAC);
  assert.equal(offer?.amount, "10000");
  assert.equal(offer?.maxTimeoutSeconds, 60);
});

test("the seller's extra survives verbatim, including fields we never knew about", () => {
  // Rebuilding `extra` from the facilitator's /supported — which our first
  // version did — would keep areFeesSponsored and drop everything else. The
  // seller's verification depends on exactly those dropped fields.
  const required = parsePaymentRequired(headersOf({ "Payment-Required": BAZAAR_PAYMENT_REQUIRED }));
  const extra = required.accepts[0]?.extra ?? {};

  assert.equal(extra["areFeesSponsored"], true);
  assert.equal(extra["method"], "GET");
  assert.equal(extra["route"], "/api/x402/swap-risk");
  assert.equal(extra["inputHash"], "WExNL1VTREN8MjUwMHxidXk");
  assert.match(String(extra["resourceUrl"]), /bazaar\.browns\.studio\/api\/x402\/swap-risk/);
});

test("the seller binds its inputs into the offer, not its output", () => {
  // inputHash is base64url of the query. The seller commits to what was
  // asked; AegisProof commits to what was delivered. Complementary layers.
  const required = parsePaymentRequired(headersOf({ "Payment-Required": BAZAAR_PAYMENT_REQUIRED }));
  const inputHash = String(required.accepts[0]?.extra["inputHash"]);

  assert.equal(Buffer.from(inputHash, "base64url").toString("utf8"), "XLM/USDC|2500|buy");
});

test("the resource description is carried through", () => {
  const required = parsePaymentRequired(headersOf({ "Payment-Required": BAZAAR_PAYMENT_REQUIRED }));
  assert.equal(required.resource?.mimeType, "application/json");
  assert.match(String(required.resource?.description), /Swap Risk Quote/);
});

// ------------------------------------------------------- header vs body

test("the header wins over the body when both are present", () => {
  const conflicting = {
    x402Version: 2,
    accepts: [{
      scheme: "exact", network: "stellar:testnet", payTo: "GSOMEONEELSE",
      asset: USDC_SAC, amount: "999999", maxTimeoutSeconds: 60, extra: {},
    }],
  };
  const required = parsePaymentRequired(
    headersOf({ "Payment-Required": BAZAAR_PAYMENT_REQUIRED }),
    conflicting,
  );
  assert.equal(required.accepts[0]?.payTo, BAZAAR_PAY_TO);
});

test("the body is accepted when a server only populates the body", () => {
  const body = JSON.parse(Buffer.from(BAZAAR_PAYMENT_REQUIRED, "base64").toString("utf8")) as unknown;
  const required = parsePaymentRequired(noHeaders, body);
  assert.equal(required.accepts[0]?.payTo, BAZAAR_PAY_TO);
});

test("a 402 with neither header nor body is refused", () => {
  assert.throws(
    () => parsePaymentRequired(noHeaders),
    (error: unknown) => error instanceof X402ProtocolError && error.code === "NO_PAYMENT_REQUIRED",
  );
});

// ------------------------------------------------ hostile seller input

test("a malformed header is refused, not half-parsed", () => {
  assert.throws(
    () => parsePaymentRequired(headersOf({ "Payment-Required": "%%%not-base64-json%%%" })),
    X402ProtocolError,
  );
});

test("a fractional amount is refused: atomic units are integers", () => {
  const body = {
    x402Version: 2,
    accepts: [{
      scheme: "exact", network: "stellar:testnet", payTo: BAZAAR_PAY_TO,
      asset: USDC_SAC, amount: "0.001", maxTimeoutSeconds: 60, extra: {},
    }],
  };
  assert.throws(
    () => parsePaymentRequired(noHeaders, body),
    (error: unknown) => error instanceof X402ProtocolError && error.code === "MALFORMED_REQUIREMENTS",
  );
});

test("a 402 offering nothing is refused", () => {
  assert.throws(
    () => parsePaymentRequired(noHeaders, { x402Version: 2, accepts: [] }),
    (error: unknown) => error instanceof X402ProtocolError && error.code === "NO_ACCEPTS",
  );
});

test("parsed requirements are frozen so a caller cannot quietly edit an offer", () => {
  const required = parsePaymentRequired(headersOf({ "Payment-Required": BAZAAR_PAYMENT_REQUIRED }));
  const offer = required.accepts[0];
  assert.ok(offer !== undefined);
  assert.throws(() => {
    (offer as unknown as { amount: string }).amount = "1";
  }, TypeError);
  assert.throws(() => {
    (offer.extra as Record<string, unknown>)["route"] = "/elsewhere";
  }, TypeError);
});

// ------------------------------------------------------------ selection

test("selects the offer we can pay", () => {
  const required = parsePaymentRequired(headersOf({ "Payment-Required": BAZAAR_PAYMENT_REQUIRED }));
  const offer = selectAccepts(required, { scheme: "exact", network: "stellar:testnet" });
  assert.equal(offer.payTo, BAZAAR_PAY_TO);
});

test("refuses when the seller only offers a network we cannot use", () => {
  const required = parsePaymentRequired(headersOf({ "Payment-Required": BAZAAR_PAYMENT_REQUIRED }));
  assert.throws(
    () => selectAccepts(required, { scheme: "exact", network: "stellar:pubnet" }),
    (error: unknown) => error instanceof X402ProtocolError && error.code === "UNSUPPORTED_OFFER",
  );
});

// ------------------------------------------------------------ settlement

test("reads the spec PAYMENT-RESPONSE header", () => {
  const header = encodePaymentResponse({ success: true, transaction: "abc123" });
  const settled = decodePaymentResponse(headersOf({ "PAYMENT-RESPONSE": header }));
  assert.equal(settled?.transaction, "abc123");
});

test("still reads the legacy header, so a missing settlement is never a silent guess", () => {
  const header = encodePaymentResponse({ success: true, transaction: "legacy1" });
  const settled = decodePaymentResponse(headersOf({ "x-payment-response": header }));
  assert.equal(settled?.transaction, "legacy1");
});

test("an absent settlement header reads as undefined, not as success", () => {
  assert.equal(decodePaymentResponse(noHeaders), undefined);
});

test("payment-required and payment-signature round-trip", () => {
  const required = parsePaymentRequired(headersOf({ "Payment-Required": BAZAAR_PAYMENT_REQUIRED }));
  const reparsed = parsePaymentRequired(
    headersOf({ [X402_PAYMENT_REQUIRED_HEADER]: encodePaymentRequired(required) }),
  );
  assert.deepEqual(reparsed, required);

  const signed = encodePaymentSignature({ x402Version: 2, payload: { transaction: "AAA" } });
  assert.ok(typeof signed["payment-signature"] === "string");
});
