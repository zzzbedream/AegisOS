import assert from "node:assert/strict";
import test from "node:test";

import { anchorRoute, type ReceiptFileV1 } from "../src/receipt-check.js";

const notarization = {} as NonNullable<ReceiptFileV1["notarization"]>;
const range = {} as NonNullable<ReceiptFileV1["range"]>;

test("a receipt counted only in its account range is proven by that range", () => {
  assert.equal(anchorRoute({ notarization, range }), "range");
});

test("a range without the notarization it recomputes proves nothing: fall back and fail closed", () => {
  assert.equal(anchorRoute({ range }), "search");
});

test("an explicit anchor wins, whatever else the file carries", () => {
  assert.equal(anchorRoute({ anchor: { mode: "individual", contractId: "C" }, notarization, range }), "individual");
  assert.equal(
    anchorRoute({ anchor: { mode: "batch", contractId: "C", root: "r", proof: [] } as never, notarization, range }),
    "batch",
  );
});

test("a legacy receipt with nothing attached is searched for in every published contract", () => {
  assert.equal(anchorRoute({}), "search");
});
