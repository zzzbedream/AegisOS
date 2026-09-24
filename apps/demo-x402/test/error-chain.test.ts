import assert from "node:assert/strict";
import test from "node:test";

import { describeErrorChain } from "../src/error-chain.js";

test("an error with no cause renders exactly one line", () => {
  const out = describeErrorChain(new RangeError("index out of range"));

  assert.equal(out, "RangeError: index out of range");
  assert.doesNotMatch(out, /caused by/);
});

test("the cause line appears in addition to the message (R5)", () => {
  const cause = new Error("connect ECONNREFUSED 127.0.0.1:9");
  const out = describeErrorChain(new TypeError("fetch failed", { cause }));

  assert.match(out, /^TypeError: fetch failed/);
  assert.match(out, /caused by: Error: connect ECONNREFUSED 127\.0\.0\.1:9/);
});

test("nested causes (cause.cause) each get their own line, root last", () => {
  const root = new Error("root cause");
  const middle = new Error("middle", { cause: root });
  const lines = describeErrorChain(new Error("top", { cause: middle })).split("\n");

  assert.equal(lines.length, 3);
  assert.match(lines[0] ?? "", /^Error: top$/);
  assert.match(lines[1] ?? "", /^ {2}caused by: Error: middle$/);
  assert.match(lines[2] ?? "", /^ {4}caused by: Error: root cause$/);
});

test("a self-referencing cause cycle terminates instead of recursing forever", () => {
  const error = new Error("loop");
  error.cause = error;

  const out = describeErrorChain(error);

  assert.match(out, /loop/);
  assert.ok(out.split("\n").length <= 10, `bounded output, got ${String(out.split("\n").length)} lines`);
  assert.match(out, /cycle/);
});

test("a thrown non-Error value still renders as itself", () => {
  assert.equal(describeErrorChain("plain string"), "plain string");
  assert.equal(describeErrorChain(undefined), "undefined");
});
