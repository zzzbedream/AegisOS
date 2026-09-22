import assert from "node:assert/strict";
import test from "node:test";
import { runSecurityBenchmark } from "../src/run.js";
import { clopperPearsonLowerBound95, runCmmiCorpus } from "../src/cmmi.js";
import { ATTACK_FAMILIES, CM_MI_CORPUS, LEGITIMATE_CORPUS } from "../src/corpus.js";

test("the frozen MVP corpus has 72 passing deterministic cases", () => {
  const report = runSecurityBenchmark();
  assert.equal(report.total, 72);
  assert.equal(report.passed, 72);
  assert.equal(report.failed, 0);
  assert.equal(report.unauthorizedExecutions, 0);
  assert.equal(report.ledgerValid, true);
});

test("every CM-MI case behaves exactly as the corpus declares", () => {
  const cmmi = runCmmiCorpus();
  assert.deepEqual(cmmi.unexpectedVerdicts, []);
  assert.equal(cmmi.attempts, CM_MI_CORPUS.length);
});

/**
 * The load-bearing assertion. Content that reaches usable context must be
 * exactly the set the corpus declares content analysis cannot catch — no more.
 * An earlier integration bug had MISMATCH deliveries stored as AVAILABLE while
 * reporting QUARANTINED; this is what caught it.
 */
test("only the declared residuals reach the model context", () => {
  const cmmi = runCmmiCorpus();
  assert.equal(cmmi.reachedModelContext, cmmi.declaredResiduals);

  for (const row of cmmi.cases) {
    if (row.reachedModelContext) {
      assert.equal(row.residual, true, `${row.id} reached context but is not a declared residual`);
    }
  }
});

test("everything content analysis is meant to catch is caught", () => {
  const cmmi = runCmmiCorpus();
  assert.equal(cmmi.nonResidualBlocked, cmmi.nonResidualAttempts);
  assert.equal(cmmi.nonResidualBlockRate, 1);
});

test("honest deliveries produce no false positives", () => {
  const cmmi = runCmmiCorpus();
  assert.equal(cmmi.falsePositives, 0);
  assert.equal(cmmi.falsePositiveRate, 0);
  assert.equal(cmmi.legitimateCases, LEGITIMATE_CORPUS.length);
});

test("the corpus exercises every declared attack family", () => {
  const cmmi = runCmmiCorpus();
  const covered = new Set(cmmi.families.filter((f) => f.attempts > 0).map((f) => f.family));
  assert.deepEqual([...covered].sort(), [...ATTACK_FAMILIES].sort());
});

test("Spanish and sub-threshold coverage is present, not optional", () => {
  // These two are the families the plan marks non-negotiable: Spanish because
  // the detector was English-only, and the encoded/multi-turn residuals because
  // they are what proves the layers are complementary rather than redundant.
  const cmmi = runCmmiCorpus();
  const spanish = cmmi.families.find((f) => f.family === "NON_ENGLISH");
  assert.ok(spanish !== undefined && spanish.attempts >= 3);
  assert.equal(spanish.blocked, spanish.attempts);

  const residualFamilies = cmmi.families.filter((f) => f.declaredResiduals > 0);
  assert.ok(residualFamilies.length >= 2, "residuals must be declared, not hidden");
});

test("the Clopper-Pearson bound matches the closed form when every trial succeeds", () => {
  // For k = n the one-sided 95% lower bound reduces to 0.05^(1/n).
  for (const n of [5, 15, 20, 48]) {
    const expected = Math.pow(0.05, 1 / n);
    assert.ok(
      Math.abs(clopperPearsonLowerBound95(n, n) - expected) < 1e-4,
      `n=${String(n)}: got ${String(clopperPearsonLowerBound95(n, n))}, expected ~${String(expected)}`,
    );
  }
});

test("the bound is never above the point estimate and zero when nothing passed", () => {
  assert.equal(clopperPearsonLowerBound95(0, 10), 0);
  assert.ok(clopperPearsonLowerBound95(7, 10) < 0.7);
  assert.ok(clopperPearsonLowerBound95(7, 10) > 0);
});

test("the benchmark report carries the CM-MI metric", () => {
  const report = runSecurityBenchmark();
  assert.equal(report.cmmi.schemaVersion, "aegisos.cmmi-report.v1");
  assert.ok(report.cmmi.blockRate > 0);
  assert.ok(report.cmmi.blockRateLowerBound95 > 0);
});
