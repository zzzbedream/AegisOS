import { generateEd25519KeyPair, generateLocalContentKey } from "@aegisos/core";
import { AegisMemoryGateway, assessMemoryRisk } from "@aegisos/plugin-eliza";
import {
  admitDelivery,
  createPurchaseCommitment,
  sellerIdFromAccount,
  type DeliveryVerdict,
} from "@aegisos/proof";
import {
  ATTACK_FAMILIES,
  CM_MI_CORPUS,
  LEGITIMATE_CORPUS,
  type AttackFamily,
} from "./corpus.js";

const SELLER_ACCOUNT = "GDARKECJYS4TXQ3AZOOKA4HCQ5AEJEPZBKQAUXQSDOCO5EEZ76F377WJ";
const BUYER_ACCOUNT = "GD5D7WRG6SIXIZHNAUOXCTR3MSV5QIM2AM52WRNYX7VBRO76D6V3SVPG";
const T0 = "2030-01-01T12:00:00.000Z";
const T_EXPIRY = "2030-01-01T12:15:00.000Z";

export interface CmmiCaseResult {
  readonly id: string;
  readonly family: AttackFamily;
  readonly expectedVerdict: DeliveryVerdict;
  readonly actualVerdict: DeliveryVerdict;
  readonly asExpected: boolean;
  readonly residual: boolean;
  readonly blocked: boolean;
  /** Measured, not assumed: did the payload come back from `retrieve()`? */
  readonly reachedModelContext: boolean;
  readonly taintScore: number;
}

export interface FamilyBreakdown {
  readonly family: AttackFamily;
  readonly attempts: number;
  readonly blocked: number;
  readonly reachedModelContext: number;
  readonly blockRate: number;
  readonly declaredResiduals: number;
}

export interface CmmiReport {
  readonly schemaVersion: "aegisos.cmmi-report.v1";
  readonly attempts: number;
  readonly blocked: number;
  /** Over the whole corpus, residuals included. The honest headline. */
  readonly blockRate: number;
  readonly blockRateLowerBound95: number;
  /** Excluding families the corpus declares content analysis cannot catch. */
  readonly nonResidualAttempts: number;
  readonly nonResidualBlocked: number;
  readonly nonResidualBlockRate: number;
  readonly nonResidualLowerBound95: number;
  readonly reachedModelContext: number;
  readonly declaredResiduals: number;
  readonly legitimateCases: number;
  readonly falsePositives: number;
  readonly falsePositiveRate: number;
  readonly unexpectedVerdicts: readonly string[];
  readonly families: readonly FamilyBreakdown[];
  readonly cases: readonly CmmiCaseResult[];
}

/**
 * Clopper–Pearson one-sided lower bound at 95%.
 *
 * Solves P(X >= k | n, p) = 0.05 for p by bisection on the binomial upper tail,
 * which is monotone in p. For k = n this reduces to 0.05^(1/n) — a useful sanity
 * check on the implementation.
 *
 * Reported because "100% blocked" over a self-authored corpus is a statement
 * about the corpus; the bound is what makes the sample size legible.
 */
export function clopperPearsonLowerBound95(successes: number, trials: number): number {
  if (trials <= 0) return 0;
  if (successes <= 0) return 0;
  if (successes > trials) throw new Error("successes cannot exceed trials.");

  const alpha = 0.05;
  const upperTail = (p: number): number => {
    let sum = 0;
    for (let i = successes; i <= trials; i += 1) {
      sum += Math.exp(logChoose(trials, i) + i * Math.log(p) + (trials - i) * Math.log1p(-p));
    }
    return sum;
  };

  let low = 0;
  let high = successes / trials;
  for (let iteration = 0; iteration < 200; iteration += 1) {
    const mid = (low + high) / 2;
    if (mid <= 0) break;
    if (upperTail(mid) > alpha) high = mid;
    else low = mid;
  }
  return Number(((low + high) / 2).toFixed(6));
}

function logChoose(n: number, k: number): number {
  return logGamma(n + 1) - logGamma(k + 1) - logGamma(n - k + 1);
}

/** Lanczos approximation; ample for the sample sizes this corpus uses. */
function logGamma(x: number): number {
  const g = [
    676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059,
    12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7,
  ];
  if (x < 0.5) {
    return Math.log(Math.PI / Math.sin(Math.PI * x)) - logGamma(1 - x);
  }
  const z = x - 1;
  let sum = 0.99999999999980993;
  for (let i = 0; i < g.length; i += 1) {
    sum += (g[i] as number) / (z + i + 1);
  }
  const t = z + g.length - 0.5;
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(sum);
}

function commitmentFor(id: string, attester: ReturnType<typeof generateEd25519KeyPair>) {
  return createPurchaseCommitment(
    {
      version: "1",
      id: `commitment:${id}`,
      resourceUrl: "https://seller.example/market-data",
      sellerId: sellerIdFromAccount(SELLER_ACCOUNT),
      expectedContentType: "application/json",
      maxAmountAtomic: "100000",
      assetId: "stellar:USDC",
      committedAt: T0,
      expiresAt: T_EXPIRY,
      nonce: `nonce:${id}`,
    },
    attester,
  );
}

/**
 * Run the corpus through the real admission path — `assessDelivery` plus the
 * gateway — so the metric describes what AegisProof actually does, not what a
 * detector scores in isolation.
 */
export function runCmmiCorpus(): CmmiReport {
  const attester = generateEd25519KeyPair("key:cmmi-attester");
  const cases: CmmiCaseResult[] = [];
  const unexpected: string[] = [];

  for (const testCase of CM_MI_CORPUS) {
    const gateway = new AegisMemoryGateway({ encryptionKey: generateLocalContentKey() });
    const bodyBytes = new TextEncoder().encode(testCase.body);
    const result = admitDelivery(
      commitmentFor(testCase.id, attester),
      {
        responseReceived: true,
        bodyBytes,
        contentType: testCase.contentType,
        sellerId: sellerIdFromAccount(SELLER_ACCOUNT),
        receivedAt: T0,
      },
      {
        assessRisk: (content) => assessMemoryRisk(content, "tool"),
        gateway,
        paymentHash: "f".repeat(64),
        attesterId: `buyer:${BUYER_ACCOUNT}`,
        signer: attester,
        memoryId: testCase.id,
      },
    );

    // Measured, by exact match: is the payload retrievable as usable context?
    // An earlier version compared a 40-char prefix, which made an empty body
    // match everything — `"".includes("")` is true — and reported phantom
    // leaks for the non-delivery cases.
    const usable = gateway.retrieve();
    const reached = testCase.body.length > 0 && usable.some((view) => view.content === testCase.body);
    const verdict = result.assessment.verdict;
    const asExpected = verdict === testCase.expectedVerdict;
    if (!asExpected) {
      unexpected.push(`${testCase.id}: expected ${testCase.expectedVerdict}, got ${verdict}`);
    }

    cases.push({
      id: testCase.id,
      family: testCase.family,
      expectedVerdict: testCase.expectedVerdict,
      actualVerdict: verdict,
      asExpected,
      residual: testCase.residual,
      blocked: verdict !== "OK",
      reachedModelContext: reached,
      taintScore: result.assessment.taintScore,
    });
  }

  let falsePositives = 0;
  for (const legit of LEGITIMATE_CORPUS) {
    const gateway = new AegisMemoryGateway({ encryptionKey: generateLocalContentKey() });
    const result = admitDelivery(
      commitmentFor(legit.id, attester),
      {
        responseReceived: true,
        bodyBytes: new TextEncoder().encode(legit.body),
        contentType: legit.contentType,
        sellerId: sellerIdFromAccount(SELLER_ACCOUNT),
        receivedAt: T0,
      },
      {
        assessRisk: (content) => assessMemoryRisk(content, "tool"),
        gateway,
        paymentHash: "e".repeat(64),
        attesterId: `buyer:${BUYER_ACCOUNT}`,
        signer: attester,
        memoryId: legit.id,
      },
    );
    if (result.assessment.verdict !== "OK") {
      falsePositives += 1;
      unexpected.push(`${legit.id}: legitimate delivery scored ${result.assessment.verdict}`);
    }
  }

  const families = ATTACK_FAMILIES.map((family): FamilyBreakdown => {
    const rows = cases.filter((row) => row.family === family);
    const blocked = rows.filter((row) => row.blocked).length;
    return {
      family,
      attempts: rows.length,
      blocked,
      reachedModelContext: rows.filter((row) => row.reachedModelContext).length,
      blockRate: rows.length === 0 ? 0 : Number((blocked / rows.length).toFixed(4)),
      declaredResiduals: rows.filter((row) => row.residual).length,
    };
  });

  const blocked = cases.filter((row) => row.blocked).length;
  const nonResidual = cases.filter((row) => !row.residual);
  const nonResidualBlocked = nonResidual.filter((row) => row.blocked).length;

  return {
    schemaVersion: "aegisos.cmmi-report.v1",
    attempts: cases.length,
    blocked,
    blockRate: Number((blocked / cases.length).toFixed(4)),
    blockRateLowerBound95: clopperPearsonLowerBound95(blocked, cases.length),
    nonResidualAttempts: nonResidual.length,
    nonResidualBlocked,
    nonResidualBlockRate: Number((nonResidualBlocked / nonResidual.length).toFixed(4)),
    nonResidualLowerBound95: clopperPearsonLowerBound95(nonResidualBlocked, nonResidual.length),
    reachedModelContext: cases.filter((row) => row.reachedModelContext).length,
    declaredResiduals: cases.filter((row) => row.residual).length,
    legitimateCases: LEGITIMATE_CORPUS.length,
    falsePositives,
    falsePositiveRate: Number((falsePositives / LEGITIMATE_CORPUS.length).toFixed(4)),
    unexpectedVerdicts: Object.freeze(unexpected),
    families: Object.freeze(families),
    cases: Object.freeze(cases),
  };
}
