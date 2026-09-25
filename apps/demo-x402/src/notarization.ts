import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { accountFromSellerId, type DeliveryReceiptV1 } from "../../../packages/proof/src/index.js";
import { paymentChainLink, type AccountHead } from "../../../packages/x402/src/index.js";
import type { PaymentNotarization } from "./agent.js";
import type { ReceiptCheck } from "./receipt-check.js";

/**
 * The public payment log of an AegisOS account.
 *
 * The account keeps only (seq, chain_head) on-chain. This log lists every
 * link — (seq, commitment, seller, amount) — so anyone can replay the chain
 * from zero and land on the head the contract holds. A missing, reordered or
 * invented payment breaks the replay. Public data: hashes, addresses, amounts.
 */

export const PAYMENT_LOG_DIR = ".aegis/payment-log";
const ZERO_HEAD = "00".repeat(32);

export type PaymentLogEntry = Omit<PaymentNotarization, "account" | "consistent">;

export function paymentLogPath(account: string, dir: string = PAYMENT_LOG_DIR): string {
  return join(dir, `${account}.json`);
}

export function readPaymentLog(account: string, dir: string = PAYMENT_LOG_DIR): readonly PaymentLogEntry[] {
  const path = paymentLogPath(account, dir);
  return existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as PaymentLogEntry[]) : [];
}

/** Append one notarized payment. Rewrites the file; the log is small. */
export function appendPaymentLog(n: PaymentNotarization, dir: string = PAYMENT_LOG_DIR): string {
  const { account, consistent: _consistent, ...entry } = n;
  const log = readPaymentLog(account, dir).filter((e) => e.seq !== entry.seq);
  const next = [...log, entry].sort((a, b) => Number(BigInt(a.seq) - BigInt(b.seq)));
  mkdirSync(dir, { recursive: true });
  const path = paymentLogPath(account, dir);
  writeFileSync(path, `${JSON.stringify(next, null, 2)}\n`, "utf8");
  return path;
}

export interface ReplayResult {
  readonly ok: boolean;
  readonly seq: bigint;
  readonly head: string;
  readonly error?: string;
}

/** Replay the log from the zero head, checking every link. */
export function replayPaymentLog(log: readonly PaymentLogEntry[]): ReplayResult {
  let head = ZERO_HEAD;
  let seq = 0n;
  for (const entry of log) {
    const expectedSeq = seq + 1n;
    if (BigInt(entry.seq) !== expectedSeq) {
      return { ok: false, seq, head, error: `gap: expected seq ${expectedSeq.toString()}, found ${entry.seq}` };
    }
    if (entry.previousHead !== head) {
      return { ok: false, seq, head, error: `seq ${entry.seq} does not continue the chain` };
    }
    const link = paymentChainLink({
      previous: head,
      seq: expectedSeq,
      commitmentHash: entry.commitmentHash,
      seller: entry.seller,
      amount: BigInt(entry.amount),
    });
    if (link !== entry.chainHead) {
      return { ok: false, seq, head, error: `seq ${entry.seq}: link does not recompute` };
    }
    head = link;
    seq = expectedSeq;
  }
  return { ok: true, seq, head };
}

/**
 * What a third party can establish about a payment from public data only:
 * the account runs the published wasm (so `seq` only advances inside a
 * committed, authority-signed transfer), and this payment is one link of a
 * chain that replays to the head the contract holds right now.
 */
export function notarizationChecks(
  receipt: DeliveryReceiptV1,
  n: PaymentNotarization,
  evidence: {
    readonly deployedWasm: string;
    /** Every account wasm AegisOS published: the current one and any it replaced. */
    readonly publishedWasms: { readonly current: string; readonly superseded: readonly string[] };
    readonly log: readonly PaymentLogEntry[];
    readonly onChainHead: AccountHead;
  },
): readonly ReceiptCheck[] {
  const link = paymentChainLink({
    previous: n.previousHead,
    seq: BigInt(n.seq),
    commitmentHash: n.commitmentHash,
    seller: n.seller,
    amount: BigInt(n.amount),
  });
  const replay = replayPaymentLog(evidence.log);
  const inLog = evidence.log.some((e) => e.seq === n.seq && e.chainHead === n.chainHead);
  const reachesHead =
    replay.ok && replay.seq === evidence.onChainHead.seq && replay.head === evidence.onChainHead.chainHead;
  const isCurrent = evidence.deployedWasm === evidence.publishedWasms.current;
  const isSuperseded = evidence.publishedWasms.superseded.includes(evidence.deployedWasm);
  return [
    {
      name: "account runs the published AegisOS wasm",
      pass: isCurrent || isSuperseded,
      detail: `${evidence.deployedWasm}${isSuperseded ? " (superseded, still published)" : ""}`,
    },
    {
      name: "notarized commitment is the receipt's",
      pass: n.commitmentHash === receipt.commitmentHash,
      detail: n.commitmentHash,
    },
    {
      name: "notarized seller is the receipt's",
      pass: n.seller === accountFromSellerId(receipt.sellerId),
      detail: n.seller,
    },
    {
      name: "chain link recomputes",
      pass: link === n.chainHead,
      detail: `seq ${n.seq}`,
    },
    {
      name: "payment log replays to the on-chain head",
      pass: reachesHead && inLog,
      detail: reachesHead
        ? `${replay.seq.toString()} payment(s), head ${replay.head.slice(0, 16)}…${inLog ? "" : " (this payment is missing from the log)"}`
        : (replay.error ?? `log ends at seq ${replay.seq.toString()}, chain at ${evidence.onChainHead.seq.toString()}`),
    },
  ];
}
