import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { Keypair } from "@stellar/stellar-sdk";
import { rpc } from "@stellar/stellar-sdk";
import { merkleProof, merkleRoot } from "../../../packages/proof/src/index.js";
import {
  MAX_RANGE_LEAVES,
  MAX_RANGE_TAIL,
  TESTNET_PASSPHRASE,
  TESTNET_RPC_URL,
  rangeLeafHash,
  readAccountHead,
  type AegisAnchorClient,
  type ChainStepInput,
  type RangeLeafInput,
} from "../../../packages/x402/src/index.js";
import { readPaymentLog, type PaymentLogEntry } from "./notarization.js";
import { RECEIPTS_DIR, readReceiptFile, saveReceipt, type ReceiptFileV1 } from "./receipt-check.js";

/**
 * Range anchoring: every payment the account notarized, in order, once.
 *
 * The payment log gives each payment's chain fields (authoritative: they must
 * recompute the account's chain on-chain). The saved receipt gives what it
 * delivered (content hash, verdict). A payment without a receipt ends the
 * range; it and everything after ride in the tail — verified, not counted —
 * and are counted by the next range once their receipts exist.
 */

export interface PendingRange {
  readonly fromSeq: bigint;
  readonly leaves: readonly RangeLeafInput[];
  readonly tail: readonly ChainStepInput[];
  readonly files: readonly ReceiptFileV1[];
  readonly leafHashes: readonly string[];
}

function receiptsByCommitment(dir: string): ReadonlyMap<string, ReceiptFileV1> {
  const out = new Map<string, ReceiptFileV1>();
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    const file = readReceiptFile(JSON.parse(readFileSync(join(dir, name), "utf8")) as unknown);
    out.set(file.receipt.commitmentHash, file);
  }
  return out;
}

export function buildPendingRange(
  account: string,
  checkpointSeq: bigint,
  headSeq: bigint,
  dirs: { readonly receipts?: string; readonly log?: string } = {},
): PendingRange | undefined {
  if (headSeq <= checkpointSeq) return undefined;
  const pending = readPaymentLog(account, dirs.log).filter((e) => BigInt(e.seq) > checkpointSeq && BigInt(e.seq) <= headSeq);
  if (BigInt(pending.length) !== headSeq - checkpointSeq) {
    throw new Error(
      `Payment log has ${String(pending.length)} of the ${(headSeq - checkpointSeq).toString()} payments after the checkpoint.`,
    );
  }
  const receipts = receiptsByCommitment(dirs.receipts ?? RECEIPTS_DIR);

  const leaves: RangeLeafInput[] = [];
  const files: ReceiptFileV1[] = [];
  let index = 0;
  for (; index < pending.length && leaves.length < MAX_RANGE_LEAVES; index += 1) {
    const entry = pending[index] as PaymentLogEntry;
    const file = receipts.get(entry.commitmentHash);
    if (file === undefined) break;
    leaves.push({
      seq: BigInt(entry.seq),
      commitmentHash: entry.commitmentHash,
      seller: entry.seller,
      amount: BigInt(entry.amount),
      contentHash: file.receipt.contentHash,
      verdict: file.receipt.verdict,
    });
    files.push(file);
  }
  if (leaves.length === 0) {
    throw new Error(`No receipt for payment seq ${(checkpointSeq + 1n).toString()}; cannot open a range.`);
  }
  const tail = pending.slice(index).map((e) => ({
    commitmentHash: e.commitmentHash,
    seller: e.seller,
    amount: BigInt(e.amount),
  }));
  if (tail.length > MAX_RANGE_TAIL) throw new Error(`Range tail exceeds ${String(MAX_RANGE_TAIL)}.`);

  return {
    fromSeq: checkpointSeq + 1n,
    leaves,
    tail,
    files,
    leafHashes: leaves.map((leaf) => rangeLeafHash(leaf)),
  };
}

export interface AnchoredRange {
  readonly fromSeq: bigint;
  readonly toSeq: bigint;
  readonly root: string;
  readonly tailLength: number;
  readonly transactionHash: string;
  readonly savedPaths: readonly string[];
}

/**
 * Anchor whatever the account has notarized since its checkpoint, then save
 * each receipt again with its range proof. Returns undefined when up to date.
 */
export async function anchorPendingRange(options: {
  readonly client: AegisAnchorClient;
  readonly contractId: string;
  readonly account: string;
  readonly session: Keypair;
  readonly rpcUrl?: string;
}): Promise<AnchoredRange | undefined> {
  const reader = options.session.publicKey();
  const server = new rpc.Server(options.rpcUrl ?? TESTNET_RPC_URL);
  const [checkpoint, head] = await Promise.all([
    options.client.getCheckpoint(options.account, reader),
    readAccountHead(server, TESTNET_PASSPHRASE, options.account, reader),
  ]);
  const range = buildPendingRange(options.account, checkpoint.seq, head.seq);
  if (range === undefined) return undefined;

  const anchored = await options.client.anchorRange(
    options.account, range.fromSeq, range.leaves, options.session, range.tail,
  );
  const root = merkleRoot([...range.leafHashes]);
  const toSeq = range.fromSeq + BigInt(range.leaves.length) - 1n;
  const savedPaths = range.files.map((file, i) =>
    saveReceipt(file.receipt, {
      ...(file.anchor === undefined ? {} : { anchor: file.anchor }),
      ...(file.notarization === undefined ? {} : { notarization: file.notarization }),
      range: {
        contractId: options.contractId,
        account: options.account,
        fromSeq: range.fromSeq.toString(),
        toSeq: toSeq.toString(),
        root,
        proof: merkleProof([...range.leafHashes], i),
        tx: anchored.transactionHash,
      },
    }),
  );
  return { fromSeq: range.fromSeq, toSeq, root, tailLength: range.tail.length, transactionHash: anchored.transactionHash, savedPaths };
}
