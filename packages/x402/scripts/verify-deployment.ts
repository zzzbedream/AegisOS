/**
 * Deployment gate: prove the deployed aegis-proof contract works end to end.
 *
 *   AEGIS_BUYER_SECRET=S... AEGIS_SELLER_ACCOUNT=G... npm run verify:deployment
 *
 * Anchors a fresh TAINTED attestation, reads it back with get_delivery, checks
 * the seller aggregate moved by exactly one, and confirms the same payment hash
 * cannot be anchored twice. Then anchors a full batch of synthetic OK
 * receipts as one Merkle root and proves a random one against the chain.
 * Then the v3 guarantees on the published smart account: it came from the
 * registry's factory, its anchored ranges cover every payment from 1 to the
 * checkpoint with no gap, and the registry refuses an invented payment and an
 * account it did not create. Those refusals fail in simulation: they cost
 * nothing. Replaces the Git Bash script, which failed under
 * WSL; this needs only Node and the TS client the demos already use.
 *
 * Re-runnable: hashes derive from a nonce, so runs never collide.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { Keypair, rpc } from "@stellar/stellar-sdk";
import { generateEd25519KeyPair } from "../../core/src/index.js";
import {
  MAX_BATCH_LEAVES,
  batchLeafForReceipt,
  createDeliveryReceipt,
  merkleProof,
  merkleRoot,
  rootFromProof,
  sellerIdFromAccount,
  type DeliveryReceiptV1,
  type SellerId,
} from "../../proof/src/index.js";
import {
  AegisAnchorClient,
  TESTNET_PASSPHRASE,
  TESTNET_RPC_URL,
  deployedWasmHash,
  readAccountHead,
  type RangeRecordV1,
} from "../src/index.js";

/** Stops a malformed registry from looping the walk forever. */
const MAX_RANGES_WALKED = 256;

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`Missing ${name}.`);
  return value;
}

function hex32(seed: string): string {
  return createHash("sha256").update(seed).digest("hex");
}

let failures = 0;
function check(step: string, pass: boolean, detail: string): void {
  if (!pass) failures += 1;
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${step} — ${detail}`);
}

function syntheticOk(
  seed: string,
  sellerId: SellerId,
  buyerAccount: string,
  signer: ReturnType<typeof generateEd25519KeyPair>,
): DeliveryReceiptV1 {
  return createDeliveryReceipt(
    {
      version: "1",
      commitmentHash: hex32(`verify:batch:commitment:${seed}`),
      paymentHash: hex32(`verify:batch:payment:${seed}`),
      sellerId,
      contentHash: hex32(`verify:batch:content:${seed}`),
      contentBytes: 1,
      contentCanonicalization: "raw-bytes-v1",
      receivedAt: new Date().toISOString(),
      verdict: "OK",
      riskSignals: [],
      taintScore: 35,
      reasons: [],
      assuranceTier: "T2",
      attesterId: `buyer:${buyerAccount}`,
      attesterRole: "buyer",
    },
    signer,
  );
}

async function main(): Promise<void> {
  const deployments = JSON.parse(
    readFileSync(new URL("../../../contracts/deployments/testnet.json", import.meta.url), "utf8"),
  ) as {
    rpcUrl?: string;
    contracts: Record<string, { contractId: string; accountWasmHash?: string }>;
    account?: { address: string; session: string };
    accountV2?: { address: string };
  };
  const contractId = deployments.contracts["aegis-proof"]?.contractId;
  if (contractId === undefined) throw new Error("aegis-proof contract id not found.");

  const buyer = Keypair.fromSecret(requireEnv("AEGIS_BUYER_SECRET"));
  const sellerAccount = requireEnv("AEGIS_SELLER_ACCOUNT");
  const sellerId = sellerIdFromAccount(sellerAccount);
  const nonce = process.argv[2] ?? String(Date.now());
  const client = new AegisAnchorClient({
    contractId,
    ...(deployments.rpcUrl === undefined ? {} : { rpcUrl: deployments.rpcUrl }),
  });

  const receipt = createDeliveryReceipt(
    {
      version: "1",
      commitmentHash: hex32(`verify:commitment:${nonce}`),
      paymentHash: hex32(`verify:payment:${nonce}`),
      sellerId,
      contentHash: hex32(`verify:content:${nonce}`),
      contentBytes: 1,
      contentCanonicalization: "raw-bytes-v1",
      receivedAt: new Date().toISOString(),
      verdict: "TAINTED",
      riskSignals: [],
      taintScore: 90,
      reasons: ["RISK_THRESHOLD_EXCEEDED"],
      assuranceTier: "T2",
      attesterId: `buyer:${buyer.publicKey()}`,
      attesterRole: "buyer",
    },
    // The contract never sees this signature; an ephemeral key is enough here.
    generateEd25519KeyPair(),
  );

  console.log(`contrato : ${contractId}`);
  console.log(`comprador: ${buyer.publicKey()}`);
  console.log(`vendedor : ${sellerAccount}`);
  console.log(`pago     : ${receipt.paymentHash}`);

  const before = await client.sellerScore(sellerId, buyer);

  const anchored = await client.anchorDelivery(receipt, buyer);
  check("1/11 anchor_delivery", true, anchored.explorerUrl);

  const record = await client.getDelivery(receipt.paymentHash, buyer.publicKey());
  check(
    "2/11 get_delivery",
    record !== undefined &&
      record.contentHash === receipt.contentHash &&
      record.commitmentHash === receipt.commitmentHash &&
      record.verdict === "TAINTED" &&
      record.buyer === buyer.publicKey() &&
      record.anchoredAt > 0,
    record === undefined ? "no record returned" : `verdict ${record.verdict}, ledger time ${String(record.anchoredAt)}`,
  );

  const after = await client.sellerScore(sellerId, buyer);
  check(
    "3/11 seller_score",
    after.tainted === before.tainted + 1 && after.total === before.total + 1,
    `tainted ${String(before.tainted)}→${String(after.tainted)}, total ${String(before.total)}→${String(after.total)}`,
  );

  let duplicateRejected = false;
  let reason = "the duplicate was accepted: history is rewritable";
  try {
    await client.anchorDelivery({ ...receipt, verdict: "OK" }, buyer);
  } catch (error: unknown) {
    duplicateRejected = true;
    reason = (error instanceof Error ? error.message : String(error)).split("\n")[0] ?? "rejected";
  }
  check("4/11 duplicate payment hash rejected", duplicateRejected, reason.slice(0, 120));

  // ---- batches: one transaction for a full batch of OK deliveries
  const signer = generateEd25519KeyPair();
  const okReceipts = Array.from({ length: MAX_BATCH_LEAVES }, (_, i) =>
    syntheticOk(`${nonce}:${String(i)}`, sellerId, buyer.publicKey(), signer),
  );
  const leaves = okReceipts.map(batchLeafForReceipt);
  const root = merkleRoot(leaves);
  const batched = await client.anchorBatch({ sellerId, root, count: okReceipts.length }, buyer);
  const onChain = await client.getBatch(root, buyer.publicKey());
  check(
    "5/11 anchor_batch + get_batch",
    onChain !== undefined && onChain.count === MAX_BATCH_LEAVES && onChain.buyer === buyer.publicKey(),
    `${String(MAX_BATCH_LEAVES)} receipts, 1 tx: ${batched.explorerUrl}`,
  );

  const pick = Math.floor(Math.random() * okReceipts.length);
  const proof = merkleProof(leaves, pick);
  const proven = rootFromProof(batchLeafForReceipt(okReceipts[pick] as DeliveryReceiptV1), proof.steps);
  const final = await client.sellerScore(sellerId, buyer);
  check(
    "6/11 random receipt proves into the anchored root",
    onChain !== undefined && proven === onChain.root &&
      (final.batchedOk ?? 0) === (after.batchedOk ?? 0) + MAX_BATCH_LEAVES,
    `receipt #${String(pick)}, ${String(proof.steps.length)} steps · batched_ok ${String(after.batchedOk ?? 0)}→${String(final.batchedOk ?? 0)}`,
  );

  await verifySmartAccount(deployments, client, buyer, sellerAccount, nonce);

  console.log(failures === 0 ? `PASS: contrato ${contractId} verificado en testnet` : `${String(failures)} comprobación(es) fallaron`);
  process.exitCode = failures === 0 ? 0 : 1;
}

/** Walk the ranges from seq 1: each must start right after the previous one. */
async function walkRanges(
  client: AegisAnchorClient,
  account: string,
  reader: string,
  checkpointSeq: bigint,
): Promise<{ ranges: RangeRecordV1[]; gapAt?: bigint }> {
  const ranges: RangeRecordV1[] = [];
  let from = 1n;
  while (from <= checkpointSeq && ranges.length < MAX_RANGES_WALKED) {
    const range = await client.getRange(account, from, reader);
    if (range === undefined) return { ranges, gapAt: from };
    ranges.push(range);
    from = range.toSeq + 1n;
  }
  return { ranges };
}

async function refusal(attempt: Promise<unknown>): Promise<string | undefined> {
  try {
    await attempt;
    return undefined;
  } catch (error: unknown) {
    return (error instanceof Error ? error.message : String(error)).split("\n")[0] ?? "refused";
  }
}

async function verifySmartAccount(
  deployments: {
    contracts: Record<string, { contractId: string; accountWasmHash?: string }>;
    account?: { address: string; session: string };
    accountV2?: { address: string };
  },
  client: AegisAnchorClient,
  buyer: Keypair,
  sellerAccount: string,
  nonce: string,
): Promise<void> {
  const account = deployments.account;
  const wasmHash = deployments.contracts["aegis-proof"]?.accountWasmHash;
  if (account === undefined || wasmHash === undefined) {
    check("7/11 smart account published", false, "testnet.json has no v3 account or account wasm");
    return;
  }
  if (account.session !== buyer.publicKey()) {
    check("7/11 smart account published", false, `session key is ${account.session}, not this buyer`);
    return;
  }
  const reader = buyer.publicKey();
  const server = new rpc.Server(TESTNET_RPC_URL);
  console.log(`cuenta   : ${account.address}`);

  const [registered, deployed] = await Promise.all([
    client.isAccount(account.address, reader),
    deployedWasmHash(server, account.address),
  ]);
  check(
    "7/11 account created by the registry factory",
    registered && deployed === wasmHash,
    `is_account ${String(registered)}, wasm ${deployed.slice(0, 16)}… (published ${wasmHash.slice(0, 16)}…)`,
  );

  const [checkpoint, head] = await Promise.all([
    client.getCheckpoint(account.address, reader),
    readAccountHead(server, TESTNET_PASSPHRASE, account.address, reader),
  ]);
  check(
    "8/11 checkpoint never passes the account head",
    checkpoint.seq <= head.seq,
    `checkpoint ${checkpoint.seq.toString()}, head ${head.seq.toString()}` +
      (head.seq > checkpoint.seq ? ` (${(head.seq - checkpoint.seq).toString()} pending)` : ""),
  );

  const { ranges, gapAt } = await walkRanges(client, account.address, reader, checkpoint.seq);
  const counted = ranges.reduce(
    (sum, r) => sum + r.counts.ok + r.counts.tainted + r.counts.mismatch + r.counts.notDelivered,
    0,
  );
  const last = ranges.at(-1);
  check(
    "9/11 ranges cover 1..checkpoint with no gap, each payment counted once",
    gapAt === undefined && (last?.toSeq ?? 0n) === checkpoint.seq && BigInt(counted) === checkpoint.seq,
    gapAt !== undefined
      ? `no range starts at seq ${gapAt.toString()}`
      : `${String(ranges.length)} range(s), ${String(counted)} verdicts counted by the contract`,
  );

  // An invented payment right after the checkpoint: the chain cannot match.
  const invented = {
    seq: checkpoint.seq + 1n,
    commitmentHash: hex32(`verify:invented:commitment:${nonce}`),
    seller: sellerAccount,
    amount: 10_000n,
    contentHash: hex32(`verify:invented:content:${nonce}`),
    verdict: "OK" as const,
  };
  const inventedRefused = await refusal(client.anchorRange(account.address, checkpoint.seq + 1n, [invented], buyer));
  check(
    "10/11 an invented payment is refused on-chain",
    inventedRefused !== undefined && /#1[23]\b/.test(inventedRefused),
    (inventedRefused ?? "the invented payment was anchored").slice(0, 120),
  );

  const stranger = deployments.accountV2?.address;
  if (stranger === undefined) {
    check("11/11 an account the registry did not create is refused", false, "no accountV2 to try");
    return;
  }
  const strangerRefused = await refusal(client.anchorRange(stranger, 1n, [{ ...invented, seq: 1n }], buyer));
  check(
    "11/11 an account the registry did not create is refused",
    strangerRefused !== undefined && /#8\b/.test(strangerRefused),
    (strangerRefused ?? "the stranger's range was anchored").slice(0, 120),
  );
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
