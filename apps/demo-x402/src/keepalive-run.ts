/**
 * Keep the ledger entries behind the public evidence alive on testnet:
 *
 *   npm run keepalive                          # report only; exit 1 if anything needs rent
 *   AEGIS_BUYER_SECRET=... npm run keepalive   # restore archived entries, extend the rest
 *
 * Reads contracts/deployments/testnet.json and docs/evidence/*\/receipt.json. Restoring
 * and extending are permissionless; the source account only pays the rent.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

import { Keypair, Operation, SorobanDataBuilder, TransactionBuilder, rpc, xdr } from "@stellar/stellar-sdk";
import { accountFromSellerId, type DeliveryReceiptV1 } from "../../../packages/proof/src/index.js";
import { TESTNET_PASSPHRASE, TESTNET_RPC_URL } from "../../../packages/x402/src/index.js";
import { describeErrorChain } from "./error-chain.js";
import {
  KEEPALIVE_EXTEND_TO_LEDGERS,
  keepaliveEntries,
  ttlAction,
  type KeepaliveSources,
  type KeptEntry,
  type TtlAction,
} from "./keepalive.js";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const EVIDENCE = join(root, "docs/evidence");
const POLL_ATTEMPTS = 30;
const POLL_INTERVAL_MS = 1000;

interface Deployments {
  readonly contracts: Record<string, { readonly contractId: string; readonly wasmHash: string; readonly status?: string }>;
  readonly account: { readonly address: string; readonly wasmHash: string };
}

interface PublishedReceipt {
  readonly receipt: DeliveryReceiptV1;
  readonly range?: { readonly contractId: string; readonly account: string; readonly fromSeq: string };
}

function loadSources(): KeepaliveSources {
  const deployments = JSON.parse(readFileSync(join(root, "contracts/deployments/testnet.json"), "utf8")) as Deployments;
  const current = Object.values(deployments.contracts).find((c) => c.status === undefined);
  if (current === undefined) throw new Error("No current registry in testnet.json.");
  const receipts = readdirSync(EVIDENCE)
    .map((dir) => join(EVIDENCE, dir, "receipt.json"))
    .filter((path) => existsSync(path))
    .map((path) => JSON.parse(readFileSync(path, "utf8")) as PublishedReceipt);
  const ranged = receipts.filter((r) => r.range !== undefined);
  return {
    registry: { contractId: current.contractId, wasmHash: current.wasmHash },
    account: deployments.account,
    ranges: ranged.map((r) => r.range as NonNullable<PublishedReceipt["range"]>),
    sellers: ranged.map((r) => accountFromSellerId(r.receipt.sellerId)),
  };
}

async function submit(server: rpc.Server, source: Keypair, operation: xdr.Operation, keys: readonly xdr.LedgerKey[], readWrite: boolean): Promise<string> {
  const data = readWrite
    ? new SorobanDataBuilder().setReadWrite([...keys]).build()
    : new SorobanDataBuilder().setReadOnly([...keys]).build();
  const built = new TransactionBuilder(await server.getAccount(source.publicKey()), { fee: "100", networkPassphrase: TESTNET_PASSPHRASE })
    .addOperation(operation)
    .setSorobanData(data)
    .setTimeout(60)
    .build();
  const prepared = await server.prepareTransaction(built);
  prepared.sign(source);
  const sent = await server.sendTransaction(prepared);
  if (sent.status === "ERROR") throw new Error(`Submission rejected: ${sent.errorResult?.toXDR("base64") ?? "unknown"}`);
  for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt += 1) {
    const status = await server.getTransaction(sent.hash);
    if (status.status === "SUCCESS") return sent.hash;
    if (status.status === "FAILED") throw new Error(`Transaction ${sent.hash} failed.`);
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  throw new Error(`Transaction ${sent.hash} not confirmed in time.`);
}

async function main(): Promise<void> {
  const server = new rpc.Server(TESTNET_RPC_URL);
  const entries = keepaliveEntries(loadSources());
  const { entries: found, latestLedger } = await server.getLedgerEntries(...entries.map((e) => e.key));
  const liveUntil = new Map(found.map((f) => [f.key.toXDR("base64"), f.liveUntilLedgerSeq]));

  const plan: { readonly entry: KeptEntry; readonly action: TtlAction }[] = entries.map((entry) => ({
    entry,
    action: ttlAction(liveUntil.get(entry.key.toXDR("base64")), latestLedger),
  }));
  for (const { entry, action } of plan) {
    const until = liveUntil.get(entry.key.toXDR("base64"));
    const days = action === "restore" ? "archived" : `${(((until ?? latestLedger) - latestLedger) / 17_280).toFixed(1)} days left`;
    console.log(`  ${action === "ok" ? "OK     " : action.toUpperCase().padEnd(7)}  ${entry.label} — ${days}`);
  }

  const restore = plan.filter((p) => p.action === "restore").map((p) => p.entry.key);
  const extend = plan.filter((p) => p.action !== "ok").map((p) => p.entry.key);
  if (extend.length === 0) {
    console.log("Todo vivo: nada que extender.");
    return;
  }
  const secret = process.env["AEGIS_BUYER_SECRET"];
  if (secret === undefined || secret === "") {
    console.log(`${String(extend.length)} entrada(s) necesitan renta. Corre con AEGIS_BUYER_SECRET para arreglarlo.`);
    process.exitCode = 1;
    return;
  }
  const source = Keypair.fromSecret(secret);
  if (restore.length > 0) {
    const hash = await submit(server, source, Operation.restoreFootprint({}), restore, true);
    console.log(`  restauradas ${String(restore.length)}: https://stellar.expert/explorer/testnet/tx/${hash}`);
  }
  const hash = await submit(server, source, Operation.extendFootprintTtl({ extendTo: KEEPALIVE_EXTEND_TO_LEDGERS }), extend, false);
  console.log(`  extendidas ${String(extend.length)} a ~60 días: https://stellar.expert/explorer/testnet/tx/${hash}`);
}

main().catch((error: unknown) => {
  console.error(describeErrorChain(error));
  process.exitCode = 1;
});
