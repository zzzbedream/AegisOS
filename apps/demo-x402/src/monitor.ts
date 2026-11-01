/**
 * Delivery monitor: buy from consenting x402 sellers on testnet and publish whether
 * each paid call delivered what was charged for.
 *
 *   npm run monitor -- --dry-run                       # what is due; pays nothing
 *   AEGIS_BUYER_SECRET=... npm run monitor             # buy from due sellers in config
 *   AEGIS_BUYER_SECRET=... AEGIS_SELLER_ACCOUNT=G... npm run monitor -- --local-demo
 *                                                      # plus our own seller, run locally
 *
 * Sellers come from config/monitor-sellers.json. Only `self` and `granted:<date>` sellers
 * are ever bought from, at their agreed pace and price (see monitor-policy.ts). Each
 * check lands in docs/evidence/monitor/history.json, its receipt next to it, and the
 * public summary in site/delivery.json.
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Keypair } from "@stellar/stellar-sdk";

import { AegisAnchorClient } from "../../../packages/x402/src/index.js";
import { DemoAgent, discoverOffer } from "./agent.js";
import { saveIndividualReceipt } from "./anchor-report.js";
import { attesterPath, loadAttester } from "./attester.js";
import { honestMarketData } from "./catalog.js";
import { contentProofChecks } from "./content-proof.js";
import { describeErrorChain } from "./error-chain.js";
import { buildFeed, dueSellers, priceWithinCap, type MonitorCheckV1, type MonitoredSeller } from "./monitor-policy.js";
import { PAYMENT_LOG_DIR, paymentLogPath } from "./notarization.js";
import { anchorPendingRange } from "./range.js";
import { reclaimCredentialsFromEnv, reclaimPaidFetch } from "./reclaim-fetch.js";
import { startSeller, type SellerHandle } from "./resource-server.js";
import { openSignerSession, USDC_SAC, type SignerSession } from "./signer-session.js";
import { loadSmartAccount } from "./smart-account-config.js";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const SELLERS_FILE = join(root, "config/monitor-sellers.json");
const MONITOR_DIR = join(root, "docs/evidence/monitor");
const HISTORY_FILE = join(MONITOR_DIR, "history.json");
const FEED_FILE = join(root, "site/delivery.json");
const PUBLISHED_LOG_DIR = join(root, "docs/evidence/payment-log");
const RPC_URL = "https://soroban-testnet.stellar.org";
const MAX_CHECKS_PER_RUN = Number(process.env["AEGIS_MONITOR_MAX_CHECKS"] ?? "3");
const LOCAL_SELLER_PORT = 4511;
const LOCAL_PRICE_ATOMIC = "10000"; // 0.001 USDC

const args = new Set(process.argv.slice(2));
const DRY_RUN = args.has("--dry-run");
const LOCAL_DEMO = args.has("--local-demo");

function readJson<T>(path: string, fallback: T): T {
  return existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as T) : fallback;
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`Missing ${name}.`);
  return value;
}

/** Our own honest seller on 127.0.0.1: consent `self`, no Reclaim (the attestor cannot reach it). */
async function startLocalSeller(): Promise<{ readonly handle: SellerHandle; readonly seller: MonitoredSeller }> {
  const facilitator = process.env["AEGIS_FACILITATOR_URL"] ?? "https://www.x402.org/facilitator";
  const supported = (await (await fetch(`${facilitator}/supported`)).json()) as {
    kinds?: { scheme: string; network: string; extra?: Record<string, unknown> }[];
  };
  const kind = (supported.kinds ?? []).find((k) => k.scheme === "exact" && k.network === "stellar:testnet");
  if (kind === undefined) throw new Error("Facilitator does not support exact on stellar:testnet.");
  const handle = await startSeller({
    name: "aegis-local", port: LOCAL_SELLER_PORT, resourcePath: "/market-data",
    requirements: {
      scheme: "exact", network: "stellar:testnet", asset: USDC_SAC, amount: LOCAL_PRICE_ATOMIC,
      payTo: requireEnv("AEGIS_SELLER_ACCOUNT"), maxTimeoutSeconds: 120, extra: { ...(kind.extra ?? {}) },
    },
    facilitatorUrl: facilitator,
    body: honestMarketData,
  });
  return {
    handle,
    seller: {
      id: "aegis-local", name: "AegisOS demo seller (ours, local)", url: handle.url, consent: "self",
      enabled: true, minIntervalHours: 0, maxChecksPerDay: 10, maxPriceAtomic: LOCAL_PRICE_ATOMIC,
    },
  };
}

function printPlan(sellers: readonly MonitoredSeller[], due: readonly MonitoredSeller[]): void {
  for (const seller of sellers) {
    const isDue = due.some((d) => d.id === seller.id);
    console.log(`  ${isDue ? "DUE " : "SKIP"}  ${seller.id.padEnd(16)} consent=${seller.consent} enabled=${String(seller.enabled)}`);
  }
}

async function main(): Promise<void> {
  const configured = readJson<MonitoredSeller[]>(SELLERS_FILE, []);
  const history = readJson<MonitorCheckV1[]>(HISTORY_FILE, []);
  const now = new Date();

  console.log("AegisOS · monitor de entregas (testnet)");
  let local: Awaited<ReturnType<typeof startLocalSeller>> | undefined;
  let session: SignerSession | undefined;
  try {
    if (LOCAL_DEMO) local = await startLocalSeller();
    const sellers = local === undefined ? configured : [...configured, local.seller];
    const due = dueSellers(sellers, history, now, MAX_CHECKS_PER_RUN);
    printPlan(sellers, due);
    if (DRY_RUN || due.length === 0) {
      console.log(DRY_RUN ? "Dry run: no se pagó nada." : "Nada que revisar ahora.");
      return;
    }

    const buyer = Keypair.fromSecret(requireEnv("AEGIS_BUYER_SECRET"));
    const attester = loadAttester(attesterPath());
    const smart = loadSmartAccount();
    const deployments = readJson<{ contracts: Record<string, { contractId: string }>; reclaim?: { witnesses: string[] } }>(
      join(root, "contracts/deployments/testnet.json"), { contracts: {} },
    );
    const contractId = deployments.contracts["aegis-proof"]?.contractId ?? "";
    const reclaim = reclaimCredentialsFromEnv();

    // Discover every due seller first (free), so the owner's policy names exactly them.
    const offers = [];
    const checks: MonitorCheckV1[] = [];
    for (const seller of due) {
      try {
        const offer = await discoverOffer(seller.url);
        if (!priceWithinCap(seller, offer.requirements.amount)) {
          checks.push({ version: "1", sellerId: seller.id, checkedAt: new Date().toISOString(), url: seller.url,
            priceAtomic: offer.requirements.amount, verdict: "ERROR", error: `price above the agreed cap ${seller.maxPriceAtomic}` });
          continue;
        }
        offers.push({ seller, offer });
      } catch (error: unknown) {
        checks.push({ version: "1", sellerId: seller.id, checkedAt: new Date().toISOString(), url: seller.url,
          verdict: "ERROR", error: describeErrorChain(error) });
      }
    }

    const saved: { readonly sellerId: string; readonly path: string; readonly index: number }[] = [];
    if (offers.length > 0) {
      const maxAmount = offers.map((o) => BigInt(o.offer.requirements.amount)).reduce((a, b) => (a > b ? a : b)).toString();
      session = await openSignerSession({
        buyer, attester, smart,
        allowedSellers: [...new Set(offers.map((o) => o.offer.requirements.payTo))],
        maxAmountAtomic: maxAmount,
      });
      const anchorClient = new AegisAnchorClient({ contractId });
      for (const { seller, offer } of offers) {
        const isLocal = /^https?:\/\/(127\.0\.0\.1|localhost)[:/]/.test(seller.url);
        const agent = new DemoAgent({
          signer: session.signer, buyer, attester, rpcUrl: RPC_URL, anchorClient,
          ...(smart === undefined ? {} : { smartAccount: { address: smart.address } }),
          ...(reclaim === undefined || isLocal ? {} : { paidFetch: reclaimPaidFetch(reclaim) }),
        });
        const checkedAt = new Date().toISOString();
        try {
          const bought = await agent.buy({ resourceUrl: offer.url, requirements: offer.requirements, memoryId: `mem:monitor-${seller.id}` });
          const receipt = bought.admission.receipt;
          const proof = bought.contentProof === undefined ? undefined : contentProofChecks(bought.contentProof.proof, {
            commitmentHash: receipt.commitmentHash, contentHash: receipt.contentHash,
            canonicalization: receipt.contentCanonicalization, trustedWitnesses: deployments.reclaim?.witnesses ?? [],
          });
          const path = saveIndividualReceipt(bought, contractId);
          if (path !== undefined) saved.push({ sellerId: seller.id, path, index: checks.length });
          checks.push({
            version: "1", sellerId: seller.id, checkedAt, url: seller.url, priceAtomic: offer.requirements.amount,
            verdict: bought.admission.assessment.verdict,
            ...(bought.settlementTx === undefined ? {} : { settlementTx: bought.settlementTx }),
            ...(proof === undefined ? {} : { contentProven: proof.length > 0 && proof.every((c) => c.pass) }),
          });
          console.log(`  ${seller.id}: ${bought.admission.assessment.verdict} · tx ${bought.settlementTx ?? "—"}`);
        } catch (error: unknown) {
          checks.push({ version: "1", sellerId: seller.id, checkedAt, url: seller.url, priceAtomic: offer.requirements.amount,
            verdict: "ERROR", error: describeErrorChain(error) });
          console.log(`  ${seller.id}: ERROR — ${describeErrorChain(error)}`);
        }
      }
      if (smart !== undefined) {
        const range = await anchorPendingRange({ client: anchorClient, contractId, account: smart.address, session: buyer });
        if (range !== undefined) console.log(`  rango ${range.fromSeq.toString()}..${range.toSeq.toString()} anclado`);
      }
    }

    // Publish: receipts (now carrying their range), the account's log, history and feed.
    for (const { sellerId, path, index } of saved) {
      const dir = join(MONITOR_DIR, sellerId);
      mkdirSync(dir, { recursive: true });
      const target = join(dir, basename(path));
      copyFileSync(path, target);
      const check = checks[index];
      if (check !== undefined) checks[index] = { ...check, receiptFile: target.slice(root.length).replaceAll("\\", "/") };
    }
    if (smart !== undefined && existsSync(paymentLogPath(smart.address, PAYMENT_LOG_DIR))) {
      mkdirSync(PUBLISHED_LOG_DIR, { recursive: true });
      copyFileSync(paymentLogPath(smart.address, PAYMENT_LOG_DIR), paymentLogPath(smart.address, PUBLISHED_LOG_DIR));
    }
    const nextHistory = [...history, ...checks];
    mkdirSync(MONITOR_DIR, { recursive: true });
    writeFileSync(HISTORY_FILE, `${JSON.stringify(nextHistory, null, 2)}\n`);
    // The local demo seller is ours and ephemeral; the public feed lists configured sellers.
    writeFileSync(FEED_FILE, `${JSON.stringify(buildFeed(configured, nextHistory, new Date()), null, 2)}\n`);
    console.log(`  ${String(checks.length)} check(s) · historial ${HISTORY_FILE.slice(root.length)} · feed site/delivery.json`);
    if (checks.some((c) => c.verdict !== "OK")) process.exitCode = 1;
  } finally {
    await session?.close();
    await new Promise<void>((resolve) => (local === undefined ? resolve() : local.handle.server.close(() => resolve())));
  }
}

main()
  .catch((error: unknown) => {
    console.error(describeErrorChain(error));
    process.exitCode = 1;
  })
  // The Reclaim client keeps its attestor connection open after a proof.
  .finally(() => process.stdout.write("", () => process.exit(process.exitCode ?? 0)));
