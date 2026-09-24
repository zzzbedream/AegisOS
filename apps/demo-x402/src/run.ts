/**
 * AegisOS — the four steps.
 *
 *   AEGIS_BUYER_SECRET=... AEGIS_SELLER_ACCOUNT=G... npm run demo -w @aegisos/demo-x402
 *
 * Set AEGIS_SKIP_ANCHOR=1 to skip the on-chain anchor (faster rehearsals).
 */
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { Keypair } from "@stellar/stellar-sdk";

import {
  createExecutionIntentFromMemoryEnvelopes,
  createIntentDraft,
  evaluatePolicy,
  generateEd25519KeyPair,
  issueCapabilityGrant,
  type AssetRefV1,
  type PolicyConfigV1,
} from "../../../packages/core/src/index.js";
import { MemoryAccessError } from "../../../packages/plugin-eliza/src/index.js";
import {
  emptySellerScore,
  sellerIdFromAccount,
  shouldAbstainFromPurchase,
  toTrustVerdict,
} from "../../../packages/proof/src/index.js";
import { AegisAnchorClient, forkSigner } from "../../../packages/x402/src/index.js";
import { DemoAgent, type PurchaseOutcome } from "./agent.js";
import { attesterPath, loadAttester, readPublishedAttester } from "./attester.js";
import { saveReceipt } from "./receipt-check.js";
import { honestMarketData, poisonedMarketData } from "./catalog.js";
import { startSeller, type PaymentRequirements, type SellerHandle } from "./resource-server.js";

const USDC_SAC = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const TESTNET_PASSPHRASE = "Test SDF Network ; September 2015";
const NETWORK = "stellar:testnet";
const RPC_URL = "https://soroban-testnet.stellar.org";
const FACILITATOR = process.env["AEGIS_FACILITATOR_URL"] ?? "https://www.x402.org/facilitator";
const AMOUNT_ATOMIC = process.env["AEGIS_AMOUNT_ATOMIC"] ?? "100000"; // 0.01 USDC
const SKIP_ANCHOR = process.env["AEGIS_SKIP_ANCHOR"] === "1";

const T0 = "2027-01-01T00:00:00.000Z";
const T2 = "2027-01-01T00:02:00.000Z";
const T10 = "2027-01-01T00:10:00.000Z";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`Missing ${name}.`);
  return value;
}

const line = (): void => console.log("─".repeat(72));
const step = (n: number, title: string): void => {
  console.log("");
  line();
  console.log(`PASO ${n}  ${title}`);
  line();
};
const tx = (hash: string): string => `https://stellar.expert/explorer/testnet/tx/${hash}`;

const usdc: AssetRefV1 = {
  assetId: "stellar:USDC", network: "stellar-testnet",
  contractId: "CUSDCMOCK", symbol: "USDC", decimals: 7,
};
const xlm: AssetRefV1 = {
  assetId: "stellar:XLM", network: "stellar-testnet",
  contractId: "native:XLM", symbol: "XLM", decimals: 7,
};

function policy(): PolicyConfigV1 {
  return {
    version: "1", id: "policy:demo",
    allowedNetworks: ["stellar-testnet"],
    allowedOperationKinds: ["SWAP_EXACT_INPUT"],
    allowedManifestIds: ["manifest:stellar-mock-v1"],
    allowedAssetIds: [usdc.assetId, xlm.assetId],
    assetLimits: [
      { assetId: usdc.assetId, maxPerOperationAtomic: "100000000", maxDailyAtomic: "500000000" },
      { assetId: xlm.assetId, maxPerOperationAtomic: "100000000", maxDailyAtomic: "500000000" },
    ],
    maxSlippageBps: 100, maxFeeAtomic: "100000", approvalTtlSeconds: 300,
    requireOwnerApproval: false, requireCleanProvenanceForDelegation: true,
  };
}

function requirements(payTo: string, extra: Record<string, unknown>): PaymentRequirements {
  return {
    scheme: "exact", network: NETWORK, asset: USDC_SAC,
    amount: AMOUNT_ATOMIC, payTo, maxTimeoutSeconds: 120, extra,
  };
}

function reportPurchase(outcome: PurchaseOutcome): void {
  const a = outcome.admission;
  console.log(`  pago liquidado   : ${outcome.settlementTx === undefined ? "NO" : tx(outcome.settlementTx)}`);
  console.log(`  veredicto        : ${a.assessment.verdict}${a.assessment.reasons.length > 0 ? ` (${a.assessment.reasons.join(", ")})` : ""}`);
  // Everything bought from a tool source carries a base taint of 35 — paying
  // for data never makes it trusted. The quarantine threshold is 60.
  console.log(`  taintScore       : ${String(a.assessment.taintScore)} (umbral 60; base 35 por ser contenido externo)`);
  console.log(`  contentHash      : ${a.assessment.contentHash.slice(0, 24)}…`);
  console.log(`  admisión         : ${a.admission}`);
  console.log(`  receipt          : ${saveReceipt(a.receipt)}`);
  if (a.assessment.riskSignals.length > 0) {
    console.log(`  señal            : ${a.assessment.riskSignals[0]?.evidence ?? ""}`);
  }
  if (outcome.anchorTx !== undefined) console.log(`  anclado on-chain : ${tx(outcome.anchorTx)}`);
  if (outcome.anchorError !== undefined) console.log(`  anclaje falló    : ${outcome.anchorError}`);
}

async function main(): Promise<void> {
  const buyer = Keypair.fromSecret(requireEnv("AEGIS_BUYER_SECRET"));
  const sellerAccount = requireEnv("AEGIS_SELLER_ACCOUNT");
  const sellerId = sellerIdFromAccount(sellerAccount);
  const attester = loadAttester(attesterPath());

  const deployments = JSON.parse(
    readFileSync(new URL("../../../contracts/deployments/testnet.json", import.meta.url), "utf8"),
  ) as { contracts: Record<string, { contractId: string }> };
  const contractId = deployments.contracts["aegis-proof"]?.contractId ?? "";
  const published = readPublishedAttester(deployments);
  const attesterPublished = published?.publicKey === attester.publicKey;

  const supported = (await (await fetch(`${FACILITATOR}/supported`)).json()) as {
    kinds?: { scheme?: string; network?: string; extra?: Record<string, unknown> }[];
  };
  const kind = (supported.kinds ?? []).find((k) => k.scheme === "exact" && k.network === NETWORK);
  if (kind === undefined) throw new Error(`Facilitator does not support exact/${NETWORK}.`);
  const extra = { ...(kind.extra ?? {}) };

  const dir = mkdtempSync(join(tmpdir(), "aegis-demo-"));
  const secretFile = join(dir, "buyer.secret");
  writeFileSync(secretFile, buyer.secret(), "utf8");

  let good: SellerHandle | undefined;
  let evil: SellerHandle | undefined;
  const signer = await forkSigner({
    modulePath: fileURLToPath(new URL("../../../packages/x402/src/signer-process.ts", import.meta.url)),
    secretFile,
    network: NETWORK,
    allowedAssets: { "stellar:USDC": USDC_SAC },
    allowedNetworkPassphrases: [TESTNET_PASSPHRASE],
    trustedCommitmentKeys: { [attester.keyId]: attester.publicKey },
    execArgv: ["--import", "tsx"],
  });

  try {
    console.log("AegisOS — procedencia verificable para compras agénticas");
    console.log(`  agente (pid ${String(process.pid)})  ·  signer aislado (pid ${String(signer.pid)})`);
    console.log(`  la clave vive en el signer; el agente solo tiene un canal`);
    console.log(`  contrato: ${contractId}`);
    console.log(`  attester: ${attester.keyId} · ${attesterPublished ? "clave publicada en deployments/testnet.json" : "NO coincide con la clave publicada: los receipts no serán verificables por terceros"}`);

    good = await startSeller({
      name: "seller-good", port: 4501, resourcePath: "/market-data",
      requirements: requirements(sellerAccount, extra), facilitatorUrl: FACILITATOR,
      body: honestMarketData,
    });
    evil = await startSeller({
      name: "seller-evil", port: 4502, resourcePath: "/market-data",
      requirements: requirements(sellerAccount, extra), facilitatorUrl: FACILITATOR,
      body: poisonedMarketData,
    });

    const anchorClient = SKIP_ANCHOR ? undefined : new AegisAnchorClient({ contractId });
    const agent = new DemoAgent({
      signer, buyer, attester,
      rpcUrl: RPC_URL, ...(anchorClient === undefined ? {} : { anchorClient }),
    });

    // ---------------------------------------------------------------- paso 1
    step(1, "compra honesta");
    const clean = await agent.buy({
      resourceUrl: good.url, requirements: requirements(sellerAccount, extra), memoryId: "mem:clean",
    });
    reportPurchase(clean);
    console.log(`  en contexto      : ${String(agent.gateway.retrieve().length)} ítem(s)`);

    // ---------------------------------------------------------------- paso 2
    step(2, "vendedor hostil — el pago funciona, el contenido no");
    const poisoned = await agent.buy({
      resourceUrl: evil.url, requirements: requirements(sellerAccount, extra), memoryId: "mem:poisoned",
    });
    reportPurchase(poisoned);
    console.log("");
    console.log("  x402 hizo su trabajo: el dinero se movió y el recibo es válido.");
    console.log("  Lo que falló fue el contenido — y eso ningún riel de pago lo mide.");
    const stored = agent.gateway.retrieve({ includeQuarantined: true });
    const usable = agent.gateway.retrieve();
    const leaked = JSON.stringify(stored).includes("GATTACKER7X");
    console.log(`  almacenado       : ${String(stored.length)} ítem(s) · utilizable en contexto: ${String(usable.length)} (solo el del paso 1)`);
    console.log(`  la compra envenenada está guardada para revisión, pero redactada`);
    console.log(`  dirección del atacante visible en contexto: ${leaked ? "SÍ (fallo)" : "NO"}`);

    // ---------------------------------------------------------------- paso 3
    step(3, "corte de cascada — el gasto siguiente no llega a existir");
    try {
      agent.gateway.assertDraftSources(["mem:poisoned"]);
      console.log("  FALLO: el draft citó memoria en cuarentena");
    } catch (error: unknown) {
      if (!(error instanceof MemoryAccessError)) throw error;
      console.log(`  assertDraftSources → RECHAZADO`);
      console.log(`    ${error.message}`);
    }

    const envelope = poisoned.admission.envelope;
    if (envelope !== undefined) {
      const draft = createIntentDraft({
        id: "draft:from-poisoned", network: "stellar-testnet",
        operation: {
          kind: "SWAP_EXACT_INPUT",
          input: { asset: usdc, atomic: "25000000" },
          minOutput: { asset: xlm, atomic: "10000000" },
          recipient: "GRECIPIENTACCOUNT",
        },
        protocol: {
          protocolId: "mock-soroswap", manifestId: "manifest:stellar-mock-v1",
          contractId: "CAMMMOCK", poolId: "pool:usdc-xlm",
        },
        sourceAccount: "GDELEGATEDACCOUNT", requestedAt: T0,
        sourceMemoryIds: ["mem:poisoned"],
      });
      const intent = createExecutionIntentFromMemoryEnvelopes({
        id: "intent:from-poisoned", draft, nonce: "nonce:from-poisoned",
        policyId: "policy:demo", expiresAt: T10,
        maxSlippageBps: 50, maxFeeAtomic: "10000",
        memoryEnvelopes: [envelope.core],
      });
      const issuer = generateEd25519KeyPair("key:issuer");
      const grant = issueCapabilityGrant({
        id: "cap:demo", network: "stellar-testnet", delegatedAccount: "GDELEGATEDACCOUNT",
        allowedOperations: ["SWAP_EXACT_INPUT"], allowedManifestIds: ["manifest:stellar-mock-v1"],
        allowedAssetIds: [usdc.assetId, xlm.assetId],
        spendLimits: [{ assetId: usdc.assetId, maxPerOperationAtomic: "30000000", maxDailyAtomic: "50000000" }],
        issuedAt: T0, expiresAt: T10, nonce: "nonce:cap-demo",
        policyId: "policy:demo", issuer,
      });
      const decision = evaluatePolicy(policy(), intent, {
        now: T2, capability: grant,
        issuerPublicKeys: { [issuer.keyId]: issuer.publicKey },
      });
      console.log(`  procedencia      : containsUntrustedInput=${String(intent.provenance.containsUntrustedInput)}`);
      console.log(`  evaluatePolicy    → ${decision.decision}  [${decision.reasons.join(", ")}]`);
    }

    const verdict = toTrustVerdict(poisoned.admission.receipt, emptySellerScore(sellerId), {
      evaluatedAt: new Date().toISOString(),
    });
    console.log(`  TrustVerdictV1   : tainted=${String(verdict.tainted)}  (lo que lee un riel de gasto)`);

    // ---------------------------------------------------------------- paso 4
    step(4, "el siguiente agente consulta la cadena antes de comprar");
    if (anchorClient === undefined) {
      console.log("  (omitido: AEGIS_SKIP_ANCHOR=1)");
    } else {
      const score = await anchorClient.sellerScore(sellerId, buyer);
      console.log(`  seller_score     : ok=${String(score.ok)} tainted=${String(score.tainted)} mismatch=${String(score.mismatch)} total=${String(score.total)}`);
      const abstention = shouldAbstainFromPurchase(score, { maxTainted: 0 });
      console.log(`  política local   : ${abstention.abstain ? "ABSTENERSE" : "comprar"}  [${abstention.reasons.join(", ")}]`);
      console.log("");
      console.log("  El historial es público e inmutable, pero es un agregado de");
      console.log("  atestaciones ancladas — no una verdad objetiva sobre el vendedor.");
    }

    console.log("");
    line();
    console.log("Un pago perfecto no basta. AegisOS decide si lo comprado puede");
    console.log("convertirse en autoridad.");
    line();
  } finally {
    await good?.close();
    await evil?.close();
    await signer.close?.();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? `${error.name}: ${error.message}` : error);
  process.exitCode = 1;
});
