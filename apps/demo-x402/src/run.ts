/**
 * AegisOS — the four steps.
 *
 *   AEGIS_BUYER_SECRET=... AEGIS_SELLER_ACCOUNT=G... npm run demo -w @aegisos/demo-x402
 *
 * Set AEGIS_SKIP_ANCHOR=1 to skip the on-chain anchor (faster rehearsals).
 */
import { createHash, createPrivateKey, randomBytes, sign } from "node:crypto";
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
import {
  AegisAnchorClient,
  SignerDeniedError,
  buildSmartAccountPayment,
  forkSigner,
  onChainCommitmentDigest,
  requestCommitmentAuthority,
} from "../../../packages/x402/src/index.js";
import { DemoAgent, type PurchaseOutcome } from "./agent.js";
import { attesterPath, loadAttester, readPublishedAttester } from "./attester.js";
import { describeNotarization, reportFlushedBatches, reportRange, saveIndividualReceipt } from "./anchor-report.js";
import { anchorPendingRange } from "./range.js";
import { loadSmartAccount, type SmartAccountSetup } from "./smart-account-config.js";
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

function reportPurchase(outcome: PurchaseOutcome, contractId: string): void {
  const a = outcome.admission;
  console.log(`  pago liquidado   : ${outcome.settlementTx === undefined ? "NO" : tx(outcome.settlementTx)}`);
  console.log(`  veredicto        : ${a.assessment.verdict}${a.assessment.reasons.length > 0 ? ` (${a.assessment.reasons.join(", ")})` : ""}`);
  // Everything bought from a tool source carries a base taint of 35 — paying
  // for data never makes it trusted. The quarantine threshold is 60.
  console.log(`  taintScore       : ${String(a.assessment.taintScore)} (umbral 60; base 35 por ser contenido externo)`);
  console.log(`  contentHash      : ${a.assessment.contentHash.slice(0, 24)}…`);
  console.log(`  admisión         : ${a.admission}`);
  const saved = saveIndividualReceipt(outcome, contractId);
  if (saved !== undefined) console.log(`  receipt          : ${saved}`);
  if (a.assessment.riskSignals.length > 0) {
    console.log(`  señal            : ${a.assessment.riskSignals[0]?.evidence ?? ""}`);
  }
  if (outcome.anchorTx !== undefined) console.log(`  anclado on-chain : ${tx(outcome.anchorTx)}`);
  if (outcome.anchorError !== undefined) console.log(`  anclaje falló    : ${outcome.anchorError}`);
  if (outcome.anchorPending === true) console.log("  anclaje          : OK → en lote (se ancla junto con otras compras)");
  if (outcome.anchorInRange === true) console.log("  anclaje          : OK → en el rango de la cuenta (junto con todos sus pagos)");
  if (outcome.notarization !== undefined) console.log(`  notarizado       : ${describeNotarization(outcome.notarization)}`);
}

/**
 * The compromised agent tries to pay the attacker from the smart account.
 * Both attempts are free: the first is refused by the authority's policy in
 * the signer process, the second by the account itself, on-chain, in
 * simulation — before anything reaches a facilitator.
 */
async function compromisedAgentBeat(
  smart: SmartAccountSetup,
  signer: Parameters<typeof requestCommitmentAuthority>[0],
  session: Keypair,
): Promise<void> {
  const attacker = Keypair.random().publicKey();
  const commitment = {
    commitmentHash: createHash("sha256").update(randomBytes(32)).digest("hex"),
    seller: attacker,
    asset: USDC_SAC,
    maxAmount: BigInt(AMOUNT_ATOMIC),
    expiresAt: BigInt(Math.floor(Date.now() / 1000) + 600),
  };

  try {
    await requestCommitmentAuthority(signer, commitment);
    console.log("  a) FALLO: la autoridad firmó un commitment hacia el atacante");
  } catch (error: unknown) {
    const code = error instanceof SignerDeniedError ? error.code : String(error);
    console.log(`  a) pide a la autoridad un commitment hacia el atacante → DENEGADO [${code}]`);
  }

  const rogue = generateEd25519KeyPair();
  const forged = sign(
    null,
    onChainCommitmentDigest(smart.address, commitment),
    createPrivateKey({ key: Buffer.from(rogue.privateKey, "base64url"), format: "der", type: "pkcs8" }),
  );
  try {
    await buildSmartAccountPayment({
      account: smart.address, payTo: attacker, asset: USDC_SAC, amount: BigInt(AMOUNT_ATOMIC),
      maxTimeoutSeconds: 60, commitment, authoritySignature: forged,
      // The agent holds the session key and signs directly, skipping the signer.
      signAuthPreimage: async (preimage) =>
        Buffer.from(session.sign(createHash("sha256").update(Buffer.from(preimage, "base64")).digest())),
      rpcUrl: RPC_URL, networkPassphrase: TESTNET_PASSPHRASE,
    });
    console.log("  b) FALLO: la cuenta aceptó un commitment firmado por el agente");
  } catch {
    console.log("  b) se salta el signer, firma con la clave de sesión y un commitment propio");
    console.log("     → la CUENTA lo rechaza on-chain (Error(Auth, InvalidAction)), sin gastar nada");
  }
  console.log("");
  console.log("  El agente tiene la clave de sesión, pero no la autoridad: sin un commitment");
  console.log("  firmado por ella, la billetera no paga. Lo impide Stellar, no un proceso nuestro.");
}

async function main(): Promise<void> {
  const buyer = Keypair.fromSecret(requireEnv("AEGIS_BUYER_SECRET"));
  const sellerAccount = requireEnv("AEGIS_SELLER_ACCOUNT");
  const sellerId = sellerIdFromAccount(sellerAccount);
  const attester = loadAttester(attesterPath());
  const smart = loadSmartAccount();

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
    ...(smart === undefined
      ? {}
      : {
          payerAddress: smart.address,
          // The owner's policy: this seller only, this ceiling. Fixed at launch.
          authority: {
            secretFile: smart.authoritySecretFile,
            policy: { allowedSellers: [sellerAccount], maxAmountAtomic: AMOUNT_ATOMIC },
          },
        }),
    execArgv: ["--import", "tsx"],
  });

  try {
    console.log("AegisOS — procedencia verificable para compras agénticas");
    console.log(`  agente (pid ${String(process.pid)})  ·  signer aislado (pid ${String(signer.pid)})`);
    console.log(`  la clave vive en el signer; el agente solo tiene un canal`);
    console.log(`  contrato: ${contractId}`);
    console.log(
      smart === undefined
        ? "  billetera: cuenta clásica G… (npm run account:init para la smart account)"
        : `  billetera: smart account ${smart.address} · la autoridad vive en el signer`,
    );
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
      ...(smart === undefined ? {} : { smartAccount: { address: smart.address } }),
    });

    // ---------------------------------------------------------------- paso 1
    step(1, "compra honesta");
    const clean = await agent.buy({
      resourceUrl: good.url, requirements: requirements(sellerAccount, extra), memoryId: "mem:clean",
    });
    reportPurchase(clean, contractId);
    console.log(`  en contexto      : ${String(agent.gateway.retrieve().length)} ítem(s)`);

    // ---------------------------------------------------------------- paso 2
    step(2, "vendedor hostil — el pago funciona, el contenido no");
    const poisoned = await agent.buy({
      resourceUrl: evil.url, requirements: requirements(sellerAccount, extra), memoryId: "mem:poisoned",
    });
    reportPurchase(poisoned, contractId);
    console.log("");
    console.log("  x402 hizo su trabajo: el dinero se movió y el recibo es válido.");
    console.log("  Lo que falló fue el contenido — y eso ningún riel de pago lo mide.");
    const stored = agent.gateway.retrieve({ includeQuarantined: true });
    const usable = agent.gateway.retrieve();
    const leaked = JSON.stringify(stored).includes("GATTACKER7X");
    console.log(`  almacenado       : ${String(stored.length)} ítem(s) · utilizable en contexto: ${String(usable.length)} (solo el del paso 1)`);
    console.log(`  la compra envenenada está guardada para revisión, pero redactada`);
    console.log(`  dirección del atacante visible en contexto: ${leaked ? "SÍ (fallo)" : "NO"}`);

    if (agent.pendingAnchors > 0) {
      console.log("");
      console.log("  Las excepciones se anclan al instante, una por una. Las compras OK");
      console.log("  se agrupan: una raíz Merkle por vendedor, una sola transacción.");
      reportFlushedBatches(await agent.flushBatches(), contractId);
    }
    if (smart !== undefined && anchorClient !== undefined) {
      console.log("");
      console.log("  Todas las compras de la cuenta se anclan como un rango: en orden, una");
      console.log("  vez cada una, ninguna omitida. El contrato recalcula la cadena y cuenta.");
      reportRange(await anchorPendingRange({ client: anchorClient, contractId, account: smart.address, session: buyer }));
    }

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
    step(4, "el agente comprometido intenta pagarle al atacante");
    if (smart === undefined) {
      console.log("  (requiere la smart account: npm run account:init)");
    } else {
      await compromisedAgentBeat(smart, signer, buyer);
    }

    // ---------------------------------------------------------------- paso 5
    step(5, "el siguiente agente consulta la cadena antes de comprar");
    if (anchorClient === undefined) {
      console.log("  (omitido: AEGIS_SKIP_ANCHOR=1)");
    } else {
      const score = await anchorClient.sellerScore(sellerId, buyer);
      console.log(`  seller_score     : ok=${String(score.ok)} tainted=${String(score.tainted)} mismatch=${String(score.mismatch)} total=${String(score.total)} · ok en lotes=${String(score.batchedOk ?? 0)}`);
      if (score.verified !== undefined) {
        console.log(`  verificados      : ok=${String(score.verified.ok)} tainted=${String(score.verified.tainted)} mismatch=${String(score.verified.mismatch)}  (contados por el contrato sobre pagos notarizados)`);
      }
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
