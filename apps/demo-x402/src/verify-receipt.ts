/**
 * Verify a delivery receipt the way a third party would: public inputs only.
 *
 *   npm run verify:receipt -- .aegis/receipts/<paymentHash>.json
 *
 * Checks the signature against the attester key published next to the
 * contract IDs, then checks the chain: an individually anchored receipt
 * against its `get_delivery` record, a batched one by recomputing its Merkle
 * path up to the root `get_batch` returns. Needs no secret; set
 * AEGIS_SKIP_CHAIN=1 to check the signature offline.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { rpc } from "@stellar/stellar-sdk";
import {
  AegisAnchorClient,
  TESTNET_PASSPHRASE,
  TESTNET_RPC_URL,
  deployedWasmHash,
  readAccountHead,
} from "../../../packages/x402/src/index.js";
import { readPublishedAttester } from "./attester.js";
import { describeErrorChain } from "./error-chain.js";
import { contentProofChecks } from "./content-proof.js";
import { notarizationChecks, readPaymentLog } from "./notarization.js";
import {
  anchorRoute,
  batchChecks,
  individualChecks,
  rangeChecks,
  readReceiptFile,
  signatureChecks,
  type ReceiptCheck,
} from "./receipt-check.js";

const DEPLOYMENTS = fileURLToPath(
  new URL("../../../contracts/deployments/testnet.json", import.meta.url),
);
const SKIP_CHAIN = process.env["AEGIS_SKIP_CHAIN"] === "1";

interface Deployments {
  readonly rpcUrl?: string;
  readonly contracts: Record<string, { readonly contractId: string; readonly deployer?: string }>;
  readonly accountWasm?: { readonly wasmHash: string };
  readonly reclaim?: { readonly witnesses: readonly string[] };
}

/** Account wasms published before the current one (e.g. `accountV2`). */
function supersededAccountWasms(raw: unknown, current: string): readonly string[] {
  if (typeof raw !== "object" || raw === null) return [];
  return Object.entries(raw)
    .filter(([key]) => key.startsWith("account"))
    .map(([, entry]) => (entry as { wasmHash?: unknown } | null)?.wasmHash)
    .filter((hash): hash is string => typeof hash === "string" && hash !== current);
}

async function main(): Promise<void> {
  const file = process.argv[2];
  if (file === undefined || file.length === 0) {
    throw new Error("Usage: npm run verify:receipt -- <receipt.json>");
  }
  const { receipt, anchor, notarization, range, contentProof } = readReceiptFile(JSON.parse(readFileSync(file, "utf8")) as unknown);
  const deploymentsRaw = JSON.parse(readFileSync(DEPLOYMENTS, "utf8")) as unknown;
  const published = readPublishedAttester(deploymentsRaw);
  if (published === undefined) {
    throw new Error("No attester published in contracts/deployments/testnet.json. Run: npm run attester:init");
  }
  const deployments = deploymentsRaw as Deployments;
  const contracts = Object.values(deployments.contracts);
  // Any published account can be the simulation source; the deployer is public.
  const reader = contracts.find((c) => c.deployer !== undefined)?.deployer ?? "";
  const clientFor = (contractId: string): AegisAnchorClient =>
    new AegisAnchorClient({
      contractId,
      ...(deployments.rpcUrl === undefined ? {} : { rpcUrl: deployments.rpcUrl }),
    });

  const checks: ReceiptCheck[] = [...signatureChecks(receipt, published)];
  let chainNote = "omitido (AEGIS_SKIP_CHAIN=1)";

  const route = anchorRoute({
    ...(anchor === undefined ? {} : { anchor }),
    ...(notarization === undefined ? {} : { notarization }),
    ...(range === undefined ? {} : { range }),
  });
  if (!SKIP_CHAIN && route === "range") {
    chainNote = "anclado en el rango de su cuenta (ver billetera)";
  } else if (!SKIP_CHAIN) {
    const known = anchor === undefined || contracts.some((c) => c.contractId === anchor.contractId);
    checks.push({
      name: "anchored in a published AegisOS contract",
      pass: known,
      detail: anchor === undefined ? "legacy receipt: searching every published contract" : anchor.contractId,
    });

    if (known && anchor?.mode === "batch") {
      const batch = await clientFor(anchor.contractId).getBatch(anchor.root, reader);
      if (batch === undefined) {
        checks.push({ name: "batch root anchored on-chain", pass: false, detail: `no batch ${anchor.root}` });
        chainNote = "la raíz del lote NO está anclada";
      } else {
        checks.push(...batchChecks(receipt, anchor.proof, batch));
        chainNote = `lote de ${String(batch.count)} compra(s), anclado en ledger time ${String(batch.anchoredAt)}`;
      }
    } else if (known) {
      const candidates =
        anchor === undefined ? contracts.map((c) => c.contractId) : [anchor.contractId];
      let found = false;
      for (const contractId of candidates) {
        const record = await clientFor(contractId).getDelivery(receipt.paymentHash, reader);
        if (record !== undefined) {
          checks.push(...individualChecks(receipt, record));
          chainNote = `anclaje individual en ${contractId.slice(0, 8)}…, ledger time ${String(record.anchoredAt)}`;
          found = true;
          break;
        }
      }
      if (!found) {
        checks.push({ name: "record anchored on-chain", pass: false, detail: "no record for this payment" });
        chainNote = "NO hay registro anclado para este pago";
      }
    }
  }

  let notarizationNote: string | undefined;
  if (!SKIP_CHAIN && notarization !== undefined) {
    const publishedWasm = deployments.accountWasm?.wasmHash;
    if (publishedWasm === undefined) {
      checks.push({ name: "AegisOS account wasm published", pass: false, detail: "no accountWasm in deployments" });
    } else {
      const server = new rpc.Server(deployments.rpcUrl ?? TESTNET_RPC_URL);
      const [deployedWasm, onChainHead] = await Promise.all([
        deployedWasmHash(server, notarization.account),
        readAccountHead(server, TESTNET_PASSPHRASE, notarization.account, reader),
      ]);
      // A published receipt ships its account's payment log next to it.
      const siblingLog = join(dirname(file), "payment-log");
      const log = existsSync(siblingLog)
        ? readPaymentLog(notarization.account, siblingLog)
        : readPaymentLog(notarization.account);
      const publishedWasms = { current: publishedWasm, superseded: supersededAccountWasms(deploymentsRaw, publishedWasm) };
      checks.push(...notarizationChecks(receipt, notarization, { deployedWasm, publishedWasms, log, onChainHead }));
      notarizationNote = `pago seq ${notarization.seq} de la cuenta ${notarization.account} (cabeza on-chain seq ${onChainHead.seq.toString()})`;
    }
    if (range !== undefined) {
      const known = contracts.some((c) => c.contractId === range.contractId);
      checks.push({ name: "range anchored in a published AegisOS registry", pass: known, detail: range.contractId });
      if (known) {
        const record = await clientFor(range.contractId).getRange(range.account, BigInt(range.fromSeq), reader);
        if (record === undefined) {
          checks.push({ name: "range exists on-chain", pass: false, detail: `no range from seq ${range.fromSeq}` });
        } else {
          checks.push(...rangeChecks(receipt, notarization, range, record));
          notarizationNote = `${notarizationNote ?? ""} · rango ${record.fromSeq.toString()}..${record.toSeq.toString()} (ok=${String(record.counts.ok)} tainted=${String(record.counts.tainted)})`;
        }
      }
    }
  }

  // Guarantee D needs no chain: the attestor's signature and a pinned witness.
  let originNote: string | undefined;
  if (contentProof !== undefined) {
    checks.push(
      ...contentProofChecks(contentProof.proof, {
        commitmentHash: receipt.commitmentHash,
        contentHash: receipt.contentHash,
        canonicalization: receipt.contentCanonicalization,
        trustedWitnesses: deployments.reclaim?.witnesses ?? [],
      }),
    );
    originNote = `prueba Reclaim (${contentProof.kind}) del attestor ${contentProof.proof.witnesses[0]?.id ?? "—"}`;
  }

  console.log("AegisOS · verificación de receipt con datos públicos");
  console.log(`  receipt  : ${file}`);
  console.log(`  veredicto: ${receipt.verdict} (atestación del comprador, no prueba contra el vendedor)`);
  console.log(`  cadena   : ${chainNote}`);
  if (notarizationNote !== undefined) console.log(`  billetera: ${notarizationNote}`);
  if (originNote !== undefined) console.log(`  origen   : ${originNote}`);
  for (const check of checks) {
    console.log(`  ${check.pass ? "PASS" : "FAIL"}  ${check.name} — ${check.detail}`);
  }
  const ok = checks.every((check) => check.pass);
  console.log(ok ? "Receipt verificado." : "El receipt NO verifica.");
  process.exitCode = ok ? 0 : 1;
}

main().catch((error: unknown) => {
  console.error(describeErrorChain(error));
  process.exitCode = 1;
});
