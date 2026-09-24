import type { Keypair } from "@stellar/stellar-sdk";
import { ExactStellarScheme } from "@x402/stellar/exact/client";

import {
  generateLocalContentKey,
  sha256Canonical,
  type SigningIdentityV1,
} from "../../../packages/core/src/index.js";
import { AegisMemoryGateway, assessMemoryRisk } from "../../../packages/plugin-eliza/src/index.js";
import {
  admitDelivery,
  computePaymentHash,
  createPurchaseCommitment,
  sellerIdFromAccount,
  type AdmitDeliveryResult,
  type PurchaseCommitmentV1,
} from "../../../packages/proof/src/index.js";
import {
  AegisAnchorClient,
  ReceiptBatcher,
  createRemoteSigner,
  decodePaymentResponse,
  encodePaymentSignature,
  parsePaymentRequired,
  selectAccepts,
  type FlushedBatch,
  type ForkedSigner,
  type PaymentRequiredV2,
  type PaymentRequirements,
} from "../../../packages/x402/src/index.js";

const COMMITMENT_TTL_MS = 900_000;
const PAYABLE = { scheme: "exact", network: "stellar:testnet" } as const;

/**
 * One idempotent GET for the offer, allowed to survive a single transport blip.
 *
 * Only a rejected fetch is retried — if the seller answers with any status,
 * that is a response, not a network failure, and the caller decides. The retry
 * is immediate and singular: no backoff library on a demo with a deadline.
 * This never wraps buy(): retrying a payment risks paying twice.
 *
 * When both attempts reject, the thrown error names the URL and keeps the
 * first transport error as `cause`, so nothing the network said is discarded.
 */
async function fetchWithRetry(url: string): Promise<Response> {
  let first: unknown;
  try {
    return await fetch(url);
  } catch (error: unknown) {
    first = error;
  }
  try {
    return await fetch(url);
  } catch (error: unknown) {
    const describe = (value: unknown): string =>
      value instanceof Error
        ? `${value.name}: ${value.message}`
        : String(value);
    throw new Error(
      `Network error requesting ${url}: ${describe(error)} (retry after: ${describe(first)})`,
      { cause: first },
    );
  }
}

export interface DiscoveredOffer {
  readonly url: string;
  readonly required: PaymentRequiredV2;
  readonly requirements: PaymentRequirements;
}

/**
 * Knobs that only exist to prove the guard. In normal use the commitment is
 * derived from the offer; the refusal tests deliberately commit to something
 * narrower than what the seller asks, and expect the signer to say no.
 */
export interface CommitmentOverrides {
  readonly maxAmountAtomic?: string;
  readonly sellerAccount?: string;
  readonly expectedContentType?: string;
  /**
   * Sign the commitment with a key the signer was never told to trust — what a
   * compromised agent would do to authorise a payment of its own choosing.
   */
  readonly commitmentSigner?: SigningIdentityV1;
}

export interface PurchaseOutcome {
  readonly commitment: PurchaseCommitmentV1;
  readonly paymentHash: string;
  readonly settlementTx?: string;
  /** The bytes the seller actually returned. Kept as evidence. */
  readonly deliveredBody: Uint8Array;
  readonly deliveredContentType?: string;
  readonly admission: AdmitDeliveryResult<ReturnType<AegisMemoryGateway["ingest"]>>;
  readonly anchorTx?: string;
  readonly anchorError?: string;
  /** OK receipt waiting in a batch; anchored by `flushBatches()`. */
  readonly anchorPending?: boolean;
}

export interface AgentOptions {
  readonly signer: ForkedSigner;
  readonly buyer: Keypair;
  /**
   * Signs commitments and receipts. Its public key is pinned in the signer at
   * launch; the agent cannot swap in another one per request.
   */
  readonly attester: SigningIdentityV1;
  readonly rpcUrl: string;
  readonly anchorClient?: AegisAnchorClient;
  /**
   * Anchor every receipt on its own instead of batching OK ones. One anchor
   * costs more than a micropayment, so batching is the default.
   */
  readonly anchorEachReceipt?: boolean;
}

/**
 * The buying agent.
 *
 * It holds no key: signing goes through a transport to a separate process. Its
 * only job is to produce a commitment BEFORE paying, and to route everything
 * that comes back through the single admission path.
 */
export class DemoAgent {
  readonly gateway: AegisMemoryGateway;
  readonly #options: AgentOptions;
  readonly #batcher = new ReceiptBatcher();
  #sequence = 0;

  public constructor(options: AgentOptions) {
    this.#options = options;
    this.gateway = new AegisMemoryGateway({ encryptionKey: generateLocalContentKey() });
  }

  /**
   * Ask a seller what it wants, without paying.
   *
   * The seller dictates the offer; we only choose whether to accept it. For a
   * seller we did not write, this is the only honest source of requirements.
   */
  public async discover(url: string): Promise<DiscoveredOffer> {
    const response = await fetchWithRetry(url);
    if (response.status !== 402) {
      throw new Error(`Expected 402 from ${url}, got ${String(response.status)}.`);
    }
    let body: unknown;
    try {
      body = (await response.json()) as unknown;
    } catch {
      body = undefined;
    }
    const required = parsePaymentRequired((name) => response.headers.get(name), body);
    return { url, required, requirements: selectAccepts(required, PAYABLE) };
  }

  /**
   * Buy once, then decide whether what arrived may become context.
   *
   * The commitment is signed before the money moves. Without that there is
   * nothing to compare the delivery against, and "mismatch" has no meaning.
   */
  public async buy(input: {
    readonly resourceUrl: string;
    readonly requirements: PaymentRequirements;
    readonly memoryId: string;
    readonly overrides?: CommitmentOverrides;
  }): Promise<PurchaseOutcome> {
    this.#sequence += 1;
    const now = new Date();
    const overrides = input.overrides ?? {};
    const commitment = createPurchaseCommitment(
      {
        version: "1",
        id: `commitment:${now.getTime()}:${this.#sequence}`,
        resourceUrl: input.resourceUrl,
        sellerId: sellerIdFromAccount(overrides.sellerAccount ?? input.requirements.payTo),
        expectedContentType: overrides.expectedContentType ?? "application/json",
        maxAmountAtomic: overrides.maxAmountAtomic ?? input.requirements.amount,
        assetId: "stellar:USDC",
        committedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + COMMITMENT_TTL_MS).toISOString(),
        nonce: `nonce:${now.getTime()}:${this.#sequence}`,
      },
      overrides.commitmentSigner ?? this.#options.attester,
    );

    // One signer proxy per purchase: SEP-43 has no slot for intent, so binding
    // the commitment at construction is what stops a single approval becoming a
    // general-purpose signing oracle.
    const remote = await createRemoteSigner({
      transport: this.#options.signer,
      commitment,
    });

    const scheme = new ExactStellarScheme(remote, { url: this.#options.rpcUrl });
    const created = await scheme.createPaymentPayload(2, input.requirements as never);
    const paymentPayload = {
      x402Version: created.x402Version,
      accepted: input.requirements,
      payload: created.payload,
    };

    const started = Date.now();
    const response = await fetch(input.resourceUrl, {
      headers: { ...encodePaymentSignature(paymentPayload) },
    });
    const bodyBytes = new Uint8Array(await response.arrayBuffer());
    const elapsedMs = Date.now() - started;
    // Reads PAYMENT-RESPONSE, falling back to the legacy name. Our first version
    // read only the legacy name, so a spec-compliant seller's settlement came
    // back undefined and the payment hash silently said "unsettled".
    const settlement = decodePaymentResponse((name) => response.headers.get(name));

    const paymentHash = computePaymentHash({
      scheme: input.requirements.scheme,
      network: input.requirements.network,
      payer: this.#options.buyer.publicKey(),
      payee: input.requirements.payTo,
      transactionRef: settlement?.transaction ?? `unsettled:${commitment.id}`,
      // The offer itself, verbatim. A seller that binds its inputs into `extra`
      // (an inputHash, say) thereby has that binding carried into ours.
      paymentRequirementsHash: sha256Canonical(input.requirements),
    });

    const admission = admitDelivery(
      commitment,
      {
        responseReceived: response.ok,
        bodyBytes,
        ...(response.headers.get("content-type") === null
          ? {}
          : { contentType: response.headers.get("content-type") as string }),
        sellerId: commitment.sellerId,
        receivedAt: new Date().toISOString(),
        elapsedMs,
      },
      {
        assessRisk: (content) => assessMemoryRisk(content, "tool"),
        gateway: this.gateway,
        paymentHash,
        attesterId: `buyer:${this.#options.buyer.publicKey()}`,
        signer: this.#options.attester,
        memoryId: input.memoryId,
      },
    );

    let anchorTx: string | undefined;
    let anchorError: string | undefined;
    const batchable =
      admission.receipt.verdict === "OK" && this.#options.anchorEachReceipt !== true;
    if (this.#options.anchorClient !== undefined && batchable) {
      this.#batcher.add(admission.receipt);
    } else if (this.#options.anchorClient !== undefined) {
      try {
        const anchored = await this.#options.anchorClient.anchorDelivery(
          admission.receipt,
          this.#options.buyer,
        );
        anchorTx = anchored.transactionHash;
      } catch (error: unknown) {
        // Anchoring is evidence, not enforcement. The verdict already stands
        // locally, so a chain hiccup must not change what the agent may do.
        anchorError = error instanceof Error ? error.message : String(error);
      }
    }

    const deliveredContentType = response.headers.get("content-type");
    return {
      commitment,
      paymentHash,
      deliveredBody: bodyBytes,
      ...(deliveredContentType === null ? {} : { deliveredContentType }),
      ...(settlement?.transaction === undefined ? {} : { settlementTx: settlement.transaction }),
      admission,
      ...(anchorTx === undefined ? {} : { anchorTx }),
      ...(anchorError === undefined ? {} : { anchorError }),
      ...(this.#options.anchorClient !== undefined && batchable ? { anchorPending: true } : {}),
    };
  }

  public get pendingAnchors(): number {
    return this.#batcher.pendingCount;
  }

  /** Anchor every pending OK receipt as one Merkle root per seller. */
  public async flushBatches(): Promise<readonly FlushedBatch[]> {
    if (this.#options.anchorClient === undefined) return [];
    return this.#batcher.flush(this.#options.anchorClient, this.#options.buyer);
  }
}
