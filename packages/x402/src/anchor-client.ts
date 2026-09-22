import {
  Address,
  Contract,
  Keypair,
  TransactionBuilder,
  rpc,
  scValToNative,
  xdr,
} from "@stellar/stellar-sdk";
import {
  accountFromSellerId,
  type DeliveryReceiptV1,
  type DeliveryVerdict,
  type SellerId,
  type SellerScoreV1,
} from "../../proof/src/index.js";

export const TESTNET_RPC_URL = "https://soroban-testnet.stellar.org";
export const TESTNET_PASSPHRASE = "Test SDF Network ; September 2015";

const BASE_FEE = "1000000";
const TX_TIMEOUT_SECONDS = 60;
const POLL_INTERVAL_MS = 1000;
const POLL_ATTEMPTS = 30;

/** Contract-side `Verdict` arm names, which differ in case from ours. */
const VERDICT_ARM: Readonly<Record<DeliveryVerdict, string>> = {
  OK: "Ok",
  TAINTED: "Tainted",
  MISMATCH: "Mismatch",
  NOT_DELIVERED: "NotDelivered",
};

const SHA256_HEX = /^[a-f0-9]{64}$/;
const ZERO_HASH = "0".repeat(64);

export class AnchorClientError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.name = "AnchorClientError";
    this.code = code;
  }
}

function hashToBytes(hash: string, label: string): xdr.ScVal {
  if (!SHA256_HEX.test(hash)) {
    throw new AnchorClientError("INVALID_HASH", `${label} must be bare lowercase 64-hex.`);
  }
  // The contract rejects zero hashes; fail here with a legible error rather
  // than burning a transaction to learn that on-chain.
  if (hash === ZERO_HASH) {
    throw new AnchorClientError("ZERO_HASH", `${label} is all zeroes; the contract rejects it.`);
  }
  return xdr.ScVal.scvBytes(Buffer.from(hash, "hex"));
}

/**
 * Build the `DeliveryInput` struct.
 *
 * Soroban `#[contracttype]` structs are ScMaps keyed by symbol, and the host
 * requires the keys in sorted order — so the field order below is load-bearing,
 * not cosmetic.
 */
function deliveryInputScVal(input: {
  readonly buyer: string;
  readonly seller: string;
  readonly paymentHash: string;
  readonly commitmentHash: string;
  readonly contentHash: string;
  readonly verdict: DeliveryVerdict;
}): xdr.ScVal {
  const field = (key: string, val: xdr.ScVal): xdr.ScMapEntry =>
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val });

  return xdr.ScVal.scvMap([
    field("buyer", new Address(input.buyer).toScVal()),
    field("commitment_hash", hashToBytes(input.commitmentHash, "commitment_hash")),
    field("content_hash", hashToBytes(input.contentHash, "content_hash")),
    field("payment_hash", hashToBytes(input.paymentHash, "payment_hash")),
    field("seller", new Address(input.seller).toScVal()),
    field("verdict", xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(VERDICT_ARM[input.verdict])])),
  ]);
}

export interface AnchorClientOptions {
  readonly contractId: string;
  readonly rpcUrl?: string;
  readonly networkPassphrase?: string;
}

export interface AnchorResult {
  readonly transactionHash: string;
  readonly explorerUrl: string;
}

/**
 * Anchors delivery attestations and reads seller aggregates from Soroban.
 *
 * Deliberately thin: the contract is the public evidence anchor, and every
 * judgement about a delivery was already made off-chain and deterministically
 * before anything reaches here.
 */
export class AegisAnchorClient {
  readonly #contract: Contract;
  readonly #server: rpc.Server;
  readonly #passphrase: string;

  public constructor(options: AnchorClientOptions) {
    this.#contract = new Contract(options.contractId);
    this.#server = new rpc.Server(options.rpcUrl ?? TESTNET_RPC_URL);
    this.#passphrase = options.networkPassphrase ?? TESTNET_PASSPHRASE;
  }

  /**
   * Anchor a receipt. The buyer signs, because the contract requires auth from
   * the buyer named in the record — a third party cannot anchor, or defame, a
   * purchase they did not make.
   */
  public async anchorDelivery(
    receipt: DeliveryReceiptV1,
    buyer: Keypair,
  ): Promise<AnchorResult> {
    const seller = accountFromSellerId(receipt.sellerId);
    if (seller === buyer.publicKey()) {
      throw new AnchorClientError(
        "SELF_DEALING",
        "Buyer and seller are the same account; the contract rejects it.",
      );
    }

    const arg = deliveryInputScVal({
      buyer: buyer.publicKey(),
      seller,
      paymentHash: receipt.paymentHash,
      commitmentHash: receipt.commitmentHash,
      contentHash: receipt.contentHash,
      verdict: receipt.verdict,
    });

    const source = await this.#server.getAccount(buyer.publicKey());
    const built = new TransactionBuilder(source, {
      fee: BASE_FEE,
      networkPassphrase: this.#passphrase,
    })
      .addOperation(this.#contract.call("anchor_delivery", arg))
      .setTimeout(TX_TIMEOUT_SECONDS)
      .build();

    const prepared = await this.#server.prepareTransaction(built);
    prepared.sign(buyer);

    const sent = await this.#server.sendTransaction(prepared);
    if (sent.status === "ERROR") {
      throw new AnchorClientError(
        "SUBMIT_FAILED",
        `Anchor submission rejected: ${JSON.stringify(sent.errorResult ?? sent.status)}`,
      );
    }

    const hash = sent.hash;
    for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt += 1) {
      const result = await this.#server.getTransaction(hash);
      if (result.status === "SUCCESS") {
        return {
          transactionHash: hash,
          explorerUrl: `https://stellar.expert/explorer/testnet/tx/${hash}`,
        };
      }
      if (result.status === "FAILED") {
        throw new AnchorClientError("ANCHOR_FAILED", `Anchor failed on-chain (tx ${hash}).`);
      }
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    }
    throw new AnchorClientError("ANCHOR_TIMEOUT", `Anchor not confirmed within timeout (tx ${hash}).`);
  }

  /**
   * Read a seller's aggregate. Read-only: simulated, never submitted.
   *
   * Remember what this is — an immutable aggregate of anchored attestations,
   * not an objective measure of service quality. Anchoring costs only a fee, so
   * the counters are grief-able and must feed policy, not verdicts.
   */
  public async sellerScore(sellerId: SellerId, reader: Keypair): Promise<SellerScoreV1> {
    const seller = accountFromSellerId(sellerId);
    const source = await this.#server.getAccount(reader.publicKey());
    const built = new TransactionBuilder(source, {
      fee: BASE_FEE,
      networkPassphrase: this.#passphrase,
    })
      .addOperation(this.#contract.call("seller_score", new Address(seller).toScVal()))
      .setTimeout(TX_TIMEOUT_SECONDS)
      .build();

    const simulated = await this.#server.simulateTransaction(built);
    if (rpc.Api.isSimulationError(simulated)) {
      throw new AnchorClientError("SIMULATION_FAILED", simulated.error);
    }
    const retval = simulated.result?.retval;
    if (retval === undefined) {
      throw new AnchorClientError("NO_RESULT", "seller_score returned no value.");
    }

    const raw = scValToNative(retval) as Record<string, unknown>;
    const count = (key: string): number => Number(raw[key] ?? 0);

    return Object.freeze({
      version: "1" as const,
      sellerId,
      ok: count("ok"),
      tainted: count("tainted"),
      mismatch: count("mismatch"),
      notDelivered: count("not_delivered"),
      disputed: count("disputed"),
      total: count("total"),
      asOf: new Date().toISOString(),
    });
  }
}
