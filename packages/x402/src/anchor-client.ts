import { randomBytes } from "node:crypto";

import {
  Address,
  Contract,
  Keypair,
  TransactionBuilder,
  nativeToScVal,
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
import {
  SorobanSubmitError,
  registryAuthScVal,
  submitSorobanOperation,
  type ContractAccountAuth,
} from "./soroban-submit.js";

export const TESTNET_RPC_URL = "https://soroban-testnet.stellar.org";
export const TESTNET_PASSPHRASE = "Test SDF Network ; September 2015";

const BASE_FEE = "1000000";
const TX_TIMEOUT_SECONDS = 60;
const READ_RETRY_DELAY_MS = 1000;

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

/** A delivery record as the contract stores it, in our own formats. */
export interface AnchoredDeliveryV1 {
  readonly buyer: string;
  readonly seller: string;
  readonly paymentHash: string;
  readonly commitmentHash: string;
  readonly contentHash: string;
  readonly verdict: DeliveryVerdict;
  /** Ledger close time of the anchor, in unix seconds — not the delivery time. */
  readonly anchoredAt: number;
}

const VERDICT_FROM_ARM: Readonly<Record<string, DeliveryVerdict>> = Object.fromEntries(
  Object.entries(VERDICT_ARM).map(([ours, arm]) => [arm, ours as DeliveryVerdict]),
);

function bytesToHex(value: unknown, label: string): string {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new AnchorClientError("BAD_RECORD", `${label} is not 32 bytes.`);
  }
  return Buffer.from(value).toString("hex");
}

/**
 * Decode `get_delivery`'s native value. `null`/`undefined` is the contract's
 * `None`. Anything that does not have the expected shape is an error, never a
 * best-effort guess: this output is what a verifier compares a receipt to.
 */
export function decodeDeliveryRecord(native: unknown): AnchoredDeliveryV1 | undefined {
  if (native === null || native === undefined) return undefined;
  if (typeof native !== "object") {
    throw new AnchorClientError("BAD_RECORD", "get_delivery returned a non-struct value.");
  }
  const raw = native as Record<string, unknown>;
  const arm = Array.isArray(raw["verdict"]) ? raw["verdict"][0] : raw["verdict"];
  const verdict = typeof arm === "string" ? VERDICT_FROM_ARM[arm] : undefined;
  if (verdict === undefined) {
    throw new AnchorClientError("BAD_RECORD", `Unknown verdict arm: ${String(arm)}.`);
  }
  if (typeof raw["buyer"] !== "string" || typeof raw["seller"] !== "string") {
    throw new AnchorClientError("BAD_RECORD", "buyer and seller must be addresses.");
  }
  return Object.freeze({
    buyer: raw["buyer"],
    seller: raw["seller"],
    paymentHash: bytesToHex(raw["payment_hash"], "payment_hash"),
    commitmentHash: bytesToHex(raw["commitment_hash"], "commitment_hash"),
    contentHash: bytesToHex(raw["content_hash"], "content_hash"),
    verdict,
    anchoredAt: Number(raw["anchored_at"] ?? 0),
  });
}

/** Mirrors the contract's MAX_RANGE_LEAVES. */
export const MAX_RANGE_LEAVES = 64;
/** Mirrors the contract's MAX_RANGE_TAIL. */
export const MAX_RANGE_TAIL = 192;

/** Mirrors the contract's MAX_BATCH_COUNT. */
export const MAX_BATCH_COUNT = 1_024;

export interface AnchoredBatchV1 {
  readonly buyer: string;
  readonly seller: string;
  readonly root: string;
  readonly count: number;
  readonly anchoredAt: number;
}

export function decodeBatchRecord(native: unknown): AnchoredBatchV1 | undefined {
  if (native === null || native === undefined) return undefined;
  if (typeof native !== "object") {
    throw new AnchorClientError("BAD_RECORD", "get_batch returned a non-struct value.");
  }
  const raw = native as Record<string, unknown>;
  if (typeof raw["buyer"] !== "string" || typeof raw["seller"] !== "string") {
    throw new AnchorClientError("BAD_RECORD", "buyer and seller must be addresses.");
  }
  const count = Number(raw["count"]);
  if (!Number.isInteger(count) || count < 1) {
    throw new AnchorClientError("BAD_RECORD", "count must be a positive integer.");
  }
  return Object.freeze({
    buyer: raw["buyer"],
    seller: raw["seller"],
    root: bytesToHex(raw["root"], "root"),
    count,
    anchoredAt: Number(raw["anchored_at"] ?? 0),
  });
}

export interface RangeLeafInput {
  readonly seq: bigint;
  readonly commitmentHash: string;
  readonly seller: string;
  readonly amount: bigint;
  readonly contentHash: string;
  readonly verdict: DeliveryVerdict;
}

/** A later payment carried only to reach the account's head (not counted). */
export interface ChainStepInput {
  readonly commitmentHash: string;
  readonly seller: string;
  readonly amount: bigint;
}

export interface RangeRecordV1 {
  readonly account: string;
  readonly fromSeq: bigint;
  readonly toSeq: bigint;
  readonly root: string;
  readonly counts: { readonly ok: number; readonly tainted: number; readonly mismatch: number; readonly notDelivered: number };
  readonly anchoredAt: number;
}

export interface CheckpointV1 {
  readonly seq: bigint;
  readonly chainHead: string;
}

function mapField(key: string, val: xdr.ScVal): xdr.ScMapEntry {
  return new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val });
}

/** `RangeInput` for `anchor_range`. Struct keys sorted, as the host requires. */
export function rangeInputScVal(
  account: string,
  fromSeq: bigint,
  leaves: readonly RangeLeafInput[],
  tail: readonly ChainStepInput[] = [],
): xdr.ScVal {
  const leafVals = leaves.map((leaf) =>
    xdr.ScVal.scvMap([
      mapField("amount", nativeToScVal(leaf.amount, { type: "i128" })),
      mapField("commitment_hash", hashToBytes(leaf.commitmentHash, "commitment_hash")),
      mapField("content_hash", hashToBytes(leaf.contentHash, "content_hash")),
      mapField("seller", new Address(leaf.seller).toScVal()),
      mapField("seq", nativeToScVal(leaf.seq, { type: "u64" })),
      mapField("verdict", xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(VERDICT_ARM[leaf.verdict])])),
    ]),
  );
  return xdr.ScVal.scvMap([
    mapField("account", new Address(account).toScVal()),
    mapField("from_seq", nativeToScVal(fromSeq, { type: "u64" })),
    mapField("leaves", xdr.ScVal.scvVec(leafVals)),
    mapField(
      "tail",
      xdr.ScVal.scvVec(
        tail.map((step) =>
          xdr.ScVal.scvMap([
            mapField("amount", nativeToScVal(step.amount, { type: "i128" })),
            mapField("commitment_hash", hashToBytes(step.commitmentHash, "commitment_hash")),
            mapField("seller", new Address(step.seller).toScVal()),
          ]),
        ),
      ),
    ),
  ]);
}

export function decodeRangeRecord(native: unknown): RangeRecordV1 | undefined {
  if (native === null || native === undefined) return undefined;
  const raw = native as Record<string, unknown>;
  if (typeof raw["account"] !== "string") throw new AnchorClientError("BAD_RECORD", "range account missing.");
  return Object.freeze({
    account: raw["account"],
    fromSeq: BigInt(raw["from_seq"] as bigint | number),
    toSeq: BigInt(raw["to_seq"] as bigint | number),
    root: bytesToHex(raw["root"], "root"),
    counts: {
      ok: Number(raw["ok"] ?? 0),
      tainted: Number(raw["tainted"] ?? 0),
      mismatch: Number(raw["mismatch"] ?? 0),
      notDelivered: Number(raw["not_delivered"] ?? 0),
    },
    anchoredAt: Number(raw["anchored_at"] ?? 0),
  });
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
    onBehalfOf?: string,
  ): Promise<AnchorResult> {
    const seller = accountFromSellerId(receipt.sellerId);
    const attestor = onBehalfOf ?? buyer.publicKey();
    if (seller === attestor) {
      throw new AnchorClientError(
        "SELF_DEALING",
        "Buyer and seller are the same account; the contract rejects it.",
      );
    }

    const arg = deliveryInputScVal({
      buyer: attestor,
      seller,
      paymentHash: receipt.paymentHash,
      commitmentHash: receipt.commitmentHash,
      contentHash: receipt.contentHash,
      verdict: receipt.verdict,
    });

    return this.#submit(this.#contract.call("anchor_delivery", arg), buyer, onBehalfOf);
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
    const retval = await this.#simulateRead(
      "seller_score",
      [new Address(seller).toScVal()],
      reader.publicKey(),
    );
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
      batchedOk: count("batched_ok"),
      verified: {
        ok: count("verified_ok"),
        tainted: count("verified_tainted"),
        mismatch: count("verified_mismatch"),
        notDelivered: count("verified_not_delivered"),
      },
      asOf: new Date().toISOString(),
    });
  }

  /**
   * Read the anchored record for one payment, or `undefined` if none exists.
   *
   * Needs no secret: `readerAccount` is any existing account address, used only
   * as the simulation source. That is what lets a third party check a receipt
   * against the chain without being the buyer.
   */
  public async getDelivery(
    paymentHash: string,
    readerAccount: string,
  ): Promise<AnchoredDeliveryV1 | undefined> {
    const retval = await this.#simulateRead(
      "get_delivery",
      [hashToBytes(paymentHash, "payment_hash")],
      readerAccount,
    );
    return retval === undefined ? undefined : decodeDeliveryRecord(scValToNative(retval));
  }

  /**
   * Anchor a Merkle root over OK receipts from `buyer` to one seller. One
   * transaction for up to MAX_BATCH_LEAVES deliveries, instead of one each.
   */
  public async anchorBatch(
    input: { readonly sellerId: SellerId; readonly root: string; readonly count: number },
    buyer: Keypair,
    onBehalfOf?: string,
  ): Promise<AnchorResult> {
    const seller = accountFromSellerId(input.sellerId);
    const attestor = onBehalfOf ?? buyer.publicKey();
    if (seller === attestor) {
      throw new AnchorClientError("SELF_DEALING", "Buyer and seller are the same account; the contract rejects it.");
    }
    if (!Number.isInteger(input.count) || input.count < 1 || input.count > MAX_BATCH_COUNT) {
      throw new AnchorClientError("BAD_BATCH_COUNT", `Batch count must be 1..${String(MAX_BATCH_COUNT)}.`);
    }
    const field = (key: string, val: xdr.ScVal): xdr.ScMapEntry =>
      new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val });
    // Keys in sorted order, as the host requires for contracttype structs.
    const arg = xdr.ScVal.scvMap([
      field("buyer", new Address(attestor).toScVal()),
      field("count", xdr.ScVal.scvU32(input.count)),
      field("root", hashToBytes(input.root, "root")),
      field("seller", new Address(seller).toScVal()),
    ]);
    return this.#submit(this.#contract.call("anchor_batch", arg), buyer, onBehalfOf);
  }

  /**
   * Create an AegisOS account through this registry, which is what makes its
   * notarization trusted: the registry only deploys the account wasm it was
   * constructed with. `source` pays; the account is controlled by the keys.
   */
  public async createAccount(
    keys: { readonly owner: Buffer; readonly authority: Buffer; readonly session: Buffer },
    allowedAssets: readonly string[],
    source: Keypair,
  ): Promise<{ readonly address: string; readonly transactionHash: string }> {
    const operation = this.#contract.call(
      "create_account",
      xdr.ScVal.scvBytes(keys.owner),
      xdr.ScVal.scvBytes(keys.authority),
      xdr.ScVal.scvBytes(keys.session),
      xdr.ScVal.scvVec(allowedAssets.map((a) => new Address(a).toScVal())),
      xdr.ScVal.scvBytes(randomBytes(32)),
    );
    const result = await submitSorobanOperation({
      server: this.#server, passphrase: this.#passphrase, source, operation,
    });
    if (result.returnValue === undefined) throw new AnchorClientError("NO_RESULT", "create_account returned nothing.");
    return { address: Address.fromScVal(result.returnValue).toString(), transactionHash: result.transactionHash };
  }

  /**
   * Anchor the next contiguous run of the account's notarized payments. The
   * registry recomputes the payment chain over `leaves` and accepts only if it
   * lands on the account's current head.
   */
  public async anchorRange(
    account: string,
    fromSeq: bigint,
    leaves: readonly RangeLeafInput[],
    session: Keypair,
    tail: readonly ChainStepInput[] = [],
  ): Promise<AnchorResult> {
    if (leaves.length === 0 || leaves.length > MAX_RANGE_LEAVES) {
      throw new AnchorClientError("BAD_RANGE", `A range holds 1..${String(MAX_RANGE_LEAVES)} payments.`);
    }
    if (tail.length > MAX_RANGE_TAIL) {
      throw new AnchorClientError("BAD_RANGE", `A range tail holds at most ${String(MAX_RANGE_TAIL)} payments.`);
    }
    return this.#submit(
      this.#contract.call("anchor_range", rangeInputScVal(account, fromSeq, leaves, tail)),
      session,
      account,
    );
  }

  public async getRange(account: string, fromSeq: bigint, readerAccount: string): Promise<RangeRecordV1 | undefined> {
    const retval = await this.#simulateRead(
      "get_range",
      [new Address(account).toScVal(), nativeToScVal(fromSeq, { type: "u64" })],
      readerAccount,
    );
    return retval === undefined ? undefined : decodeRangeRecord(scValToNative(retval));
  }

  /** Whether the registry's own factory created `account`. */
  public async isAccount(account: string, readerAccount: string): Promise<boolean> {
    const retval = await this.#simulateRead("is_account", [new Address(account).toScVal()], readerAccount);
    return retval !== undefined && scValToNative(retval) === true;
  }

  public async getCheckpoint(account: string, readerAccount: string): Promise<CheckpointV1> {
    const retval = await this.#simulateRead("checkpoint", [new Address(account).toScVal()], readerAccount);
    if (retval === undefined) throw new AnchorClientError("NO_RESULT", "checkpoint returned nothing.");
    const raw = scValToNative(retval) as { seq: bigint | number; chain_head: Uint8Array };
    return { seq: BigInt(raw.seq), chainHead: Buffer.from(raw.chain_head).toString("hex") };
  }

  /** Read an anchored batch by root, or `undefined`. Needs no secret. */
  public async getBatch(root: string, readerAccount: string): Promise<AnchoredBatchV1 | undefined> {
    const retval = await this.#simulateRead("get_batch", [hashToBytes(root, "root")], readerAccount);
    return retval === undefined ? undefined : decodeBatchRecord(scValToNative(retval));
  }

  /**
   * Submit, paid by `buyer`. With `onBehalfOf` (an AegisOS smart account),
   * `buyer` is its session key and signs the account's `Registry` auth, which
   * the account accepts only for calls into its registry: the session key can
   * anchor, never move funds.
   */
  async #submit(operation: xdr.Operation, buyer: Keypair, onBehalfOf?: string): Promise<AnchorResult> {
    const accountAuth: ContractAccountAuth | undefined =
      onBehalfOf === undefined
        ? undefined
        : { account: onBehalfOf, signatureFor: async (preimage) => registryAuthScVal(buyer, preimage) };
    try {
      const result = await submitSorobanOperation({
        server: this.#server,
        passphrase: this.#passphrase,
        source: buyer,
        operation,
        ...(accountAuth === undefined ? {} : { accountAuth }),
      });
      return { transactionHash: result.transactionHash, explorerUrl: result.explorerUrl };
    } catch (error: unknown) {
      if (!(error instanceof SorobanSubmitError)) throw error;
      const code = { TX_FAILED: "ANCHOR_FAILED", TX_TIMEOUT: "ANCHOR_TIMEOUT" }[error.code] ?? error.code;
      throw new AnchorClientError(code, error.message);
    }
  }

  async #simulateRead(
    method: string,
    args: readonly xdr.ScVal[],
    readerAccount: string,
  ): Promise<xdr.ScVal | undefined> {
    // Reads change nothing, so one retry is safe. Testnet RPC occasionally
    // answers "Account not found" for an account that exists.
    try {
      return await this.#simulateReadOnce(method, args, readerAccount);
    } catch (error: unknown) {
      if (error instanceof AnchorClientError) throw error;
      await new Promise((resolve) => setTimeout(resolve, READ_RETRY_DELAY_MS));
      return this.#simulateReadOnce(method, args, readerAccount);
    }
  }

  async #simulateReadOnce(
    method: string,
    args: readonly xdr.ScVal[],
    readerAccount: string,
  ): Promise<xdr.ScVal | undefined> {
    const source = await this.#server.getAccount(readerAccount);
    const built = new TransactionBuilder(source, {
      fee: BASE_FEE,
      networkPassphrase: this.#passphrase,
    })
      .addOperation(this.#contract.call(method, ...args))
      .setTimeout(TX_TIMEOUT_SECONDS)
      .build();

    const simulated = await this.#server.simulateTransaction(built);
    if (rpc.Api.isSimulationError(simulated)) {
      throw new AnchorClientError("SIMULATION_FAILED", simulated.error);
    }
    return simulated.result?.retval;
  }
}
