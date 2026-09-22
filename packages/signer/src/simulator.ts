import { hashToUInt, sha256Canonical } from "./canonical.js";
import type {
  AddLiquidityOperationV1,
  ApprovedPolicyV1,
  BalanceChangeV1,
  CapabilityGrantV1,
  CapabilityReferenceV1,
  Erc20ApproveExactOperationV1,
  EthereumMockTransactionV1,
  MockReceiptV1,
  NarrowOperationRequestV1,
  NarrowOperationV1,
  OperationKind,
  OwnerApprovalV1,
  SignerRejectionCode,
  SignerSimulatorOptions,
  SimulationResultV1,
  StellarMockTransactionV1,
  SupportedChain,
  TokenAmountV1,
} from "./types.js";

type UnknownRecord = Record<string, unknown>;

class RejectedRequest extends Error {
  public constructor(
    public readonly code: SignerRejectionCode,
    message: string,
  ) {
    super(message);
  }
}

const opaqueFieldNames = new Set([
  "xdr",
  "calldata",
  "payload",
  "rawpayload",
  "serializedpayload",
  "serializedtransaction",
  "rawtransaction",
  "signedtransaction",
  "transaction",
  "transactiondata",
  "transactionpayload",
  "envelope",
  "envelopexdr",
  "signature",
  "signatures",
  "privatekey",
  "secretkey",
  "seedphrase",
  "mnemonic",
  "rpc",
  "rpcurl",
]);

function reject(code: SignerRejectionCode, message: string): never {
  throw new RejectedRequest(code, message);
}

function isRecord(value: unknown): value is UnknownRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireRecord(value: unknown, path: string): UnknownRecord {
  if (!isRecord(value)) reject("MALFORMED_REQUEST", `${path} must be a plain object`);
  return value;
}

function requireExactKeys(
  record: UnknownRecord,
  path: string,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      reject("UNEXPECTED_FIELD", `${path}.${key} is not accepted by the narrow request schema`);
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(record, key)) {
      reject("MALFORMED_REQUEST", `${path}.${key} is required`);
    }
  }
}

function requireNonBlankString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > 512) {
    reject("MALFORMED_REQUEST", `${path} must be a non-blank string of at most 512 characters`);
  }
  return value;
}

function requireDate(value: unknown, path: string): string {
  const date = requireNonBlankString(value, path);
  if (Number.isNaN(Date.parse(date))) {
    reject("MALFORMED_REQUEST", `${path} must be an ISO-8601 timestamp`);
  }
  return date;
}

function requireDigest(value: unknown, path: string): string {
  const digest = requireNonBlankString(value, path);
  if (!/^sha256:[a-f0-9]{64}$/.test(digest)) {
    reject("MALFORMED_REQUEST", `${path} must be a sha256:<hex> digest`);
  }
  return digest;
}

function requireNonce(value: unknown, path: string): string {
  const nonce = requireNonBlankString(value, path);
  if (!/^[A-Za-z0-9._:-]{1,256}$/.test(nonce)) {
    reject("MALFORMED_REQUEST", `${path} contains unsupported characters`);
  }
  return nonce;
}

function requirePositiveAtomic(value: unknown, path: string): string {
  const amount = requireNonBlankString(value, path);
  if (!/^[1-9][0-9]*$/.test(amount)) {
    reject("MALFORMED_REQUEST", `${path} must be a positive base-unit integer string`);
  }
  return amount;
}

function requireNonNegativeAtomic(value: unknown, path: string): string {
  const amount = requireNonBlankString(value, path);
  if (!/^(0|[1-9][0-9]*)$/.test(amount)) {
    reject("MALFORMED_REQUEST", `${path} must be a non-negative base-unit integer string`);
  }
  return amount;
}

function requireBps(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 10_000) {
    reject("MALFORMED_REQUEST", `${path} must be an integer from 0 to 10000`);
  }
  return value;
}

function findOpaqueField(value: unknown, path = "$", seen = new Set<object>()): string | undefined {
  if (value === null || typeof value !== "object") return undefined;
  if (seen.has(value)) return undefined;
  seen.add(value);

  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const found = findOpaqueField(value[index], `${path}[${index}]`, seen);
      if (found) return found;
    }
    return undefined;
  }

  if (!isRecord(value)) return undefined;
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
    if (
      opaqueFieldNames.has(normalized) ||
      normalized.includes("calldata") ||
      normalized.includes("serialized") ||
      normalized.includes("rawtransaction") ||
      normalized.includes("signedtransaction")
    ) {
      return `${path}.${key}`;
    }
    const found = findOpaqueField(child, `${path}.${key}`, seen);
    if (found) return found;
  }
  return undefined;
}

function parseTokenAmount(value: unknown, path: string): TokenAmountV1 {
  const record = requireRecord(value, path);
  requireExactKeys(record, path, ["asset", "amountAtomic"]);
  return {
    asset: requireNonBlankString(record.asset, `${path}.asset`),
    amountAtomic: requirePositiveAtomic(record.amountAtomic, `${path}.amountAtomic`),
  };
}

function parseOwnerApproval(value: unknown): OwnerApprovalV1 {
  const record = requireRecord(value, "$.ownerApproval");
  requireExactKeys(record, "$.ownerApproval", [
    "schemaVersion",
    "approvalId",
    "ownerId",
    "intentHash",
    "expiresAt",
  ]);
  if (record.schemaVersion !== "aegisos.owner-approval.v1") {
    reject("MALFORMED_REQUEST", "$.ownerApproval.schemaVersion is unsupported");
  }
  return {
    schemaVersion: "aegisos.owner-approval.v1",
    approvalId: requireNonBlankString(record.approvalId, "$.ownerApproval.approvalId"),
    ownerId: requireNonBlankString(record.ownerId, "$.ownerApproval.ownerId"),
    intentHash: requireDigest(record.intentHash, "$.ownerApproval.intentHash"),
    expiresAt: requireDate(record.expiresAt, "$.ownerApproval.expiresAt"),
  };
}

function parseCapabilityReference(value: unknown): CapabilityReferenceV1 {
  const record = requireRecord(value, "$.capability");
  requireExactKeys(record, "$.capability", ["schemaVersion", "id", "hash", "nonce"]);
  if (record.schemaVersion !== "aegisos.capability-reference.v1") {
    reject("MALFORMED_REQUEST", "$.capability.schemaVersion is unsupported");
  }
  return {
    schemaVersion: "aegisos.capability-reference.v1",
    id: requireNonBlankString(record.id, "$.capability.id"),
    hash: requireDigest(record.hash, "$.capability.hash"),
    nonce: requireNonce(record.nonce, "$.capability.nonce"),
  };
}

function parseOperation(value: unknown): NarrowOperationV1 {
  const record = requireRecord(value, "$.operation");
  const kind = record.kind;
  const common = ["kind", "protocol", "pool", "slippageBps", "feeAtomic"] as const;

  if (kind === "SWAP_EXACT_INPUT") {
    requireExactKeys(record, "$.operation", [...common, "input", "outputAsset", "minOutputAmountAtomic"]);
    return {
      kind,
      protocol: requireNonBlankString(record.protocol, "$.operation.protocol"),
      pool: requireNonBlankString(record.pool, "$.operation.pool"),
      slippageBps: requireBps(record.slippageBps, "$.operation.slippageBps"),
      feeAtomic: requireNonNegativeAtomic(record.feeAtomic, "$.operation.feeAtomic"),
      input: parseTokenAmount(record.input, "$.operation.input"),
      outputAsset: requireNonBlankString(record.outputAsset, "$.operation.outputAsset"),
      minOutputAmountAtomic: requirePositiveAtomic(
        record.minOutputAmountAtomic,
        "$.operation.minOutputAmountAtomic",
      ),
    };
  }

  if (kind === "ADD_LIQUIDITY") {
    requireExactKeys(record, "$.operation", [...common, "assetA", "assetB", "minLpAmountAtomic"]);
    return {
      kind,
      protocol: requireNonBlankString(record.protocol, "$.operation.protocol"),
      pool: requireNonBlankString(record.pool, "$.operation.pool"),
      slippageBps: requireBps(record.slippageBps, "$.operation.slippageBps"),
      feeAtomic: requireNonNegativeAtomic(record.feeAtomic, "$.operation.feeAtomic"),
      assetA: parseTokenAmount(record.assetA, "$.operation.assetA"),
      assetB: parseTokenAmount(record.assetB, "$.operation.assetB"),
      minLpAmountAtomic: requirePositiveAtomic(record.minLpAmountAtomic, "$.operation.minLpAmountAtomic"),
    };
  }

  if (kind === "REMOVE_LIQUIDITY") {
    requireExactKeys(record, "$.operation", [...common, "lpToken", "minOutputs"]);
    if (!Array.isArray(record.minOutputs) || record.minOutputs.length === 0 || record.minOutputs.length > 8) {
      reject("MALFORMED_REQUEST", "$.operation.minOutputs must contain between one and eight token amounts");
    }
    return {
      kind,
      protocol: requireNonBlankString(record.protocol, "$.operation.protocol"),
      pool: requireNonBlankString(record.pool, "$.operation.pool"),
      slippageBps: requireBps(record.slippageBps, "$.operation.slippageBps"),
      feeAtomic: requireNonNegativeAtomic(record.feeAtomic, "$.operation.feeAtomic"),
      lpToken: parseTokenAmount(record.lpToken, "$.operation.lpToken"),
      minOutputs: record.minOutputs.map((output, index) => parseTokenAmount(output, `$.operation.minOutputs[${index}]`)),
    };
  }

  if (kind === "ERC20_APPROVE_EXACT") {
    requireExactKeys(record, "$.operation", [...common, "asset", "spender", "amountAtomic", "approvalExpiresAt"]);
    return {
      kind,
      protocol: requireNonBlankString(record.protocol, "$.operation.protocol"),
      pool: requireNonBlankString(record.pool, "$.operation.pool"),
      slippageBps: requireBps(record.slippageBps, "$.operation.slippageBps"),
      feeAtomic: requireNonNegativeAtomic(record.feeAtomic, "$.operation.feeAtomic"),
      asset: requireNonBlankString(record.asset, "$.operation.asset"),
      spender: requireNonBlankString(record.spender, "$.operation.spender"),
      amountAtomic: requirePositiveAtomic(record.amountAtomic, "$.operation.amountAtomic"),
      approvalExpiresAt: requireDate(record.approvalExpiresAt, "$.operation.approvalExpiresAt"),
    };
  }

  reject("MALFORMED_REQUEST", "$.operation.kind is unsupported");
}

/**
 * Converts untrusted JSON into a newly allocated, strict request object.  It
 * is intentionally public so an IPC boundary can validate before dispatching.
 */
export function parseNarrowOperationRequest(value: unknown): NarrowOperationRequestV1 {
  const opaqueField = findOpaqueField(value);
  if (opaqueField) {
    reject("OPAQUE_PAYLOAD_FORBIDDEN", `${opaqueField} is an opaque serialized or signing field`);
  }

  const record = requireRecord(value, "$");
  requireExactKeys(
    record,
    "$",
    [
      "schemaVersion",
      "requestId",
      "chain",
      "createdAt",
      "expiresAt",
      "nonce",
      "policy",
      "intentHash",
      "operation",
    ],
    ["ownerApproval", "capability"],
  );
  if (record.schemaVersion !== "aegisos.operation-request.v1") {
    reject("MALFORMED_REQUEST", "$.schemaVersion is unsupported");
  }
  if (record.chain !== "stellar-testnet" && record.chain !== "ethereum-sepolia") {
    reject("MALFORMED_REQUEST", "$.chain is unsupported");
  }

  const policy = requireRecord(record.policy, "$.policy");
  requireExactKeys(policy, "$.policy", ["id", "hash"]);

  const parsed: NarrowOperationRequestV1 = {
    schemaVersion: "aegisos.operation-request.v1",
    requestId: requireNonBlankString(record.requestId, "$.requestId"),
    chain: record.chain,
    createdAt: requireDate(record.createdAt, "$.createdAt"),
    expiresAt: requireDate(record.expiresAt, "$.expiresAt"),
    nonce: requireNonce(record.nonce, "$.nonce"),
    policy: {
      id: requireNonBlankString(policy.id, "$.policy.id"),
      hash: requireDigest(policy.hash, "$.policy.hash"),
    },
    intentHash: requireDigest(record.intentHash, "$.intentHash"),
    operation: parseOperation(record.operation),
  };

  if (Object.hasOwn(record, "ownerApproval")) {
    (parsed as { ownerApproval?: OwnerApprovalV1 }).ownerApproval = parseOwnerApproval(record.ownerApproval);
  }
  if (Object.hasOwn(record, "capability")) {
    (parsed as { capability?: CapabilityReferenceV1 }).capability = parseCapabilityReference(record.capability);
  }
  return parsed;
}

function hashWithoutField<T extends { readonly hash: string }>(value: T): string {
  const { hash: _ignored, ...withoutHash } = value;
  return sha256Canonical(withoutHash);
}

export function hashApprovedPolicy(policy: ApprovedPolicyV1): string {
  return hashWithoutField(policy);
}

export function hashCapabilityGrant(grant: CapabilityGrantV1): string {
  return hashWithoutField(grant);
}

/** The owner approval binds this projection, not an opaque transaction. */
export function hashExecutionIntent(request: NarrowOperationRequestV1): string {
  const { intentHash: _intentHash, ownerApproval: _ownerApproval, capability: _capability, ...intent } = request;
  return sha256Canonical(intent);
}

function assertDateString(value: string, label: string): void {
  if (Number.isNaN(Date.parse(value))) {
    throw new TypeError(`${label} must be an ISO-8601 timestamp`);
  }
}

function assertPositiveAtomic(value: string, label: string): void {
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new TypeError(`${label} must be a positive base-unit integer string`);
  }
}

function assertNonNegativeAtomic(value: string, label: string): void {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new TypeError(`${label} must be a non-negative base-unit integer string`);
  }
}

function assertConfiguredPolicy(policy: ApprovedPolicyV1): void {
  if (policy.schemaVersion !== "aegisos.approved-policy.v1" || policy.status !== "APPROVED") {
    throw new TypeError(`Policy ${policy.id} is not an approved V1 policy`);
  }
  assertDateString(policy.validFrom, `Policy ${policy.id}.validFrom`);
  assertDateString(policy.expiresAt, `Policy ${policy.id}.expiresAt`);
  if (Date.parse(policy.validFrom) >= Date.parse(policy.expiresAt)) {
    throw new TypeError(`Policy ${policy.id} must expire after it becomes valid`);
  }
  if (policy.executionMode !== "OWNER_APPROVAL" && policy.executionMode !== "DELEGATED") {
    throw new TypeError(`Policy ${policy.id} has an unsupported execution mode`);
  }
  if (!Number.isInteger(policy.maxSlippageBps) || policy.maxSlippageBps < 0 || policy.maxSlippageBps > 10_000) {
    throw new TypeError(`Policy ${policy.id}.maxSlippageBps is invalid`);
  }
  assertNonNegativeAtomic(policy.maxFeeAtomic, `Policy ${policy.id}.maxFeeAtomic`);
  for (const [asset, amount] of Object.entries(policy.maxInputByAsset)) {
    if (asset.trim().length === 0) throw new TypeError(`Policy ${policy.id} contains a blank asset`);
    assertPositiveAtomic(amount, `Policy ${policy.id}.maxInputByAsset.${asset}`);
  }
  if (policy.hash !== hashApprovedPolicy(policy)) {
    throw new TypeError(`Policy ${policy.id} hash does not match its canonical contents`);
  }
}

function assertConfiguredCapability(grant: CapabilityGrantV1): void {
  if (grant.schemaVersion !== "aegisos.capability-grant.v1") {
    throw new TypeError(`Capability ${grant.id} is not a V1 grant`);
  }
  assertDateString(grant.validFrom, `Capability ${grant.id}.validFrom`);
  assertDateString(grant.expiresAt, `Capability ${grant.id}.expiresAt`);
  if (Date.parse(grant.validFrom) >= Date.parse(grant.expiresAt)) {
    throw new TypeError(`Capability ${grant.id} must expire after it becomes valid`);
  }
  if (!Number.isInteger(grant.maxSlippageBps) || grant.maxSlippageBps < 0 || grant.maxSlippageBps > 10_000) {
    throw new TypeError(`Capability ${grant.id}.maxSlippageBps is invalid`);
  }
  assertNonNegativeAtomic(grant.maxFeeAtomic, `Capability ${grant.id}.maxFeeAtomic`);
  for (const [asset, amount] of Object.entries(grant.maxInputByAsset)) {
    if (asset.trim().length === 0) throw new TypeError(`Capability ${grant.id} contains a blank asset`);
    assertPositiveAtomic(amount, `Capability ${grant.id}.maxInputByAsset.${asset}`);
  }
  if (grant.hash !== hashCapabilityGrant(grant)) {
    throw new TypeError(`Capability ${grant.id} hash does not match its canonical contents`);
  }
}

function operationInputs(operation: NarrowOperationV1): readonly TokenAmountV1[] {
  switch (operation.kind) {
    case "SWAP_EXACT_INPUT":
      return [operation.input];
    case "ADD_LIQUIDITY":
      return [operation.assetA, operation.assetB];
    case "REMOVE_LIQUIDITY":
      return [operation.lpToken];
    case "ERC20_APPROVE_EXACT":
      return [{ asset: operation.asset, amountAtomic: operation.amountAtomic }];
  }
}

function operationAssets(operation: NarrowOperationV1): readonly string[] {
  switch (operation.kind) {
    case "SWAP_EXACT_INPUT":
      return [operation.input.asset, operation.outputAsset];
    case "ADD_LIQUIDITY":
      return [operation.assetA.asset, operation.assetB.asset];
    case "REMOVE_LIQUIDITY":
      return [operation.lpToken.asset, ...operation.minOutputs.map((output) => output.asset)];
    case "ERC20_APPROVE_EXACT":
      return [operation.asset];
  }
}

function compareLimit(value: string, maximum: string): boolean {
  return BigInt(value) <= BigInt(maximum);
}

function isCurrent(now: Date, validFrom: string, expiresAt: string): boolean {
  const timestamp = now.getTime();
  return timestamp >= Date.parse(validFrom) && timestamp < Date.parse(expiresAt);
}

function enforceRoute(
  request: NarrowOperationRequestV1,
  allowedChains: readonly SupportedChain[],
  allowedOperations: readonly OperationKind[],
  allowedProtocols: readonly string[],
  allowedPools: readonly string[],
  allowedAssets: readonly string[],
  maxInputByAsset: Readonly<Record<string, string>>,
  maxSlippageBps: number,
  maxFeeAtomic: string,
  codes: {
    readonly operation: SignerRejectionCode;
    readonly route: SignerRejectionCode;
    readonly asset: SignerRejectionCode;
    readonly limit: SignerRejectionCode;
  },
): void {
  if (!allowedChains.includes(request.chain) || !allowedOperations.includes(request.operation.kind)) {
    reject(codes.operation, "The operation or chain is not authorized");
  }
  if (!allowedProtocols.includes(request.operation.protocol) || !allowedPools.includes(request.operation.pool)) {
    reject(codes.route, "The requested protocol route is not authorized");
  }
  for (const asset of operationAssets(request.operation)) {
    if (!allowedAssets.includes(asset)) {
      reject(codes.asset, `Asset ${asset} is not authorized`);
    }
  }
  if (request.operation.slippageBps > maxSlippageBps || !compareLimit(request.operation.feeAtomic, maxFeeAtomic)) {
    reject(codes.limit, "The requested slippage or fee exceeds its limit");
  }
  for (const input of operationInputs(request.operation)) {
    const maximum = maxInputByAsset[input.asset];
    if (maximum === undefined || !compareLimit(input.amountAtomic, maximum)) {
      reject(codes.limit, `Input limit exceeded for ${input.asset}`);
    }
  }
}

function makeBalanceChanges(operation: NarrowOperationV1): readonly BalanceChangeV1[] {
  const debit = (amount: TokenAmountV1): BalanceChangeV1 => ({
    asset: amount.asset,
    deltaAtomic: `-${amount.amountAtomic}`,
  });
  const credit = (asset: string, amountAtomic: string): BalanceChangeV1 => ({ asset, deltaAtomic: amountAtomic });

  switch (operation.kind) {
    case "SWAP_EXACT_INPUT":
      return [debit(operation.input), credit(operation.outputAsset, operation.minOutputAmountAtomic)];
    case "ADD_LIQUIDITY":
      return [
        debit(operation.assetA),
        debit(operation.assetB),
        credit(`lp:${operation.pool}`, operation.minLpAmountAtomic),
      ];
    case "REMOVE_LIQUIDITY":
      return [debit(operation.lpToken), ...operation.minOutputs.map((output) => credit(output.asset, output.amountAtomic))];
    case "ERC20_APPROVE_EXACT":
      return [];
  }
}

function createMockReceipt(request: NarrowOperationRequestV1, requestHash: string): MockReceiptV1 {
  const transactionSeed = sha256Canonical({
    domain: "aegisos.mock-transaction.v1",
    chain: request.chain,
    requestHash,
  });
  const transaction: StellarMockTransactionV1 | EthereumMockTransactionV1 =
    request.chain === "stellar-testnet"
      ? {
          kind: "stellar-testnet-mock",
          transactionId: transactionSeed,
          ledgerSequence: hashToUInt(transactionSeed, 1_000_000, 1_000_000),
        }
      : {
          kind: "ethereum-sepolia-mock",
          transactionHash: transactionSeed,
          blockNumber: hashToUInt(transactionSeed, 5_000_000, 1_000_000),
          gasUsed: hashToUInt(transactionSeed.slice(0, 48), 21_000, 200_000),
        };
  const receiptId = sha256Canonical({ domain: "aegisos.mock-receipt-id.v1", requestHash });
  const withoutReceiptHash = {
    schemaVersion: "aegisos.mock-receipt.v1" as const,
    status: "SIMULATED_ACCEPTED" as const,
    receiptId,
    requestHash,
    intentHash: request.intentHash,
    chain: request.chain,
    operation: request.operation.kind,
    policyId: request.policy.id,
    // Receipt timestamps deliberately derive from the request, not wall time.
    simulatedAt: request.createdAt,
    balanceChanges: makeBalanceChanges(request.operation),
    transaction,
  };
  return {
    ...withoutReceiptHash,
    receiptHash: sha256Canonical(withoutReceiptHash),
  };
}

/**
 * A network-free stand-in for the isolated signer process.  It accepts only
 * typed operation intent, verifies a pre-provisioned policy, and returns a
 * synthetic receipt.  It neither holds keys nor signs, broadcasts, or parses
 * a serialized chain transaction.
 */
export class DeterministicSignerSimulator {
  private readonly policies = new Map<string, ApprovedPolicyV1>();
  private readonly capabilities = new Map<string, CapabilityGrantV1>();
  private readonly usedRequestNonces = new Set<string>();
  private readonly usedCapabilityNonces = new Set<string>();
  private readonly now: () => Date;

  public constructor(options: SignerSimulatorOptions) {
    this.now = options.now ?? (() => new Date());
    for (const policy of options.policies) this.registerPolicy(policy);
    for (const capability of options.capabilities ?? []) this.registerCapability(capability);
  }

  /** Trusted bootstrap only; agent requests cannot register or alter policy. */
  public registerPolicy(policy: ApprovedPolicyV1): void {
    assertConfiguredPolicy(policy);
    if (this.policies.has(policy.id)) {
      throw new TypeError(`Duplicate policy id ${policy.id}`);
    }
    this.policies.set(policy.id, policy);
  }

  /** Trusted bootstrap only; a capability is intentionally one-use in this MVP. */
  public registerCapability(capability: CapabilityGrantV1): void {
    assertConfiguredCapability(capability);
    if (this.capabilities.has(capability.id)) {
      throw new TypeError(`Duplicate capability id ${capability.id}`);
    }
    this.capabilities.set(capability.id, capability);
  }

  public simulate(untrustedRequest: unknown): SimulationResultV1 {
    let request: NarrowOperationRequestV1;
    try {
      request = parseNarrowOperationRequest(untrustedRequest);
    } catch (error) {
      return this.toRejection(error);
    }

    try {
      const now = this.now();
      if (Number.isNaN(now.getTime())) throw new TypeError("The configured signer clock returned an invalid date");
      if (now.getTime() >= Date.parse(request.expiresAt)) {
        reject("EXPIRED_REQUEST", "The operation request has expired");
      }
      if (
        request.operation.kind === "ERC20_APPROVE_EXACT" &&
        (request.chain !== "ethereum-sepolia" || Date.parse(request.operation.approvalExpiresAt) > Date.parse(request.expiresAt))
      ) {
        reject("UNSUPPORTED_CHAIN_OPERATION", "ERC-20 approvals require Sepolia and cannot outlive the request");
      }

      const nonceKey = `${request.policy.id}:${request.chain}:${request.nonce}`;
      if (this.usedRequestNonces.has(nonceKey)) {
        reject("REPLAYED_NONCE", "This request nonce has already been consumed");
      }

      const policy = this.policies.get(request.policy.id);
      if (!policy) reject("UNKNOWN_POLICY", "No trusted policy matches the request");
      if (policy.hash !== request.policy.hash) {
        reject("POLICY_HASH_MISMATCH", "The request policy hash differs from the trusted policy");
      }
      if (!isCurrent(now, policy.validFrom, policy.expiresAt)) {
        reject("POLICY_NOT_CURRENT", "The trusted policy is not currently valid");
      }
      enforceRoute(
        request,
        policy.allowedChains,
        policy.allowedOperations,
        policy.allowedProtocols,
        policy.allowedPools,
        policy.allowedAssets,
        policy.maxInputByAsset,
        policy.maxSlippageBps,
        policy.maxFeeAtomic,
        {
          operation: "POLICY_DENIED_OPERATION",
          route: "POLICY_DENIED_ROUTE",
          asset: "POLICY_DENIED_ASSET",
          limit: "POLICY_LIMIT_EXCEEDED",
        },
      );

      const calculatedIntentHash = hashExecutionIntent(request);
      if (request.intentHash !== calculatedIntentHash) {
        reject("INVALID_OWNER_APPROVAL", "The request intent hash does not bind its typed operation");
      }

      let capabilityNonceKey: string | undefined;
      if (policy.executionMode === "OWNER_APPROVAL") {
        if (request.capability) {
          reject("AUTHORIZATION_MODE_MISMATCH", "A delegated capability cannot be used with owner approval mode");
        }
        if (!request.ownerApproval) {
          reject("MISSING_OWNER_APPROVAL", "This policy requires a typed owner approval");
        }
        if (request.ownerApproval.intentHash !== calculatedIntentHash) {
          reject("INVALID_OWNER_APPROVAL", "The owner approval does not bind this operation intent");
        }
        if (now.getTime() >= Date.parse(request.ownerApproval.expiresAt)) {
          reject("EXPIRED_OWNER_APPROVAL", "The owner approval has expired");
        }
      } else {
        if (request.ownerApproval) {
          reject("AUTHORIZATION_MODE_MISMATCH", "Owner approval cannot be substituted for a delegated capability");
        }
        if (!request.capability) {
          reject("UNKNOWN_CAPABILITY", "This policy requires a delegated capability");
        }
        const capability = this.capabilities.get(request.capability.id);
        if (!capability) reject("UNKNOWN_CAPABILITY", "No trusted capability matches the request");
        if (capability.hash !== request.capability.hash) {
          reject("CAPABILITY_HASH_MISMATCH", "The capability hash differs from the trusted grant");
        }
        if (
          capability.policyId !== policy.id ||
          capability.policyHash !== policy.hash ||
          capability.nonce !== request.capability.nonce
        ) {
          reject("CAPABILITY_MISMATCH", "The capability is not bound to this policy and nonce");
        }
        if (!isCurrent(now, capability.validFrom, capability.expiresAt)) {
          reject("CAPABILITY_NOT_CURRENT", "The trusted capability is not currently valid");
        }
        capabilityNonceKey = `${capability.id}:${capability.nonce}`;
        if (this.usedCapabilityNonces.has(capabilityNonceKey)) {
          reject("CAPABILITY_REPLAYED", "This one-use capability has already been consumed");
        }
        enforceRoute(
          request,
          capability.allowedChains,
          capability.allowedOperations,
          capability.allowedProtocols,
          capability.allowedPools,
          capability.allowedAssets,
          capability.maxInputByAsset,
          capability.maxSlippageBps,
          capability.maxFeeAtomic,
          {
            operation: "CAPABILITY_DENIED_OPERATION",
            route: "CAPABILITY_DENIED_ROUTE",
            asset: "CAPABILITY_DENIED_ASSET",
            limit: "CAPABILITY_LIMIT_EXCEEDED",
          },
        );
      }

      const requestHash = sha256Canonical(request);
      const receipt = createMockReceipt(request, requestHash);
      // State changes occur only after every check and receipt calculation succeeds.
      this.usedRequestNonces.add(nonceKey);
      if (capabilityNonceKey) this.usedCapabilityNonces.add(capabilityNonceKey);
      return { ok: true, receipt };
    } catch (error) {
      return this.toRejection(error);
    }
  }

  private toRejection(error: unknown): SimulationResultV1 {
    if (error instanceof RejectedRequest) {
      return { ok: false, rejection: { code: error.code, message: error.message } };
    }
    // Configuration and implementation failures must not accidentally look like authorization.
    return {
      ok: false,
      rejection: {
        code: "MALFORMED_REQUEST",
        message: "Signer simulation failed closed while validating the request",
      },
    };
  }
}

/** Exposed for tests and adapters that need to derive a narrow approval request. */
export function isErc20Approval(operation: NarrowOperationV1): operation is Erc20ApproveExactOperationV1 {
  return operation.kind === "ERC20_APPROVE_EXACT";
}

/** Exposed only to make discriminated-union integrations ergonomic. */
export function isAddLiquidity(operation: NarrowOperationV1): operation is AddLiquidityOperationV1 {
  return operation.kind === "ADD_LIQUIDITY";
}
