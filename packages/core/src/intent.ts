import { sha256Canonical } from "./crypto.js";
import { fail } from "./errors.js";
import { validateMemoryEnvelope, verifyMemoryEnvelope, type MemoryEnvelopeV1 } from "./memory.js";
import {
  asRecord,
  assertUnique,
  exactKeys,
  optionalString,
  requiredAddress,
  requiredArray,
  requiredAtomic,
  requiredBoolean,
  requiredHash,
  requiredId,
  requiredInteger,
  requiredIsoTimestamp,
} from "./validation.js";
import { randomUUID } from "node:crypto";

export const NETWORK_IDS = ["stellar-testnet", "ethereum-sepolia"] as const;
export type NetworkId = (typeof NETWORK_IDS)[number];

export const OPERATION_KINDS = ["SWAP_EXACT_INPUT", "ADD_LIQUIDITY", "REMOVE_LIQUIDITY", "APPROVE_EXACT"] as const;
export type OperationKind = (typeof OPERATION_KINDS)[number];

export interface AssetRefV1 {
  /** Stable policy identifier, e.g. stellar:USDC or ethereum-sepolia:mock-usdc. */
  readonly assetId: string;
  readonly network: NetworkId;
  /** Token contract / Soroban contract / native asset marker from a fixed manifest. */
  readonly contractId?: string;
  readonly symbol?: string;
  readonly decimals?: number;
}

/** Non-negative integer in the asset's smallest unit; decimal values are forbidden. */
export interface AssetAmountV1 {
  readonly asset: AssetRefV1;
  readonly atomic: string;
}

/** A named, versioned deployment. The isolated signer resolves it through a pinned manifest. */
export interface ProtocolTargetV1 {
  readonly protocolId: string;
  readonly manifestId: string;
  readonly contractId: string;
  readonly poolId?: string;
}

export interface SwapExactInputOperationV1 {
  readonly kind: "SWAP_EXACT_INPUT";
  readonly input: AssetAmountV1;
  readonly minOutput: AssetAmountV1;
  readonly recipient: string;
}

export interface AddLiquidityOperationV1 {
  readonly kind: "ADD_LIQUIDITY";
  readonly amounts: readonly AssetAmountV1[];
  readonly recipient: string;
  readonly minimumShares?: string;
}

export interface RemoveLiquidityOperationV1 {
  readonly kind: "REMOVE_LIQUIDITY";
  readonly lpToken: AssetAmountV1;
  readonly minAmounts: readonly AssetAmountV1[];
  readonly recipient: string;
}

/** Exact and expiring approvals only. Unlimited approvals have no representation. */
export interface ApproveExactOperationV1 {
  readonly kind: "APPROVE_EXACT";
  readonly token: AssetRefV1;
  readonly spender: string;
  readonly amount: string;
  readonly expiresAt: string;
}

export type FinancialOperationV1 =
  | SwapExactInputOperationV1
  | AddLiquidityOperationV1
  | RemoveLiquidityOperationV1
  | ApproveExactOperationV1;

export interface IntentDraftV1 {
  readonly version: "1";
  readonly id: string;
  readonly network: NetworkId;
  readonly operation: FinancialOperationV1;
  readonly protocol: ProtocolTargetV1;
  readonly sourceAccount: string;
  readonly requestedAt: string;
  readonly sourceMemoryIds: readonly string[];
  /** Never interpreted by policy; useful only for display and human review. */
  readonly rationale?: string;
}

export interface IntentProvenanceV1 {
  readonly draftId: string;
  readonly memoryEnvelopeIds: readonly string[];
  readonly memoryContentHashes: readonly string[];
  readonly containsUntrustedInput: boolean;
}

/** Fully parameterized operation. This is the only data the signer may consider. */
export interface ExecutionIntentV1 {
  readonly version: "1";
  readonly id: string;
  readonly draftHash: string;
  readonly network: NetworkId;
  readonly operation: FinancialOperationV1;
  readonly protocol: ProtocolTargetV1;
  readonly sourceAccount: string;
  readonly nonce: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly policyId: string;
  readonly maxSlippageBps: number;
  readonly maxFeeAtomic: string;
  readonly provenance: IntentProvenanceV1;
}

export interface CreateIntentDraftInput {
  readonly id?: string;
  readonly network: NetworkId;
  readonly operation: FinancialOperationV1;
  readonly protocol: ProtocolTargetV1;
  readonly sourceAccount: string;
  readonly requestedAt?: string;
  readonly sourceMemoryIds: readonly string[];
  readonly rationale?: string;
}

export interface CreateExecutionIntentInput {
  readonly id?: string;
  readonly draft: IntentDraftV1;
  readonly nonce: string;
  readonly policyId: string;
  readonly expiresAt: string;
  readonly maxSlippageBps: number;
  readonly maxFeeAtomic: string;
  readonly createdAt?: string;
  readonly memoryContentHashes: readonly string[];
  readonly containsUntrustedInput: boolean;
}

export type MemoryPublicKeyLookup = Readonly<Record<string, string>> | ((keyId: string) => string | undefined);

/**
 * Safer constructor input: provenance is computed from sealed envelopes rather
 * than a caller-provided taint boolean. Without verified signatures, content
 * remains tainted and cannot use a clean delegated capability.
 */
export interface CreateExecutionIntentFromMemoryEnvelopesInput
  extends Omit<CreateExecutionIntentInput, "memoryContentHashes" | "containsUntrustedInput"> {
  readonly memoryEnvelopes: readonly MemoryEnvelopeV1[];
  readonly memoryPublicKeys?: MemoryPublicKeyLookup;
}

function newId(prefix: string): string {
  return `${prefix}:${randomUUID()}`;
}

function validateNetwork(value: unknown, path: string): asserts value is NetworkId {
  if (!NETWORK_IDS.includes(value as NetworkId)) {
    fail(path, "must be stellar-testnet or ethereum-sepolia; mainnet is unsupported");
  }
}

export function validateAssetRef(value: unknown): asserts value is AssetRefV1 {
  const record = asRecord(value, "asset");
  exactKeys(record, ["assetId", "network"], ["contractId", "symbol", "decimals"], "asset");
  requiredId(record.assetId, "asset.assetId");
  validateNetwork(record.network, "asset.network");
  if (record.contractId !== undefined) requiredAddress(record.contractId, "asset.contractId");
  if (record.symbol !== undefined) optionalString(record.symbol, "asset.symbol", { max: 32, pattern: /^[A-Za-z0-9._-]+$/ });
  if (record.decimals !== undefined) requiredInteger(record.decimals, "asset.decimals", 0, 36);
}

export function validateAssetAmount(value: unknown, path = "amount"): asserts value is AssetAmountV1 {
  const record = asRecord(value, path);
  exactKeys(record, ["asset", "atomic"], [], path);
  validateAssetRef(record.asset);
  requiredAtomic(record.atomic, `${path}.atomic`, true);
}

export function validateProtocolTarget(value: unknown): asserts value is ProtocolTargetV1 {
  const record = asRecord(value, "protocol");
  exactKeys(record, ["protocolId", "manifestId", "contractId"], ["poolId"], "protocol");
  requiredId(record.protocolId, "protocol.protocolId");
  requiredId(record.manifestId, "protocol.manifestId");
  requiredAddress(record.contractId, "protocol.contractId");
  if (record.poolId !== undefined) requiredId(record.poolId, "protocol.poolId");
}

function validateAmountsMatchNetwork(amounts: readonly unknown[], network: NetworkId, path: string): void {
  const assetIds: string[] = [];
  for (let index = 0; index < amounts.length; index += 1) {
    validateAssetAmount(amounts[index], `${path}[${index}]`);
    const amount = amounts[index] as AssetAmountV1;
    if (amount.asset.network !== network) fail(`${path}[${index}].asset.network`, "must match the intent network");
    assetIds.push(amount.asset.assetId);
  }
  assertUnique(assetIds, path);
}

export function validateFinancialOperation(value: unknown, network?: NetworkId): asserts value is FinancialOperationV1 {
  const record = asRecord(value, "operation");
  const kind = record.kind;
  if (!OPERATION_KINDS.includes(kind as OperationKind)) {
    fail("operation.kind", "must be a supported typed financial operation");
  }
  switch (kind) {
    case "SWAP_EXACT_INPUT": {
      exactKeys(record, ["kind", "input", "minOutput", "recipient"], [], "operation");
      validateAssetAmount(record.input, "operation.input");
      validateAssetAmount(record.minOutput, "operation.minOutput");
      const input = record.input as AssetAmountV1;
      const output = record.minOutput as AssetAmountV1;
      if (input.asset.assetId === output.asset.assetId) fail("operation.minOutput.asset.assetId", "must differ from input asset");
      if (input.asset.network !== output.asset.network) fail("operation", "swap assets must use one network");
      if (network !== undefined && (input.asset.network !== network || output.asset.network !== network)) {
        fail("operation", "all assets must match the intent network");
      }
      requiredAddress(record.recipient, "operation.recipient");
      break;
    }
    case "ADD_LIQUIDITY": {
      exactKeys(record, ["kind", "amounts", "recipient"], ["minimumShares"], "operation");
      const amounts = requiredArray(record.amounts, "operation.amounts", 2, 8);
      if (network !== undefined) validateAmountsMatchNetwork(amounts, network, "operation.amounts");
      else {
        amounts.forEach((amount, index) => validateAssetAmount(amount, `operation.amounts[${index}]`));
        assertUnique(amounts.map((amount) => (amount as AssetAmountV1).asset.assetId), "operation.amounts");
        const firstNetwork = (amounts[0] as AssetAmountV1).asset.network;
        if (amounts.some((amount) => (amount as AssetAmountV1).asset.network !== firstNetwork)) {
          fail("operation.amounts", "all assets must use one network");
        }
      }
      requiredAddress(record.recipient, "operation.recipient");
      if (record.minimumShares !== undefined) requiredAtomic(record.minimumShares, "operation.minimumShares");
      break;
    }
    case "REMOVE_LIQUIDITY": {
      exactKeys(record, ["kind", "lpToken", "minAmounts", "recipient"], [], "operation");
      validateAssetAmount(record.lpToken, "operation.lpToken");
      const minAmounts = requiredArray(record.minAmounts, "operation.minAmounts", 2, 8);
      if (network !== undefined) {
        const lpToken = record.lpToken as AssetAmountV1;
        if (lpToken.asset.network !== network) fail("operation.lpToken.asset.network", "must match the intent network");
        validateAmountsMatchNetwork(minAmounts, network, "operation.minAmounts");
      } else {
        minAmounts.forEach((amount, index) => validateAssetAmount(amount, `operation.minAmounts[${index}]`));
        assertUnique(minAmounts.map((amount) => (amount as AssetAmountV1).asset.assetId), "operation.minAmounts");
        const lpNetwork = (record.lpToken as AssetAmountV1).asset.network;
        if (minAmounts.some((amount) => (amount as AssetAmountV1).asset.network !== lpNetwork)) {
          fail("operation.minAmounts", "all assets must use the LP token's network");
        }
      }
      requiredAddress(record.recipient, "operation.recipient");
      break;
    }
    case "APPROVE_EXACT": {
      exactKeys(record, ["kind", "token", "spender", "amount", "expiresAt"], [], "operation");
      validateAssetRef(record.token);
      if (network !== undefined && (record.token as AssetRefV1).network !== network) {
        fail("operation.token.network", "must match the intent network");
      }
      requiredAddress(record.spender, "operation.spender");
      requiredAtomic(record.amount, "operation.amount", true);
      requiredIsoTimestamp(record.expiresAt, "operation.expiresAt");
      break;
    }
  }
}

export function validateIntentDraft(value: unknown): asserts value is IntentDraftV1 {
  const record = asRecord(value, "intentDraft");
  exactKeys(record, ["version", "id", "network", "operation", "protocol", "sourceAccount", "requestedAt", "sourceMemoryIds"], ["rationale"], "intentDraft");
  if (record.version !== "1") fail("intentDraft.version", "must be 1");
  requiredId(record.id, "intentDraft.id");
  validateNetwork(record.network, "intentDraft.network");
  validateFinancialOperation(record.operation, record.network as NetworkId);
  validateProtocolTarget(record.protocol);
  requiredAddress(record.sourceAccount, "intentDraft.sourceAccount");
  requiredIsoTimestamp(record.requestedAt, "intentDraft.requestedAt");
  const memoryIds = requiredArray(record.sourceMemoryIds, "intentDraft.sourceMemoryIds", 0, 256).map((id, index) =>
    requiredId(id, `intentDraft.sourceMemoryIds[${index}]`),
  );
  assertUnique(memoryIds, "intentDraft.sourceMemoryIds");
  if (record.rationale !== undefined) optionalString(record.rationale, "intentDraft.rationale", { max: 2_000 });
}

export function createIntentDraft(input: CreateIntentDraftInput): IntentDraftV1 {
  const draft: IntentDraftV1 = {
    version: "1",
    id: input.id ?? newId("draft"),
    network: input.network,
    operation: input.operation,
    protocol: input.protocol,
    sourceAccount: input.sourceAccount,
    requestedAt: input.requestedAt ?? new Date().toISOString(),
    sourceMemoryIds: [...input.sourceMemoryIds],
    ...(input.rationale === undefined ? {} : { rationale: input.rationale }),
  };
  validateIntentDraft(draft);
  return draft;
}

export function hashIntentDraft(draft: IntentDraftV1): string {
  validateIntentDraft(draft);
  return sha256Canonical(draft);
}

export function validateIntentProvenance(value: unknown): asserts value is IntentProvenanceV1 {
  const record = asRecord(value, "intent.provenance");
  exactKeys(record, ["draftId", "memoryEnvelopeIds", "memoryContentHashes", "containsUntrustedInput"], [], "intent.provenance");
  requiredId(record.draftId, "intent.provenance.draftId");
  const ids = requiredArray(record.memoryEnvelopeIds, "intent.provenance.memoryEnvelopeIds", 1, 256).map((id, index) =>
    requiredId(id, `intent.provenance.memoryEnvelopeIds[${index}]`),
  );
  assertUnique(ids, "intent.provenance.memoryEnvelopeIds");
  const hashes = requiredArray(record.memoryContentHashes, "intent.provenance.memoryContentHashes", 1, 256).map((hash, index) =>
    requiredHash(hash, `intent.provenance.memoryContentHashes[${index}]`),
  );
  assertUnique(hashes, "intent.provenance.memoryContentHashes");
  if (hashes.length !== ids.length) fail("intent.provenance.memoryContentHashes", "must have one hash per memory envelope id");
  requiredBoolean(record.containsUntrustedInput, "intent.provenance.containsUntrustedInput");
}

export function validateExecutionIntent(value: unknown): asserts value is ExecutionIntentV1 {
  const record = asRecord(value, "intent");
  exactKeys(
    record,
    [
      "version",
      "id",
      "draftHash",
      "network",
      "operation",
      "protocol",
      "sourceAccount",
      "nonce",
      "createdAt",
      "expiresAt",
      "policyId",
      "maxSlippageBps",
      "maxFeeAtomic",
      "provenance",
    ],
    [],
    "intent",
  );
  if (record.version !== "1") fail("intent.version", "must be 1");
  requiredId(record.id, "intent.id");
  requiredHash(record.draftHash, "intent.draftHash");
  validateNetwork(record.network, "intent.network");
  validateFinancialOperation(record.operation, record.network as NetworkId);
  validateProtocolTarget(record.protocol);
  requiredAddress(record.sourceAccount, "intent.sourceAccount");
  requiredId(record.nonce, "intent.nonce");
  const createdAt = requiredIsoTimestamp(record.createdAt, "intent.createdAt");
  const expiresAt = requiredIsoTimestamp(record.expiresAt, "intent.expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(createdAt)) fail("intent.expiresAt", "must be later than createdAt");
  requiredId(record.policyId, "intent.policyId");
  requiredInteger(record.maxSlippageBps, "intent.maxSlippageBps", 0, 10_000);
  requiredAtomic(record.maxFeeAtomic, "intent.maxFeeAtomic");
  validateIntentProvenance(record.provenance);
  const operation = record.operation as FinancialOperationV1;
  if (operation.kind === "APPROVE_EXACT" && Date.parse(operation.expiresAt) > Date.parse(expiresAt)) {
    fail("intent.operation.expiresAt", "must not outlive intent.expiresAt");
  }
}

export function createExecutionIntent(input: CreateExecutionIntentInput): ExecutionIntentV1 {
  validateIntentDraft(input.draft);
  const createdAt = input.createdAt ?? new Date().toISOString();
  const intent: ExecutionIntentV1 = {
    version: "1",
    id: input.id ?? newId("intent"),
    draftHash: hashIntentDraft(input.draft),
    network: input.draft.network,
    operation: input.draft.operation,
    protocol: input.draft.protocol,
    sourceAccount: input.draft.sourceAccount,
    nonce: input.nonce,
    createdAt,
    expiresAt: input.expiresAt,
    policyId: input.policyId,
    maxSlippageBps: input.maxSlippageBps,
    maxFeeAtomic: input.maxFeeAtomic,
    provenance: {
      draftId: input.draft.id,
      memoryEnvelopeIds: [...input.draft.sourceMemoryIds],
      memoryContentHashes: [...input.memoryContentHashes],
      containsUntrustedInput: input.containsUntrustedInput,
    },
  };
  validateExecutionIntent(intent);
  return intent;
}

function lookupMemoryPublicKey(keys: MemoryPublicKeyLookup, keyId: string): string | undefined {
  return typeof keys === "function" ? keys(keyId) : keys[keyId];
}

/**
 * Derives immutable intent provenance from the exact envelopes cited by a
 * draft. An envelope is clean only when it has a valid known signature and a
 * REVIEWED/CONTROLLED tier; all other input stays tainted.
 */
export function deriveIntentProvenance(
  draft: IntentDraftV1,
  memoryEnvelopes: readonly MemoryEnvelopeV1[],
  memoryPublicKeys?: MemoryPublicKeyLookup,
): IntentProvenanceV1 {
  validateIntentDraft(draft);
  if (memoryEnvelopes.length !== draft.sourceMemoryIds.length) {
    fail("memoryEnvelopes", "must contain exactly the draft's cited memory envelopes");
  }
  const byId = new Map<string, MemoryEnvelopeV1>();
  for (const envelope of memoryEnvelopes) {
    validateMemoryEnvelope(envelope);
    if (byId.has(envelope.id)) fail("memoryEnvelopes", `contains duplicate envelope ${envelope.id}`);
    byId.set(envelope.id, envelope);
  }
  const ordered = draft.sourceMemoryIds.map((id) => {
    const envelope = byId.get(id);
    if (envelope === undefined) fail("memoryEnvelopes", `is missing cited envelope ${id}`);
    return envelope;
  });
  const containsUntrustedInput = ordered.some((envelope) => {
    if (envelope.trust === "UNTRUSTED" || envelope.trust === "QUARANTINED") return true;
    if (envelope.signature === undefined || memoryPublicKeys === undefined) return true;
    const publicKey = lookupMemoryPublicKey(memoryPublicKeys, envelope.signature.keyId);
    return publicKey === undefined || !verifyMemoryEnvelope(envelope, publicKey);
  });
  return {
    draftId: draft.id,
    memoryEnvelopeIds: [...draft.sourceMemoryIds],
    memoryContentHashes: ordered.map((envelope) => envelope.contentHash),
    containsUntrustedInput,
  };
}

export function createExecutionIntentFromMemoryEnvelopes(
  input: CreateExecutionIntentFromMemoryEnvelopesInput,
): ExecutionIntentV1 {
  const provenance = deriveIntentProvenance(input.draft, input.memoryEnvelopes, input.memoryPublicKeys);
  return createExecutionIntent({
    ...(input.id === undefined ? {} : { id: input.id }),
    draft: input.draft,
    nonce: input.nonce,
    policyId: input.policyId,
    expiresAt: input.expiresAt,
    maxSlippageBps: input.maxSlippageBps,
    maxFeeAtomic: input.maxFeeAtomic,
    ...(input.createdAt === undefined ? {} : { createdAt: input.createdAt }),
    memoryContentHashes: provenance.memoryContentHashes,
    containsUntrustedInput: provenance.containsUntrustedInput,
  });
}

/** Hash used by owner approvals, capabilities, policy receipts, and the signer. */
export function hashExecutionIntent(intent: ExecutionIntentV1): string {
  validateExecutionIntent(intent);
  return sha256Canonical(intent);
}

/** Backwards-friendly concise name for callers that only handle execution intents. */
export const hashIntent = hashExecutionIntent;

/** Assets whose balance or approval authority can be consumed by this operation. */
export function spendAmountsForOperation(operation: FinancialOperationV1): readonly AssetAmountV1[] {
  validateFinancialOperation(operation);
  switch (operation.kind) {
    case "SWAP_EXACT_INPUT":
      return [operation.input];
    case "ADD_LIQUIDITY":
      return [...operation.amounts];
    case "REMOVE_LIQUIDITY":
      return [operation.lpToken];
    case "APPROVE_EXACT":
      return [{ asset: operation.token, atomic: operation.amount }];
  }
}

/** Every asset referenced by the operation, including received/minimum-output assets. */
export function assetRefsForOperation(operation: FinancialOperationV1): readonly AssetRefV1[] {
  validateFinancialOperation(operation);
  switch (operation.kind) {
    case "SWAP_EXACT_INPUT":
      return [operation.input.asset, operation.minOutput.asset];
    case "ADD_LIQUIDITY":
      return operation.amounts.map((amount) => amount.asset);
    case "REMOVE_LIQUIDITY":
      return [operation.lpToken.asset, ...operation.minAmounts.map((amount) => amount.asset)];
    case "APPROVE_EXACT":
      return [operation.token];
  }
}
