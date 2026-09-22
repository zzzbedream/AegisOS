import {
  sha256Canonical,
  signCanonical,
  validateDetachedSignature,
  verifyCanonical,
  type DetachedSignatureV1,
  type SigningIdentityV1,
} from "./crypto.js";
import { fail } from "./errors.js";
import {
  OPERATION_KINDS,
  NETWORK_IDS,
  assetRefsForOperation,
  hashExecutionIntent,
  spendAmountsForOperation,
  validateExecutionIntent,
  type ExecutionIntentV1,
  type NetworkId,
  type OperationKind,
} from "./intent.js";
import {
  asRecord,
  assertUnique,
  atomicBigInt,
  exactKeys,
  requiredAddress,
  requiredArray,
  requiredAtomic,
  requiredBoolean,
  requiredHash,
  requiredId,
  requiredInteger,
  requiredIsoTimestamp,
  requiredString,
} from "./validation.js";
import { randomUUID } from "node:crypto";

export type PolicyDecision = "DENY" | "PENDING_OWNER" | "ALLOW";
export type AuthorizationKind = "NONE" | "OWNER" | "CAPABILITY";

export interface AssetSpendLimitV1 {
  readonly assetId: string;
  readonly maxPerOperationAtomic: string;
  readonly maxDailyAtomic: string;
}

/** Deterministic policy input. There is no natural-language permission field. */
export interface PolicyConfigV1 {
  readonly version: "1";
  readonly id: string;
  readonly allowedNetworks: readonly NetworkId[];
  readonly allowedOperationKinds: readonly OperationKind[];
  readonly allowedManifestIds: readonly string[];
  readonly allowedAssetIds: readonly string[];
  readonly assetLimits: readonly AssetSpendLimitV1[];
  readonly maxSlippageBps: number;
  readonly maxFeeAtomic: string;
  readonly approvalTtlSeconds: number;
  /** Individual owner approval is required even when a delegation is present. */
  readonly requireOwnerApproval: boolean;
  /** Untrusted memory may produce a draft, but cannot spend through delegation. */
  readonly requireCleanProvenanceForDelegation: boolean;
}

export interface CapabilityGrantV1 {
  readonly version: "1";
  readonly id: string;
  readonly network: NetworkId;
  readonly delegatedAccount: string;
  readonly allowedOperations: readonly OperationKind[];
  readonly allowedManifestIds: readonly string[];
  readonly allowedAssetIds: readonly string[];
  readonly spendLimits: readonly AssetSpendLimitV1[];
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly policyId: string;
  readonly issuerKeyId: string;
  readonly signature: DetachedSignatureV1;
}

export interface OwnerApprovalV1 {
  readonly version: "1";
  readonly id: string;
  readonly intentHash: string;
  readonly policyHash: string;
  readonly ownerKeyId: string;
  readonly approvedAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly signature: DetachedSignatureV1;
}

export interface PolicyReceiptV1 {
  readonly version: "1";
  readonly id: string;
  readonly intentHash: string;
  readonly policyId: string;
  readonly policyHash: string;
  readonly decision: PolicyDecision;
  readonly authorization: AuthorizationKind;
  /** Stable machine-readable reason codes, never untrusted text. */
  readonly reasons: readonly string[];
  readonly evaluatedAt: string;
  readonly expiresAt: string;
  readonly signerKeyId?: string;
  readonly signature?: DetachedSignatureV1;
}

export interface IssueCapabilityGrantInput {
  readonly id?: string;
  readonly network: NetworkId;
  readonly delegatedAccount: string;
  readonly allowedOperations: readonly OperationKind[];
  readonly allowedManifestIds: readonly string[];
  readonly allowedAssetIds: readonly string[];
  readonly spendLimits: readonly AssetSpendLimitV1[];
  readonly issuedAt?: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly policyId: string;
  readonly issuer: SigningIdentityV1;
}

export interface CreateOwnerApprovalInput {
  readonly id?: string;
  readonly intent: ExecutionIntentV1;
  readonly policy: PolicyConfigV1;
  readonly approvedAt?: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly owner: SigningIdentityV1;
}

export interface PolicyEvaluationContextV1 {
  /** Supplied by a trusted clock at the signer boundary. */
  readonly now: string;
  readonly ownerApproval?: OwnerApprovalV1;
  readonly ownerPublicKeys?: Readonly<Record<string, string>>;
  readonly capability?: CapabilityGrantV1;
  readonly issuerPublicKeys?: Readonly<Record<string, string>>;
  /** Current UTC-day committed spend in smallest units, keyed by assetId. */
  readonly spentTodayByAsset?: Readonly<Record<string, string>>;
  /** Committed spend under this capability, keyed by assetId. */
  readonly spentCapabilityByAsset?: Readonly<Record<string, string>>;
  /** Nonces already committed in the ledger. Any hit fails closed. */
  readonly consumedNonces?: readonly string[];
}

export type PolicyConfig = PolicyConfigV1;
export type CapabilityGrant = CapabilityGrantV1;
export type OwnerApproval = OwnerApprovalV1;
export type PolicyReceipt = PolicyReceiptV1;

function newId(prefix: string): string {
  return `${prefix}:${randomUUID()}`;
}

function validateNetwork(value: unknown, path: string): asserts value is NetworkId {
  if (!NETWORK_IDS.includes(value as NetworkId)) fail(path, "must be a supported test network");
}

function validateOperationKind(value: unknown, path: string): asserts value is OperationKind {
  if (!OPERATION_KINDS.includes(value as OperationKind)) fail(path, "must be a supported operation kind");
}

function validateIdArray(value: unknown, path: string, min = 0): readonly string[] {
  const values = requiredArray(value, path, min, 256).map((entry, index) => requiredId(entry, `${path}[${index}]`));
  assertUnique(values, path);
  return values;
}

function validateOperationKindArray(value: unknown, path: string, min = 0): readonly OperationKind[] {
  const values = requiredArray(value, path, min, 16).map((entry, index) => {
    validateOperationKind(entry, `${path}[${index}]`);
    return entry as OperationKind;
  });
  assertUnique(values, path);
  return values;
}

function validateNetworkArray(value: unknown, path: string, min = 0): readonly NetworkId[] {
  const values = requiredArray(value, path, min, 8).map((entry, index) => {
    validateNetwork(entry, `${path}[${index}]`);
    return entry as NetworkId;
  });
  assertUnique(values, path);
  return values;
}

export function validateAssetSpendLimit(value: unknown, path = "assetLimit"): asserts value is AssetSpendLimitV1 {
  const record = asRecord(value, path);
  exactKeys(record, ["assetId", "maxPerOperationAtomic", "maxDailyAtomic"], [], path);
  requiredId(record.assetId, `${path}.assetId`);
  requiredAtomic(record.maxPerOperationAtomic, `${path}.maxPerOperationAtomic`);
  requiredAtomic(record.maxDailyAtomic, `${path}.maxDailyAtomic`);
  if (atomicBigInt(record.maxPerOperationAtomic as string) > atomicBigInt(record.maxDailyAtomic as string)) {
    fail(`${path}.maxPerOperationAtomic`, "must not exceed maxDailyAtomic");
  }
}

function validateAssetSpendLimitArray(value: unknown, path: string): readonly AssetSpendLimitV1[] {
  const limits = requiredArray(value, path, 0, 256).map((entry, index) => {
    validateAssetSpendLimit(entry, `${path}[${index}]`);
    return entry as AssetSpendLimitV1;
  });
  assertUnique(limits.map((limit) => limit.assetId), path);
  return limits;
}

export function validatePolicyConfig(value: unknown): asserts value is PolicyConfigV1 {
  const record = asRecord(value, "policy");
  exactKeys(
    record,
    [
      "version",
      "id",
      "allowedNetworks",
      "allowedOperationKinds",
      "allowedManifestIds",
      "allowedAssetIds",
      "assetLimits",
      "maxSlippageBps",
      "maxFeeAtomic",
      "approvalTtlSeconds",
      "requireOwnerApproval",
      "requireCleanProvenanceForDelegation",
    ],
    [],
    "policy",
  );
  if (record.version !== "1") fail("policy.version", "must be 1");
  requiredId(record.id, "policy.id");
  validateNetworkArray(record.allowedNetworks, "policy.allowedNetworks", 1);
  validateOperationKindArray(record.allowedOperationKinds, "policy.allowedOperationKinds", 1);
  validateIdArray(record.allowedManifestIds, "policy.allowedManifestIds", 1);
  const assetIds = validateIdArray(record.allowedAssetIds, "policy.allowedAssetIds", 1);
  const limits = validateAssetSpendLimitArray(record.assetLimits, "policy.assetLimits");
  for (const limit of limits) {
    if (!assetIds.includes(limit.assetId)) fail("policy.assetLimits", `contains unallowed asset ${limit.assetId}`);
  }
  requiredInteger(record.maxSlippageBps, "policy.maxSlippageBps", 0, 10_000);
  requiredAtomic(record.maxFeeAtomic, "policy.maxFeeAtomic");
  requiredInteger(record.approvalTtlSeconds, "policy.approvalTtlSeconds", 1, 86_400);
  requiredBoolean(record.requireOwnerApproval, "policy.requireOwnerApproval");
  requiredBoolean(record.requireCleanProvenanceForDelegation, "policy.requireCleanProvenanceForDelegation");
}

export function policyHash(policy: PolicyConfigV1): string {
  validatePolicyConfig(policy);
  return sha256Canonical(policy);
}

export function capabilityGrantSignable(grant: CapabilityGrantV1): Omit<CapabilityGrantV1, "signature"> {
  const { signature: _signature, ...signable } = grant;
  return signable;
}

export function validateCapabilityGrant(value: unknown): asserts value is CapabilityGrantV1 {
  const record = asRecord(value, "capability");
  exactKeys(
    record,
    [
      "version",
      "id",
      "network",
      "delegatedAccount",
      "allowedOperations",
      "allowedManifestIds",
      "allowedAssetIds",
      "spendLimits",
      "issuedAt",
      "expiresAt",
      "nonce",
      "policyId",
      "issuerKeyId",
      "signature",
    ],
    [],
    "capability",
  );
  if (record.version !== "1") fail("capability.version", "must be 1");
  requiredId(record.id, "capability.id");
  validateNetwork(record.network, "capability.network");
  requiredAddress(record.delegatedAccount, "capability.delegatedAccount");
  validateOperationKindArray(record.allowedOperations, "capability.allowedOperations", 1);
  validateIdArray(record.allowedManifestIds, "capability.allowedManifestIds", 1);
  const assetIds = validateIdArray(record.allowedAssetIds, "capability.allowedAssetIds", 1);
  const limits = validateAssetSpendLimitArray(record.spendLimits, "capability.spendLimits");
  for (const limit of limits) {
    if (!assetIds.includes(limit.assetId)) fail("capability.spendLimits", `contains unallowed asset ${limit.assetId}`);
  }
  const issuedAt = requiredIsoTimestamp(record.issuedAt, "capability.issuedAt");
  const expiresAt = requiredIsoTimestamp(record.expiresAt, "capability.expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) fail("capability.expiresAt", "must be later than issuedAt");
  requiredId(record.nonce, "capability.nonce");
  requiredId(record.policyId, "capability.policyId");
  requiredId(record.issuerKeyId, "capability.issuerKeyId");
  validateDetachedSignature(record.signature);
  if ((record.signature as DetachedSignatureV1).keyId !== record.issuerKeyId) {
    fail("capability.signature.keyId", "must match issuerKeyId");
  }
}

export function issueCapabilityGrant(input: IssueCapabilityGrantInput): CapabilityGrantV1 {
  const issuedAt = input.issuedAt ?? new Date().toISOString();
  const unsigned: Omit<CapabilityGrantV1, "signature"> = {
    version: "1",
    id: input.id ?? newId("cap"),
    network: input.network,
    delegatedAccount: input.delegatedAccount,
    allowedOperations: [...input.allowedOperations],
    allowedManifestIds: [...input.allowedManifestIds],
    allowedAssetIds: [...input.allowedAssetIds],
    spendLimits: input.spendLimits.map((limit) => ({ ...limit })),
    issuedAt,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
    policyId: input.policyId,
    issuerKeyId: input.issuer.keyId,
  };
  // Validate signed shape after assigning a temporary valid signature below.
  const signature = signCanonical(unsigned, input.issuer);
  const grant: CapabilityGrantV1 = { ...unsigned, signature };
  validateCapabilityGrant(grant);
  return grant;
}

export function verifyCapabilityGrant(grant: CapabilityGrantV1, issuerPublicKey: string): boolean {
  try {
    validateCapabilityGrant(grant);
    return verifyCanonical(capabilityGrantSignable(grant), grant.signature, issuerPublicKey);
  } catch {
    return false;
  }
}

export function ownerApprovalSignable(approval: OwnerApprovalV1): Omit<OwnerApprovalV1, "signature"> {
  const { signature: _signature, ...signable } = approval;
  return signable;
}

export function validateOwnerApproval(value: unknown): asserts value is OwnerApprovalV1 {
  const record = asRecord(value, "ownerApproval");
  exactKeys(record, ["version", "id", "intentHash", "policyHash", "ownerKeyId", "approvedAt", "expiresAt", "nonce", "signature"], [], "ownerApproval");
  if (record.version !== "1") fail("ownerApproval.version", "must be 1");
  requiredId(record.id, "ownerApproval.id");
  requiredHash(record.intentHash, "ownerApproval.intentHash");
  requiredHash(record.policyHash, "ownerApproval.policyHash");
  requiredId(record.ownerKeyId, "ownerApproval.ownerKeyId");
  const approvedAt = requiredIsoTimestamp(record.approvedAt, "ownerApproval.approvedAt");
  const expiresAt = requiredIsoTimestamp(record.expiresAt, "ownerApproval.expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(approvedAt)) fail("ownerApproval.expiresAt", "must be later than approvedAt");
  requiredId(record.nonce, "ownerApproval.nonce");
  validateDetachedSignature(record.signature);
  if ((record.signature as DetachedSignatureV1).keyId !== record.ownerKeyId) {
    fail("ownerApproval.signature.keyId", "must match ownerKeyId");
  }
}

export function createOwnerApproval(input: CreateOwnerApprovalInput): OwnerApprovalV1 {
  validateExecutionIntent(input.intent);
  validatePolicyConfig(input.policy);
  const approvedAt = input.approvedAt ?? new Date().toISOString();
  const unsigned: Omit<OwnerApprovalV1, "signature"> = {
    version: "1",
    id: input.id ?? newId("owner-approval"),
    intentHash: hashExecutionIntent(input.intent),
    policyHash: policyHash(input.policy),
    ownerKeyId: input.owner.keyId,
    approvedAt,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
  };
  const approval: OwnerApprovalV1 = { ...unsigned, signature: signCanonical(unsigned, input.owner) };
  validateOwnerApproval(approval);
  return approval;
}

export function verifyOwnerApproval(
  approval: OwnerApprovalV1,
  intent: ExecutionIntentV1,
  policy: PolicyConfigV1,
  ownerPublicKey: string,
): boolean {
  try {
    validateOwnerApproval(approval);
    validateExecutionIntent(intent);
    validatePolicyConfig(policy);
    return (
      approval.intentHash === hashExecutionIntent(intent) &&
      approval.policyHash === policyHash(policy) &&
      verifyCanonical(ownerApprovalSignable(approval), approval.signature, ownerPublicKey)
    );
  } catch {
    return false;
  }
}

export function policyReceiptSignable(receipt: PolicyReceiptV1): Omit<PolicyReceiptV1, "signature" | "signerKeyId"> {
  const { signature: _signature, signerKeyId: _signerKeyId, ...signable } = receipt;
  return signable;
}

export function validatePolicyReceipt(value: unknown): asserts value is PolicyReceiptV1 {
  const record = asRecord(value, "receipt");
  exactKeys(
    record,
    ["version", "id", "intentHash", "policyId", "policyHash", "decision", "authorization", "reasons", "evaluatedAt", "expiresAt"],
    ["signerKeyId", "signature"],
    "receipt",
  );
  if (record.version !== "1") fail("receipt.version", "must be 1");
  requiredId(record.id, "receipt.id");
  requiredHash(record.intentHash, "receipt.intentHash");
  requiredId(record.policyId, "receipt.policyId");
  requiredHash(record.policyHash, "receipt.policyHash");
  if (record.decision !== "DENY" && record.decision !== "PENDING_OWNER" && record.decision !== "ALLOW") {
    fail("receipt.decision", "must be DENY, PENDING_OWNER, or ALLOW");
  }
  if (record.authorization !== "NONE" && record.authorization !== "OWNER" && record.authorization !== "CAPABILITY") {
    fail("receipt.authorization", "must be NONE, OWNER, or CAPABILITY");
  }
  const reasons = requiredArray(record.reasons, "receipt.reasons", 1, 64).map((reason, index) =>
    requiredString(reason, `receipt.reasons[${index}]`, { max: 128, pattern: /^[A-Za-z0-9._:-]+$/ }),
  );
  assertUnique(reasons, "receipt.reasons");
  requiredIsoTimestamp(record.evaluatedAt, "receipt.evaluatedAt");
  requiredIsoTimestamp(record.expiresAt, "receipt.expiresAt");
  if (record.signerKeyId === undefined && record.signature !== undefined) fail("receipt.signature", "requires signerKeyId");
  if (record.signerKeyId !== undefined && record.signature === undefined) fail("receipt.signerKeyId", "requires signature");
  if (record.signerKeyId !== undefined) requiredId(record.signerKeyId, "receipt.signerKeyId");
  if (record.signature !== undefined) {
    validateDetachedSignature(record.signature);
    if ((record.signature as DetachedSignatureV1).keyId !== record.signerKeyId) {
      fail("receipt.signature.keyId", "must match signerKeyId");
    }
  }
}

export function signPolicyReceipt(receipt: PolicyReceiptV1, signer: SigningIdentityV1): PolicyReceiptV1 {
  validatePolicyReceipt(receipt);
  const unsigned = policyReceiptSignable(receipt);
  const signed: PolicyReceiptV1 = {
    ...unsigned,
    signerKeyId: signer.keyId,
    signature: signCanonical(unsigned, signer),
  };
  validatePolicyReceipt(signed);
  return signed;
}

export function verifyPolicyReceipt(receipt: PolicyReceiptV1, publicKey: string): boolean {
  try {
    validatePolicyReceipt(receipt);
    return receipt.signature !== undefined && verifyCanonical(policyReceiptSignable(receipt), receipt.signature, publicKey);
  } catch {
    return false;
  }
}

function findLimit(limits: readonly AssetSpendLimitV1[], assetId: string): AssetSpendLimitV1 | undefined {
  return limits.find((limit) => limit.assetId === assetId);
}

function contextAmount(map: Readonly<Record<string, string>> | undefined, assetId: string, path: string): bigint {
  const value = map?.[assetId] ?? "0";
  return atomicBigInt(requiredAtomic(value, path));
}

function isConsumed(nonce: string, consumed: readonly string[] | undefined): boolean {
  if (consumed === undefined) return false;
  return consumed.includes(nonce);
}

function minExpiry(left: string, right: string): string {
  return Date.parse(left) <= Date.parse(right) ? left : right;
}

function addSeconds(timestamp: string, seconds: number): string {
  return new Date(Date.parse(timestamp) + seconds * 1_000).toISOString();
}

function receipt(
  intent: ExecutionIntentV1,
  policy: PolicyConfigV1,
  now: string,
  decision: PolicyDecision,
  authorization: AuthorizationKind,
  reasons: readonly string[],
): PolicyReceiptV1 {
  const intentHash = hashExecutionIntent(intent);
  const policyDigest = policyHash(policy);
  const expiresAt = decision === "DENY" ? now : minExpiry(intent.expiresAt, addSeconds(now, policy.approvalTtlSeconds));
  const id = `receipt:${sha256Canonical({ intentHash, policyDigest, now, decision, authorization, reasons }).slice(0, 32)}`;
  const result: PolicyReceiptV1 = {
    version: "1",
    id,
    intentHash,
    policyId: policy.id,
    policyHash: policyDigest,
    decision,
    authorization,
    reasons: reasons.length === 0 ? ["POLICY_OK"] : [...reasons],
    evaluatedAt: now,
    expiresAt,
  };
  validatePolicyReceipt(result);
  return result;
}

function validateContext(context: PolicyEvaluationContextV1): void {
  requiredIsoTimestamp(context.now, "context.now");
  if (context.consumedNonces !== undefined) validateIdArray(context.consumedNonces, "context.consumedNonces");
  if (context.spentTodayByAsset !== undefined) {
    const spentToday = asRecord(context.spentTodayByAsset, "context.spentTodayByAsset");
    for (const [assetId, amount] of Object.entries(spentToday)) {
      requiredId(assetId, "context.spentTodayByAsset key");
      requiredAtomic(amount, `context.spentTodayByAsset.${assetId}`);
    }
  }
  if (context.spentCapabilityByAsset !== undefined) {
    const spentCapability = asRecord(context.spentCapabilityByAsset, "context.spentCapabilityByAsset");
    for (const [assetId, amount] of Object.entries(spentCapability)) {
      requiredId(assetId, "context.spentCapabilityByAsset key");
      requiredAtomic(amount, `context.spentCapabilityByAsset.${assetId}`);
    }
  }
}

/**
 * Pure, deterministic, fail-closed authorization decision. It neither invokes
 * an LLM nor accesses a wallet/network. The isolated signer must sign the
 * returned receipt before it is treated as executable evidence.
 */
export function evaluatePolicy(
  policy: PolicyConfigV1,
  intent: ExecutionIntentV1,
  context: PolicyEvaluationContextV1,
): PolicyReceiptV1 {
  validatePolicyConfig(policy);
  validateExecutionIntent(intent);
  validateContext(context);
  const now = context.now;
  const reasons: string[] = [];

  if (intent.policyId !== policy.id) reasons.push("POLICY_ID_MISMATCH");
  if (Date.parse(now) >= Date.parse(intent.expiresAt)) reasons.push("INTENT_EXPIRED");
  if (!policy.allowedNetworks.includes(intent.network)) reasons.push("NETWORK_NOT_ALLOWED");
  if (!policy.allowedOperationKinds.includes(intent.operation.kind)) reasons.push("OPERATION_NOT_ALLOWED");
  if (!policy.allowedManifestIds.includes(intent.protocol.manifestId)) reasons.push("MANIFEST_NOT_ALLOWED");
  if (intent.maxSlippageBps > policy.maxSlippageBps) reasons.push("SLIPPAGE_EXCEEDS_POLICY");
  if (atomicBigInt(intent.maxFeeAtomic) > atomicBigInt(policy.maxFeeAtomic)) reasons.push("FEE_EXCEEDS_POLICY");

  for (const asset of assetRefsForOperation(intent.operation)) {
    if (!policy.allowedAssetIds.includes(asset.assetId)) reasons.push(`ASSET_NOT_ALLOWED:${asset.assetId}`);
  }
  for (const amount of spendAmountsForOperation(intent.operation)) {
    if (!policy.allowedAssetIds.includes(amount.asset.assetId)) continue;
    const limit = findLimit(policy.assetLimits, amount.asset.assetId);
    if (limit === undefined) {
      reasons.push(`ASSET_LIMIT_MISSING:${amount.asset.assetId}`);
      continue;
    }
    const spend = atomicBigInt(amount.atomic);
    if (spend > atomicBigInt(limit.maxPerOperationAtomic)) reasons.push(`PER_OPERATION_LIMIT:${amount.asset.assetId}`);
    const previouslySpent = contextAmount(context.spentTodayByAsset, amount.asset.assetId, "context.spentTodayByAsset");
    if (previouslySpent + spend > atomicBigInt(limit.maxDailyAtomic)) reasons.push(`DAILY_LIMIT:${amount.asset.assetId}`);
  }

  if (reasons.length > 0) return receipt(intent, policy, now, "DENY", "NONE", reasons);

  if (context.ownerApproval !== undefined) {
    try {
      validateOwnerApproval(context.ownerApproval);
    } catch {
      return receipt(intent, policy, now, "DENY", "NONE", ["INVALID_OWNER_APPROVAL"]);
    }
    const ownerKey = context.ownerPublicKeys?.[context.ownerApproval.ownerKeyId];
    if (ownerKey === undefined || !verifyOwnerApproval(context.ownerApproval, intent, policy, ownerKey)) {
      return receipt(intent, policy, now, "DENY", "NONE", ["INVALID_OWNER_APPROVAL"]);
    }
    if (Date.parse(now) >= Date.parse(context.ownerApproval.expiresAt)) {
      return receipt(intent, policy, now, "DENY", "NONE", ["OWNER_APPROVAL_EXPIRED"]);
    }
    if (Date.parse(now) < Date.parse(context.ownerApproval.approvedAt)) {
      return receipt(intent, policy, now, "DENY", "NONE", ["OWNER_APPROVAL_NOT_ACTIVE"]);
    }
    if (isConsumed(context.ownerApproval.nonce, context.consumedNonces)) {
      return receipt(intent, policy, now, "DENY", "NONE", ["OWNER_APPROVAL_REPLAY"]);
    }
    return receipt(intent, policy, now, "ALLOW", "OWNER", []);
  }

  if (policy.requireOwnerApproval) return receipt(intent, policy, now, "PENDING_OWNER", "NONE", ["OWNER_APPROVAL_REQUIRED"]);
  if (context.capability === undefined) return receipt(intent, policy, now, "PENDING_OWNER", "NONE", ["AUTHORIZATION_REQUIRED"]);
  if (intent.provenance.containsUntrustedInput && policy.requireCleanProvenanceForDelegation) {
    return receipt(intent, policy, now, "DENY", "NONE", ["TAINTED_PROVENANCE_REQUIRES_OWNER"]);
  }

  const capability = context.capability;
  try {
    validateCapabilityGrant(capability);
  } catch {
    return receipt(intent, policy, now, "DENY", "NONE", ["INVALID_CAPABILITY"]);
  }
  const issuerKey = context.issuerPublicKeys?.[capability.issuerKeyId];
  if (issuerKey === undefined || !verifyCapabilityGrant(capability, issuerKey)) {
    return receipt(intent, policy, now, "DENY", "NONE", ["INVALID_CAPABILITY"]);
  }
  if (Date.parse(now) >= Date.parse(capability.expiresAt)) return receipt(intent, policy, now, "DENY", "NONE", ["CAPABILITY_EXPIRED"]);
  if (Date.parse(now) < Date.parse(capability.issuedAt)) return receipt(intent, policy, now, "DENY", "NONE", ["CAPABILITY_NOT_ACTIVE"]);
  if (isConsumed(capability.nonce, context.consumedNonces)) return receipt(intent, policy, now, "DENY", "NONE", ["CAPABILITY_REPLAY"]);
  if (capability.network !== intent.network) return receipt(intent, policy, now, "DENY", "NONE", ["CAPABILITY_NETWORK_MISMATCH"]);
  if (capability.policyId !== policy.id) return receipt(intent, policy, now, "DENY", "NONE", ["CAPABILITY_POLICY_MISMATCH"]);
  if (capability.delegatedAccount !== intent.sourceAccount) return receipt(intent, policy, now, "DENY", "NONE", ["CAPABILITY_ACCOUNT_MISMATCH"]);
  if (!capability.allowedOperations.includes(intent.operation.kind)) return receipt(intent, policy, now, "DENY", "NONE", ["CAPABILITY_OPERATION_MISMATCH"]);
  if (!capability.allowedManifestIds.includes(intent.protocol.manifestId)) return receipt(intent, policy, now, "DENY", "NONE", ["CAPABILITY_MANIFEST_MISMATCH"]);

  const capabilityReasons: string[] = [];
  for (const asset of assetRefsForOperation(intent.operation)) {
    if (!capability.allowedAssetIds.includes(asset.assetId)) {
      capabilityReasons.push(`CAPABILITY_ASSET_MISMATCH:${asset.assetId}`);
    }
  }
  for (const amount of spendAmountsForOperation(intent.operation)) {
    const assetId = amount.asset.assetId;
    if (!capability.allowedAssetIds.includes(assetId)) continue;
    const limit = findLimit(capability.spendLimits, assetId);
    if (limit === undefined) {
      capabilityReasons.push(`CAPABILITY_LIMIT_MISSING:${assetId}`);
      continue;
    }
    const spend = atomicBigInt(amount.atomic);
    if (spend > atomicBigInt(limit.maxPerOperationAtomic)) capabilityReasons.push(`CAPABILITY_PER_OPERATION_LIMIT:${assetId}`);
    const committed = contextAmount(context.spentCapabilityByAsset, assetId, "context.spentCapabilityByAsset");
    if (committed + spend > atomicBigInt(limit.maxDailyAtomic)) capabilityReasons.push(`CAPABILITY_TOTAL_LIMIT:${assetId}`);
  }
  if (capabilityReasons.length > 0) return receipt(intent, policy, now, "DENY", "NONE", capabilityReasons);
  return receipt(intent, policy, now, "ALLOW", "CAPABILITY", []);
}
