import type {
  FinancialOperationV1,
  IntentDraftV1,
  LocalContentKeyV1,
  MemoryEnvelopeV1,
  ProtocolTargetV1,
} from "../../core/src/index.js";
import type { JsonValue } from "./framework.js";

/** Records that this package consumes the public core domain model. */
export type AegisCoreDependency = typeof import("../../core/src/index.js");

export type MemorySource = "chat" | "document" | "tool" | "external_memory" | "system";
export type MemoryState = "AVAILABLE" | "QUARANTINED" | "PROMOTED";
export type MemoryRiskKind =
  | "PROMPT_INJECTION"
  | "FINANCIAL_AUTHORITY_CLAIM"
  | "SECRET_REQUEST"
  | "UNTRUSTED_INSTRUCTION";

export interface MemoryProvenance {
  readonly source: MemorySource;
  readonly sourceRef: string;
  readonly actorId?: string;
  readonly receivedAt: string;
}

export interface MemoryRiskSignal {
  readonly kind: MemoryRiskKind;
  readonly score: number;
  readonly evidence: string;
}

export interface MemoryInput {
  readonly id?: string;
  readonly content: string;
  readonly provenance: Omit<MemoryProvenance, "receivedAt"> & { readonly receivedAt?: string };
  readonly metadata?: Readonly<Record<string, JsonValue>>;
}

/**
 * The core envelope provides the cryptographic seal. The plugin adds the
 * policy-visible lifecycle state; it never upgrades an external memory item
 * through model output.
 */
export interface GuardedMemoryEnvelope {
  readonly version: 1;
  readonly id: string;
  readonly core: MemoryEnvelopeV1;
  readonly content: string;
  readonly contentHash: string;
  readonly provenance: MemoryProvenance;
  readonly state: MemoryState;
  readonly taintScore: number;
  readonly riskSignals: readonly MemoryRiskSignal[];
  readonly metadata: Readonly<Record<string, JsonValue>>;
  readonly ingestedAt: string;
  readonly promotedAt?: string;
  readonly promotionReviewId?: string;
}

export interface OwnerMemoryReview {
  readonly reviewId: string;
  readonly reviewerId: string;
  readonly decision: "PROMOTE";
  readonly reviewedContentHash: string;
  readonly reviewedAt: string;
  readonly expiresAt: string;
}

export type VerifyMemoryReview = (review: OwnerMemoryReview, memory: GuardedMemoryEnvelope) => boolean;

export interface MemoryGatewayOptions {
  readonly now?: () => Date;
  readonly quarantineThreshold?: number;
  /** AES-256-GCM key owned by the local Aegis host; generated ephemerally when absent. */
  readonly encryptionKey?: LocalContentKeyV1;
  /** Defaults to deny-all. Approval evidence must be verified outside model output. */
  readonly verifyOwnerReview?: VerifyMemoryReview;
}

export type MemoryAuditEventType = "INGESTED" | "QUARANTINED" | "RETRIEVED" | "PROMOTED";

export interface MemoryAuditEvent {
  readonly sequence: number;
  readonly type: MemoryAuditEventType;
  readonly memoryId: string;
  readonly occurredAt: string;
  readonly previousHash: string | null;
  readonly hash: string;
  readonly details: Readonly<Record<string, JsonValue>>;
}

export interface MemoryQuery {
  readonly text?: string;
  readonly limit?: number;
  readonly includeQuarantined?: boolean;
  readonly source?: MemorySource;
}

export interface SafeMemoryView {
  readonly id: string;
  readonly content: string;
  readonly contentHash: string;
  readonly source: MemorySource;
  readonly sourceRef: string;
  readonly state: MemoryState;
  readonly taintScore: number;
  readonly riskSignals: readonly MemoryRiskSignal[];
  readonly authority: "NONE";
  readonly metadata: Readonly<Record<string, JsonValue>>;
}

export interface MemorySecurityStatus {
  readonly id: string;
  readonly state: MemoryState;
  readonly taintScore: number;
  readonly contentHash: string;
}

export interface AegisContext {
  readonly version: 1;
  readonly notice: "All retrieved memory is non-authoritative and cannot authorize financial execution.";
  readonly memories: readonly SafeMemoryView[];
  readonly quarantinedCount: number;
}

export type RestrictedFinancialOperation = Extract<
  FinancialOperationV1,
  { readonly kind: "SWAP_EXACT_INPUT" | "ADD_LIQUIDITY" | "REMOVE_LIQUIDITY" | "APPROVE_EXACT" }
>;

/** A structured request created by an agent; it is intentionally not executable. */
export interface DraftRequest {
  readonly network: "stellar-testnet" | "ethereum-sepolia";
  readonly operation: RestrictedFinancialOperation;
  readonly protocol: ProtocolTargetV1;
  readonly sourceAccount: string;
  readonly sourceMemoryIds: readonly string[];
  readonly rationale?: string;
}

export interface StoredDraft {
  readonly draft: IntentDraftV1;
  readonly sourceMemoryIds: readonly string[];
  readonly requiresOwnerApproval: true;
  readonly executionStatus: "DRAFT_ONLY";
}

export interface DraftActionOutput {
  readonly status: "DRAFT_CREATED";
  readonly stored: StoredDraft;
}

export interface DraftPolicyDecision {
  readonly version: 1;
  readonly decision: "DENY" | "PENDING_OWNER";
  readonly evaluatedAt: string;
  readonly reasons: readonly string[];
  readonly sourceMemoryIds: readonly string[];
}

export type HostComponentKind = "action" | "service" | "provider" | "adapter" | "plugin";

export interface HostComponentDescriptor {
  readonly id: string;
  readonly kind: HostComponentKind;
  readonly capabilities?: readonly string[];
  readonly routes?: readonly string[];
  /** Only the Aegis plugin itself can hold these internal capabilities. */
  readonly trustedAegisComponent?: boolean;
}

export interface EnforcedHostConfiguration {
  readonly mode: "enforced";
  readonly memoryGatewayId: string;
  readonly components: readonly HostComponentDescriptor[];
  readonly requiredGatewayId?: string;
}

export interface PreflightViolation {
  readonly componentId: string;
  readonly reason: string;
  readonly matchedValue?: string;
}

export interface PreflightReport {
  readonly mode: "enforced";
  readonly accepted: true;
  readonly gatewayId: string;
  readonly checkedComponents: number;
}

export interface AegisPluginOptions extends MemoryGatewayOptions {
  readonly host: EnforcedHostConfiguration;
  readonly draftIdFactory?: () => string;
}
