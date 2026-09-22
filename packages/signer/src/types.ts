/**
 * The signer accepts these deliberately small, data-only request types.  In
 * particular, there is no field for XDR, calldata, RPC endpoints, generic
 * transactions, signatures, or keys.
 */

export const SUPPORTED_CHAINS = ["stellar-testnet", "ethereum-sepolia"] as const;
export type SupportedChain = (typeof SUPPORTED_CHAINS)[number];

export const OPERATION_KINDS = [
  "SWAP_EXACT_INPUT",
  "ADD_LIQUIDITY",
  "REMOVE_LIQUIDITY",
  "ERC20_APPROVE_EXACT",
] as const;
export type OperationKind = (typeof OPERATION_KINDS)[number];

export type ExecutionMode = "OWNER_APPROVAL" | "DELEGATED";

/** Amounts are unsigned base-unit integers, represented as strings. */
export interface TokenAmountV1 {
  readonly asset: string;
  readonly amountAtomic: string;
}

interface BaseOperationV1 {
  readonly protocol: string;
  readonly pool: string;
  readonly slippageBps: number;
  readonly feeAtomic: string;
}

export interface SwapExactInputOperationV1 extends BaseOperationV1 {
  readonly kind: "SWAP_EXACT_INPUT";
  readonly input: TokenAmountV1;
  readonly outputAsset: string;
  readonly minOutputAmountAtomic: string;
}

export interface AddLiquidityOperationV1 extends BaseOperationV1 {
  readonly kind: "ADD_LIQUIDITY";
  readonly assetA: TokenAmountV1;
  readonly assetB: TokenAmountV1;
  readonly minLpAmountAtomic: string;
}

export interface RemoveLiquidityOperationV1 extends BaseOperationV1 {
  readonly kind: "REMOVE_LIQUIDITY";
  readonly lpToken: TokenAmountV1;
  readonly minOutputs: readonly TokenAmountV1[];
}

/** ERC-20 approval is constrained to a precise amount and a short expiry. */
export interface Erc20ApproveExactOperationV1 extends BaseOperationV1 {
  readonly kind: "ERC20_APPROVE_EXACT";
  readonly asset: string;
  readonly spender: string;
  readonly amountAtomic: string;
  readonly approvalExpiresAt: string;
}

export type NarrowOperationV1 =
  | SwapExactInputOperationV1
  | AddLiquidityOperationV1
  | RemoveLiquidityOperationV1
  | Erc20ApproveExactOperationV1;

export interface PolicyReferenceV1 {
  readonly id: string;
  readonly hash: string;
}

/**
 * A typed approval supplied by a trusted owner-approval boundary.  This
 * simulator validates its binding and expiry; it deliberately does not accept
 * a raw signature or serialized wallet payload.
 */
export interface OwnerApprovalV1 {
  readonly schemaVersion: "aegisos.owner-approval.v1";
  readonly approvalId: string;
  readonly ownerId: string;
  readonly intentHash: string;
  readonly expiresAt: string;
}

export interface CapabilityReferenceV1 {
  readonly schemaVersion: "aegisos.capability-reference.v1";
  readonly id: string;
  readonly hash: string;
  readonly nonce: string;
}

/** The only request shape accepted by DeterministicSignerSimulator. */
export interface NarrowOperationRequestV1 {
  readonly schemaVersion: "aegisos.operation-request.v1";
  readonly requestId: string;
  readonly chain: SupportedChain;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly policy: PolicyReferenceV1;
  readonly intentHash: string;
  readonly operation: NarrowOperationV1;
  readonly ownerApproval?: OwnerApprovalV1;
  readonly capability?: CapabilityReferenceV1;
}

/**
 * Trusted policy records are provisioned to the simulator, never received
 * from the agent as part of an execution request.
 */
export interface ApprovedPolicyV1 {
  readonly schemaVersion: "aegisos.approved-policy.v1";
  readonly id: string;
  readonly hash: string;
  readonly status: "APPROVED";
  readonly validFrom: string;
  readonly expiresAt: string;
  readonly executionMode: ExecutionMode;
  readonly allowedChains: readonly SupportedChain[];
  readonly allowedOperations: readonly OperationKind[];
  readonly allowedProtocols: readonly string[];
  readonly allowedPools: readonly string[];
  readonly allowedAssets: readonly string[];
  readonly maxInputByAsset: Readonly<Record<string, string>>;
  readonly maxSlippageBps: number;
  readonly maxFeeAtomic: string;
}

/** A one-use delegated grant.  Its nonce is consumed only after a success. */
export interface CapabilityGrantV1 {
  readonly schemaVersion: "aegisos.capability-grant.v1";
  readonly id: string;
  readonly hash: string;
  readonly policyId: string;
  readonly policyHash: string;
  readonly nonce: string;
  readonly validFrom: string;
  readonly expiresAt: string;
  readonly allowedChains: readonly SupportedChain[];
  readonly allowedOperations: readonly OperationKind[];
  readonly allowedProtocols: readonly string[];
  readonly allowedPools: readonly string[];
  readonly allowedAssets: readonly string[];
  readonly maxInputByAsset: Readonly<Record<string, string>>;
  readonly maxSlippageBps: number;
  readonly maxFeeAtomic: string;
}

export type SignerRejectionCode =
  | "MALFORMED_REQUEST"
  | "OPAQUE_PAYLOAD_FORBIDDEN"
  | "UNEXPECTED_FIELD"
  | "EXPIRED_REQUEST"
  | "REPLAYED_NONCE"
  | "UNKNOWN_POLICY"
  | "POLICY_HASH_MISMATCH"
  | "POLICY_NOT_CURRENT"
  | "POLICY_DENIED_OPERATION"
  | "POLICY_DENIED_ROUTE"
  | "POLICY_DENIED_ASSET"
  | "POLICY_LIMIT_EXCEEDED"
  | "AUTHORIZATION_MODE_MISMATCH"
  | "MISSING_OWNER_APPROVAL"
  | "INVALID_OWNER_APPROVAL"
  | "EXPIRED_OWNER_APPROVAL"
  | "UNKNOWN_CAPABILITY"
  | "CAPABILITY_HASH_MISMATCH"
  | "CAPABILITY_MISMATCH"
  | "CAPABILITY_NOT_CURRENT"
  | "CAPABILITY_REPLAYED"
  | "CAPABILITY_DENIED_OPERATION"
  | "CAPABILITY_DENIED_ROUTE"
  | "CAPABILITY_DENIED_ASSET"
  | "CAPABILITY_LIMIT_EXCEEDED"
  | "UNSUPPORTED_CHAIN_OPERATION";

export interface SignerRejectionV1 {
  readonly code: SignerRejectionCode;
  readonly message: string;
}

export interface BalanceChangeV1 {
  readonly asset: string;
  readonly deltaAtomic: string;
}

export interface StellarMockTransactionV1 {
  readonly kind: "stellar-testnet-mock";
  readonly transactionId: string;
  readonly ledgerSequence: number;
}

export interface EthereumMockTransactionV1 {
  readonly kind: "ethereum-sepolia-mock";
  readonly transactionHash: string;
  readonly blockNumber: number;
  readonly gasUsed: number;
}

export interface MockReceiptV1 {
  readonly schemaVersion: "aegisos.mock-receipt.v1";
  readonly status: "SIMULATED_ACCEPTED";
  readonly receiptId: string;
  readonly receiptHash: string;
  readonly requestHash: string;
  readonly intentHash: string;
  readonly chain: SupportedChain;
  readonly operation: OperationKind;
  readonly policyId: string;
  readonly simulatedAt: string;
  readonly balanceChanges: readonly BalanceChangeV1[];
  readonly transaction: StellarMockTransactionV1 | EthereumMockTransactionV1;
}

export type SimulationResultV1 =
  | { readonly ok: true; readonly receipt: MockReceiptV1 }
  | { readonly ok: false; readonly rejection: SignerRejectionV1 };

export interface SignerSimulatorOptions {
  readonly policies: readonly ApprovedPolicyV1[];
  readonly capabilities?: readonly CapabilityGrantV1[];
  /** A deterministic clock can be provided by tests or the benchmark runner. */
  readonly now?: () => Date;
}
