import {
  createIntentDraft,
  validateFinancialOperation,
  validateIntentDraft,
  validateProtocolTarget,
} from "../../core/src/index.js";
import type { AgentRuntimeLike, ElizaActionLike } from "./framework.js";
import { AegisMemoryGateway, MemoryAccessError } from "./memory-gateway.js";
import type { DraftActionOutput, DraftRequest, StoredDraft } from "./types.js";

const ALLOWED_TOP_LEVEL_KEYS = new Set(["network", "operation", "protocol", "sourceAccount", "sourceMemoryIds", "rationale"]);
const ALLOWED_OPERATION_KINDS = new Set(["SWAP_EXACT_INPUT", "ADD_LIQUIDITY", "REMOVE_LIQUIDITY", "APPROVE_EXACT"]);
const FORBIDDEN_TRANSPORT_KEYS = new Set([
  "xdr",
  "rawxdr",
  "calldata",
  "rawcalldata",
  "rawtransaction",
  "transaction",
  "rpc",
  "rpcurl",
  "privatekey",
  "seed",
  "mnemonic",
  "signature",
  "signedpayload",
]);
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ADDRESS_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{1,255}$/;

export class DraftValidationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "DraftValidationError";
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Object.keys(value).every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && !("get" in descriptor) && !("set" in descriptor);
  });
}

function hasForbiddenTransportKey(value: unknown, seen = new WeakSet<object>()): boolean {
  if (value === null || typeof value !== "object") return false;
  if (seen.has(value)) return true;
  seen.add(value);
  if (Array.isArray(value)) {
    return value.some((entry) => hasForbiddenTransportKey(entry, seen));
  }
  if (!isPlainRecord(value)) return true;
  for (const key of Object.keys(value)) {
    if (FORBIDDEN_TRANSPORT_KEYS.has(key.toLowerCase())) {
      return true;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || "get" in descriptor || "set" in descriptor) {
      return true;
    }
    if (hasForbiddenTransportKey(descriptor.value, seen)) {
      return true;
    }
  }
  return false;
}

/** Runtime guard for the only financial-looking agent action exposed by Aegis. */
export function isDraftRequest(value: unknown): value is DraftRequest {
  if (!isPlainRecord(value)) return false;
  if (Object.keys(value).some((key) => !ALLOWED_TOP_LEVEL_KEYS.has(key))) return false;
  if (value.network !== "stellar-testnet" && value.network !== "ethereum-sepolia") return false;
  if (!isPlainRecord(value.operation) || typeof value.operation.kind !== "string" || !ALLOWED_OPERATION_KINDS.has(value.operation.kind)) {
    return false;
  }
  if (!isPlainRecord(value.protocol) || typeof value.protocol.protocolId !== "string" || typeof value.protocol.manifestId !== "string" || typeof value.protocol.contractId !== "string") {
    return false;
  }
  if (typeof value.sourceAccount !== "string" || !ADDRESS_PATTERN.test(value.sourceAccount)) return false;
  if (!Array.isArray(value.sourceMemoryIds) || value.sourceMemoryIds.length === 0 || value.sourceMemoryIds.some((id) => typeof id !== "string" || !ID_PATTERN.test(id))) {
    return false;
  }
  if (new Set(value.sourceMemoryIds).size !== value.sourceMemoryIds.length) return false;
  if (value.rationale !== undefined && (typeof value.rationale !== "string" || value.rationale.length > 2_000)) return false;
  if (hasForbiddenTransportKey(value)) return false;

  try {
    validateFinancialOperation(value.operation, value.network);
    validateProtocolTarget(value.protocol);
  } catch {
    return false;
  }

  const protocolId = value.protocol.protocolId.toLowerCase();
  if (value.network === "stellar-testnet" && protocolId !== "soroswap" && protocolId !== "mock") return false;
  if (value.network === "ethereum-sepolia" && protocolId !== "uniswap-v4" && protocolId !== "mock") return false;
  return true;
}

export interface DraftStoreOptions {
  readonly now?: () => Date;
  readonly idFactory?: () => string;
}

/**
 * Holds deliberately non-executable drafts. It has no signer reference, RPC
 * configuration, XDR/calldata field, or method that can turn a draft into a
 * transaction.
 */
export class AegisDraftStore {
  private readonly drafts = new Map<string, StoredDraft>();
  private readonly now: () => Date;
  private readonly idFactory: () => string;
  private sequence = 1;

  public constructor(private readonly gateway: AegisMemoryGateway, options: DraftStoreOptions = {}) {
    this.now = options.now ?? (() => new Date());
    this.idFactory = options.idFactory ?? (() => `draft-${this.sequence++}`);
  }

  public create(request: DraftRequest): StoredDraft {
    if (!isDraftRequest(request)) {
      throw new DraftValidationError("Draft request is malformed or contains a forbidden transport field.");
    }
    this.gateway.assertDraftSources(request.sourceMemoryIds);

    const id = this.idFactory();
    if (!ID_PATTERN.test(id)) {
      throw new DraftValidationError("Generated draft id is invalid.");
    }
    if (this.drafts.has(id)) {
      throw new DraftValidationError(`Draft id ${id} already exists.`);
    }
    const draft = createIntentDraft({
      id,
      network: request.network,
      operation: request.operation,
      protocol: request.protocol,
      sourceAccount: request.sourceAccount,
      requestedAt: this.now().toISOString(),
      sourceMemoryIds: [...request.sourceMemoryIds],
      ...(request.rationale === undefined ? {} : { rationale: request.rationale }),
    });
    validateIntentDraft(draft);
    const stored: StoredDraft = Object.freeze({
      draft,
      sourceMemoryIds: Object.freeze([...request.sourceMemoryIds]),
      requiresOwnerApproval: true,
      executionStatus: "DRAFT_ONLY",
    });
    this.drafts.set(draft.id, stored);
    return stored;
  }

  public get(draftId: string): StoredDraft | undefined {
    return this.drafts.get(draftId);
  }

  public list(): readonly StoredDraft[] {
    return Object.freeze([...this.drafts.values()]);
  }
}

export class CreateIntentDraftAction implements ElizaActionLike<DraftRequest, DraftActionOutput> {
  public readonly name = "AEGIS_CREATE_INTENT_DRAFT";
  public readonly description = "Creates a typed, non-executable financial intent draft that always requires owner approval.";
  public readonly similes = ["draft swap", "draft liquidity operation", "draft exact approval"];

  public constructor(private readonly drafts: AegisDraftStore) {}

  public validate(_runtime: AgentRuntimeLike, input: unknown): input is DraftRequest {
    return isDraftRequest(input);
  }

  public async handler(_runtime: AgentRuntimeLike, input: DraftRequest): Promise<DraftActionOutput> {
    try {
      return Object.freeze({ status: "DRAFT_CREATED", stored: this.drafts.create(input) });
    } catch (error) {
      if (error instanceof MemoryAccessError || error instanceof DraftValidationError) throw error;
      // Core validation errors are intentionally propagated unchanged so hosts
      // cannot mistake malformed financial data for a sendable transaction.
      throw error;
    }
  }
}
