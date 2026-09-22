import { canonicalize, type CanonicalValue } from "./canonical.js";
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
  asRecord,
  exactKeys,
  requiredHash,
  requiredId,
  requiredInteger,
  requiredIsoTimestamp,
} from "./validation.js";
import { randomUUID } from "node:crypto";

export const LEDGER_EVENT_TYPES = [
  "MEMORY_INGESTED",
  "MEMORY_QUARANTINED",
  "MEMORY_RETRIEVED",
  "MEMORY_PROMOTED",
  "INTENT_DRAFTED",
  "INTENT_CREATED",
  "POLICY_EVALUATED",
  "OWNER_APPROVED",
  "CAPABILITY_ISSUED",
  "SIGNATURE_CREATED",
  "TRANSACTION_SUBMITTED",
  "TRANSACTION_RECEIPT",
  "EXECUTION_DENIED",
] as const;
export type LedgerEventType = (typeof LEDGER_EVENT_TYPES)[number];

export interface LedgerEntryV1 {
  readonly version: "1";
  readonly sequence: number;
  readonly id: string;
  readonly type: LedgerEventType;
  readonly occurredAt: string;
  readonly payload: CanonicalValue;
  readonly payloadHash: string;
  /** null only for the genesis entry. */
  readonly previousHash: string | null;
  readonly entryHash: string;
  readonly signerKeyId: string;
  readonly signature: DetachedSignatureV1;
}

export interface LedgerCheckpointV1 {
  readonly version: "1";
  readonly entryCount: number;
  readonly headHash: string | null;
  readonly createdAt: string;
  readonly signerKeyId: string;
  readonly signature: DetachedSignatureV1;
}

export interface AppendLedgerEntryInput {
  readonly id?: string;
  readonly type: LedgerEventType;
  readonly payload: unknown;
  readonly occurredAt?: string;
}

export interface AppendOnlyLedgerOptions {
  readonly signer: SigningIdentityV1;
  readonly now?: () => string;
}

export type PublicKeyLookup = Readonly<Record<string, string>> | ((keyId: string) => string | undefined);

export interface VerifyLedgerOptions {
  readonly publicKeys: PublicKeyLookup;
  /** Pins expected length/head and makes deletion of a trailing event detectable. */
  readonly checkpoint?: LedgerCheckpointV1;
}

export interface LedgerVerificationResult {
  readonly valid: boolean;
  readonly verifiedEntries: number;
  readonly headHash: string | null;
  readonly error?: string;
}

function newId(prefix: string): string {
  return `${prefix}:${randomUUID()}`;
}

function isLedgerEventType(value: unknown): value is LedgerEventType {
  return LEDGER_EVENT_TYPES.includes(value as LedgerEventType);
}

function lookupPublicKey(keys: PublicKeyLookup, keyId: string): string | undefined {
  return typeof keys === "function" ? keys(keyId) : keys[keyId];
}

export function ledgerEntrySignable(entry: LedgerEntryV1): Omit<LedgerEntryV1, "entryHash" | "signature"> {
  const { entryHash: _entryHash, signature: _signature, ...signable } = entry;
  return signable;
}

export function computeLedgerEntryHash(entry: Omit<LedgerEntryV1, "entryHash" | "signature">): string {
  return sha256Canonical({ domain: "aegisos.ledger-entry.v1", entry });
}

function ledgerEntrySignaturePayload(entryHash: string): object {
  return { domain: "aegisos.ledger-entry-signature.v1", entryHash };
}

export function validateLedgerEntry(value: unknown): asserts value is LedgerEntryV1 {
  const record = asRecord(value, "ledgerEntry");
  exactKeys(
    record,
    ["version", "sequence", "id", "type", "occurredAt", "payload", "payloadHash", "previousHash", "entryHash", "signerKeyId", "signature"],
    [],
    "ledgerEntry",
  );
  if (record.version !== "1") fail("ledgerEntry.version", "must be 1");
  requiredInteger(record.sequence, "ledgerEntry.sequence", 0, Number.MAX_SAFE_INTEGER);
  requiredId(record.id, "ledgerEntry.id");
  if (!isLedgerEventType(record.type)) fail("ledgerEntry.type", "must be a known audit event type");
  requiredIsoTimestamp(record.occurredAt, "ledgerEntry.occurredAt");
  canonicalize(record.payload, "ledgerEntry.payload");
  requiredHash(record.payloadHash, "ledgerEntry.payloadHash");
  if (record.previousHash !== null) requiredHash(record.previousHash, "ledgerEntry.previousHash");
  requiredHash(record.entryHash, "ledgerEntry.entryHash");
  requiredId(record.signerKeyId, "ledgerEntry.signerKeyId");
  validateDetachedSignature(record.signature);
  if ((record.signature as DetachedSignatureV1).keyId !== record.signerKeyId) {
    fail("ledgerEntry.signature.keyId", "must match signerKeyId");
  }
}

function verifyLedgerEntryIntegrity(entry: LedgerEntryV1): string | undefined {
  if (sha256Canonical(entry.payload) !== entry.payloadHash) return "PAYLOAD_HASH_MISMATCH";
  if (computeLedgerEntryHash(ledgerEntrySignable(entry)) !== entry.entryHash) return "ENTRY_HASH_MISMATCH";
  return undefined;
}

export function ledgerCheckpointSignable(checkpoint: LedgerCheckpointV1): Omit<LedgerCheckpointV1, "signature"> {
  const { signature: _signature, ...signable } = checkpoint;
  return signable;
}

function checkpointSignaturePayload(checkpoint: Omit<LedgerCheckpointV1, "signature">): object {
  return { domain: "aegisos.ledger-checkpoint.v1", checkpoint };
}

export function validateLedgerCheckpoint(value: unknown): asserts value is LedgerCheckpointV1 {
  const record = asRecord(value, "checkpoint");
  exactKeys(record, ["version", "entryCount", "headHash", "createdAt", "signerKeyId", "signature"], [], "checkpoint");
  if (record.version !== "1") fail("checkpoint.version", "must be 1");
  const entryCount = requiredInteger(record.entryCount, "checkpoint.entryCount", 0, Number.MAX_SAFE_INTEGER);
  if (record.headHash !== null) requiredHash(record.headHash, "checkpoint.headHash");
  if (entryCount === 0 && record.headHash !== null) fail("checkpoint.headHash", "must be null for an empty ledger");
  if (entryCount > 0 && record.headHash === null) fail("checkpoint.headHash", "is required for a non-empty ledger");
  requiredIsoTimestamp(record.createdAt, "checkpoint.createdAt");
  requiredId(record.signerKeyId, "checkpoint.signerKeyId");
  validateDetachedSignature(record.signature);
  if ((record.signature as DetachedSignatureV1).keyId !== record.signerKeyId) {
    fail("checkpoint.signature.keyId", "must match signerKeyId");
  }
}

export function createLedgerCheckpoint(
  entries: readonly LedgerEntryV1[],
  signer: SigningIdentityV1,
  createdAt = new Date().toISOString(),
): LedgerCheckpointV1 {
  // Check internal consistency before an operator publishes an anchor.
  for (const entry of entries) validateLedgerEntry(entry);
  const unsigned: Omit<LedgerCheckpointV1, "signature"> = {
    version: "1",
    entryCount: entries.length,
    headHash: entries.length === 0 ? null : (entries[entries.length - 1] as LedgerEntryV1).entryHash,
    createdAt,
    signerKeyId: signer.keyId,
  };
  const checkpoint: LedgerCheckpointV1 = {
    ...unsigned,
    signature: signCanonical(checkpointSignaturePayload(unsigned), signer),
  };
  validateLedgerCheckpoint(checkpoint);
  return checkpoint;
}

export function verifyLedgerCheckpoint(checkpoint: LedgerCheckpointV1, publicKey: string): boolean {
  try {
    validateLedgerCheckpoint(checkpoint);
    return verifyCanonical(checkpointSignaturePayload(ledgerCheckpointSignable(checkpoint)), checkpoint.signature, publicKey);
  } catch {
    return false;
  }
}

function failed(verifiedEntries: number, headHash: string | null, error: string): LedgerVerificationResult {
  return { valid: false, verifiedEntries, headHash, error };
}

function freezeCanonical<T extends CanonicalValue>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Array.isArray(value) ? value : Object.values(value)) {
      freezeCanonical(child);
    }
    Object.freeze(value);
  }
  return value;
}

function snapshotEntry(entry: LedgerEntryV1): LedgerEntryV1 {
  return canonicalize(entry) as unknown as LedgerEntryV1;
}

/**
 * Standalone verifier: it does not rely on AppendOnlyLedger's in-memory state.
 * A valid signed checkpoint also detects a missing trailing event.
 */
export function verifyLedger(entries: readonly unknown[], options: VerifyLedgerOptions): LedgerVerificationResult {
  let priorHash: string | null = null;
  for (let index = 0; index < entries.length; index += 1) {
    const raw = entries[index];
    try {
      validateLedgerEntry(raw);
    } catch {
      return failed(index, priorHash, "INVALID_ENTRY_SCHEMA");
    }
    const entry = raw as LedgerEntryV1;
    if (entry.sequence !== index) return failed(index, priorHash, "SEQUENCE_MISMATCH");
    if (entry.previousHash !== priorHash) return failed(index, priorHash, "CHAIN_LINK_MISMATCH");
    const integrityError = verifyLedgerEntryIntegrity(entry);
    if (integrityError !== undefined) return failed(index, priorHash, integrityError);
    const publicKey = lookupPublicKey(options.publicKeys, entry.signerKeyId);
    if (publicKey === undefined || !verifyCanonical(ledgerEntrySignaturePayload(entry.entryHash), entry.signature, publicKey)) {
      return failed(index, priorHash, "INVALID_ENTRY_SIGNATURE");
    }
    priorHash = entry.entryHash;
  }

  if (options.checkpoint !== undefined) {
    const checkpoint = options.checkpoint;
    try {
      validateLedgerCheckpoint(checkpoint);
    } catch {
      return failed(entries.length, priorHash, "INVALID_CHECKPOINT_SCHEMA");
    }
    const publicKey = lookupPublicKey(options.publicKeys, checkpoint.signerKeyId);
    if (publicKey === undefined || !verifyLedgerCheckpoint(checkpoint, publicKey)) {
      return failed(entries.length, priorHash, "INVALID_CHECKPOINT_SIGNATURE");
    }
    if (checkpoint.entryCount !== entries.length || checkpoint.headHash !== priorHash) {
      return failed(entries.length, priorHash, "CHECKPOINT_MISMATCH");
    }
  }
  return { valid: true, verifiedEntries: entries.length, headHash: priorHash };
}

/**
 * Mutable append API with no deletion/reorder surface. Exported snapshots are
 * immutable copies; independently verify them before importing elsewhere.
 */
export class AppendOnlyLedger {
  readonly #signer: SigningIdentityV1;
  readonly #now: () => string;
  readonly #entriesInternal: LedgerEntryV1[] = [];

  public constructor(options: AppendOnlyLedgerOptions) {
    requiredId(options.signer.keyId, "ledger.signer.keyId");
    this.#signer = Object.freeze({ ...options.signer });
    this.#now = options.now ?? (() => new Date().toISOString());
  }

  public append(input: AppendLedgerEntryInput): LedgerEntryV1 {
    if (!isLedgerEventType(input.type)) fail("ledger.type", "must be a known audit event type");
    const payload = canonicalize(input.payload);
    const occurredAt = input.occurredAt ?? this.#now();
    requiredIsoTimestamp(occurredAt, "ledger.occurredAt");
    const unsigned: Omit<LedgerEntryV1, "entryHash" | "signature"> = {
      version: "1",
      sequence: this.#entriesInternal.length,
      id: input.id ?? newId("ledger"),
      type: input.type,
      occurredAt,
      payload,
      payloadHash: sha256Canonical(payload),
      previousHash: this.#entriesInternal.length === 0 ? null : (this.#entriesInternal[this.#entriesInternal.length - 1] as LedgerEntryV1).entryHash,
      signerKeyId: this.#signer.keyId,
    };
    const entryHash = computeLedgerEntryHash(unsigned);
    const entry: LedgerEntryV1 = {
      ...unsigned,
      entryHash,
      signature: signCanonical(ledgerEntrySignaturePayload(entryHash), this.#signer),
    };
    validateLedgerEntry(entry);
    const stored = freezeCanonical(canonicalize(entry)) as unknown as LedgerEntryV1;
    this.#entriesInternal.push(stored);
    return snapshotEntry(stored);
  }

  public entries(): readonly LedgerEntryV1[] {
    // A canonical round trip returns a detached snapshot, so caller mutation cannot
    // alter the append-only in-memory chain.
    return this.#entriesInternal.map(snapshotEntry);
  }

  public headHash(): string | null {
    const last = this.#entriesInternal[this.#entriesInternal.length - 1];
    return last?.entryHash ?? null;
  }

  public checkpoint(createdAt = this.#now()): LedgerCheckpointV1 {
    return createLedgerCheckpoint(this.#entriesInternal, this.#signer, createdAt);
  }
}
