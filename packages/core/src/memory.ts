import {
  decryptLocalContent,
  encryptLocalContent,
  sha256Canonical,
  signCanonical,
  validateDetachedSignature,
  validateEncryptedContent,
  verifyCanonical,
  type DetachedSignatureV1,
  type EncryptedContentV1,
  type LocalContentKeyV1,
  type SigningIdentityV1,
} from "./crypto.js";
import { fail } from "./errors.js";
import {
  asRecord,
  assertUnique,
  exactKeys,
  optionalString,
  requiredArray,
  requiredHash,
  requiredId,
  requiredIsoTimestamp,
  requiredString,
} from "./validation.js";
import type { CanonicalValue } from "./canonical.js";
import { randomUUID } from "node:crypto";

export const MEMORY_SOURCES = ["CHAT", "DOCUMENT", "TOOL_RESULT", "EXTERNAL_MEMORY", "SYSTEM", "OWNER"] as const;
export type MemorySourceV1 = (typeof MEMORY_SOURCES)[number];

export const TRUST_TIERS = ["UNTRUSTED", "QUARANTINED", "REVIEWED", "CONTROLLED"] as const;
export type TrustTier = (typeof TRUST_TIERS)[number];

export interface MemoryProvenanceV1 {
  readonly source: MemorySourceV1;
  readonly sourceId: string;
  readonly receivedAt: string;
  readonly actorId?: string;
}

/**
 * The envelope contains encrypted content and a stable plaintext hash only.
 * `trust` is evidence metadata, never financial authority on its own.
 */
export interface MemoryEnvelopeV1 {
  readonly version: "1";
  readonly id: string;
  readonly provenance: MemoryProvenanceV1;
  readonly contentHash: string;
  readonly trust: TrustTier;
  readonly taintReasons: readonly string[];
  readonly analysisVersion: string;
  readonly createdAt: string;
  readonly encryptedContent: EncryptedContentV1;
  readonly signature?: DetachedSignatureV1;
}

export interface CreateMemoryEnvelopeInput {
  readonly id?: string;
  readonly content: unknown;
  readonly source: MemorySourceV1;
  readonly sourceId: string;
  readonly receivedAt?: string;
  readonly actorId?: string;
  readonly trust?: TrustTier;
  readonly taintReasons?: readonly string[];
  readonly analysisVersion?: string;
  readonly createdAt?: string;
  readonly encryptionKey: LocalContentKeyV1;
  readonly signer?: SigningIdentityV1;
}

function newId(): string {
  return `mem:${randomUUID()}`;
}

function memoryAad(envelope: Pick<MemoryEnvelopeV1, "id" | "provenance" | "contentHash">): object {
  return {
    domain: "aegisos.memory-envelope.v1",
    id: envelope.id,
    provenance: envelope.provenance,
    contentHash: envelope.contentHash,
  };
}

export function memoryEnvelopeSignable(envelope: MemoryEnvelopeV1): Omit<MemoryEnvelopeV1, "signature"> {
  const { signature: _signature, ...signable } = envelope;
  return signable;
}

export function validateMemoryEnvelope(value: unknown): asserts value is MemoryEnvelopeV1 {
  const record = asRecord(value, "memoryEnvelope");
  exactKeys(
    record,
    ["version", "id", "provenance", "contentHash", "trust", "taintReasons", "analysisVersion", "createdAt", "encryptedContent"],
    ["signature"],
    "memoryEnvelope",
  );
  if (record.version !== "1") fail("memoryEnvelope.version", "must be 1");
  requiredId(record.id, "memoryEnvelope.id");

  const provenance = asRecord(record.provenance, "memoryEnvelope.provenance");
  exactKeys(provenance, ["source", "sourceId", "receivedAt"], ["actorId"], "memoryEnvelope.provenance");
  if (!MEMORY_SOURCES.includes(provenance.source as MemorySourceV1)) {
    fail("memoryEnvelope.provenance.source", "must be a known memory source");
  }
  requiredId(provenance.sourceId, "memoryEnvelope.provenance.sourceId");
  requiredIsoTimestamp(provenance.receivedAt, "memoryEnvelope.provenance.receivedAt");
  optionalString(provenance.actorId, "memoryEnvelope.provenance.actorId", { max: 128 });

  requiredHash(record.contentHash, "memoryEnvelope.contentHash");
  if (!TRUST_TIERS.includes(record.trust as TrustTier)) {
    fail("memoryEnvelope.trust", "must be a known trust tier");
  }
  const reasons = requiredArray(record.taintReasons, "memoryEnvelope.taintReasons", 0, 128).map((reason, index) =>
    requiredString(reason, `memoryEnvelope.taintReasons[${index}]`, { max: 256 }),
  );
  assertUnique(reasons, "memoryEnvelope.taintReasons");
  requiredString(record.analysisVersion, "memoryEnvelope.analysisVersion", { max: 128 });
  requiredIsoTimestamp(record.createdAt, "memoryEnvelope.createdAt");
  validateEncryptedContent(record.encryptedContent);
  if (record.signature !== undefined) validateDetachedSignature(record.signature);
}

/**
 * Ingress always defaults to UNTRUSTED. A caller may record a higher tier, but
 * this function does not promote content based on the content itself.
 */
export function createMemoryEnvelope(input: CreateMemoryEnvelopeInput): MemoryEnvelopeV1 {
  const createdAt = input.createdAt ?? new Date().toISOString();
  const receivedAt = input.receivedAt ?? createdAt;
  const provenance: MemoryProvenanceV1 = {
    source: input.source,
    sourceId: input.sourceId,
    receivedAt,
    ...(input.actorId === undefined ? {} : { actorId: input.actorId }),
  };
  const base = {
    version: "1" as const,
    id: input.id ?? newId(),
    provenance,
    contentHash: sha256Canonical(input.content),
    trust: input.trust ?? "UNTRUSTED",
    taintReasons: [...(input.taintReasons ?? [])],
    analysisVersion: input.analysisVersion ?? "aegisos-core/1",
    createdAt,
  };
  const encryptedContent = encryptLocalContent(input.content, input.encryptionKey, memoryAad(base));
  const unsigned: MemoryEnvelopeV1 = { ...base, encryptedContent };
  validateMemoryEnvelope(unsigned);
  if (input.signer === undefined) return unsigned;
  return { ...unsigned, signature: signCanonical(memoryEnvelopeSignable(unsigned), input.signer) };
}

export function verifyMemoryEnvelope(envelope: MemoryEnvelopeV1, publicKey: string): boolean {
  try {
    validateMemoryEnvelope(envelope);
    if (envelope.signature === undefined) return false;
    return verifyCanonical(memoryEnvelopeSignable(envelope), envelope.signature, publicKey);
  } catch {
    return false;
  }
}

/** Decrypts and re-hashes content, so ciphertext substitution is detectable. */
export function decryptMemoryContent(
  envelope: MemoryEnvelopeV1,
  encryptionKey: LocalContentKeyV1,
): CanonicalValue {
  validateMemoryEnvelope(envelope);
  const content = decryptLocalContent(envelope.encryptedContent, encryptionKey, memoryAad(envelope));
  if (sha256Canonical(content) !== envelope.contentHash) {
    fail("memoryEnvelope.contentHash", "does not match decrypted content");
  }
  return content;
}

/** Explicit review operation; source text alone cannot promote itself. */
export function promoteMemoryTrust(
  envelope: MemoryEnvelopeV1,
  trust: "REVIEWED" | "CONTROLLED",
  reviewer: SigningIdentityV1,
): MemoryEnvelopeV1 {
  validateMemoryEnvelope(envelope);
  if (envelope.trust === "CONTROLLED") {
    fail("memoryEnvelope.trust", "CONTROLLED memory cannot be promoted further");
  }
  const unsigned: Omit<MemoryEnvelopeV1, "signature"> = {
    ...memoryEnvelopeSignable(envelope),
    trust,
  };
  return { ...unsigned, signature: signCanonical(unsigned, reviewer) };
}
