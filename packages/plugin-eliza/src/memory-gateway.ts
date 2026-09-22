import { createHash } from "node:crypto";

import { createMemoryEnvelope, generateLocalContentKey, sha256Canonical, type LocalContentKeyV1 } from "../../core/src/index.js";
import { assessMemoryRisk } from "./risk.js";
import type {
  GuardedMemoryEnvelope,
  MemoryAuditEvent,
  MemoryGatewayOptions,
  MemoryInput,
  MemoryQuery,
  MemorySecurityStatus,
  OwnerMemoryReview,
  SafeMemoryView,
} from "./types.js";
import type { JsonValue } from "./framework.js";

const DEFAULT_QUARANTINE_THRESHOLD = 60;
const QUARANTINED_CONTENT = "[QUARANTINED: owner review required]";

const CORE_MEMORY_SOURCES = {
  chat: "CHAT",
  document: "DOCUMENT",
  tool: "TOOL_RESULT",
  external_memory: "EXTERNAL_MEMORY",
  system: "SYSTEM",
} as const;

export class MemoryAccessError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "MemoryAccessError";
  }
}

export class MemoryPromotionError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "MemoryPromotionError";
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(",")}]`;
  }
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`)
    .join(",")}}`;
}

function isValidDate(value: string): boolean {
  return Number.isFinite(Date.parse(value));
}

function nonEmpty(value: string, label: string): void {
  if (value.trim().length === 0) {
    throw new MemoryAccessError(`${label} must not be empty.`);
  }
}

function readOnlyView(memory: GuardedMemoryEnvelope, revealContent: boolean): SafeMemoryView {
  return Object.freeze({
    id: memory.id,
    content: revealContent ? memory.content : QUARANTINED_CONTENT,
    contentHash: memory.contentHash,
    source: memory.provenance.source,
    sourceRef: memory.provenance.sourceRef,
    state: memory.state,
    taintScore: memory.taintScore,
    riskSignals: Object.freeze([...memory.riskSignals]),
    authority: "NONE" as const,
    metadata: Object.freeze({ ...memory.metadata }),
  });
}

/** Detects mutation, deletion, or reordering in a serialized gateway audit trail. */
export function verifyMemoryAuditTrail(events: readonly MemoryAuditEvent[]): boolean {
  let previousHash: string | null = null;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (event === undefined || event.sequence !== index + 1 || event.previousHash !== previousHash) {
      return false;
    }
    const expectedHash = sha256(stableJson({
      sequence: event.sequence,
      type: event.type,
      memoryId: event.memoryId,
      occurredAt: event.occurredAt,
      previousHash: event.previousHash,
      details: event.details,
    }));
    if (event.hash !== expectedHash) {
      return false;
    }
    previousHash = event.hash;
  }
  return true;
}

/**
 * Security-owned memory boundary. It accepts untrusted text, assigns taint at
 * ingress, and never returns quarantined plaintext to a context provider.
 *
 * Each stored item is sealed through the core envelope factory. All security
 * decisions in this package use the locally computed content hash and
 * lifecycle state, never model-generated fields.
 */
export class AegisMemoryGateway {
  private readonly memories = new Map<string, GuardedMemoryEnvelope>();
  private readonly events: MemoryAuditEvent[] = [];
  private readonly now: () => Date;
  private readonly quarantineThreshold: number;
  private readonly verifyOwnerReview: NonNullable<MemoryGatewayOptions["verifyOwnerReview"]>;
  private readonly encryptionKey: LocalContentKeyV1;
  private nextMemorySequence = 1;

  public constructor(options: MemoryGatewayOptions = {}) {
    this.now = options.now ?? (() => new Date());
    this.quarantineThreshold = options.quarantineThreshold ?? DEFAULT_QUARANTINE_THRESHOLD;
    if (this.quarantineThreshold < 1 || this.quarantineThreshold > 100) {
      throw new MemoryAccessError("quarantineThreshold must be between 1 and 100.");
    }
    this.verifyOwnerReview = options.verifyOwnerReview ?? (() => false);
    this.encryptionKey = options.encryptionKey ?? generateLocalContentKey();
  }

  public ingest(input: MemoryInput): GuardedMemoryEnvelope {
    nonEmpty(input.content, "Memory content");
    nonEmpty(input.provenance.sourceRef, "Memory provenance sourceRef");
    const receivedAt = input.provenance.receivedAt ?? this.now().toISOString();
    if (!isValidDate(receivedAt)) {
      throw new MemoryAccessError("Memory provenance receivedAt must be an ISO date.");
    }

    const contentHash = sha256Canonical(input.content);
    const id = input.id ?? `mem-${this.nextMemorySequence}-${contentHash.slice(0, 12)}`;
    nonEmpty(id, "Memory id");
    if (this.memories.has(id)) {
      throw new MemoryAccessError(`Memory id ${id} already exists.`);
    }

    const assessment = assessMemoryRisk(input.content, input.provenance.source);
    const state = assessment.taintScore >= this.quarantineThreshold ? "QUARANTINED" : "AVAILABLE";
    const ingestedAt = this.now().toISOString();
    const provenance = Object.freeze({
      source: input.provenance.source,
      sourceRef: input.provenance.sourceRef,
      ...(input.provenance.actorId === undefined ? {} : { actorId: input.provenance.actorId }),
      receivedAt,
    });

    const envelope: GuardedMemoryEnvelope = Object.freeze({
      version: 1,
      id,
      core: this.sealCoreEnvelope({
        id,
        content: input.content,
        source: input.provenance.source,
        sourceRef: input.provenance.sourceRef,
        receivedAt,
        ...(input.provenance.actorId === undefined ? {} : { actorId: input.provenance.actorId }),
        trust: state === "QUARANTINED" ? "QUARANTINED" : "UNTRUSTED",
        taintReasons: assessment.signals.map((signal) => `${signal.kind}:${signal.evidence}`),
        createdAt: ingestedAt,
      }),
      content: input.content,
      contentHash,
      provenance,
      state,
      taintScore: assessment.taintScore,
      riskSignals: Object.freeze([...assessment.signals]),
      metadata: Object.freeze({ ...(input.metadata ?? {}) }),
      ingestedAt,
    });
    this.memories.set(id, envelope);
    this.nextMemorySequence += 1;
    this.appendEvent("INGESTED", envelope, { state, taintScore: assessment.taintScore });
    if (state === "QUARANTINED") {
      this.appendEvent("QUARANTINED", envelope, { signals: assessment.signals.map((signal) => signal.kind) });
    }
    return envelope;
  }

  /**
   * Returns structured, explicitly non-authoritative memory. `includeQuarantined`
   * only includes a redacted placeholder; it never releases plaintext.
   */
  public retrieve(query: MemoryQuery = {}): readonly SafeMemoryView[] {
    const limit = query.limit ?? 20;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new MemoryAccessError("Memory query limit must be an integer between 1 and 100.");
    }
    const normalizedQuery = query.text?.trim().toLowerCase();
    const candidates = [...this.memories.values()].filter((memory) => {
      if (query.source !== undefined && memory.provenance.source !== query.source) {
        return false;
      }
      if (memory.state === "QUARANTINED" && query.includeQuarantined !== true) {
        return false;
      }
      return normalizedQuery === undefined || normalizedQuery.length === 0 || memory.content.toLowerCase().includes(normalizedQuery);
    });

    const results = candidates.slice(0, limit).map((memory) => {
      this.appendEvent("RETRIEVED", memory, { redacted: memory.state === "QUARANTINED" });
      return readOnlyView(memory, memory.state !== "QUARANTINED");
    });
    return Object.freeze(results);
  }

  /**
   * Promoting memory requires evidence bound to the exact content hash and a
   * caller-supplied owner-verification function. There is no LLM fallback.
   */
  public promote(memoryId: string, review: OwnerMemoryReview): GuardedMemoryEnvelope {
    const memory = this.memories.get(memoryId);
    if (memory === undefined) {
      throw new MemoryPromotionError(`Unknown memory id ${memoryId}.`);
    }
    if (memory.state === "PROMOTED") {
      throw new MemoryPromotionError(`Memory ${memoryId} is already promoted.`);
    }
    if (review.decision !== "PROMOTE") {
      throw new MemoryPromotionError("Only an explicit PROMOTE owner decision is accepted.");
    }
    if (review.reviewedContentHash !== memory.contentHash) {
      throw new MemoryPromotionError("Owner review is not bound to this exact memory content.");
    }
    if (
      !isValidDate(review.reviewedAt) ||
      !isValidDate(review.expiresAt) ||
      Date.parse(review.reviewedAt) > this.now().getTime() ||
      Date.parse(review.expiresAt) <= this.now().getTime()
    ) {
      throw new MemoryPromotionError("Owner review is expired or malformed.");
    }
    if (!this.verifyOwnerReview(review, memory)) {
      throw new MemoryPromotionError("Owner review verification failed.");
    }

    const promoted: GuardedMemoryEnvelope = Object.freeze({
      ...memory,
      core: this.sealCoreEnvelope({
        id: memory.id,
        content: memory.content,
        source: memory.provenance.source,
        sourceRef: memory.provenance.sourceRef,
        receivedAt: memory.provenance.receivedAt,
        ...(memory.provenance.actorId === undefined ? {} : { actorId: memory.provenance.actorId }),
        trust: "REVIEWED",
        taintReasons: memory.riskSignals.map((signal) => `${signal.kind}:${signal.evidence}`),
        createdAt: memory.ingestedAt,
      }),
      state: "PROMOTED",
      promotedAt: this.now().toISOString(),
      promotionReviewId: review.reviewId,
    });
    this.memories.set(memoryId, promoted);
    this.appendEvent("PROMOTED", promoted, { reviewId: review.reviewId, reviewerId: review.reviewerId });
    return promoted;
  }

  /** Used by the draft action to keep provenance attached without exposing raw storage. */
  public assertDraftSources(sourceMemoryIds: readonly string[]): void {
    if (sourceMemoryIds.length === 0) {
      throw new MemoryAccessError("A draft must cite at least one memory source.");
    }
    for (const memoryId of sourceMemoryIds) {
      const memory = this.memories.get(memoryId);
      if (memory === undefined) {
        throw new MemoryAccessError(`Draft cites unknown memory ${memoryId}.`);
      }
      if (memory.state === "QUARANTINED") {
        throw new MemoryAccessError(`Draft cites quarantined memory ${memoryId}. Owner review is required first.`);
      }
    }
  }

  public get quarantinedCount(): number {
    return [...this.memories.values()].filter((memory) => memory.state === "QUARANTINED").length;
  }

  public getAuditTrail(): readonly MemoryAuditEvent[] {
    return Object.freeze(this.events.map((event) => Object.freeze({ ...event, details: Object.freeze({ ...event.details }) })));
  }

  /** Metadata-only state used by the deterministic policy service. */
  public getSecurityStatus(memoryId: string): MemorySecurityStatus | undefined {
    const memory = this.memories.get(memoryId);
    if (memory === undefined) return undefined;
    return Object.freeze({
      id: memory.id,
      state: memory.state,
      taintScore: memory.taintScore,
      contentHash: memory.contentHash,
    });
  }

  private appendEvent(
    type: MemoryAuditEvent["type"],
    memory: GuardedMemoryEnvelope,
    details: Readonly<Record<string, JsonValue>>,
  ): void {
    const previousHash = this.events.at(-1)?.hash ?? null;
    const occurredAt = this.now().toISOString();
    const sequence = this.events.length + 1;
    const serialized = stableJson({ sequence, type, memoryId: memory.id, occurredAt, previousHash, details });
    const event: MemoryAuditEvent = Object.freeze({
      sequence,
      type,
      memoryId: memory.id,
      occurredAt,
      previousHash,
      hash: sha256(serialized),
      details: Object.freeze(details),
    });
    this.events.push(event);
  }

  private sealCoreEnvelope(input: {
    readonly id: string;
    readonly content: string;
    readonly source: keyof typeof CORE_MEMORY_SOURCES;
    readonly sourceRef: string;
    readonly receivedAt: string;
    readonly actorId?: string;
    readonly trust: "UNTRUSTED" | "QUARANTINED" | "REVIEWED";
    readonly taintReasons: readonly string[];
    readonly createdAt: string;
  }) {
    return createMemoryEnvelope({
      id: input.id,
      content: input.content,
      source: CORE_MEMORY_SOURCES[input.source],
      sourceId: input.sourceRef,
      receivedAt: input.receivedAt,
      ...(input.actorId === undefined ? {} : { actorId: input.actorId }),
      trust: input.trust,
      taintReasons: [...input.taintReasons],
      analysisVersion: "aegis-plugin-eliza/1",
      createdAt: input.createdAt,
      encryptionKey: this.encryptionKey,
    });
  }
}
