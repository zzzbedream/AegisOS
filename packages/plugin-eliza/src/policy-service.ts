import { isDraftRequest } from "./draft-action.js";
import { AegisMemoryGateway } from "./memory-gateway.js";
import type { DraftPolicyDecision, DraftRequest } from "./types.js";

/**
 * Deterministic pre-signing policy for the agent host. This service never
 * returns ALLOW: only the isolated signer can issue a signed ALLOW receipt
 * after owner approval and network-specific simulation.
 */
export class AegisPolicyService {
  public readonly serviceType = "aegis-policy";
  public readonly capability = "aegis-policy-evaluate-draft";

  public constructor(
    private readonly gateway: AegisMemoryGateway,
    private readonly now: () => Date = () => new Date(),
  ) {}

  public evaluateDraft(request: unknown): DraftPolicyDecision {
    const evaluatedAt = this.now().toISOString();
    if (!isDraftRequest(request)) {
      return Object.freeze({
        version: 1,
        decision: "DENY",
        evaluatedAt,
        reasons: Object.freeze(["Malformed draft or forbidden raw transaction transport."]),
        sourceMemoryIds: Object.freeze([]),
      });
    }
    return this.evaluateValidDraft(request, evaluatedAt);
  }

  private evaluateValidDraft(request: DraftRequest, evaluatedAt: string): DraftPolicyDecision {
    const reasons: string[] = [];
    for (const memoryId of request.sourceMemoryIds) {
      const status = this.gateway.getSecurityStatus(memoryId);
      if (status === undefined) {
        reasons.push(`Unknown source memory: ${memoryId}.`);
      } else if (status.state === "QUARANTINED") {
        reasons.push(`Quarantined source memory: ${memoryId}.`);
      }
    }
    if (reasons.length > 0) {
      return Object.freeze({
        version: 1,
        decision: "DENY",
        evaluatedAt,
        reasons: Object.freeze(reasons),
        sourceMemoryIds: Object.freeze([...request.sourceMemoryIds]),
      });
    }

    return Object.freeze({
      version: 1,
      decision: "PENDING_OWNER",
      evaluatedAt,
      reasons: Object.freeze([
        "A draft is non-executable until an owner approval and isolated signer policy receipt are present.",
      ]),
      sourceMemoryIds: Object.freeze([...request.sourceMemoryIds]),
    });
  }
}
