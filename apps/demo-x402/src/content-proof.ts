/**
 * Guarantee D: the content came from the seller.
 *
 * A Reclaim zkFetch proof is an attestor's signature over a claim that names
 * the request and carries, in its signed context, the body it saw over TLS.
 * Checking one needs no Reclaim service: recompute the claim identifier,
 * recover the signer, and require that signer to be a witness we pinned, the
 * context to name our commitment, and the proven body to hash to the
 * receipt's contentHash. The proof's own `extractedParameterValues` sit
 * outside the signature, so they are never read here.
 */
import { utils } from "ethers";

import { hashDeliveredContent, type ContentCanonicalization } from "../../../packages/proof/src/index.js";
import type { ReceiptCheck } from "./receipt-check.js";

export interface ReclaimClaimV1 {
  readonly provider: string;
  readonly parameters: string;
  readonly context: string;
  readonly owner: string;
  readonly timestampS: number;
  readonly epoch: number;
  readonly identifier: string;
}

/** The fields of a zkFetch `Proof` this module relies on. */
export interface ReclaimProofV1 {
  readonly identifier: string;
  readonly claimData: ReclaimClaimV1;
  readonly signatures: readonly string[];
  readonly witnesses: readonly { readonly id: string; readonly url: string }[];
  readonly extractedParameterValues?: unknown;
}

export interface ContentProofExpectation {
  readonly commitmentHash: string;
  readonly contentHash: string;
  readonly canonicalization: ContentCanonicalization;
  /** Attestor addresses we trust, pinned out of band. */
  readonly trustedWitnesses: readonly string[];
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/** Reclaim's claim id: keccak256(provider \n parameters \n canonical context). */
export function claimIdentifier(claim: Pick<ReclaimClaimV1, "provider" | "parameters" | "context">): string {
  const context = claim.context.length > 0 ? canonicalJson(JSON.parse(claim.context) as unknown) : "";
  return utils.keccak256(utils.toUtf8Bytes(`${claim.provider}\n${claim.parameters}\n${context}`)).toLowerCase();
}

interface SignedContext {
  readonly contextMessage?: unknown;
  readonly extractedParameters?: { readonly body?: unknown };
}

function signedContext(claim: ReclaimClaimV1): SignedContext {
  try {
    const parsed = JSON.parse(claim.context) as unknown;
    return typeof parsed === "object" && parsed !== null ? (parsed as SignedContext) : {};
  } catch {
    return {};
  }
}

function recoverSigners(proof: ReclaimProofV1): readonly string[] {
  const c = proof.claimData;
  const signData = [claimIdentifier(c), c.owner.toLowerCase(), String(c.timestampS), String(c.epoch)].join("\n");
  return proof.signatures.flatMap((signature) => {
    try {
      return [utils.verifyMessage(signData, signature).toLowerCase()];
    } catch {
      return [];
    }
  });
}

/** The HTTP response the attestor saw, as captured by a whole-response match. */
export interface ProvenResponse {
  readonly status: number;
  readonly header: (name: string) => string | null;
  readonly body: string;
}

/**
 * Split a proven response into status, headers and body. The attestor signs
 * the status line and headers too, so a seller's PAYMENT-RESPONSE header is
 * proven along with the content.
 */
export function parseProvenResponse(text: string): ProvenResponse | undefined {
  const split = text.indexOf("\r\n\r\n");
  if (split === -1 || !text.startsWith("HTTP/")) return undefined;
  const [statusLine = "", ...lines] = text.slice(0, split).split("\r\n");
  const status = Number(statusLine.split(" ")[1]);
  if (!Number.isInteger(status)) return undefined;
  const headers = new Map<string, string>();
  for (const line of lines) {
    const colon = line.indexOf(":");
    if (colon > 0) headers.set(line.slice(0, colon).trim().toLowerCase(), line.slice(colon + 1).trim());
  }
  return { status, header: (name) => headers.get(name.toLowerCase()) ?? null, body: text.slice(split + 4) };
}

/** The response inside a proof's signed context, or undefined. */
export function provenResponse(proof: ReclaimProofV1): ProvenResponse | undefined {
  const captured = signedContext(proof.claimData).extractedParameters?.body;
  return typeof captured === "string" ? parseProvenResponse(captured) : undefined;
}

function provenContentHash(body: string, canonicalization: ContentCanonicalization): string | undefined {
  try {
    return hashDeliveredContent({ bodyBytes: new TextEncoder().encode(body), canonicalization }).contentHash;
  } catch {
    return undefined;
  }
}

export function contentProofChecks(proof: ReclaimProofV1, expected: ContentProofExpectation): readonly ReceiptCheck[] {
  let recomputed: string | undefined;
  try {
    recomputed = claimIdentifier(proof.claimData);
  } catch {
    recomputed = undefined;
  }
  const identifierOk = recomputed !== undefined && recomputed === proof.claimData.identifier.toLowerCase();

  const trusted = new Set(expected.trustedWitnesses.map((w) => w.toLowerCase()));
  const signers = identifierOk ? recoverSigners(proof) : [];
  const pinned = signers.find((s) => trusted.has(s));

  const context = signedContext(proof.claimData);
  const response = provenResponse(proof);
  const proven = response === undefined ? undefined : provenContentHash(response.body, expected.canonicalization);

  return [
    {
      name: "claim identifier recomputes",
      pass: identifierOk,
      detail: recomputed ?? "claim context is not JSON",
    },
    {
      name: "signed by a pinned Reclaim witness",
      pass: pinned !== undefined,
      detail: pinned ?? (signers.length === 0 ? "no valid signature" : `signed by ${signers.join(", ")}, not pinned`),
    },
    {
      name: "proof is bound to this commitment",
      pass: context.contextMessage === expected.commitmentHash,
      detail: typeof context.contextMessage === "string" ? context.contextMessage : "no context message",
    },
    {
      name: "the seller answered 2xx over TLS",
      pass: response !== undefined && response.status >= 200 && response.status < 300,
      detail: response === undefined ? "no proven HTTP response in the signed context" : `HTTP ${String(response.status)}`,
    },
    {
      name: "proven body is the receipt's content",
      pass: proven === expected.contentHash,
      detail: proven ?? "no proven body in the signed context",
    },
  ];
}
