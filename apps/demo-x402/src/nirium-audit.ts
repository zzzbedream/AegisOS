/**
 * Nirium Audit Trail: an external, public anchor for an AegisOS receipt file.
 *
 * Nirium pins a sha-256 to IPFS and returns a CID. With an `agent` attestation it also
 * records who declared the hash: an ed25519 signature, by a Stellar key, over
 * `nirium-audit-v1:<sha256>`. The CID proves the hash was not altered after anchoring;
 * the signature proves which key declared it. Neither says anything about the receipt's
 * content: that is what `verify:receipt` checks.
 *
 * The anchor lives in a sibling `nirium-anchor.json`, never inside the receipt: writing
 * the CID into the receipt would change the hash that was anchored.
 */
import { createHash } from "node:crypto";

import { Keypair } from "@stellar/stellar-sdk";

export const NIRIUM_AUDIT_DOMAIN = "nirium-audit-v1";
export const NIRIUM_TESTNET_URL = "https://nirium-agent.fly.dev";

export interface NiriumAttestation {
  readonly id: string;
  /** Stellar G address of the declaring key. */
  readonly key: string;
  /** base64 ed25519 over `nirium-audit-v1:<sha256>`. */
  readonly signature: string;
}

export interface NiriumAnchorRequest {
  readonly hash: string;
  readonly tag: string;
  readonly txHash?: string;
  readonly agent: NiriumAttestation;
}

/** What we keep next to the receipt: the request we signed and Nirium's answer. */
export interface NiriumAnchorFileV1 {
  readonly version: "1";
  readonly node: string;
  readonly receiptFile: string;
  readonly receiptSha256: string;
  readonly request: NiriumAnchorRequest;
  readonly response: { readonly cid: string; readonly contentSha256?: string; readonly gatewayUrl?: string; readonly anchoredAt?: string; readonly attestedBy?: string };
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function auditMessage(sha256: string): Buffer {
  if (!/^[0-9a-f]{64}$/.test(sha256)) throw new Error(`Not a lowercase sha-256 hex: ${sha256}`);
  return Buffer.from(`${NIRIUM_AUDIT_DOMAIN}:${sha256}`);
}

export function buildAnchorRequest(input: {
  readonly receiptBytes: Uint8Array;
  readonly signer: Keypair;
  readonly tag: string;
  readonly txHash?: string;
}): NiriumAnchorRequest {
  const hash = sha256Hex(input.receiptBytes);
  const signature = Buffer.from(input.signer.sign(auditMessage(hash))).toString("base64");
  return {
    hash,
    tag: input.tag,
    ...(input.txHash === undefined ? {} : { txHash: input.txHash }),
    agent: { id: "aegisos", key: input.signer.publicKey(), signature },
  };
}

/** Checks the anchor file against the receipt bytes alone; no network. */
export function verifyAnchorFile(file: NiriumAnchorFileV1, receiptBytes: Uint8Array): readonly { readonly name: string; readonly pass: boolean; readonly detail: string }[] {
  const hash = sha256Hex(receiptBytes);
  const { agent } = file.request;
  let signatureValid = false;
  try {
    signatureValid = Keypair.fromPublicKey(agent.key).verify(auditMessage(file.request.hash), Buffer.from(agent.signature, "base64"));
  } catch {
    signatureValid = false;
  }
  return [
    { name: "anchored hash is this receipt file's sha-256", pass: file.request.hash === hash && file.receiptSha256 === hash, detail: hash },
    { name: "attestation signature verifies", pass: signatureValid, detail: agent.key },
    { name: "Nirium returned a CID", pass: /^(b[a-z2-7]{50,}|Qm[1-9A-HJ-NP-Za-km-z]{44})$/.test(file.response.cid), detail: file.response.cid },
  ];
}
