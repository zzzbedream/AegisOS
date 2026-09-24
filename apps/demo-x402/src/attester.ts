import { createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import {
  deriveEd25519KeyId,
  generateEd25519KeyPair,
  type Ed25519KeyPairV1,
} from "../../../packages/core/src/index.js";

/**
 * The buyer-side attester: signs purchase commitments and delivery receipts.
 *
 * It used to be generated fresh on every run, which made every receipt
 * unverifiable the moment the process exited. Now it is one key per
 * environment, kept in a gitignored file, with its PUBLIC half published next
 * to the contract ID so anyone can check a receipt later.
 *
 * What the key proves, and only that: this buyer environment attested to this
 * receipt. It is not the seller's signature, and it is not the buyer's Stellar
 * account key.
 */

export const DEFAULT_ATTESTER_FILE = ".aegis/attester.json";
export const ATTESTER_ENV = "AEGIS_ATTESTER_SECRET_FILE";

/** What goes into deployments/testnet.json. Never the private key. */
export interface PublishedAttesterV1 {
  readonly keyId: string;
  readonly publicKey: string;
  readonly algorithm: "ed25519";
  readonly encoding: "spki-der-base64url";
  readonly role: "buyer";
  readonly createdAt: string;
}

export class AttesterError extends Error {
  public constructor(message: string, options?: { readonly cause?: unknown }) {
    super(message, options);
    this.name = "AttesterError";
  }
}

export function attesterPath(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env[ATTESTER_ENV];
  return configured !== undefined && configured.length > 0 ? configured : DEFAULT_ATTESTER_FILE;
}

/**
 * Load the attester and prove the file is self-consistent: the public key is
 * derived from the private key, and the keyId from the public key. A file that
 * was hand-edited to pair someone else's public key with our private key would
 * otherwise produce receipts that verify against the wrong identity.
 */
export function loadAttester(path: string): Ed25519KeyPairV1 {
  if (!existsSync(path)) {
    throw new AttesterError(
      `No attester key at ${path}. Create one with: npm run attester:init`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch (error: unknown) {
    throw new AttesterError(`Attester file ${path} is not valid JSON.`, { cause: error });
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new AttesterError(`Attester file ${path} must hold an object.`);
  }
  const { keyId, privateKey, publicKey } = parsed as Record<string, unknown>;
  if (typeof keyId !== "string" || typeof privateKey !== "string" || typeof publicKey !== "string") {
    throw new AttesterError(`Attester file ${path} needs keyId, privateKey and publicKey.`);
  }

  const derivedPublic = createPublicKey(
    createPrivateKey({ key: Buffer.from(privateKey, "base64url"), format: "der", type: "pkcs8" }),
  )
    .export({ format: "der", type: "spki" })
    .toString("base64url");
  if (derivedPublic !== publicKey) {
    throw new AttesterError(`Attester file ${path}: publicKey does not match privateKey.`);
  }
  if (deriveEd25519KeyId(publicKey) !== keyId) {
    throw new AttesterError(`Attester file ${path}: keyId does not match publicKey.`);
  }
  return Object.freeze({ keyId, privateKey, publicKey });
}

/**
 * Create the attester once. Refuses to overwrite: replacing the key silently
 * would orphan every receipt already signed under the published one.
 */
export function initAttester(path: string, now: Date = new Date()): {
  readonly keyPair: Ed25519KeyPairV1;
  readonly published: PublishedAttesterV1;
} {
  if (existsSync(path)) {
    throw new AttesterError(
      `${path} already exists. Rotating the attester orphans old receipts; move it aside first if you mean it.`,
    );
  }
  const keyPair = generateEd25519KeyPair();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(keyPair, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  return { keyPair, published: publishedFrom(keyPair, now) };
}

export function publishedFrom(keyPair: Ed25519KeyPairV1, now: Date = new Date()): PublishedAttesterV1 {
  return Object.freeze({
    keyId: keyPair.keyId,
    publicKey: keyPair.publicKey,
    algorithm: "ed25519",
    encoding: "spki-der-base64url",
    role: "buyer",
    createdAt: now.toISOString(),
  });
}

/** Read the published attester from a deployments file, if one is published. */
export function readPublishedAttester(deployments: unknown): PublishedAttesterV1 | undefined {
  if (typeof deployments !== "object" || deployments === null) return undefined;
  const attester = (deployments as Record<string, unknown>)["attester"];
  if (typeof attester !== "object" || attester === null) return undefined;
  const { keyId, publicKey } = attester as Record<string, unknown>;
  if (typeof keyId !== "string" || typeof publicKey !== "string") return undefined;
  return attester as PublishedAttesterV1;
}
