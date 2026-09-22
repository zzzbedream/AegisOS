import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import { canonicalBytes, canonicalJson, canonicalize, type CanonicalValue } from "./canonical.js";
import { fail } from "./errors.js";
import { asRecord, exactKeys, requiredHash, requiredId, requiredString } from "./validation.js";

export const SHA_256_HEX_LENGTH = 64;

export interface DetachedSignatureV1 {
  readonly algorithm: "ed25519";
  readonly keyId: string;
  /** base64url Ed25519 signature */
  readonly value: string;
}

export interface SigningIdentityV1 {
  readonly keyId: string;
  /** base64url PKCS#8 DER. Keep this only in the isolated signer process. */
  readonly privateKey: string;
}

export interface Ed25519KeyPairV1 extends SigningIdentityV1 {
  /** base64url SPKI DER */
  readonly publicKey: string;
}

export interface LocalContentKeyV1 {
  readonly version: "1";
  readonly algorithm: "aes-256-gcm";
  /** base64url, 32-byte key. Do not put this into ledger events or agent context. */
  readonly key: string;
}

export interface EncryptedContentV1 {
  readonly version: "1";
  readonly algorithm: "aes-256-gcm";
  readonly nonce: string;
  readonly ciphertext: string;
  readonly authTag: string;
  readonly aadHash?: string;
}

function toBuffer(value: string | Uint8Array): Buffer {
  return typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
}

function decodeBase64Url(value: string, path: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    fail(path, "must be base64url without padding");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length === 0 || decoded.toString("base64url") !== value) {
    fail(path, "is not valid canonical base64url");
  }
  return decoded;
}

function publicKeyObject(publicKey: string) {
  return createPublicKey({
    key: decodeBase64Url(publicKey, "publicKey"),
    format: "der",
    type: "spki",
  });
}

function privateKeyObject(privateKey: string) {
  return createPrivateKey({
    key: decodeBase64Url(privateKey, "privateKey"),
    format: "der",
    type: "pkcs8",
  });
}

export function sha256Hex(value: string | Uint8Array): string {
  return createHash("sha256").update(toBuffer(value)).digest("hex");
}

export function sha256Canonical(value: unknown): string {
  return sha256Hex(canonicalBytes(value));
}

export function secureEqual(left: string | Uint8Array, right: string | Uint8Array): boolean {
  const leftBytes = toBuffer(left);
  const rightBytes = toBuffer(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

export function deriveEd25519KeyId(publicKey: string): string {
  return `ed25519:${sha256Hex(decodeBase64Url(publicKey, "publicKey")).slice(0, 24)}`;
}

export function generateEd25519KeyPair(keyId?: string): Ed25519KeyPairV1 {
  const pair = generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const privateKey = pair.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64url");
  return {
    keyId: keyId ?? deriveEd25519KeyId(publicKey),
    privateKey,
    publicKey,
  };
}

export function signEd25519(message: string | Uint8Array, identity: SigningIdentityV1): DetachedSignatureV1 {
  requiredId(identity.keyId, "identity.keyId");
  requiredString(identity.privateKey, "identity.privateKey", { min: 1, max: 8_192 });
  return {
    algorithm: "ed25519",
    keyId: identity.keyId,
    value: sign(null, toBuffer(message), privateKeyObject(identity.privateKey)).toString("base64url"),
  };
}

export function validateDetachedSignature(value: unknown): asserts value is DetachedSignatureV1 {
  const record = asRecord(value, "signature");
  exactKeys(record, ["algorithm", "keyId", "value"], [], "signature");
  if (record.algorithm !== "ed25519") {
    fail("signature.algorithm", "must be ed25519");
  }
  requiredId(record.keyId, "signature.keyId");
  decodeBase64Url(requiredString(record.value, "signature.value", { min: 1, max: 256 }), "signature.value");
}

export function verifyEd25519(
  message: string | Uint8Array,
  signature: DetachedSignatureV1,
  publicKey: string,
): boolean {
  try {
    validateDetachedSignature(signature);
    return verify(null, toBuffer(message), publicKeyObject(publicKey), decodeBase64Url(signature.value, "signature.value"));
  } catch {
    return false;
  }
}

export function signCanonical(value: unknown, identity: SigningIdentityV1): DetachedSignatureV1 {
  return signEd25519(canonicalBytes(value), identity);
}

export function verifyCanonical(value: unknown, signature: DetachedSignatureV1, publicKey: string): boolean {
  return verifyEd25519(canonicalBytes(value), signature, publicKey);
}

export function generateLocalContentKey(): LocalContentKeyV1 {
  return {
    version: "1",
    algorithm: "aes-256-gcm",
    key: randomBytes(32).toString("base64url"),
  };
}

function decodeContentKey(key: LocalContentKeyV1): Buffer {
  if (key.version !== "1" || key.algorithm !== "aes-256-gcm") {
    fail("encryptionKey", "must be a version 1 AES-256-GCM content key");
  }
  const decoded = decodeBase64Url(key.key, "encryptionKey.key");
  if (decoded.length !== 32) {
    fail("encryptionKey.key", "must be exactly 32 bytes");
  }
  return decoded;
}

function normalizeAad(aad: unknown): Buffer | undefined {
  return aad === undefined ? undefined : Buffer.from(canonicalJson(aad), "utf8");
}

/** Encrypt canonical local content; callers retain the key outside agent memory. */
export function encryptLocalContent(value: unknown, key: LocalContentKeyV1, aad?: unknown): EncryptedContentV1 {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", decodeContentKey(key), nonce);
  const normalizedAad = normalizeAad(aad);
  if (normalizedAad !== undefined) cipher.setAAD(normalizedAad);
  const plaintext = Buffer.from(canonicalJson(value), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const result: EncryptedContentV1 = {
    version: "1",
    algorithm: "aes-256-gcm",
    nonce: nonce.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    authTag: cipher.getAuthTag().toString("base64url"),
  };
  if (normalizedAad !== undefined) {
    return { ...result, aadHash: sha256Hex(normalizedAad) };
  }
  return result;
}

export function validateEncryptedContent(value: unknown): asserts value is EncryptedContentV1 {
  const record = asRecord(value, "encryptedContent");
  exactKeys(record, ["version", "algorithm", "nonce", "ciphertext", "authTag"], ["aadHash"], "encryptedContent");
  if (record.version !== "1") fail("encryptedContent.version", "must be 1");
  if (record.algorithm !== "aes-256-gcm") fail("encryptedContent.algorithm", "must be aes-256-gcm");
  if (decodeBase64Url(requiredString(record.nonce, "encryptedContent.nonce", { min: 1, max: 64 }), "encryptedContent.nonce").length !== 12) {
    fail("encryptedContent.nonce", "must decode to 12 bytes");
  }
  decodeBase64Url(requiredString(record.ciphertext, "encryptedContent.ciphertext", { min: 1, max: 2_000_000 }), "encryptedContent.ciphertext");
  if (decodeBase64Url(requiredString(record.authTag, "encryptedContent.authTag", { min: 1, max: 64 }), "encryptedContent.authTag").length !== 16) {
    fail("encryptedContent.authTag", "must decode to 16 bytes");
  }
  if (record.aadHash !== undefined) requiredHash(record.aadHash, "encryptedContent.aadHash");
}

export function decryptLocalContent(
  encryptedContent: EncryptedContentV1,
  key: LocalContentKeyV1,
  aad?: unknown,
): CanonicalValue {
  validateEncryptedContent(encryptedContent);
  const normalizedAad = normalizeAad(aad);
  if (encryptedContent.aadHash !== undefined) {
    if (normalizedAad === undefined || !secureEqual(encryptedContent.aadHash, sha256Hex(normalizedAad))) {
      fail("encryptedContent.aadHash", "does not match supplied associated data");
    }
  } else if (normalizedAad !== undefined) {
    fail("aad", "was supplied but encrypted content has no associated-data hash");
  }
  try {
    const decipher = createDecipheriv("aes-256-gcm", decodeContentKey(key), decodeBase64Url(encryptedContent.nonce, "encryptedContent.nonce"));
    if (normalizedAad !== undefined) decipher.setAAD(normalizedAad);
    decipher.setAuthTag(decodeBase64Url(encryptedContent.authTag, "encryptedContent.authTag"));
    const plaintext = Buffer.concat([
      decipher.update(decodeBase64Url(encryptedContent.ciphertext, "encryptedContent.ciphertext")),
      decipher.final(),
    ]).toString("utf8");
    return canonicalize(JSON.parse(plaintext) as unknown);
  } catch {
    fail("encryptedContent", "cannot be decrypted or authenticated");
  }
}
