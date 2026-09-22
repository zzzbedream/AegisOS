import { createHash } from "node:crypto";

/** A small canonical JSON encoder used for hashes and deterministic receipts. */
export function canonicalStringify(value: unknown): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError("Canonical values cannot contain non-finite numbers");
      }
      return JSON.stringify(value);
    case "bigint":
    case "undefined":
    case "function":
    case "symbol":
      throw new TypeError("Canonical values must be JSON data");
    case "object":
      break;
    default:
      throw new TypeError("Unsupported canonical value");
  }

  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalStringify(entry)).join(",")}]`;
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("Canonical objects must be plain objects");
  }

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalStringify(record[key])}`)
    .join(",")}}`;
}

export function sha256Canonical(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalStringify(value)).digest("hex")}`;
}

export function hashToUInt(hash: string, minimum: number, spread: number): number {
  const hex = hash.startsWith("sha256:") ? hash.slice("sha256:".length) : hash;
  const prefix = Number.parseInt(hex.slice(0, 8), 16);
  return minimum + (prefix % spread);
}
