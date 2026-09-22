import { AegisValidationError, fail } from "./errors.js";

/** Values that may safely enter hashes, signatures, or the audit ledger. */
export type CanonicalValue =
  | null
  | boolean
  | number
  | string
  | readonly CanonicalValue[]
  | { readonly [key: string]: CanonicalValue };

function isPlainRecord(value: object): value is Record<string, unknown> {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Recursively validates JSON data and returns a detached, key-sorted copy.
 * It intentionally rejects Date, Buffer, bigint, sparse arrays, accessors,
 * non-finite numbers and class instances: all are ambiguous at a signature
 * boundary.
 */
export function canonicalize(value: unknown, path = "$", seen = new WeakSet<object>()): CanonicalValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail(path, "must be a finite number");
    }
    // JSON has one representation for signed zero. Normalize before hashing.
    return Object.is(value, -0) ? 0 : value;
  }

  if (Array.isArray(value)) {
    if (seen.has(value)) {
      fail(path, "must not contain a cycle");
    }
    seen.add(value);
    const result: CanonicalValue[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) {
        fail(`${path}[${index}]`, "sparse arrays are not canonical");
      }
      result.push(canonicalize(value[index], `${path}[${index}]`, seen));
    }
    seen.delete(value);
    return result;
  }

  if (typeof value === "object") {
    if (!isPlainRecord(value)) {
      fail(path, "must be a plain JSON object");
    }
    if (seen.has(value)) {
      fail(path, "must not contain a cycle");
    }
    seen.add(value);
    const result: Record<string, CanonicalValue> = {};
    for (const key of Object.keys(value).sort()) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || "get" in descriptor || "set" in descriptor) {
        fail(`${path}.${key}`, "accessor properties are not canonical");
      }
      Object.defineProperty(result, key, {
        configurable: true,
        enumerable: true,
        value: canonicalize(descriptor.value, `${path}.${key}`, seen),
        writable: false,
      });
    }
    seen.delete(value);
    return result;
  }

  fail(path, `unsupported canonical value type ${typeof value}`);
}

function stringifyCanonical(value: CanonicalValue): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object":
      if (Array.isArray(value)) {
        return `[${value.map(stringifyCanonical).join(",")}]`;
      }
      const record = value as { readonly [key: string]: CanonicalValue };
      return `{${Object.keys(record)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${stringifyCanonical(record[key] as CanonicalValue)}`)
        .join(",")}}`;
    default:
      throw new AegisValidationError("$", "unreachable canonical value");
  }
}

/** Stable JSON serialization used everywhere Aegis hashes or signs data. */
export function canonicalJson(value: unknown): string {
  return stringifyCanonical(canonicalize(value));
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(value));
}

export function parseCanonicalJson(value: string): CanonicalValue {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    fail("$", "must contain valid JSON");
  }
  const canonical = canonicalize(parsed);
  if (stringifyCanonical(canonical) !== value) {
    fail("$", "JSON is not in canonical form");
  }
  return canonical;
}
