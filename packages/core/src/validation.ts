import { assertCondition, fail } from "./errors.js";

export type UnknownRecord = Record<string, unknown>;

export function asRecord(value: unknown, path: string): UnknownRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(path, "must be an object");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail(path, "must be a plain object");
  }
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor)) {
      fail(`${path}.${key}`, "accessor properties are not allowed");
    }
  }
  return value as UnknownRecord;
}

export function exactKeys(
  record: UnknownRecord,
  required: readonly string[],
  optional: readonly string[],
  path: string,
): void {
  const known = new Set([...required, ...optional]);
  for (const key of Object.keys(record)) {
    if (!known.has(key)) {
      fail(`${path}.${key}`, "is not an allowed property");
    }
  }
  for (const key of required) {
    if (!(key in record)) {
      fail(`${path}.${key}`, "is required");
    }
  }
}

export function requiredString(value: unknown, path: string, options: { readonly min?: number; readonly max?: number; readonly pattern?: RegExp } = {}): string {
  if (typeof value !== "string") {
    fail(path, "must be a string");
  }
  const min = options.min ?? 1;
  const max = options.max ?? 4_096;
  if (value.length < min || value.length > max) {
    fail(path, `must have between ${min} and ${max} characters`);
  }
  if (options.pattern !== undefined && !options.pattern.test(value)) {
    fail(path, "has an invalid format");
  }
  return value;
}

export function optionalString(value: unknown, path: string, options: { readonly min?: number; readonly max?: number; readonly pattern?: RegExp } = {}): string | undefined {
  if (value === undefined) return undefined;
  return requiredString(value, path, options);
}

export function requiredBoolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") {
    fail(path, "must be a boolean");
  }
  return value;
}

export function requiredInteger(value: unknown, path: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    fail(path, `must be an integer from ${min} to ${max}`);
  }
  return value;
}

export function requiredArray(value: unknown, path: string, min = 0, max = 1_024): readonly unknown[] {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    fail(path, `must be an array with ${min} to ${max} entries`);
  }
  return value;
}

export const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
export const HASH_PATTERN = /^[a-f0-9]{64}$/;
export const ATOMIC_PATTERN = /^(0|[1-9][0-9]{0,77})$/;
export const ADDRESS_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{1,255}$/;

export function requiredId(value: unknown, path: string): string {
  return requiredString(value, path, { max: 128, pattern: ID_PATTERN });
}

export function requiredHash(value: unknown, path: string): string {
  return requiredString(value, path, { min: 64, max: 64, pattern: HASH_PATTERN });
}

export function requiredAtomic(value: unknown, path: string, nonZero = false): string {
  const atomic = requiredString(value, path, { max: 78, pattern: ATOMIC_PATTERN });
  if (nonZero && atomic === "0") {
    fail(path, "must be greater than zero");
  }
  return atomic;
}

export function atomicBigInt(value: string): bigint {
  return BigInt(value);
}

export function requiredAddress(value: unknown, path: string): string {
  return requiredString(value, path, { min: 2, max: 256, pattern: ADDRESS_PATTERN });
}

const ISO_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function requiredIsoTimestamp(value: unknown, path: string): string {
  const timestamp = requiredString(value, path, { min: 24, max: 24, pattern: ISO_UTC_PATTERN });
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== timestamp) {
    fail(path, "must be a canonical UTC ISO timestamp");
  }
  return timestamp;
}

export function assertUnique(values: readonly string[], path: string): void {
  assertCondition(new Set(values).size === values.length, path, "must not contain duplicates");
}
