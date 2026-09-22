/** A deterministic, path-aware error used by every public runtime validator. */
export class AegisValidationError extends Error {
  public readonly path: string;

  public constructor(path: string, message: string) {
    super(`${path}: ${message}`);
    this.name = "AegisValidationError";
    this.path = path;
  }
}

export function fail(path: string, message: string): never {
  throw new AegisValidationError(path, message);
}

export function assertCondition(condition: unknown, path: string, message: string): asserts condition {
  if (!condition) {
    fail(path, message);
  }
}
