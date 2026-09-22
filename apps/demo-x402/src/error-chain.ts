/**
 * Render an error the way a fatal handler should: message first, then the
 * chain of `cause` that explains it — one `caused by:` line per level,
 * indented one step deeper than its parent.
 *
 * Node puts the real reason for network failures in `error.cause`
 * (ECONNREFUSED, ENOTFOUND, TLS…). Printing only `error.message` discards it
 * and leaves a bare "fetch failed" with nothing to diagnose from.
 *
 * The walk is iterative and bounded: a self-referencing cause
 * (`error.cause = error`) terminates with a `[cycle …]` marker instead of
 * recursing forever.
 */
export function describeErrorChain(error: unknown, maxDepth = 16): string {
  const lines: string[] = [];
  const seen = new Set<unknown>();
  let current: unknown = error;

  for (let depth = 0; depth <= maxDepth; depth += 1) {
    const indent = "  ".repeat(depth);
    const entry = depth === 0 ? "" : `${indent}caused by: `;

    if (current === undefined || current === null) {
      // depth 0: the thrown value itself IS undefined — render it.
      // deeper: a missing `cause` ends the chain, it is not a line of its own.
      if (depth === 0) lines.push(String(current));
      break;
    }
    if (seen.has(current)) {
      lines.push(`${entry}[cycle ${describeValue(current)}]`);
      break;
    }
    seen.add(current);

    if (current instanceof Error) {
      lines.push(`${entry}${current.name}: ${current.message}`);
      current = current.cause;
    } else {
      lines.push(`${entry}${describeValue(current)}`);
      break;
    }
  }

  if (lines.length === 0) lines.push(String(error));
  return lines.join("\n");
}

function describeValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "object") {
    try {
      return JSON.stringify(value) ?? String(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}
