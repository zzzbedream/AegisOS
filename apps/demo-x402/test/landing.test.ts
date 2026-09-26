import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

/**
 * The landing page is evidence for a jury. Every hash, address and key it
 * shows must come from the published evidence or deployments, and every check
 * or error name it quotes must exist in the code that produces it.
 */
const root = fileURLToPath(new URL("../../../", import.meta.url));
const html = readFileSync(join(root, "site/index.html"), "utf8");

function filesUnder(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? filesUnder(path) : [path];
  });
}

/** Every string value inside the published evidence and deployments. */
function knownValues(): Set<string> {
  const out = new Set<string>();
  const walk = (value: unknown): void => {
    if (typeof value === "string") {
      out.add(value);
      // Proven HTTP responses and claim contexts nest JSON and base64 inside strings.
      for (const m of value.matchAll(/[A-Za-z0-9+/=]{40,}/g)) {
        try {
          out.add(Buffer.from(m[0], "base64").toString("utf8"));
        } catch {
          // not base64
        }
      }
    } else if (Array.isArray(value)) value.forEach(walk);
    else if (value !== null && typeof value === "object") Object.values(value).forEach(walk);
  };
  const sources = [
    ...filesUnder(join(root, "docs/evidence")).filter((f) => f.endsWith(".json")),
    join(root, "contracts/deployments/testnet.json"),
  ];
  for (const file of sources) walk(JSON.parse(readFileSync(file, "utf8")) as unknown);
  return out;
}

const known = [...knownValues()].join("\n");
const text = html.replace(/<[^>]+>/g, " ");

test("every full hash, address and key on the landing comes from the published evidence", () => {
  const patterns = [
    /\b[0-9a-f]{64}\b/g, // tx hashes, commitments, content hashes, roots
    /\b0x[0-9a-f]{40,64}\b/g, // Reclaim witness and claim id
    /\b[GC][A-Z2-7]{55}\b/g, // Stellar accounts and contracts
    /ed25519:[0-9a-f]{24}/g, // attester key id
  ];
  const found = new Set(patterns.flatMap((p) => [...html.matchAll(p)].map((m) => m[0])));
  assert.ok(found.size >= 15, `expected many identifiers, found ${String(found.size)}`);
  const unknown = [...found].filter((value) => !known.includes(value.replace(/^ed25519:/, "")));
  assert.deepEqual(unknown, [], "identifiers not backed by docs/evidence or deployments");
});

test("every shortened identifier expands to a real one", () => {
  const shortened = [...text.matchAll(/\b([0-9a-zA-Z]{4,})…([0-9a-zA-Z]{4})\b/g)];
  assert.ok(shortened.length > 0);
  const values = known.split(/[^0-9a-zA-Z]+/);
  for (const [whole, head, tail] of shortened) {
    const expands = values.some((v) => v.length > head.length + tail.length && v.startsWith(head) && v.endsWith(tail));
    assert.ok(expands, `${whole} does not shorten any published value`);
  }
});

test("the verification output shown is the real verifier's check list", () => {
  const sources = ["receipt-check.ts", "notarization.ts", "content-proof.ts", "verify-receipt.ts"]
    .map((f) => readFileSync(join(root, "apps/demo-x402/src", f), "utf8"))
    .join("\n");
  const shown = [...html.matchAll(/<span class="p">PASS<\/span>([^<]+)</g)].map((m) => (m[1] ?? "").split(" — ")[0]?.trim() ?? "");
  assert.equal(shown.length, 16, "the published receipt runs 16 checks");
  for (const name of shown) {
    const decoded = name.replace(/&#39;|&apos;/g, "'");
    assert.ok(sources.includes(`"${decoded}"`), `"${decoded}" is not a check name in the verifier`);
  }
});

test("every refusal code quoted exists in the code that raises it", () => {
  const code = [
    ...filesUnder(join(root, "packages")).filter((f) => f.endsWith(".ts") && !f.includes("node_modules")),
    ...filesUnder(join(root, "contracts/aegis-proof/src")),
  ]
    .map((f) => readFileSync(f, "utf8"))
    .join("\n");
  for (const name of [
    "COMMITMENT_POLICY_DENIED",
    "COMMITMENT_KEY_UNTRUSTED",
    "AMOUNT_EXCEEDS_COMMITMENT",
    "TAINTED_PROVENANCE_REQUIRES_OWNER",
    "RangeNotAtHead",
    "UnknownAccount",
  ]) {
    assert.ok(html.includes(name), `${name} expected on the page`);
    assert.ok(code.includes(name), `${name} not found in the code`);
  }
  assert.match(code, /RangeNotAtHead = 12/);
  assert.match(code, /UnknownAccount = 8/);
});
