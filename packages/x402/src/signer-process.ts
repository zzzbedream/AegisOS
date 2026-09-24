import { readFileSync } from "node:fs";
import { IsolatedSignerService, type Caip2Network } from "./signer-service.js";
import { SIGNER_PROTOCOL_VERSION } from "./protocol.js";

/**
 * Entry point for the signer process.
 *
 * Launched with `fork()`, it reads its own key and never returns it. The
 * parent — the agent — speaks to it only through the typed request union.
 *
 * Key provisioning, in order of preference:
 *   AEGIS_SIGNER_SECRET_FILE  the parent passes a PATH, never the secret, so
 *                             the agent process never holds the bytes
 *   AEGIS_SIGNER_SECRET       dev convenience; the launcher does see the key
 */
export function readSignerSecret(env: NodeJS.ProcessEnv = process.env): string {
  const file = env["AEGIS_SIGNER_SECRET_FILE"];
  if (file !== undefined && file.length > 0) {
    const secret = readFileSync(file, "utf8").trim();
    if (secret.length === 0) {
      throw new Error("AEGIS_SIGNER_SECRET_FILE is empty.");
    }
    return secret;
  }
  const inline = env["AEGIS_SIGNER_SECRET"];
  if (inline !== undefined && inline.length > 0) {
    return inline;
  }
  throw new Error("No signer secret: set AEGIS_SIGNER_SECRET_FILE or AEGIS_SIGNER_SECRET.");
}

export interface SignerProcessConfig {
  readonly network: Caip2Network;
  readonly allowedAssets: Readonly<Record<string, string>>;
  readonly allowedNetworkPassphrases: readonly string[];
  readonly trustedCommitmentKeys: Readonly<Record<string, string>>;
}

export function readSignerConfig(env: NodeJS.ProcessEnv = process.env): SignerProcessConfig {
  const raw = env["AEGIS_SIGNER_CONFIG"];
  if (raw === undefined || raw.length === 0) {
    throw new Error("AEGIS_SIGNER_CONFIG is required.");
  }
  const parsed: unknown = JSON.parse(raw);
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("AEGIS_SIGNER_CONFIG must be an object.");
  }
  const config = parsed as Partial<SignerProcessConfig>;
  if (
    typeof config.network !== "string" ||
    typeof config.allowedAssets !== "object" ||
    config.allowedAssets === null ||
    !Array.isArray(config.allowedNetworkPassphrases) ||
    typeof config.trustedCommitmentKeys !== "object" ||
    config.trustedCommitmentKeys === null ||
    Object.keys(config.trustedCommitmentKeys).length === 0 ||
    !Object.values(config.trustedCommitmentKeys).every(
      (key) => typeof key === "string" && key.length > 0,
    )
  ) {
    throw new Error("AEGIS_SIGNER_CONFIG is incomplete.");
  }
  return {
    network: config.network as Caip2Network,
    allowedAssets: config.allowedAssets,
    allowedNetworkPassphrases: config.allowedNetworkPassphrases,
    trustedCommitmentKeys: config.trustedCommitmentKeys,
  };
}

export function startSignerProcess(): void {
  if (typeof process.send !== "function") {
    throw new Error("Signer process must be started with fork().");
  }

  const service = new IsolatedSignerService({
    privateKey: readSignerSecret(),
    ...readSignerConfig(),
    // Decisions go to stderr so the parent can show them without them ever
    // being part of the reply payload.
    onDecision: (entry) => {
      process.stderr.write(`${JSON.stringify({ signerAudit: entry })}\n`);
    },
  });

  process.on("message", (raw: unknown) => {
    void service.handle(raw).then((response) => {
      process.send?.(response);
    });
  });

  process.send({ protocol: SIGNER_PROTOCOL_VERSION, kind: "ready", address: service.address });
}

// Only auto-start when actually forked as the signer, never on import.
if (process.env["AEGIS_SIGNER_ROLE"] === "signer" && typeof process.send === "function") {
  startSignerProcess();
}
