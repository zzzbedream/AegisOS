import { fork, type ChildProcess } from "node:child_process";
import { SIGNER_PROTOCOL_VERSION, type SignerRequest, type SignerResponse } from "./protocol.js";
import type { SignerTransport } from "./remote-signer.js";

export interface ForkSignerOptions {
  /** Path to the signer process module. */
  readonly modulePath: string;
  readonly network: string;
  readonly allowedAssets: Readonly<Record<string, string>>;
  readonly allowedNetworkPassphrases: readonly string[];
  /**
   * Path to a file containing the secret. Preferred: the parent passes the
   * path, so the agent process never holds the key bytes.
   */
  readonly secretFile?: string;
  /** Dev-only fallback. The launcher does see the key when this is used. */
  readonly secret?: string;
  readonly execArgv?: readonly string[];
  readonly requestTimeoutMs?: number;
  readonly onAudit?: (line: string) => void;
}

export interface ForkedSigner extends SignerTransport {
  readonly address: string;
  readonly pid: number | undefined;
}

const DEFAULT_TIMEOUT_MS = 15_000;

interface Pending {
  readonly resolve: (value: SignerResponse) => void;
  readonly reject: (reason: Error) => void;
  readonly timer: NodeJS.Timeout;
}

/**
 * Start the signer in its own OS process and return a transport for it.
 *
 * The separation is the product: an agent that reads attacker-controlled
 * content cannot reach the key, because the key is not in its address space.
 */
export async function forkSigner(options: ForkSignerOptions): Promise<ForkedSigner> {
  if (options.secretFile === undefined && options.secret === undefined) {
    throw new Error("forkSigner needs secretFile (preferred) or secret.");
  }

  const child: ChildProcess = fork(options.modulePath, [], {
    execArgv: [...(options.execArgv ?? [])],
    stdio: ["ignore", "inherit", "pipe", "ipc"],
    env: {
      ...process.env,
      AEGIS_SIGNER_ROLE: "signer",
      AEGIS_SIGNER_CONFIG: JSON.stringify({
        network: options.network,
        allowedAssets: options.allowedAssets,
        allowedNetworkPassphrases: options.allowedNetworkPassphrases,
      }),
      ...(options.secretFile === undefined ? {} : { AEGIS_SIGNER_SECRET_FILE: options.secretFile }),
      ...(options.secret === undefined ? {} : { AEGIS_SIGNER_SECRET: options.secret }),
    },
  });

  const pending = new Map<string, Pending>();

  child.stderr?.on("data", (chunk: Buffer) => {
    options.onAudit?.(chunk.toString("utf8").trim());
  });

  const address = await new Promise<string>((resolve, reject) => {
    const onReady = (message: unknown): void => {
      if (
        typeof message === "object" &&
        message !== null &&
        (message as { kind?: unknown }).kind === "ready"
      ) {
        child.off("message", onReady);
        resolve(String((message as { address?: unknown }).address ?? ""));
      }
    };
    child.on("message", onReady);
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`Signer process exited early (code ${code}).`)));
  });

  child.on("message", (message: unknown) => {
    if (typeof message !== "object" || message === null) return;
    const id = (message as { id?: unknown }).id;
    if (typeof id !== "string") return;
    const waiting = pending.get(id);
    if (waiting === undefined) return;
    pending.delete(id);
    clearTimeout(waiting.timer);
    waiting.resolve(message as SignerResponse);
  });

  return {
    address,
    pid: child.pid,
    async request(message: SignerRequest): Promise<SignerResponse> {
      return new Promise<SignerResponse>((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(message.id);
          reject(new Error(`Signer request ${message.id} timed out.`));
        }, options.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS);
        pending.set(message.id, { resolve, reject, timer });
        child.send(message, (error) => {
          if (error) {
            pending.delete(message.id);
            clearTimeout(timer);
            reject(error);
          }
        });
      });
    },
    async close(): Promise<void> {
      for (const [, waiting] of pending) clearTimeout(waiting.timer);
      pending.clear();
      await new Promise<void>((resolve) => {
        child.once("exit", () => resolve());
        child.kill();
      });
    },
  };
}

export const SIGNER_READY_PROTOCOL = SIGNER_PROTOCOL_VERSION;
