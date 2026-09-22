import { createEd25519Signer } from "@x402/stellar";
import { assertSignableTransfer, type DecodedTransfer, type SignerGuardConfig } from "./guard.js";
import {
  SIGNER_PROTOCOL_VERSION,
  SignerDeniedError,
  parseSignerRequest,
  type SignerResponse,
} from "./protocol.js";

/** CAIP-2 network identifier, e.g. "stellar:testnet". */
export type Caip2Network = `${string}:${string}`;

export interface IsolatedSignerOptions {
  /** Read from the environment of the SIGNER process only. */
  readonly privateKey: string;
  readonly network: Caip2Network;
  readonly allowedAssets: Readonly<Record<string, string>>;
  readonly allowedNetworkPassphrases: readonly string[];
  readonly now?: () => Date;
  /** Audit sink. Every decision is recorded, including the denials. */
  readonly onDecision?: (entry: SignerAuditEntry) => void;
}

export interface SignerAuditEntry {
  readonly at: string;
  readonly requestId: string;
  readonly kind: string;
  readonly decision: "ok" | "denied";
  readonly code?: string;
  readonly transfer?: DecodedTransfer;
}

interface Ed25519SignerLike {
  readonly address: string;
  signAuthEntry(
    authEntry: string,
    opts?: { networkPassphrase?: string; address?: string },
  ): Promise<{ signedAuthEntry: string }>;
}

/**
 * Holds the key and decides what it will sign.
 *
 * Runs in its own process in production, but is a plain class so the policy
 * can be tested without spawning anything.
 */
export class IsolatedSignerService {
  readonly #signer: Ed25519SignerLike;
  readonly #guard: SignerGuardConfig;
  readonly #onDecision: (entry: SignerAuditEntry) => void;
  readonly #now: () => Date;

  public constructor(options: IsolatedSignerOptions) {
    this.#signer = createEd25519Signer(options.privateKey, options.network) as Ed25519SignerLike;
    this.#now = options.now ?? ((): Date => new Date());
    this.#guard = {
      allowedAssets: options.allowedAssets,
      allowedNetworkPassphrases: options.allowedNetworkPassphrases,
      signerAddress: this.#signer.address,
      now: this.#now,
    };
    this.#onDecision = options.onDecision ?? ((): void => {});
  }

  public get address(): string {
    return this.#signer.address;
  }

  public async handle(raw: unknown): Promise<SignerResponse> {
    let requestId = "unknown";
    let kind = "unknown";
    try {
      const request = parseSignerRequest(raw);
      requestId = request.id;
      kind = request.kind;

      if (request.kind === "get_address") {
        this.#record({ requestId, kind, decision: "ok" });
        return this.#ok(requestId, this.#signer.address);
      }

      const transfer = assertSignableTransfer(
        request.authEntryXdr,
        request.commitment,
        request.buyerPublicKey,
        this.#guard,
        request.networkPassphrase,
      );

      let signed: { readonly signedAuthEntry: string };
      try {
        signed = await this.#signer.signAuthEntry(request.authEntryXdr, {
          ...(request.networkPassphrase === undefined
            ? {}
            : { networkPassphrase: request.networkPassphrase }),
          ...(request.address === undefined ? {} : { address: request.address }),
        });
      } catch (error: unknown) {
        throw new SignerDeniedError(
          "SIGNING_FAILED",
          error instanceof Error ? error.message : "Signing failed.",
        );
      }

      this.#record({ requestId, kind, decision: "ok", transfer });
      return this.#ok(requestId, signed.signedAuthEntry);
    } catch (error: unknown) {
      const denied =
        error instanceof SignerDeniedError
          ? error
          : new SignerDeniedError(
              "MALFORMED_REQUEST",
              error instanceof Error ? error.message : "Unhandled signer error.",
            );
      this.#record({ requestId, kind, decision: "denied", code: denied.code });
      return {
        protocol: SIGNER_PROTOCOL_VERSION,
        id: requestId,
        kind: "denied",
        code: denied.code,
        message: denied.message,
      };
    }
  }

  #ok(id: string, value: string): SignerResponse {
    return { protocol: SIGNER_PROTOCOL_VERSION, id, kind: "ok", value };
  }

  #record(entry: Omit<SignerAuditEntry, "at">): void {
    this.#onDecision({ at: this.#now().toISOString(), ...entry });
  }
}
