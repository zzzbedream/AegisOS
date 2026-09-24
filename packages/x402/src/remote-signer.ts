import type { PurchaseCommitmentV1 } from "../../proof/src/index.js";
import {
  SIGNER_PROTOCOL_VERSION,
  SignerDeniedError,
  type SignerRequest,
  type SignerResponse,
} from "./protocol.js";

/** How the agent reaches the signer. In production: another process. */
export interface SignerTransport {
  request(message: SignerRequest): Promise<SignerResponse>;
  close?(): Promise<void>;
}

/**
 * SEP-43 client signer shape, as `ExactStellarScheme` consumes it.
 *
 * Three members — `address`, `signAuthEntry`, and optionally
 * `signTransaction` — and the scheme accepts any structural object. That is
 * what makes real key isolation cheap here rather than a rewrite.
 */
export interface ClientStellarSignerLike {
  readonly address: string;
  signAuthEntry(
    authEntry: string,
    opts?: { networkPassphrase?: string; address?: string },
  ): Promise<{ signedAuthEntry: string; signerAddress?: string }>;
}

export interface RemoteSignerOptions {
  readonly transport: SignerTransport;
  /**
   * A signer proxy is bound to ONE purchase. SEP-43 has no slot for intent, so
   * scoping it at construction is what keeps a single approval from becoming a
   * general-purpose signing oracle.
   */
  readonly commitment: PurchaseCommitmentV1;
  readonly idFactory?: () => string;
}

let counter = 0;
const defaultIdFactory = (): string => `sig-req:${Date.now()}:${(counter += 1)}`;

/**
 * Build a signer the agent can hold safely: it carries no key material, only
 * a channel. Every call is a typed request the signer is free to refuse.
 */
export async function createRemoteSigner(
  options: RemoteSignerOptions,
): Promise<ClientStellarSignerLike> {
  const newId = options.idFactory ?? defaultIdFactory;

  const send = async (message: SignerRequest): Promise<string> => {
    const response = await options.transport.request(message);
    if (response.kind === "denied") {
      throw new SignerDeniedError(response.code, response.message);
    }
    return response.value;
  };

  const address = await send({
    protocol: SIGNER_PROTOCOL_VERSION,
    id: newId(),
    kind: "get_address",
  });

  return Object.freeze({
    address,
    async signAuthEntry(
      authEntry: string,
      opts?: { networkPassphrase?: string; address?: string },
    ): Promise<{ signedAuthEntry: string; signerAddress?: string }> {
      const signedAuthEntry = await send({
        protocol: SIGNER_PROTOCOL_VERSION,
        id: newId(),
        kind: "sign_auth_entry",
        authEntryXdr: authEntry,
        ...(opts?.networkPassphrase === undefined
          ? {}
          : { networkPassphrase: opts.networkPassphrase }),
        ...(opts?.address === undefined ? {} : { address: opts.address }),
        commitment: options.commitment,
      });
      return { signedAuthEntry, signerAddress: address };
    },
  });
}

/** In-process transport. For tests and for exercising policy without a fork. */
export function inProcessTransport(handler: {
  handle(raw: unknown): Promise<SignerResponse>;
}): SignerTransport {
  return {
    async request(message: SignerRequest): Promise<SignerResponse> {
      // Round-trip through JSON so the in-process path cannot accidentally
      // share references the real IPC boundary would have severed.
      return handler.handle(JSON.parse(JSON.stringify(message)) as unknown);
    },
  };
}
