/**
 * Guarantee D at purchase time: send the paid request through a Reclaim
 * attestor, so the seller's answer arrives with a proof that it came over TLS
 * from the seller's host.
 *
 * The payment signature travels in the private headers: the attestor proves
 * the response without the proof revealing it. The whole response — status
 * line, headers and body — is captured into the signed claim, so the seller's
 * PAYMENT-RESPONSE (its settlement) is proven along with the content. The
 * proof's context names the purchase commitment, so it cannot back another.
 *
 * One attempt only: a retry would resend a payment the seller has already
 * settled. Credentials come from the environment and are never logged.
 */
import { ReclaimClient } from "@reclaimprotocol/zk-fetch";

import type { PaidFetch } from "./agent.js";
import { provenResponse, type ReclaimProofV1 } from "./content-proof.js";

const NO_CONTEXT_ADDRESS = "0x0000000000000000000000000000000000000000";
const WHOLE_RESPONSE = "(?<body>[\\s\\S]*)";
const SINGLE_ATTEMPT = 1;

export interface ReclaimCredentials {
  readonly appId: string;
  readonly appSecret: string;
}

export function reclaimCredentialsFromEnv(): ReclaimCredentials | undefined {
  const appId = process.env["AEGIS_RECLAIM_APP_ID"];
  const appSecret = process.env["AEGIS_RECLAIM_APP_SECRET"];
  if (appId === undefined || appId.length === 0 || appSecret === undefined || appSecret.length === 0) {
    return undefined;
  }
  return { appId, appSecret };
}

/** The one zkFetch call this module makes; injectable for tests. */
export interface ZkFetcher {
  zkFetch(
    url: string,
    options: { method: string; context: { contextAddress: string; contextMessage: string } },
    secretOptions: { headers: Record<string, string>; responseMatches: { type: "regex"; value: string }[] },
    retries: number,
  ): Promise<unknown>;
}

export function reclaimPaidFetch(
  credentials: ReclaimCredentials,
  client: ZkFetcher = new ReclaimClient(credentials.appId, credentials.appSecret, false, SINGLE_ATTEMPT),
): PaidFetch {
  return async (url, paymentHeaders, commitmentHash) => {
    const proof = (await client.zkFetch(
      url,
      { method: "GET", context: { contextAddress: NO_CONTEXT_ADDRESS, contextMessage: commitmentHash } },
      { headers: { ...paymentHeaders }, responseMatches: [{ type: "regex", value: WHOLE_RESPONSE }] },
      SINGLE_ATTEMPT,
    )) as ReclaimProofV1 | undefined;
    if (proof === undefined) throw new Error("Reclaim returned no proof for the paid request.");
    const response = provenResponse(proof);
    if (response === undefined) throw new Error("The Reclaim proof carries no HTTP response.");
    return {
      ok: response.status >= 200 && response.status < 300,
      header: response.header,
      body: new TextEncoder().encode(response.body),
      contentProof: { kind: "reclaim-zkfetch-v1", proof },
    };
  };
}
