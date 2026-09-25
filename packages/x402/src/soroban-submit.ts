import { createHash } from "node:crypto";

import {
  Address,
  Keypair,
  Operation,
  TransactionBuilder,
  authorizeEntry,
  rpc,
  xdr,
} from "@stellar/stellar-sdk";

const BASE_FEE = "1000000";
const TX_TIMEOUT_SECONDS = 60;
const POLL_INTERVAL_MS = 1000;
const POLL_ATTEMPTS = 30;
const AUTH_VALID_LEDGERS = 60;

export class SorobanSubmitError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.name = "SorobanSubmitError";
    this.code = code;
  }
}

/**
 * Authorize an operation on behalf of a contract account. `signatureFor`
 * receives the whole `HashIdPreimage` (base64 XDR) and returns the account's
 * own signature ScVal — the account decides what that must look like.
 */
export interface ContractAccountAuth {
  readonly account: string;
  readonly signatureFor: (preimageXdr: string) => Promise<xdr.ScVal>;
}

export interface SubmitResult {
  readonly transactionHash: string;
  readonly explorerUrl: string;
  readonly returnValue?: xdr.ScVal;
}

/** The AegisOS account's `AegisAuth::Registry(session_sig)` for `preimage`. */
export function registryAuthScVal(session: Keypair, preimageXdr: string): xdr.ScVal {
  const payload = createHash("sha256").update(Buffer.from(preimageXdr, "base64")).digest();
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol("Registry"),
    xdr.ScVal.scvBytes(Buffer.from(session.sign(payload))),
  ]);
}

async function authorizeFor(
  server: rpc.Server,
  passphrase: string,
  built: ReturnType<TransactionBuilder["build"]>,
  source: Keypair,
  operation: xdr.Operation,
  auth: ContractAccountAuth,
): Promise<xdr.Operation> {
  // Recording simulation tells us which auth entries the call needs.
  const recorded = await server.simulateTransaction(built);
  if (rpc.Api.isSimulationError(recorded)) {
    throw new SorobanSubmitError("SIMULATION_FAILED", recorded.error);
  }
  const latest = await server.getLatestLedger();
  const entries = recorded.result?.auth ?? [];
  const signed: xdr.SorobanAuthorizationEntry[] = [];
  for (const entry of entries) {
    const credentials = entry.credentials();
    if (credentials.switch().name === "sorobanCredentialsSourceAccount") {
      signed.push(entry);
      continue;
    }
    const who = Address.fromScAddress(credentials.address().address()).toString();
    if (who !== auth.account) {
      throw new SorobanSubmitError(
        "UNEXPECTED_SIGNER",
        `Operation needs a signature from ${who}, not only ${auth.account} and ${source.publicKey()}.`,
      );
    }
    signed.push(
      await authorizeEntry(
        entry,
        async (preimage: xdr.HashIdPreimage) =>
          ({ signatureScVal: await auth.signatureFor(preimage.toXDR("base64")) }) as never,
        latest.sequence + AUTH_VALID_LEDGERS,
        passphrase,
      ),
    );
  }
  return Operation.invokeHostFunction({
    func: operation.body().invokeHostFunctionOp().hostFunction(),
    auth: signed,
  });
}

/**
 * Submit one Soroban operation, paid and signed by `source`, and wait for it.
 * With `accountAuth`, entries the contract account must authorize are signed
 * first; the enforcing simulation that follows runs its `__check_auth`, so a
 * refusal surfaces before anything is sent.
 */
export async function submitSorobanOperation(options: {
  readonly server: rpc.Server;
  readonly passphrase: string;
  readonly source: Keypair;
  readonly operation: xdr.Operation;
  readonly accountAuth?: ContractAccountAuth;
}): Promise<SubmitResult> {
  const { server, passphrase, source } = options;
  const build = async (operation: xdr.Operation) =>
    new TransactionBuilder(await server.getAccount(source.publicKey()), {
      fee: BASE_FEE,
      networkPassphrase: passphrase,
    })
      .addOperation(operation)
      .setTimeout(TX_TIMEOUT_SECONDS)
      .build();

  let operation = options.operation;
  if (options.accountAuth !== undefined) {
    operation = await authorizeFor(
      server, passphrase, await build(operation), source, operation, options.accountAuth,
    );
  }

  let prepared;
  try {
    prepared = await server.prepareTransaction(await build(operation));
  } catch (error: unknown) {
    throw new SorobanSubmitError(
      "SIMULATION_FAILED",
      error instanceof Error ? error.message : String(error),
    );
  }
  prepared.sign(source);

  const sent = await server.sendTransaction(prepared);
  if (sent.status === "ERROR") {
    throw new SorobanSubmitError(
      "SUBMIT_FAILED",
      `Submission rejected: ${JSON.stringify(sent.errorResult ?? sent.status)}`,
    );
  }
  const hash = sent.hash;
  for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt += 1) {
    const result = await server.getTransaction(hash);
    if (result.status === "SUCCESS") {
      return {
        transactionHash: hash,
        explorerUrl: `https://stellar.expert/explorer/testnet/tx/${hash}`,
        ...(result.returnValue === undefined ? {} : { returnValue: result.returnValue }),
      };
    }
    if (result.status === "FAILED") {
      throw new SorobanSubmitError("TX_FAILED", `Transaction failed on-chain (tx ${hash}).`);
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  throw new SorobanSubmitError("TX_TIMEOUT", `Transaction not confirmed within timeout (tx ${hash}).`);
}
