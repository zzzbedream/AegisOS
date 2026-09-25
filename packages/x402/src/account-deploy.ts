import { createHash, randomBytes } from "node:crypto";

import {
  Address,
  Contract,
  Keypair,
  Operation,
  TransactionBuilder,
  rpc,
  scValToNative,
  xdr,
} from "@stellar/stellar-sdk";

import { submitSorobanOperation } from "./soroban-submit.js";

/** Mirrors `Config` in `contracts/aegis-account`. Keys are raw ed25519. */
export interface AccountConfigV1 {
  readonly owner: Buffer;
  readonly authority: Buffer;
  readonly session: Buffer;
  readonly allowedAssets: readonly string[];
  readonly registry?: string;
}

export interface AccountHead {
  readonly seq: bigint;
  /** Bare 64-hex. */
  readonly chainHead: string;
}

function field(key: string, val: xdr.ScVal): xdr.ScMapEntry {
  return new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val });
}

function raw32(value: Buffer, label: string): xdr.ScVal {
  if (value.length !== 32) throw new Error(`${label} must be a raw 32-byte ed25519 key.`);
  return xdr.ScVal.scvBytes(value);
}

/** `Config` as the constructor expects it. Map keys sorted; `None` is void. */
export function accountConfigScVal(config: AccountConfigV1): xdr.ScVal {
  return xdr.ScVal.scvMap([
    field("allowed_assets", xdr.ScVal.scvVec(config.allowedAssets.map((a) => new Address(a).toScVal()))),
    field("authority", raw32(config.authority, "authority")),
    field("owner", raw32(config.owner, "owner")),
    field("registry", config.registry === undefined ? xdr.ScVal.scvVoid() : new Address(config.registry).toScVal()),
    field("session", raw32(config.session, "session")),
  ]);
}

/** Raw ed25519 key from a base64url SPKI DER public key (our key-pair files). */
export function rawFromSpki(spkiBase64Url: string): Buffer {
  return Buffer.from(spkiBase64Url, "base64url").subarray(-32);
}

export function wasmHashOf(wasm: Buffer): string {
  return createHash("sha256").update(wasm).digest("hex");
}

/** Upload the account wasm unless the network already has it. */
export async function uploadWasm(
  server: rpc.Server,
  passphrase: string,
  source: Keypair,
  wasm: Buffer,
): Promise<string> {
  const hash = wasmHashOf(wasm);
  const key = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: Buffer.from(hash, "hex") }));
  const existing = await server.getLedgerEntries(key);
  if (existing.entries.length === 0) {
    await submitSorobanOperation({ server, passphrase, source, operation: Operation.uploadContractWasm({ wasm }) });
  }
  return hash;
}

/** Deploy an account instance from an uploaded wasm; returns its `C…` address. */
export async function deployAccount(
  server: rpc.Server,
  passphrase: string,
  source: Keypair,
  wasmHash: string,
  config: AccountConfigV1,
): Promise<{ readonly address: string; readonly transactionHash: string }> {
  const result = await submitSorobanOperation({
    server,
    passphrase,
    source,
    operation: Operation.createCustomContract({
      address: new Address(source.publicKey()),
      wasmHash: Buffer.from(wasmHash, "hex"),
      salt: randomBytes(32),
      constructorArgs: [accountConfigScVal(config)],
    }),
  });
  if (result.returnValue === undefined) throw new Error("Deploy returned no contract address.");
  return { address: Address.fromScVal(result.returnValue).toString(), transactionHash: result.transactionHash };
}

/** Keep instance and code alive. Permissionless; kept off the payment path. */
export async function extendAccountTtl(
  server: rpc.Server,
  passphrase: string,
  source: Keypair,
  account: string,
): Promise<void> {
  await submitSorobanOperation({ server, passphrase, source, operation: new Contract(account).call("extend_ttl") });
}

/** Read `head()` by simulation. `reader` is any existing account; no secret. */
export async function readAccountHead(
  server: rpc.Server,
  passphrase: string,
  account: string,
  reader: string,
): Promise<AccountHead> {
  const tx = new TransactionBuilder(await server.getAccount(reader), { fee: "100", networkPassphrase: passphrase })
    .addOperation(new Contract(account).call("head"))
    .setTimeout(30)
    .build();
  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim) || sim.result === undefined) {
    throw new Error(`Cannot read head of ${account}.`);
  }
  const native = scValToNative(sim.result.retval) as { seq: bigint | number; chain_head: Uint8Array };
  return { seq: BigInt(native.seq), chainHead: Buffer.from(native.chain_head).toString("hex") };
}

/** Wasm hash an account actually runs, read from its instance. */
export async function deployedWasmHash(server: rpc.Server, account: string): Promise<string> {
  const key = xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(account).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );
  const { entries } = await server.getLedgerEntries(key);
  const entry = entries[0];
  if (entry === undefined) throw new Error(`No contract instance at ${account}.`);
  const executable = entry.val.contractData().val().instance().executable();
  return Buffer.from(executable.wasmHash()).toString("hex");
}
