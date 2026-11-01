/**
 * The ledger entries the public evidence depends on, and which of them need rent.
 *
 * Soroban archives a persistent entry when its TTL runs out. Nothing breaks loudly:
 * the next payment restores it automatically, its simulated fee jumps to millions of
 * stroops, and the facilitator answers 402 `fee_exceeds_maximum`. Reads of an archived
 * range make `verify:receipt` fail. This module lists the entries to keep alive:
 * the registry and account instances, their wasm, the account's USDC balance, and the
 * registry records that published receipts point at.
 */
import { Address, xdr } from "@stellar/stellar-sdk";

export const USDC_SAC = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const DAY_IN_LEDGERS = 17_280;
/** Extend whatever expires within this window... */
export const KEEPALIVE_THRESHOLD_LEDGERS = 30 * DAY_IN_LEDGERS;
/** ...to this far ahead. Below testnet's max entry TTL. */
export const KEEPALIVE_EXTEND_TO_LEDGERS = 60 * DAY_IN_LEDGERS;

export interface KeptEntry {
  readonly label: string;
  readonly key: xdr.LedgerKey;
}

export interface KeepaliveSources {
  readonly registry: { readonly contractId: string; readonly wasmHash: string };
  readonly account: { readonly address: string; readonly wasmHash: string };
  /** `range` blocks of the published receipts. */
  readonly ranges: readonly { readonly contractId: string; readonly account: string; readonly fromSeq: string }[];
  /** Sellers counted by the registry in published receipts. */
  readonly sellers: readonly string[];
}

export type TtlAction = "ok" | "extend" | "restore";

function instanceKey(contractId: string): xdr.LedgerKey {
  return xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );
}

function codeKey(wasmHash: string): xdr.LedgerKey {
  return xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: Buffer.from(wasmHash, "hex") }));
}

/** A `#[contracttype]` enum variant is a vec: its name, then its fields. */
function dataKey(contractId: string, variant: string, fields: readonly xdr.ScVal[]): xdr.LedgerKey {
  return xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(variant), ...fields]),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );
}

const address = (value: string): xdr.ScVal => new Address(value).toScVal();

export function keepaliveEntries(sources: KeepaliveSources): readonly KeptEntry[] {
  const { registry, account } = sources;
  const entries: KeptEntry[] = [
    { label: "registry instance", key: instanceKey(registry.contractId) },
    { label: "registry wasm", key: codeKey(registry.wasmHash) },
    { label: "account instance", key: instanceKey(account.address) },
    { label: "account wasm", key: codeKey(account.wasmHash) },
    { label: "account USDC balance", key: dataKey(USDC_SAC, "Balance", [address(account.address)]) },
    { label: "registry Account(account)", key: dataKey(registry.contractId, "Account", [address(account.address)]) },
    { label: "registry Checkpoint(account)", key: dataKey(registry.contractId, "Checkpoint", [address(account.address)]) },
  ];
  const ranges = new Set<string>();
  for (const range of sources.ranges) {
    const id = `${range.contractId}:${range.account}:${range.fromSeq}`;
    if (range.contractId !== registry.contractId || ranges.has(id)) continue;
    ranges.add(id);
    entries.push({
      label: `registry Range(${range.account.slice(0, 8)}…, ${range.fromSeq})`,
      key: dataKey(registry.contractId, "Range", [address(range.account), xdr.ScVal.scvU64(new xdr.Uint64(BigInt(range.fromSeq)))]),
    });
  }
  for (const seller of new Set(sources.sellers)) {
    entries.push({ label: `registry SellerScore(${seller.slice(0, 8)}…)`, key: dataKey(registry.contractId, "SellerScore", [address(seller)]) });
  }
  return entries;
}

/** `liveUntil` undefined means the entry was not found: archived or never written. */
export function ttlAction(liveUntil: number | undefined, latestLedger: number): TtlAction {
  if (liveUntil === undefined || liveUntil < latestLedger) return "restore";
  return liveUntil - latestLedger < KEEPALIVE_THRESHOLD_LEDGERS ? "extend" : "ok";
}
