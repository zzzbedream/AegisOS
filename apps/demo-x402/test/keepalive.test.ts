import assert from "node:assert/strict";
import test from "node:test";

import {
  KEEPALIVE_THRESHOLD_LEDGERS,
  keepaliveEntries,
  ttlAction,
  type KeepaliveSources,
} from "../src/keepalive.js";

const REGISTRY = "CBPGIT7F2LU3PDDHWW7QIBEKVVDQVRME4WEUUHNU7YQLINZBR24IU4NN";
const ACCOUNT = "CDUZ2FIOVNG25VU5ZGNCDT26C2N2LN5S24FJDHXEDXNY3JTIPAZJAPVZ";
const SELLER = "GC4Q5TWWXI7IHN6DYCBEKCOWJWCKY4JE2NLKLU5SE3YL44IUUFPKUOPC";

const sources: KeepaliveSources = {
  registry: { contractId: REGISTRY, wasmHash: "5f7b9f89bfe3919d63f09055c78312b069bcccfb632369e45e90bf755c320a21" },
  account: { address: ACCOUNT, wasmHash: "933a1d46734fd70578c31182305de666830185fe0d81301ccedfe4429a02662a" },
  ranges: [
    { contractId: REGISTRY, account: ACCOUNT, fromSeq: "5" },
    { contractId: REGISTRY, account: ACCOUNT, fromSeq: "5" },
    { contractId: "CD4BMCIKKOCVM66NYSC4LGWUWS4Z5ZMBU3KCVCSGZYI726ZVL7NZ2ZOF", account: ACCOUNT, fromSeq: "1" },
  ],
  sellers: [SELLER, SELLER],
};

test("keeps instances, wasm, the USDC balance and the registry records the evidence reads", () => {
  const labels = keepaliveEntries(sources).map((e) => e.label);

  assert.deepEqual(labels, [
    "registry instance",
    "registry wasm",
    "account instance",
    "account wasm",
    "account USDC balance",
    "registry Account(account)",
    "registry Checkpoint(account)",
    "registry Range(CDUZ2FIO…, 5)",
    "registry SellerScore(GC4Q5TWW…)",
  ]);
});

test("the USDC balance key is the one the SAC stores for a contract holder", () => {
  const balance = keepaliveEntries(sources).find((e) => e.label === "account USDC balance");

  // Restored on testnet by hand on 2026-11-01 with exactly this key.
  assert.equal(
    balance?.key.contractData().key().toXDR("base64"),
    "AAAAEAAAAAEAAAACAAAADwAAAAdCYWxhbmNlAAAAABIAAAAB6Z0VDqtNrtadyZohz14Wm6W3stcKkZ7kHduNpmh4MpA=",
  );
});

test("restores archived entries, extends ones near expiry, leaves the rest", () => {
  const latest = 5_500_000;

  assert.equal(ttlAction(undefined, latest), "restore");
  assert.equal(ttlAction(latest - 1, latest), "restore");
  assert.equal(ttlAction(latest + KEEPALIVE_THRESHOLD_LEDGERS - 1, latest), "extend");
  assert.equal(ttlAction(latest + KEEPALIVE_THRESHOLD_LEDGERS, latest), "ok");
});
