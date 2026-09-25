import assert from "node:assert/strict";
import test from "node:test";

import { onChainCommitmentDigest, paymentChainLink, paymentAuthScVal } from "../src/index.js";

// Printed by `cargo test -p aegis-account commitment_digest -- --nocapture`.
// If either side changes its byte layout, the account rejects every payment.
const VECTOR = {
  commitment: {
    commitmentHash: "ab".repeat(32),
    seller: "GDVR2KDK5DSMNYZJKNISUIOBDC6FZK3XZOIQWSS7KL4BRMD5BMW6RMCQ",
    asset: "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
    maxAmount: 10_000n,
    expiresAt: 1_900_000_900n,
  },
  account: "CDZ2HUKOYV5GR4NOZWFZN673V36KYWIXGFWFSUFHI2X6UVYAPBZWHCPQ",
  digest: "5113d17413cc9bb16edfc653f503c0fe9dd232dad2ffb08a3d3db8033e16070d",
  chainLink1: "8d59d4113fa07fadb6bcc0feeb18d6634441a256657ce31abc4911fe51856137",
};

test("the commitment digest matches the contract byte for byte", () => {
  assert.equal(onChainCommitmentDigest(VECTOR.account, VECTOR.commitment).toString("hex"), VECTOR.digest);
});

test("the payment chain link matches the contract byte for byte", () => {
  assert.equal(
    paymentChainLink({
      previous: "00".repeat(32),
      seq: 1n,
      commitmentHash: VECTOR.commitment.commitmentHash,
      seller: VECTOR.commitment.seller,
      amount: 10_000n,
    }),
    VECTOR.chainLink1,
  );
});

test("changing any committed field changes the digest", () => {
  const base = onChainCommitmentDigest(VECTOR.account, VECTOR.commitment).toString("hex");
  const variants = [
    { ...VECTOR.commitment, maxAmount: 10_001n },
    { ...VECTOR.commitment, expiresAt: 1_900_000_901n },
    { ...VECTOR.commitment, seller: "GDARKECJYS4TXQ3AZOOKA4HCQ5AEJEPZBKQAUXQSDOCO5EEZ76F377WJ" },
    { ...VECTOR.commitment, commitmentHash: "ac".repeat(32) },
  ];
  for (const variant of variants) {
    assert.notEqual(onChainCommitmentDigest(VECTOR.account, variant).toString("hex"), base);
  }
  const otherAccount = "CCMFGMPV2ZMEWE4EKF5KPR6RJM7K65ZJ5NLU25CBQBFE6IYML72VRPZS";
  assert.notEqual(onChainCommitmentDigest(otherAccount, VECTOR.commitment).toString("hex"), base);
});

test("the payment signature is the contract's AegisAuth::Payment shape", () => {
  const scVal = paymentAuthScVal({
    commitment: VECTOR.commitment,
    authoritySignature: Buffer.alloc(64, 1),
    sessionSignature: Buffer.alloc(64, 2),
  });
  const [tag, body] = scVal.vec() ?? [];
  assert.equal(tag?.sym().toString(), "Payment");
  const keys = body?.map()?.map((entry) => entry.key().sym().toString());
  assert.deepEqual(keys, ["authority_sig", "commitment", "session_sig"]);
});
