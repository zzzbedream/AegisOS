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
  digest: "da961c2d72269eea690775c234c6b1e5a5054a9cad427517490f7e21d2f0f578",
  chainLink1: "8d59d4113fa07fadb6bcc0feeb18d6634441a256657ce31abc4911fe51856137",
};

test("the commitment digest matches the contract byte for byte", () => {
  assert.equal(onChainCommitmentDigest(VECTOR.commitment).toString("hex"), VECTOR.digest);
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
  const base = onChainCommitmentDigest(VECTOR.commitment).toString("hex");
  const variants = [
    { ...VECTOR.commitment, maxAmount: 10_001n },
    { ...VECTOR.commitment, expiresAt: 1_900_000_901n },
    { ...VECTOR.commitment, seller: "GDARKECJYS4TXQ3AZOOKA4HCQ5AEJEPZBKQAUXQSDOCO5EEZ76F377WJ" },
    { ...VECTOR.commitment, commitmentHash: "ac".repeat(32) },
  ];
  for (const variant of variants) {
    assert.notEqual(onChainCommitmentDigest(variant).toString("hex"), base);
  }
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
