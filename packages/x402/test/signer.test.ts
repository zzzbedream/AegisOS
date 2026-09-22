import assert from "node:assert/strict";
import test from "node:test";

import { Address, Keypair, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { generateEd25519KeyPair } from "../../core/src/index.js";
import {
  createPurchaseCommitment,
  sellerIdFromAccount,
  type PurchaseCommitmentV1,
} from "../../proof/src/index.js";
import {
  IsolatedSignerService,
  SIGNER_PROTOCOL_VERSION,
  createRemoteSigner,
  inProcessTransport,
  type SignerAuditEntry,
} from "../src/index.js";

const USDC_TESTNET = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const TESTNET_PASSPHRASE = "Test SDF Network ; September 2015";
const NOW = new Date("2027-05-10T12:00:00.000Z");

const signerKeypair = Keypair.random();
const sellerKeypair = Keypair.random();
const attackerKeypair = Keypair.random();
const buyerIdentity = generateEd25519KeyPair("key:buyer");

const SELLER_ID = sellerIdFromAccount(sellerKeypair.publicKey());

interface AuthEntryShape {
  readonly from?: string;
  readonly to?: string;
  readonly amount?: bigint;
  readonly token?: string;
  readonly functionName?: string;
  readonly withSubInvocation?: boolean;
}

function authEntry(shape: AuthEntryShape = {}): string {
  const from = shape.from ?? signerKeypair.publicKey();
  const to = shape.to ?? sellerKeypair.publicKey();
  const amount = shape.amount ?? 10000n;
  const token = shape.token ?? USDC_TESTNET;

  const contractFn = new xdr.InvokeContractArgs({
    contractAddress: new Address(token).toScAddress(),
    functionName: shape.functionName ?? "transfer",
    args: [
      new Address(from).toScVal(),
      new Address(to).toScVal(),
      nativeToScVal(amount, { type: "i128" }),
    ],
  });

  const sub = shape.withSubInvocation === true
    ? [
        new xdr.SorobanAuthorizedInvocation({
          function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(contractFn),
          subInvocations: [],
        }),
      ]
    : [];

  const entry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: new Address(from).toScAddress(),
        nonce: xdr.Int64.fromString("1"),
        signatureExpirationLedger: 100000,
        signature: xdr.ScVal.scvVoid(),
      }),
    ),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(contractFn),
      subInvocations: sub,
    }),
  });

  return entry.toXDR("base64");
}

function commitment(overrides: Partial<PurchaseCommitmentV1> = {}): PurchaseCommitmentV1 {
  return createPurchaseCommitment(
    {
      version: "1",
      id: "commitment:x402",
      resourceUrl: "https://seller.example/market-data",
      sellerId: SELLER_ID,
      expectedContentType: "application/json",
      maxAmountAtomic: "100000",
      assetId: "stellar:USDC",
      committedAt: "2027-05-10T11:59:00.000Z",
      expiresAt: "2027-05-10T12:15:00.000Z",
      nonce: "nonce:x402-1",
      ...overrides,
    },
    buyerIdentity,
  );
}

function service(audit?: SignerAuditEntry[]): IsolatedSignerService {
  return new IsolatedSignerService({
    privateKey: signerKeypair.secret(),
    network: "stellar:testnet",
    allowedAssets: { "stellar:USDC": USDC_TESTNET },
    allowedNetworkPassphrases: [TESTNET_PASSPHRASE],
    now: () => NOW,
    ...(audit === undefined ? {} : { onDecision: (entry) => audit.push(entry) }),
  });
}

function signRequest(entryXdr: string, c: PurchaseCommitmentV1 = commitment()) {
  return {
    protocol: SIGNER_PROTOCOL_VERSION,
    id: "req-1",
    kind: "sign_auth_entry",
    authEntryXdr: entryXdr,
    networkPassphrase: TESTNET_PASSPHRASE,
    commitment: c,
    buyerPublicKey: buyerIdentity.publicKey,
  };
}

// ------------------------------------------------------------- happy path

test("the signer signs a transfer that matches the commitment", async () => {
  const audit: SignerAuditEntry[] = [];
  const response = await service(audit).handle(signRequest(authEntry()));

  assert.equal(response.kind, "ok");
  if (response.kind !== "ok") return;
  assert.ok(response.value.length > 0);
  assert.notEqual(response.value, authEntry());
  assert.equal(audit.at(-1)?.decision, "ok");
  assert.equal(audit.at(-1)?.transfer?.to, sellerKeypair.publicKey());
});

// --------------------------------------------- the poisoned-agent scenarios

test("a redirected recipient is refused even with a valid commitment", async () => {
  // This is the attack the whole product exists for: the agent has read
  // poisoned content telling it the treasury address changed.
  const response = await service().handle(
    signRequest(authEntry({ to: attackerKeypair.publicKey() })),
  );

  assert.equal(response.kind, "denied");
  if (response.kind !== "denied") return;
  assert.equal(response.code, "SELLER_NOT_ALLOWED");
});

test("an amount above the committed ceiling is refused", async () => {
  const response = await service().handle(signRequest(authEntry({ amount: 999_999_999n })));

  assert.equal(response.kind, "denied");
  if (response.kind !== "denied") return;
  assert.equal(response.code, "AMOUNT_EXCEEDS_COMMITMENT");
});

test("a transfer of an unexpected token is refused", async () => {
  const other = "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75";
  const response = await service().handle(signRequest(authEntry({ token: other })));

  assert.equal(response.kind, "denied");
  if (response.kind !== "denied") return;
  assert.equal(response.code, "ASSET_NOT_ALLOWED");
});

test("an entry carrying sub-invocations is refused", async () => {
  const response = await service().handle(signRequest(authEntry({ withSubInvocation: true })));

  assert.equal(response.kind, "denied");
  if (response.kind !== "denied") return;
  assert.equal(response.code, "AUTH_ENTRY_MISMATCH");
});

test("a non-transfer function is refused", async () => {
  const response = await service().handle(signRequest(authEntry({ functionName: "set_admin" })));

  assert.equal(response.kind, "denied");
  if (response.kind !== "denied") return;
  assert.equal(response.code, "AUTH_ENTRY_MISMATCH");
});

test("a transfer debiting someone else is refused", async () => {
  const response = await service().handle(
    signRequest(authEntry({ from: attackerKeypair.publicKey() })),
  );

  assert.equal(response.kind, "denied");
  if (response.kind !== "denied") return;
  assert.equal(response.code, "AUTH_ENTRY_MISMATCH");
});

// ---------------------------------------------------- commitment integrity

test("a forged commitment cannot justify a payment", async () => {
  const forged = { ...commitment(), maxAmountAtomic: "999999999" };
  const response = await service().handle(signRequest(authEntry(), forged));

  assert.equal(response.kind, "denied");
  if (response.kind !== "denied") return;
  assert.equal(response.code, "COMMITMENT_SIGNATURE_INVALID");
});

test("an expired commitment cannot justify a payment", async () => {
  const stale = commitment({
    committedAt: "2027-05-10T10:00:00.000Z",
    expiresAt: "2027-05-10T10:05:00.000Z",
  });
  const response = await service().handle(signRequest(authEntry(), stale));

  assert.equal(response.kind, "denied");
  if (response.kind !== "denied") return;
  assert.equal(response.code, "COMMITMENT_EXPIRED");
});

test("a request carrying key material is refused outright", async () => {
  const poisoned = { ...signRequest(authEntry()), privateKey: signerKeypair.secret() };
  const response = await service().handle(poisoned);

  assert.equal(response.kind, "denied");
  if (response.kind !== "denied") return;
  assert.equal(response.code, "KEY_MATERIAL_IN_REQUEST");
});

test("denials are audited, not silent", async () => {
  const audit: SignerAuditEntry[] = [];
  await service(audit).handle(signRequest(authEntry({ to: attackerKeypair.publicKey() })));

  assert.equal(audit.length, 1);
  assert.equal(audit[0]?.decision, "denied");
  assert.equal(audit[0]?.code, "SELLER_NOT_ALLOWED");
});

// ------------------------------------------------------------ the boundary

test("the agent-side signer holds a channel, never key material", async () => {
  const signer = await createRemoteSigner({
    transport: inProcessTransport(service()),
    commitment: commitment(),
    buyerPublicKey: buyerIdentity.publicKey,
  });

  assert.equal(signer.address, signerKeypair.publicKey());

  // Everything reachable from the object the agent holds, serialized.
  const exposed = JSON.stringify(signer, (_key, value: unknown) =>
    typeof value === "function" ? "[function]" : value,
  );
  assert.ok(!exposed.includes(signerKeypair.secret()));
  assert.deepEqual(Object.keys(signer).sort(), ["address", "signAuthEntry"]);
});

test("the proxy signs a committed payment and refuses a redirected one", async () => {
  const signer = await createRemoteSigner({
    transport: inProcessTransport(service()),
    commitment: commitment(),
    buyerPublicKey: buyerIdentity.publicKey,
  });

  const ok = await signer.signAuthEntry(authEntry(), { networkPassphrase: TESTNET_PASSPHRASE });
  assert.ok(ok.signedAuthEntry.length > 0);

  await assert.rejects(
    () =>
      signer.signAuthEntry(authEntry({ to: attackerKeypair.publicKey() }), {
        networkPassphrase: TESTNET_PASSPHRASE,
      }),
    /SELLER_NOT_ALLOWED|not the committed seller/,
  );
});
