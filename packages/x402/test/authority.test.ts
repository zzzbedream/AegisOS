import assert from "node:assert/strict";
import { createPublicKey, randomBytes, verify } from "node:crypto";
import test from "node:test";

import { Address, Keypair, StrKey, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { generateEd25519KeyPair } from "../../core/src/index.js";
import {
  createPurchaseCommitment,
  sellerIdFromAccount,
  type PurchaseCommitmentV1,
} from "../../proof/src/index.js";
import {
  IsolatedSignerService,
  SIGNER_PROTOCOL_VERSION,
  inProcessTransport,
  onChainCommitmentDigest,
  readSignerConfig,
  requestCommitmentAuthority,
  SignerDeniedError,
  type OnChainCommitmentV1,
} from "../src/index.js";

const USDC = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const PASSPHRASE = "Test SDF Network ; September 2015";
const NOW = new Date("2027-05-10T12:00:00.000Z");
const NOW_S = BigInt(NOW.getTime() / 1000);

const session = Keypair.random();
const account = StrKey.encodeContract(randomBytes(32));
const approved = Keypair.random().publicKey();
const stranger = Keypair.random().publicKey();
const authority = generateEd25519KeyPair();
const attester = generateEd25519KeyPair("key:attester");

function service(withAuthority = true): IsolatedSignerService {
  return new IsolatedSignerService({
    privateKey: session.secret(),
    network: "stellar:testnet",
    allowedAssets: { "stellar:USDC": USDC },
    allowedNetworkPassphrases: [PASSPHRASE],
    trustedCommitmentKeys: { [attester.keyId]: attester.publicKey },
    payerAddress: account,
    ...(withAuthority
      ? { authority: { privateKey: authority.privateKey, policy: { allowedSellers: [approved], maxAmountAtomic: "100000" } } }
      : {}),
    now: () => NOW,
  });
}

function onChain(overrides: Partial<OnChainCommitmentV1> = {}): OnChainCommitmentV1 {
  return {
    commitmentHash: "ab".repeat(32),
    seller: approved,
    asset: USDC,
    maxAmount: 10_000n,
    expiresAt: NOW_S + 900n,
    ...overrides,
  };
}

async function deniedCode(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return "SIGNED";
  } catch (error: unknown) {
    return error instanceof SignerDeniedError ? error.code : `ERROR ${String(error)}`;
  }
}

// ------------------------------------------------------------ authority

test("the authority signs an approved commitment, bound to the paying account", async () => {
  const c = onChain();
  const signature = await requestCommitmentAuthority(inProcessTransport(service()), c);
  const key = createPublicKey({ key: Buffer.from(authority.publicKey, "base64url"), format: "der", type: "spki" });

  assert.equal(verify(null, onChainCommitmentDigest(account, c), key, signature), true);
  // The same signature is worthless for any other account.
  const elsewhere = StrKey.encodeContract(randomBytes(32));
  assert.equal(verify(null, onChainCommitmentDigest(elsewhere, c), key, signature), false);
});

test("the authority refuses what the owner did not approve", async () => {
  const transport = inProcessTransport(service());
  const cases: readonly Partial<OnChainCommitmentV1>[] = [
    { seller: stranger },
    { maxAmount: 100_001n },
    { expiresAt: NOW_S - 1n },
    { expiresAt: NOW_S + 3_601n },
    { asset: StrKey.encodeContract(randomBytes(32)) },
  ];
  for (const overrides of cases) {
    assert.equal(await deniedCode(requestCommitmentAuthority(transport, onChain(overrides))), "COMMITMENT_POLICY_DENIED", JSON.stringify(overrides, (_k, v: unknown) => typeof v === "bigint" ? v.toString() : v));
  }
});

test("a signer without an authority cannot sign commitments at all", async () => {
  assert.equal(
    await deniedCode(requestCommitmentAuthority(inProcessTransport(service(false)), onChain())),
    "AUTHORITY_NOT_CONFIGURED",
  );
});

test("a malformed on-chain commitment request is refused before any policy", async () => {
  const response = await service().handle({
    protocol: SIGNER_PROTOCOL_VERSION,
    id: "req",
    kind: "sign_onchain_commitment",
    commitment: { commitmentHash: "zz", seller: approved, asset: USDC, maxAmount: "1", expiresAt: "1" },
  });
  assert.equal(response.kind === "denied" ? response.code : "ok", "MALFORMED_REQUEST");
});

// ------------------------------------------------------------ smart mode

function offChainCommitment(): PurchaseCommitmentV1 {
  return createPurchaseCommitment(
    {
      version: "1",
      id: "commitment:smart",
      resourceUrl: "https://seller.example/data",
      sellerId: sellerIdFromAccount(approved),
      expectedContentType: "application/json",
      maxAmountAtomic: "10000",
      assetId: "stellar:USDC",
      committedAt: "2027-05-10T11:59:00.000Z",
      expiresAt: "2027-05-10T12:15:00.000Z",
      nonce: "nonce:smart",
    },
    attester,
  );
}

function preimage(from: string): string {
  const fn = new xdr.InvokeContractArgs({
    contractAddress: new Address(USDC).toScAddress(),
    functionName: "transfer",
    args: [new Address(from).toScVal(), new Address(approved).toScVal(), nativeToScVal(10_000n, { type: "i128" })],
  });
  return xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
    new xdr.HashIdPreimageSorobanAuthorization({
      networkId: Buffer.alloc(32, 1),
      nonce: xdr.Int64.fromString("7"),
      signatureExpirationLedger: 100,
      invocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(fn),
        subInvocations: [],
      }),
    }),
  ).toXDR("base64");
}

async function signPayment(from: string) {
  return service().handle({
    protocol: SIGNER_PROTOCOL_VERSION,
    id: "req",
    kind: "sign_auth_entry",
    authEntryXdr: preimage(from),
    networkPassphrase: PASSPHRASE,
    commitment: offChainCommitment(),
  });
}

test("in smart mode the signer pays from the account, as its session key", async () => {
  const response = await signPayment(account);
  assert.equal(response.kind, "ok");
  const address = await service().handle({ protocol: SIGNER_PROTOCOL_VERSION, id: "a", kind: "get_address" });
  assert.equal(address.kind === "ok" ? address.value : "", account);
});

test("in smart mode a transfer from the bare session account is refused", async () => {
  const response = await signPayment(session.publicKey());
  assert.equal(response.kind === "denied" ? response.code : "ok", "AUTH_ENTRY_MISMATCH");
});

// ------------------------------------------------------------ launch config

test("launch config validates the payer and the authority policy", () => {
  const base = {
    network: "stellar:testnet",
    allowedAssets: { "stellar:USDC": USDC },
    allowedNetworkPassphrases: [PASSPHRASE],
    trustedCommitmentKeys: { [attester.keyId]: attester.publicKey },
  };
  const env = (config: unknown) => ({ AEGIS_SIGNER_CONFIG: JSON.stringify(config) });

  assert.throws(() => readSignerConfig(env({ ...base, payerAddress: session.publicKey() })), /contract address/);
  assert.throws(
    () => readSignerConfig(env({ ...base, authorityPolicy: { allowedSellers: "all", maxAmountAtomic: "1" } })),
    /authorityPolicy/,
  );
  const ok = readSignerConfig(
    env({ ...base, payerAddress: account, authorityPolicy: { allowedSellers: [approved], maxAmountAtomic: "100" } }),
  );
  assert.equal(ok.payerAddress, account);
  assert.deepEqual(ok.authorityPolicy?.allowedSellers, [approved]);
});
