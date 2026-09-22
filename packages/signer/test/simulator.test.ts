import assert from "node:assert/strict";
import test from "node:test";

import {
  DeterministicSignerSimulator,
  hashApprovedPolicy,
  hashCapabilityGrant,
  hashExecutionIntent,
  type ApprovedPolicyV1,
  type CapabilityGrantV1,
  type NarrowOperationRequestV1,
} from "../src/index.js";

const NOW = new Date("2027-05-10T12:00:00.000Z");

function makePolicy(
  overrides: Partial<Omit<ApprovedPolicyV1, "hash">> = {},
): ApprovedPolicyV1 {
  const withoutHash: Omit<ApprovedPolicyV1, "hash"> & { hash?: string } = {
    schemaVersion: "aegisos.approved-policy.v1",
    id: "policy-stellar-owner",
    status: "APPROVED",
    validFrom: "2027-05-01T00:00:00.000Z",
    expiresAt: "2027-06-01T00:00:00.000Z",
    executionMode: "OWNER_APPROVAL",
    allowedChains: ["stellar-testnet"],
    allowedOperations: ["SWAP_EXACT_INPUT", "ADD_LIQUIDITY", "REMOVE_LIQUIDITY"],
    allowedProtocols: ["mock-soroswap"],
    allowedPools: ["mock-usdc-xlm"],
    allowedAssets: ["USDC", "XLM", "LP-USDC-XLM"],
    maxInputByAsset: { USDC: "1000000", XLM: "1000000", "LP-USDC-XLM": "1000000" },
    maxSlippageBps: 150,
    maxFeeAtomic: "1000",
    ...overrides,
  };
  const provisional = { ...withoutHash, hash: "" } as ApprovedPolicyV1;
  return { ...withoutHash, hash: hashApprovedPolicy(provisional) } as ApprovedPolicyV1;
}

function makeRequest(
  policy: ApprovedPolicyV1,
  overrides: Partial<NarrowOperationRequestV1> = {},
): NarrowOperationRequestV1 {
  const operation = overrides.operation ?? {
    kind: "SWAP_EXACT_INPUT" as const,
    protocol: "mock-soroswap",
    pool: "mock-usdc-xlm",
    slippageBps: 50,
    feeAtomic: "10",
    input: { asset: "USDC", amountAtomic: "1000" },
    outputAsset: "XLM",
    minOutputAmountAtomic: "900",
  };
  const unsigned: NarrowOperationRequestV1 = {
    schemaVersion: "aegisos.operation-request.v1",
    requestId: "request-1",
    chain: "stellar-testnet",
    createdAt: "2027-05-10T11:59:00.000Z",
    expiresAt: "2027-05-10T12:10:00.000Z",
    nonce: "request-nonce-1",
    policy: { id: policy.id, hash: policy.hash },
    intentHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    operation,
    ...overrides,
  };
  const intentHash = hashExecutionIntent(unsigned);
  const withIntent = { ...unsigned, intentHash };
  if (policy.executionMode === "OWNER_APPROVAL") {
    return {
      ...withIntent,
      ownerApproval: {
        schemaVersion: "aegisos.owner-approval.v1",
        approvalId: "approval-1",
        ownerId: "demo-owner",
        intentHash,
        expiresAt: "2027-05-10T12:05:00.000Z",
      },
    };
  }
  return withIntent;
}

function simulator(policy: ApprovedPolicyV1, capabilities: readonly CapabilityGrantV1[] = []) {
  return new DeterministicSignerSimulator({ policies: [policy], capabilities, now: () => NOW });
}

test("accepts a narrowly typed Stellar testnet request and produces a mock receipt", () => {
  const policy = makePolicy();
  const result = simulator(policy).simulate(makeRequest(policy));

  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.receipt.chain, "stellar-testnet");
  assert.equal(result.receipt.transaction.kind, "stellar-testnet-mock");
  assert.deepEqual(result.receipt.balanceChanges, [
    { asset: "USDC", deltaAtomic: "-1000" },
    { asset: "XLM", deltaAtomic: "900" },
  ]);
});

test("same typed request yields the same deterministic mock receipt in a fresh simulator", () => {
  const policy = makePolicy();
  const request = makeRequest(policy);

  const first = simulator(policy).simulate(request);
  const second = simulator(policy).simulate(request);

  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  if (!first.ok || !second.ok) return;
  assert.deepEqual(first.receipt, second.receipt);
});

test("rejects an expired request without consuming a nonce", () => {
  const policy = makePolicy();
  const request = makeRequest(policy, { expiresAt: "2027-05-10T11:59:59.000Z" });
  const result = simulator(policy).simulate(request);

  assert.deepEqual(result, {
    ok: false,
    rejection: { code: "EXPIRED_REQUEST", message: "The operation request has expired" },
  });
});

test("rejects a replayed request nonce after a successful simulation", () => {
  const policy = makePolicy();
  const request = makeRequest(policy);
  const signer = simulator(policy);

  assert.equal(signer.simulate(request).ok, true);
  const replay = signer.simulate(request);
  assert.equal(replay.ok, false);
  if (replay.ok) return;
  assert.equal(replay.rejection.code, "REPLAYED_NONCE");
});

test("fails closed when a request contains an opaque serialized payload field", () => {
  const policy = makePolicy();
  const request = { ...makeRequest(policy), xdr: "opaque-serialized-content" };
  const result = simulator(policy).simulate(request);

  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.rejection.code, "OPAQUE_PAYLOAD_FORBIDDEN");
});

test("consumes a delegated capability nonce after a successful Sepolia simulation", () => {
  const delegatedPolicy = makePolicy({
    id: "policy-sepolia-delegated",
    executionMode: "DELEGATED",
    allowedChains: ["ethereum-sepolia"],
    allowedOperations: ["ERC20_APPROVE_EXACT"],
    allowedProtocols: ["mock-uniswap-v4"],
    allowedPools: ["mock-usdc-weth"],
    allowedAssets: ["USDC"],
  });
  const unsignedGrant: Omit<CapabilityGrantV1, "hash"> & { hash?: string } = {
    schemaVersion: "aegisos.capability-grant.v1",
    id: "capability-1",
    policyId: delegatedPolicy.id,
    policyHash: delegatedPolicy.hash,
    nonce: "capability-nonce-1",
    validFrom: "2027-05-01T00:00:00.000Z",
    expiresAt: "2027-05-20T00:00:00.000Z",
    allowedChains: ["ethereum-sepolia"],
    allowedOperations: ["ERC20_APPROVE_EXACT"],
    allowedProtocols: ["mock-uniswap-v4"],
    allowedPools: ["mock-usdc-weth"],
    allowedAssets: ["USDC"],
    maxInputByAsset: { USDC: "10000" },
    maxSlippageBps: 100,
    maxFeeAtomic: "100",
  };
  const provisionalGrant = { ...unsignedGrant, hash: "" } as CapabilityGrantV1;
  const grant: CapabilityGrantV1 = {
    ...unsignedGrant,
    hash: hashCapabilityGrant(provisionalGrant),
  } as CapabilityGrantV1;

  const request = makeRequest(delegatedPolicy, {
    chain: "ethereum-sepolia",
    requestId: "request-sepolia-1",
    nonce: "request-sepolia-nonce-1",
    operation: {
      kind: "ERC20_APPROVE_EXACT",
      protocol: "mock-uniswap-v4",
      pool: "mock-usdc-weth",
      slippageBps: 0,
      feeAtomic: "5",
      asset: "USDC",
      spender: "mock-uniswap-router",
      amountAtomic: "1000",
      approvalExpiresAt: "2027-05-10T12:05:00.000Z",
    },
    capability: {
      schemaVersion: "aegisos.capability-reference.v1",
      id: grant.id,
      hash: grant.hash,
      nonce: grant.nonce,
    },
  });
  // makeRequest intentionally does not add owner approval for delegated mode.
  const signer = simulator(delegatedPolicy, [grant]);
  const accepted = signer.simulate(request);
  assert.equal(accepted.ok, true);

  const nextUnsigned = { ...request, requestId: "request-sepolia-2", nonce: "request-sepolia-nonce-2" };
  const replayedCapability: NarrowOperationRequestV1 = {
    ...nextUnsigned,
    intentHash: hashExecutionIntent(nextUnsigned),
  };
  const replay = signer.simulate(replayedCapability);
  assert.equal(replay.ok, false);
  if (replay.ok) return;
  assert.equal(replay.rejection.code, "CAPABILITY_REPLAYED");
});
