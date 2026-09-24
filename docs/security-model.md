# AegisOS security model

## Enforced boundary

The agent process may create only a typed draft. It never receives a private key, a generic signing endpoint, raw Stellar XDR, Ethereum calldata, an RPC URL, or an approval token. A separate signer accepts a narrow operation request and fails closed when it finds opaque payloads or policy drift.

`enforced` startup rejects a host that exposes a direct wallet/signing capability or an unguarded memory route. It is not a sandbox for malicious code running with operating-system access: a compromised host, sidecar, owner wallet, or plugin with unrestricted local access remains outside the MVP threat model.

## Memory lifecycle

All connector, tool, document and imported-memory content begins as `UNTRUSTED`. Risky content is quarantined and cannot become policy or authority through model output. Promotion requires external owner-review evidence bound to the content hash. Retrieved memory is data-only and is tainted in the draft provenance.

## Financial lifecycle

1. The agent emits a non-executable intent draft.
2. A dashboard or trusted application turns it into a canonical execution intent.
3. The owner approves an exact vault transaction or a bounded delegation grant.
4. The signer validates policy, nonce, expiry, route, asset, quote/simulation result, fees and limits.
5. It emits a verifiable receipt and appends a signed ledger event.

Stellar Testnet uses a native 2-of-2 vault. Ethereum Sepolia uses a Safe 2-of-2 vault. Delegated actions use a separate, pre-funded account so the on-chain balance bounds exposure.

## Route restrictions

The MVP supports only typed exact-input swaps, liquidity add/remove, and exact ERC-20 approvals. Generic contract invocation, unlimited approvals, bridges, borrowing, raw transaction submission, and mainnet are rejected by design.

## Verifiable provenance for x402 purchases

AegisOS enforces one invariant on paid content: **no purchased content may justify a later
spend unless there is a prior commitment, a verifiable payment–delivery binding, and a
deterministic risk evaluation.**

### Trust boundaries

| Component | Holds | Must never |
|---|---|---|
| Agent | offers, commitments, receipts, delivered content | hold the buyer key or ask for an untyped signature |
| Isolated signer (own OS process) | buyer Stellar key; trusted commitment keys pinned at launch | accept a verification key, or any key material, from a request |
| x402 facilitator | the signed auth entry | decide whether content is trustworthy |
| Memory gateway | delivered content and its provenance | sign payments |
| `aegis-proof` contract | hashes and verdicts | hold content, or be read as verifying it |

### Signer guard

The signer signs a Soroban auth entry only when all of these hold; otherwise it denies
before signing, so no payment happens:

1. The commitment is signed by a key in `trustedCommitmentKeys`, set in `AEGIS_SIGNER_CONFIG`
   when the process starts (`COMMITMENT_KEY_UNTRUSTED`, `COMMITMENT_SIGNATURE_INVALID`).
   Lookups use own properties only.
2. The commitment has not expired (`COMMITMENT_EXPIRED`).
3. The entry is a single SAC `transfer` debiting the signer's own account, with no
   sub-invocations (`AUTH_ENTRY_MISMATCH`).
4. Recipient, asset, network and amount match the commitment and the launch allowlists
   (`SELLER_NOT_ALLOWED`, `ASSET_NOT_ALLOWED`, `NETWORK_NOT_ALLOWED`,
   `AMOUNT_EXCEEDS_COMMITMENT`).
5. The request carries no key-like field (`KEY_MATERIAL_IN_REQUEST`).

Every decision, including denials, is written to the signer's audit stream.

### Delivery verdict and admission

Precedence is strict: `NOT_DELIVERED → MISMATCH → TAINTED → OK`. Content is hashed from the
exact bytes received, with an explicit canonicalization mode; normalization for pattern
matching never touches the hashed evidence. Only `OK` and `TAINTED` deliveries are stored,
and `TAINTED` is quarantined: `retrieve()` does not return it, and a draft citing it fails
`assertDraftSources` before policy evaluation, which would also deny it with
`TAINTED_PROVENANCE_REQUIRES_OWNER`.

### Receipts and third-party verification

Commitments and receipts are signed by a per-environment attester key
(`AEGIS_ATTESTER_SECRET_FILE`, default `.aegis/attester.json`, gitignored). Only its public
half is published in `contracts/deployments/testnet.json`. `npm run verify:receipt` checks a
receipt against that published key and against the record returned by `get_delivery`,
without any secret.

All hashes are domain-separated (`aegisproof:purchase-commitment:v1`,
`aegisproof:delivery-receipt:v1`, …). These identifiers are part of what is signed and
anchored, and do not change with product naming.

### What this does not prove

- The contract anchors a **buyer attestation**. It does not verify that the payment settled,
  that the seller was paid, or that the content hash matches the HTTP body.
- `seller_score` is an aggregate of anchored attestations, open to griefing and collusion.
  It must feed policy, never be presented as proof of seller misconduct.
- A receipt signature is the buyer's, not the seller's.
- Plausible but false data (a manipulated price) is not detectable at this layer.
- Detection is pattern-based. Declared residuals: base64/hex-encoded payloads, Cyrillic
  homoglyphs, multi-turn attacks.

### Known gap

The commitment/attester key lives in the launcher process, which in the demo is the agent
process. Requests can no longer supply their own key, but an attacker with full control of
that process could use the key it holds. The planned fix moves the policy on-chain, into a
smart account's `__check_auth` via a policy signer or an external policy contract, following
Stellar's *Advanced contract account patterns*.
