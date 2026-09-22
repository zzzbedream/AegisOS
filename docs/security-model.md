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
