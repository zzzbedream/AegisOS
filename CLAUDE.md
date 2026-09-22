# AegisOS MVP

Enforced security layer for ElizaOS-style financial agents. It separates untrusted
memory from financial authority and permits only typed, policy-checked operations
through an isolated signer.

**This repository is testnet/mock-only.**

## Commands

| Task | Command | Notes |
|---|---|---|
| Build | `npm run build` | `tsc -b` across all project references |
| Typecheck | `npm run typecheck` | `tsc -b --pretty false` |
| Test | `npm test` | `tsx --test` (node:test runner) |
| Benchmark | `npm run benchmark` | Deterministic, mock adapters |
| Demo | `npm run demo` | Dashboard; port from `AEGIS_DASHBOARD_PORT` (default 4173) |
| Clean | `npm run clean` | `tsc -b --clean` |

There is no lint or format script, and no ESLint/Prettier config. `tsc` is the only
static check. Do not invent a lint step.

## Toolchain

`package.json` declares `packageManager: bun@1.2.17`, but **bun is not installed** on
this machine. Use `npm` (11.6.2 / Node v24.12.0). Docker is likewise not installed, so
`docker-compose.local.yml` (stellar-quickstart, anvil) cannot run here — both services
are behind opt-in profiles anyway.

## Layout

```
packages/core           canonical encoding, crypto, intent, ledger, memory, policy, validation
packages/plugin-eliza   memory gateway, preflight, risk, policy service, draft action
packages/signer         isolated signer + simulator
apps/benchmark          deterministic benchmark harness
apps/dashboard          node:http server that turns drafts into execution intents
```

Workspaces are `packages/*` and `apps/*`, wired through TypeScript project references
in `tsconfig.json`. Shared compiler options live in `tsconfig.base.json` and are strict:
`strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`. Keep them on.

Packages carry **zero runtime dependencies** — only `node:*` builtins. Adding a runtime
dependency to `packages/core` or `packages/signer` is a security-relevant change; raise
it rather than doing it silently.

## Enforced boundary — do not cross

The agent process may create only a typed, non-executable draft. It must never receive
a private key, a generic signing endpoint, raw Stellar XDR, Ethereum calldata, an RPC
URL, or an approval token. The signer fails closed on opaque payloads or policy drift.

Rejected by design: generic contract invocation, unlimited approvals, bridges,
borrowing, raw transaction submission, and mainnet.

All connector, tool, document, and imported-memory content starts as `UNTRUSTED`.
Promotion requires external owner-review evidence bound to the content hash. Retrieved
memory is data-only and taints draft provenance.

See [docs/security-model.md](docs/security-model.md) for the full model.

## Secrets

`.env` is gitignored; `.env.example` holds testnet endpoints only. Never commit private
keys, and never add a key to a ledger event or to agent context.
