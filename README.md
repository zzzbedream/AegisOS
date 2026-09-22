# AegisOS MVP 2

AegisOS is an enforced security layer for ElizaOS-style financial agents. It separates untrusted memory from financial authority and only permits typed, policy-checked operations through an isolated signer.

## Safety boundary

This repository is testnet/mock-only. It does not accept private keys from an agent, raw Stellar XDR, arbitrary Ethereum calldata, arbitrary RPC URLs, mainnet configuration, or unlimited approvals.

## Quick start

Install Bun (preferred) or use the checked-in npm workspace during development, then run:

```powershell
npm install
npm run typecheck
npm test
npm run benchmark
npm run demo
```

The benchmark is deterministic and uses mock adapters. Stellar Testnet and Sepolia configuration is intentionally inert until approved manifests, wallet owners, and dedicated test accounts are supplied outside this repository.
