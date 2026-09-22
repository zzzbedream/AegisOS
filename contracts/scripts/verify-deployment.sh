#!/usr/bin/env bash
# Hito 0 gate: prove the deployed aegis-proof contract works end to end on testnet.
#
# Anchors a fresh attestation, reads it back, checks the seller aggregate moved,
# and confirms the same payment_hash cannot be anchored twice.
#
# Re-runnable: the payment hash is derived from a nonce (default: epoch seconds),
# so a second run does not collide with the first.
#
#   ./verify-deployment.sh [nonce]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOYMENTS="${SCRIPT_DIR}/../deployments/testnet.json"

NETWORK="testnet"
BUYER_KEY="${AEGIS_BUYER_KEY:-aegis-deployer}"
SELLER_KEY="${AEGIS_SELLER_KEY:-aegis-seller-demo}"
NONCE="${1:-$(date +%s)}"

# Piped through stdin rather than require()'d by path: under Git Bash on Windows
# `pwd` yields /c/... which Node cannot resolve as a module path.
CID="$(cat "${DEPLOYMENTS}" | node -e "
  let d = '';
  process.stdin.on('data', (c) => (d += c));
  process.stdin.on('end', () => process.stdout.write(JSON.parse(d).contracts['aegis-proof'].contractId));
")"
BUYER="$(stellar keys address "${BUYER_KEY}")"
SELLER="$(stellar keys address "${SELLER_KEY}")"

# 32-byte hex fixtures, distinct per run.
pad() { printf '%s%0*d' "$1" $((64 - ${#1})) "$2"; }
PAYMENT_HASH="$(pad a1 "${NONCE}")"
COMMITMENT_HASH="$(pad c0 "${NONCE}")"
CONTENT_HASH="$(pad c1 "${NONCE}")"

echo "contract : ${CID}"
echo "buyer    : ${BUYER}"
echo "seller   : ${SELLER}"
echo "payment  : ${PAYMENT_HASH}"
echo

invoke() { stellar contract invoke --id "${CID}" --source-account "${BUYER_KEY}" --network "${NETWORK}" -- "$@"; }

echo "1/4 anchor_delivery (verdict=Tainted)"
invoke anchor_delivery --input "{ \"buyer\": \"${BUYER}\", \"seller\": \"${SELLER}\", \"payment_hash\": \"${PAYMENT_HASH}\", \"commitment_hash\": \"${COMMITMENT_HASH}\", \"content_hash\": \"${CONTENT_HASH}\", \"verdict\": \"Tainted\" }"

echo
echo "2/4 get_delivery"
RECORD="$(invoke get_delivery --payment_hash "${PAYMENT_HASH}" 2>/dev/null | tail -1)"
echo "${RECORD}"
node -e "
  const r = JSON.parse(process.argv[1]);
  const fail = (m) => { console.error('FAIL: ' + m); process.exit(1); };
  if (r.payment_hash !== process.argv[2]) fail('payment_hash mismatch');
  if (r.content_hash !== process.argv[3]) fail('content_hash mismatch');
  if (r.verdict !== 'Tainted') fail('verdict mismatch');
  if (!Number.isInteger(r.anchored_at) || r.anchored_at <= 0) fail('anchored_at not ledger-stamped');
" "${RECORD}" "${PAYMENT_HASH}" "${CONTENT_HASH}"

echo
echo "3/4 seller_score"
SCORE="$(invoke seller_score --seller "${SELLER}" 2>/dev/null | tail -1)"
echo "${SCORE}"
node -e "
  const s = JSON.parse(process.argv[1]);
  if (!(s.tainted >= 1 && s.total >= 1)) { console.error('FAIL: tainted/total did not increment'); process.exit(1); }
" "${SCORE}"

echo
echo "4/4 duplicate payment_hash must be rejected (expect Error(Contract, #1))"
if invoke anchor_delivery --input "{ \"buyer\": \"${BUYER}\", \"seller\": \"${SELLER}\", \"payment_hash\": \"${PAYMENT_HASH}\", \"commitment_hash\": \"${COMMITMENT_HASH}\", \"content_hash\": \"${CONTENT_HASH}\", \"verdict\": \"Ok\" }" >/dev/null 2>&1; then
  echo "FAIL: duplicate anchor was accepted; history is rewritable"
  exit 1
fi
echo "rejected as expected"

echo
echo "PASS: contract ${CID} verified on ${NETWORK}"
