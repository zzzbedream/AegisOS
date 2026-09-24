#![no_std]

//! AegisProof — public anchor for delivery attestations in agentic commerce.
//!
//! What this contract proves:
//!   1. An authenticated buyer account anchored a record.
//!   2. The record binds buyer, seller, payment_hash, commitment_hash,
//!      content_hash and a verdict.
//!   3. That payment_hash cannot be overwritten.
//!   4. History and aggregates are publicly queryable.
//!
//! What this contract does NOT prove:
//!   - That `payment_hash` corresponds to a settled x402 payment.
//!   - That the seller received that payment.
//!   - That `content_hash` matches the HTTP body actually received.
//!   - That a Mismatch/Tainted verdict is truthful.
//!   - That buyer and seller are not the same party inflating reputation.
//!   - For a batch: that the root has `count` leaves, that every leaf is an
//!     OK delivery, or that a payment appears in only one batch. Inclusion of
//!     a receipt is proven off-chain against the root; the contract never sees
//!     the leaves.
//!
//! Therefore `seller_score` is an immutable aggregate of anchored attestations,
//! NOT an objective measure of service quality. Evaluation happens off-chain
//! and deterministically; this contract is the public evidence anchor.
//!
//! ## Known, unmitigated: score griefing and collusion
//!
//! Anchoring costs only a network fee, and nothing here proves the buyer ever
//! paid the seller. So an attacker can anchor many `Mismatch` attestations
//! against a seller they never transacted with, and colluding parties can
//! manufacture `Ok` history for each other. `SelfDealing` blocks only the
//! degenerate case where buyer == seller.
//!
//! Consumers MUST therefore treat `seller_score` as unweighted, unverified
//! input to their own policy — for example by weighting distinct buyers over
//! raw counts, or by requiring an assurance tier that binds a seller-signed
//! offer. Do not present these counters as proof a seller misbehaved.
//!
//! ## On `require_auth` over a caller-supplied address
//!
//! The Soroban security guidance warns that `who.require_auth()` on an
//! arbitrary caller-supplied `who` proves nothing. That warning targets
//! *privileged* paths, where the authority must be loaded from storage.
//! Here there is no privilege to escalate: anchoring is permissionless and
//! grants the caller nothing. `record.buyer.require_auth()` establishes
//! *authorship* — this attestation is signed by the identity it is stored
//! under — which is precisely the property the off-chain layer needs.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, BytesN, Env,
};

const DAY_IN_LEDGERS: u32 = 17_280;
const RECORD_BUMP_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const RECORD_LIFETIME_THRESHOLD: u32 = RECORD_BUMP_AMOUNT - 5 * DAY_IN_LEDGERS;

/// Upper bound on the deliveries one batch may claim. The contract cannot see
/// the leaves behind a root, so `count` is the buyer's word; the cap bounds how
/// much OK history a single cheap transaction can assert.
pub const MAX_BATCH_COUNT: u32 = 1_024;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    DuplicatePayment = 1,
    ZeroHash = 2,
    CounterOverflow = 3,
    SelfDealing = 4,
    EmptyBatch = 5,
    BatchTooLarge = 6,
    DuplicateBatch = 7,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    Ok,
    Tainted,
    Mismatch,
    NotDelivered,
}

/// Caller-supplied fields. `anchored_at` is deliberately absent: a caller-
/// supplied anchor time would be forgeable, so the contract stamps it from
/// the ledger instead.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryInput {
    pub buyer: Address,
    pub seller: Address,
    pub payment_hash: BytesN<32>,
    pub commitment_hash: BytesN<32>,
    pub content_hash: BytesN<32>,
    pub verdict: Verdict,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRecord {
    pub buyer: Address,
    pub seller: Address,
    pub payment_hash: BytesN<32>,
    pub commitment_hash: BytesN<32>,
    pub content_hash: BytesN<32>,
    pub verdict: Verdict,
    /// Ledger time at which the attestation was anchored. The delivery itself
    /// happened off-chain and earlier; this is not the delivery time.
    pub anchored_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SellerScore {
    pub ok: u32,
    pub tainted: u32,
    pub mismatch: u32,
    pub not_delivered: u32,
    pub disputed: u32,
    /// Individually anchored records only.
    pub total: u32,
    /// OK deliveries asserted through batches. Kept apart from `ok` because a
    /// batch count is not backed by one record per delivery, so consumers must
    /// be able to weight it lower.
    pub batched_ok: u32,
}

/// A Merkle root over OK delivery receipts to one seller.
///
/// Anchoring every micropayment individually costs more than the payment; a
/// batch amortises one write over up to `MAX_BATCH_COUNT` deliveries. Only OK
/// verdicts are batched: exceptions stay individual so they are visible per
/// payment, immediately.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchInput {
    pub buyer: Address,
    pub seller: Address,
    pub root: BytesN<32>,
    pub count: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchRecord {
    pub buyer: Address,
    pub seller: Address,
    pub root: BytesN<32>,
    pub count: u32,
    pub anchored_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Delivery(BytesN<32>),
    SellerScore(Address),
    Batch(BytesN<32>),
}

/// Emitted on every successful anchor. `payment_hash` and `seller` are topics
/// so indexers can follow a single payment or a single seller's history.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryAnchored {
    #[topic]
    pub payment_hash: BytesN<32>,
    #[topic]
    pub seller: Address,
    pub buyer: Address,
    pub commitment_hash: BytesN<32>,
    pub content_hash: BytesN<32>,
    pub verdict: Verdict,
}

/// Emitted on every successful batch anchor.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchAnchored {
    #[topic]
    pub root: BytesN<32>,
    #[topic]
    pub seller: Address,
    pub buyer: Address,
    pub count: u32,
}

fn is_zero(env: &Env, value: &BytesN<32>) -> bool {
    *value == BytesN::from_array(env, &[0u8; 32])
}

fn bump(env: &Env, key: &DataKey) {
    env.storage()
        .persistent()
        .extend_ttl(key, RECORD_LIFETIME_THRESHOLD, RECORD_BUMP_AMOUNT);
}

#[contract]
pub struct AegisProof;

#[contractimpl]
impl AegisProof {
    /// Anchor a buyer attestation about one delivery.
    ///
    /// Authority is the buyer named *in the record*, so a third party cannot
    /// anchor (or defame) a purchase they did not make.
    pub fn anchor_delivery(env: Env, input: DeliveryInput) -> Result<(), Error> {
        input.buyer.require_auth();

        if input.buyer == input.seller {
            return Err(Error::SelfDealing);
        }
        if is_zero(&env, &input.payment_hash)
            || is_zero(&env, &input.commitment_hash)
            || is_zero(&env, &input.content_hash)
        {
            return Err(Error::ZeroHash);
        }

        let delivery_key = DataKey::Delivery(input.payment_hash.clone());
        if env.storage().persistent().has(&delivery_key) {
            return Err(Error::DuplicatePayment);
        }

        let record = DeliveryRecord {
            buyer: input.buyer.clone(),
            seller: input.seller.clone(),
            payment_hash: input.payment_hash.clone(),
            commitment_hash: input.commitment_hash.clone(),
            content_hash: input.content_hash.clone(),
            verdict: input.verdict.clone(),
            anchored_at: env.ledger().timestamp(),
        };

        let score_key = DataKey::SellerScore(input.seller.clone());
        let mut score: SellerScore = env
            .storage()
            .persistent()
            .get(&score_key)
            .unwrap_or_default();

        let counter = match record.verdict {
            Verdict::Ok => &mut score.ok,
            Verdict::Tainted => &mut score.tainted,
            Verdict::Mismatch => &mut score.mismatch,
            Verdict::NotDelivered => &mut score.not_delivered,
        };
        *counter = counter.checked_add(1).ok_or(Error::CounterOverflow)?;
        score.total = score.total.checked_add(1).ok_or(Error::CounterOverflow)?;

        env.storage().persistent().set(&delivery_key, &record);
        env.storage().persistent().set(&score_key, &score);
        bump(&env, &delivery_key);
        bump(&env, &score_key);

        DeliveryAnchored {
            payment_hash: record.payment_hash.clone(),
            seller: record.seller.clone(),
            buyer: record.buyer.clone(),
            commitment_hash: record.commitment_hash.clone(),
            content_hash: record.content_hash.clone(),
            verdict: record.verdict.clone(),
        }
        .publish(&env);

        Ok(())
    }

    /// Anchor a Merkle root over OK deliveries from one buyer to one seller.
    ///
    /// Proves only that this buyer committed to this root; inclusion of any
    /// given receipt is checked off-chain against the root. The contract does
    /// not enforce payment-hash uniqueness inside a batch — it never sees the
    /// leaves.
    pub fn anchor_batch(env: Env, input: BatchInput) -> Result<(), Error> {
        input.buyer.require_auth();

        if input.buyer == input.seller {
            return Err(Error::SelfDealing);
        }
        if is_zero(&env, &input.root) {
            return Err(Error::ZeroHash);
        }
        if input.count == 0 {
            return Err(Error::EmptyBatch);
        }
        if input.count > MAX_BATCH_COUNT {
            return Err(Error::BatchTooLarge);
        }

        let batch_key = DataKey::Batch(input.root.clone());
        if env.storage().persistent().has(&batch_key) {
            return Err(Error::DuplicateBatch);
        }

        let score_key = DataKey::SellerScore(input.seller.clone());
        let mut score: SellerScore = env
            .storage()
            .persistent()
            .get(&score_key)
            .unwrap_or_default();
        score.batched_ok = score
            .batched_ok
            .checked_add(input.count)
            .ok_or(Error::CounterOverflow)?;

        let record = BatchRecord {
            buyer: input.buyer.clone(),
            seller: input.seller.clone(),
            root: input.root.clone(),
            count: input.count,
            anchored_at: env.ledger().timestamp(),
        };

        env.storage().persistent().set(&batch_key, &record);
        env.storage().persistent().set(&score_key, &score);
        bump(&env, &batch_key);
        bump(&env, &score_key);

        BatchAnchored {
            root: record.root.clone(),
            seller: record.seller.clone(),
            buyer: record.buyer.clone(),
            count: record.count,
        }
        .publish(&env);

        Ok(())
    }

    pub fn get_batch(env: Env, root: BytesN<32>) -> Option<BatchRecord> {
        let key = DataKey::Batch(root);
        let record: Option<BatchRecord> = env.storage().persistent().get(&key);
        if record.is_some() {
            bump(&env, &key);
        }
        record
    }

    pub fn get_delivery(env: Env, payment_hash: BytesN<32>) -> Option<DeliveryRecord> {
        let key = DataKey::Delivery(payment_hash);
        let record: Option<DeliveryRecord> = env.storage().persistent().get(&key);
        if record.is_some() {
            bump(&env, &key);
        }
        record
    }

    /// Returns a zeroed score for an unknown seller rather than erroring, so an
    /// agent can query before its first purchase from that seller.
    pub fn seller_score(env: Env, seller: Address) -> SellerScore {
        let key = DataKey::SellerScore(seller);
        let score: Option<SellerScore> = env.storage().persistent().get(&key);
        match score {
            Some(value) => {
                bump(&env, &key);
                value
            }
            None => SellerScore::default(),
        }
    }
}

#[cfg(test)]
mod test;
