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

use aegis_chain::{chain_link, merkle_root, range_leaf};
use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, Address,
    BytesN, Env, Map, Vec,
};

const DAY_IN_LEDGERS: u32 = 17_280;
const RECORD_BUMP_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const RECORD_LIFETIME_THRESHOLD: u32 = RECORD_BUMP_AMOUNT - 5 * DAY_IN_LEDGERS;

/// Upper bound on the deliveries one batch may claim. The contract cannot see
/// the leaves behind a root, so `count` is the buyer's word; the cap bounds how
/// much OK history a single cheap transaction can assert.
pub const MAX_BATCH_COUNT: u32 = 1_024;

/// Payments one range may cover. Bounded by the transaction's CPU and size
/// budget: every leaf is hashed twice on-chain (chain link and range leaf).
pub const MAX_RANGE_LEAVES: u32 = 64;

/// Later payments a range may carry only to reach the account's head. They are
/// verified, not counted; they become leaves of the next range. Without this an
/// account more than MAX_RANGE_LEAVES payments behind could never anchor again.
pub const MAX_RANGE_TAIL: u32 = 192;

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
    UnknownAccount = 8,
    EmptyRange = 9,
    RangeTooLarge = 10,
    RangeOutOfOrder = 11,
    RangeNotAtHead = 12,
    ChainMismatch = 13,
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
    /// Verdicts from ranges: each one is bound to a payment the buyer's
    /// AegisOS account notarized, counted once, with no payment omitted. These
    /// are the counters that do not rest on the buyer's word about *which*
    /// payments happened — only about what each one delivered.
    pub verified_ok: u32,
    pub verified_tainted: u32,
    pub verified_mismatch: u32,
    pub verified_not_delivered: u32,
}

/// Mirrors the account's `Config`. Map field names are the ABI.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountConfig {
    pub owner: BytesN<32>,
    pub authority: BytesN<32>,
    pub session: BytesN<32>,
    pub allowed_assets: Vec<Address>,
    pub registry: Option<Address>,
}

/// Mirrors the account's `Head`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountHead {
    pub seq: u64,
    pub chain_head: BytesN<32>,
}

/// The one account function the registry relies on.
#[contractclient(name = "AccountClient")]
pub trait AccountInterface {
    fn head(env: Env) -> AccountHead;
}

/// One notarized payment and what it delivered.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeLeaf {
    pub seq: u64,
    pub commitment_hash: BytesN<32>,
    pub seller: Address,
    pub amount: i128,
    pub content_hash: BytesN<32>,
    pub verdict: Verdict,
}

/// A later payment, supplied only so the chain can be followed to the head.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainStep {
    pub commitment_hash: BytesN<32>,
    pub seller: Address,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeInput {
    pub account: Address,
    pub from_seq: u64,
    pub leaves: Vec<RangeLeaf>,
    /// Payments after the last leaf, up to the account's head. Not counted.
    pub tail: Vec<ChainStep>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeRecord {
    pub account: Address,
    pub from_seq: u64,
    pub to_seq: u64,
    pub root: BytesN<32>,
    pub ok: u32,
    pub tainted: u32,
    pub mismatch: u32,
    pub not_delivered: u32,
    pub anchored_at: u64,
}

/// How far an account's payments have been anchored.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub seq: u64,
    pub chain_head: BytesN<32>,
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
    AccountWasm,
    Account(Address),
    Checkpoint(Address),
    Range(Address, u64),
}

/// Emitted when a range is accepted.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeAnchored {
    #[topic]
    pub account: Address,
    pub from_seq: u64,
    pub to_seq: u64,
    pub root: BytesN<32>,
}

fn verdict_code(verdict: &Verdict) -> u32 {
    match verdict {
        Verdict::Ok => 0,
        Verdict::Tainted => 1,
        Verdict::Mismatch => 2,
        Verdict::NotDelivered => 3,
    }
}

fn zero_checkpoint(env: &Env) -> Checkpoint {
    Checkpoint { seq: 0, chain_head: BytesN::from_array(env, &[0u8; 32]) }
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
    /// `account_wasm_hash` is the only account code this registry will
    /// create, and therefore the only notarization it trusts. Fixed for the
    /// life of the registry: a new account version means a new registry.
    pub fn __constructor(env: Env, account_wasm_hash: BytesN<32>) {
        env.storage().instance().set(&DataKey::AccountWasm, &account_wasm_hash);
    }

    pub fn account_wasm(env: Env) -> BytesN<32> {
        env.storage().instance().get(&DataKey::AccountWasm).unwrap()
    }

    /// Deploy an AegisOS account that points back at this registry. Anyone may
    /// create one; it is controlled only by the keys in its config.
    pub fn create_account(
        env: Env,
        owner: BytesN<32>,
        authority: BytesN<32>,
        session: BytesN<32>,
        allowed_assets: Vec<Address>,
        salt: BytesN<32>,
    ) -> Address {
        let config = AccountConfig {
            owner,
            authority,
            session,
            allowed_assets,
            registry: Some(env.current_contract_address()),
        };
        let wasm: BytesN<32> = env.storage().instance().get(&DataKey::AccountWasm).unwrap();
        let account = env
            .deployer()
            .with_current_contract(salt)
            .deploy_v2(wasm, (config,));
        let key = DataKey::Account(account.clone());
        env.storage().persistent().set(&key, &true);
        bump(&env, &key);
        account
    }

    pub fn is_account(env: Env, account: Address) -> bool {
        env.storage().persistent().has(&DataKey::Account(account))
    }

    pub fn checkpoint(env: Env, account: Address) -> Checkpoint {
        env.storage()
            .persistent()
            .get(&DataKey::Checkpoint(account))
            .unwrap_or_else(|| zero_checkpoint(&env))
    }

    pub fn get_range(env: Env, account: Address, from_seq: u64) -> Option<RangeRecord> {
        let key = DataKey::Range(account, from_seq);
        let record: Option<RangeRecord> = env.storage().persistent().get(&key);
        if record.is_some() {
            bump(&env, &key);
        }
        record
    }

    /// Anchor the next contiguous run of an account's notarized payments.
    ///
    /// The registry recomputes the account's payment chain from its last
    /// checkpoint over the given leaves, and accepts only if that lands exactly
    /// on the head the account holds now. So every payment the account
    /// notarized is anchored exactly once, in order, none invented, none left
    /// out; and the verdict counts are computed here, from the leaves.
    pub fn anchor_range(env: Env, input: RangeInput) -> Result<(), Error> {
        let account_key = DataKey::Account(input.account.clone());
        if !env.storage().persistent().has(&account_key) {
            return Err(Error::UnknownAccount);
        }
        input.account.require_auth();

        let count = input.leaves.len();
        if count == 0 {
            return Err(Error::EmptyRange);
        }
        if count > MAX_RANGE_LEAVES || input.tail.len() > MAX_RANGE_TAIL {
            return Err(Error::RangeTooLarge);
        }

        let checkpoint_key = DataKey::Checkpoint(input.account.clone());
        let checkpoint: Checkpoint = env
            .storage()
            .persistent()
            .get(&checkpoint_key)
            .unwrap_or_else(|| zero_checkpoint(&env));
        if input.from_seq != checkpoint.seq + 1 {
            return Err(Error::RangeOutOfOrder);
        }

        let mut head = checkpoint.chain_head.clone();
        let mut leaves: Vec<BytesN<32>> = Vec::new(&env);
        let mut scores: Map<Address, SellerScore> = Map::new(&env);
        let (mut ok, mut tainted, mut mismatch, mut not_delivered) = (0u32, 0u32, 0u32, 0u32);

        for (i, leaf) in input.leaves.iter().enumerate() {
            if leaf.seq != input.from_seq + i as u64 {
                return Err(Error::RangeOutOfOrder);
            }
            if is_zero(&env, &leaf.commitment_hash) || is_zero(&env, &leaf.content_hash) {
                return Err(Error::ZeroHash);
            }
            if leaf.seller == input.account {
                return Err(Error::SelfDealing);
            }
            head = chain_link(&env, &head, leaf.seq, &leaf.commitment_hash, &leaf.seller, leaf.amount);
            leaves.push_back(range_leaf(
                &env,
                leaf.seq,
                &leaf.commitment_hash,
                &leaf.seller,
                leaf.amount,
                &leaf.content_hash,
                verdict_code(&leaf.verdict),
            ));

            let mut score = match scores.get(leaf.seller.clone()) {
                Some(score) => score,
                None => env
                    .storage()
                    .persistent()
                    .get(&DataKey::SellerScore(leaf.seller.clone()))
                    .unwrap_or_default(),
            };
            let (range_counter, seller_counter) = match leaf.verdict {
                Verdict::Ok => (&mut ok, &mut score.verified_ok),
                Verdict::Tainted => (&mut tainted, &mut score.verified_tainted),
                Verdict::Mismatch => (&mut mismatch, &mut score.verified_mismatch),
                Verdict::NotDelivered => (&mut not_delivered, &mut score.verified_not_delivered),
            };
            *range_counter += 1;
            *seller_counter = seller_counter.checked_add(1).ok_or(Error::CounterOverflow)?;
            scores.set(leaf.seller.clone(), score);
        }

        let to_seq = input.from_seq + count as u64 - 1;

        // Follow the chain past the range to the head, without counting.
        let mut tail_head = head.clone();
        let mut tail_seq = to_seq;
        for step in input.tail.iter() {
            tail_seq += 1;
            tail_head = chain_link(&env, &tail_head, tail_seq, &step.commitment_hash, &step.seller, step.amount);
        }
        let account_head = AccountClient::new(&env, &input.account).head();
        if account_head.seq != tail_seq {
            return Err(Error::RangeNotAtHead);
        }
        if account_head.chain_head != tail_head {
            return Err(Error::ChainMismatch);
        }

        let root = merkle_root(&env, &leaves);
        let record = RangeRecord {
            account: input.account.clone(),
            from_seq: input.from_seq,
            to_seq,
            root: root.clone(),
            ok,
            tainted,
            mismatch,
            not_delivered,
            anchored_at: env.ledger().timestamp(),
        };
        let range_key = DataKey::Range(input.account.clone(), input.from_seq);
        env.storage().persistent().set(&range_key, &record);
        env.storage()
            .persistent()
            .set(&checkpoint_key, &Checkpoint { seq: to_seq, chain_head: head });
        bump(&env, &range_key);
        bump(&env, &checkpoint_key);
        bump(&env, &account_key);
        for (seller, score) in scores.iter() {
            let key = DataKey::SellerScore(seller);
            env.storage().persistent().set(&key, &score);
            bump(&env, &key);
        }

        RangeAnchored { account: input.account, from_seq: input.from_seq, to_seq, root }.publish(&env);
        Ok(())
    }

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
