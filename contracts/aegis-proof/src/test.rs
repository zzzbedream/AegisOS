#![cfg(test)]

use super::*;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger, MockAuth, MockAuthInvoke};
use soroban_sdk::{Address, BytesN, Env, Event as _, IntoVal};

const NOW: u64 = 1_900_000_000;

struct Fixture {
    env: Env,
    client: AegisProofClient<'static>,
    contract_id: Address,
    buyer: Address,
    seller: Address,
}

fn setup() -> Fixture {
    let env = Env::default();
    env.ledger().set_timestamp(NOW);
    let contract_id = env.register(AegisProof, ());
    let client = AegisProofClient::new(&env, &contract_id);
    let buyer = Address::generate(&env);
    let seller = Address::generate(&env);
    Fixture { env, client, contract_id, buyer, seller }
}

fn hash(env: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(env, &[byte; 32])
}

fn input(f: &Fixture, payment: u8, verdict: Verdict) -> DeliveryInput {
    DeliveryInput {
        buyer: f.buyer.clone(),
        seller: f.seller.clone(),
        payment_hash: hash(&f.env, payment),
        commitment_hash: hash(&f.env, 0xC0),
        content_hash: hash(&f.env, 0xC1),
        verdict,
    }
}

#[test]
fn anchor_ok_increments_ok_score() {
    let f = setup();
    f.env.mock_all_auths();
    f.client.anchor_delivery(&input(&f, 1, Verdict::Ok));

    let score = f.client.seller_score(&f.seller);
    assert_eq!(score.ok, 1);
    assert_eq!(score.total, 1);
    assert_eq!(score.tainted, 0);
    assert_eq!(score.mismatch, 0);
}

#[test]
fn anchor_tainted_increments_tainted_score() {
    let f = setup();
    f.env.mock_all_auths();
    f.client.anchor_delivery(&input(&f, 2, Verdict::Tainted));

    let score = f.client.seller_score(&f.seller);
    assert_eq!(score.tainted, 1);
    assert_eq!(score.ok, 0);
    assert_eq!(score.total, 1);
}

#[test]
fn anchor_mismatch_increments_mismatch_score() {
    let f = setup();
    f.env.mock_all_auths();
    f.client.anchor_delivery(&input(&f, 3, Verdict::Mismatch));

    let score = f.client.seller_score(&f.seller);
    assert_eq!(score.mismatch, 1);
    assert_eq!(score.total, 1);
}

#[test]
fn anchor_not_delivered_increments_its_own_counter() {
    let f = setup();
    f.env.mock_all_auths();
    f.client.anchor_delivery(&input(&f, 4, Verdict::NotDelivered));

    let score = f.client.seller_score(&f.seller);
    assert_eq!(score.not_delivered, 1);
    assert_eq!(score.total, 1);
}

#[test]
fn duplicate_payment_hash_is_rejected() {
    let f = setup();
    f.env.mock_all_auths();
    f.client.anchor_delivery(&input(&f, 5, Verdict::Ok));

    // A second attestation for the same payment must not overwrite the first,
    // otherwise a buyer could rewrite history after the fact.
    let result = f.client.try_anchor_delivery(&input(&f, 5, Verdict::Tainted));
    assert_eq!(result, Err(Ok(Error::DuplicatePayment)));

    let record = f.client.get_delivery(&hash(&f.env, 5)).unwrap();
    assert_eq!(record.verdict, Verdict::Ok);
    assert_eq!(f.client.seller_score(&f.seller).total, 1);
}

#[test]
#[should_panic(expected = "Auth, InvalidAction")]
fn only_record_buyer_can_anchor() {
    let f = setup();
    let mallory = Address::generate(&f.env);
    let record = input(&f, 6, Verdict::Ok);

    // Authorize mallory only. The contract requires auth from the buyer named
    // in the record, so this must fail. `mock_all_auths` would authorize
    // everything and silently pass, which is why it is not used here.
    f.env.mock_auths(&[MockAuth {
        address: &mallory,
        invoke: &MockAuthInvoke {
            contract: &f.contract_id,
            fn_name: "anchor_delivery",
            args: (record.clone(),).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);

    f.client.anchor_delivery(&record);
}

#[test]
fn zero_hashes_are_rejected() {
    let f = setup();
    f.env.mock_all_auths();

    let mut bad = input(&f, 7, Verdict::Ok);
    bad.payment_hash = hash(&f.env, 0);
    assert_eq!(f.client.try_anchor_delivery(&bad), Err(Ok(Error::ZeroHash)));

    let mut bad = input(&f, 7, Verdict::Ok);
    bad.commitment_hash = hash(&f.env, 0);
    assert_eq!(f.client.try_anchor_delivery(&bad), Err(Ok(Error::ZeroHash)));

    let mut bad = input(&f, 7, Verdict::Ok);
    bad.content_hash = hash(&f.env, 0);
    assert_eq!(f.client.try_anchor_delivery(&bad), Err(Ok(Error::ZeroHash)));
}

#[test]
fn self_dealing_is_rejected() {
    let f = setup();
    f.env.mock_all_auths();

    let mut record = input(&f, 8, Verdict::Ok);
    record.seller = f.buyer.clone();
    assert_eq!(
        f.client.try_anchor_delivery(&record),
        Err(Ok(Error::SelfDealing))
    );
}

#[test]
fn get_missing_delivery_returns_none() {
    let f = setup();
    assert_eq!(f.client.get_delivery(&hash(&f.env, 0xEE)), None);
}

#[test]
fn unknown_seller_scores_zero() {
    let f = setup();
    let stranger = Address::generate(&f.env);
    let score = f.client.seller_score(&stranger);
    assert_eq!(score.total, 0);
    assert_eq!(score.ok, 0);
}

#[test]
fn seller_scores_are_isolated() {
    let f = setup();
    f.env.mock_all_auths();
    let other_seller = Address::generate(&f.env);

    f.client.anchor_delivery(&input(&f, 10, Verdict::Ok));

    let mut second = input(&f, 11, Verdict::Tainted);
    second.seller = other_seller.clone();
    f.client.anchor_delivery(&second);

    assert_eq!(f.client.seller_score(&f.seller).ok, 1);
    assert_eq!(f.client.seller_score(&f.seller).tainted, 0);
    assert_eq!(f.client.seller_score(&other_seller).tainted, 1);
    assert_eq!(f.client.seller_score(&other_seller).ok, 0);
}

#[test]
fn anchored_at_comes_from_the_ledger_not_the_caller() {
    let f = setup();
    f.env.mock_all_auths();
    f.client.anchor_delivery(&input(&f, 12, Verdict::Ok));

    let record = f.client.get_delivery(&hash(&f.env, 12)).unwrap();
    assert_eq!(record.anchored_at, NOW);
}

#[test]
fn score_counter_overflow_is_checked() {
    let f = setup();
    f.env.mock_all_auths();

    // Seed a maxed-out counter directly; anchoring 2^32 times is not testable.
    f.env.as_contract(&f.contract_id, || {
        let key = DataKey::SellerScore(f.seller.clone());
        let maxed = SellerScore {
            ok: u32::MAX,
            tainted: 0,
            mismatch: 0,
            not_delivered: 0,
            disputed: 0,
            total: u32::MAX,
            batched_ok: 0,
        };
        f.env.storage().persistent().set(&key, &maxed);
    });

    assert_eq!(
        f.client.try_anchor_delivery(&input(&f, 13, Verdict::Ok)),
        Err(Ok(Error::CounterOverflow))
    );
}

#[test]
fn events_contain_payment_hash_and_seller() {
    let f = setup();
    f.env.mock_all_auths();
    let record = input(&f, 14, Verdict::Tainted);
    f.client.anchor_delivery(&record);

    let expected = DeliveryAnchored {
        payment_hash: record.payment_hash.clone(),
        seller: record.seller.clone(),
        buyer: record.buyer.clone(),
        commitment_hash: record.commitment_hash.clone(),
        content_hash: record.content_hash.clone(),
        verdict: Verdict::Tainted,
    };

    assert_eq!(
        f.env.events().all(),
        [expected.to_xdr(&f.env, &f.contract_id)]
    );
}

// ------------------------------------------------------------------ batches

fn batch(f: &Fixture, root: u8, count: u32) -> BatchInput {
    BatchInput {
        buyer: f.buyer.clone(),
        seller: f.seller.clone(),
        root: hash(&f.env, root),
        count,
    }
}

#[test]
fn batch_counts_apart_from_individual_ok() {
    let f = setup();
    f.env.mock_all_auths();
    f.client.anchor_delivery(&input(&f, 20, Verdict::Ok));
    f.client.anchor_batch(&batch(&f, 0xB1, 100));

    let score = f.client.seller_score(&f.seller);
    assert_eq!(score.ok, 1);
    assert_eq!(score.total, 1);
    assert_eq!(score.batched_ok, 100);
}

#[test]
fn batch_record_is_stamped_by_the_ledger() {
    let f = setup();
    f.env.mock_all_auths();
    f.client.anchor_batch(&batch(&f, 0xB2, 7));

    let record = f.client.get_batch(&hash(&f.env, 0xB2)).unwrap();
    assert_eq!(record.buyer, f.buyer);
    assert_eq!(record.seller, f.seller);
    assert_eq!(record.count, 7);
    assert_eq!(record.anchored_at, NOW);
    assert_eq!(f.client.get_batch(&hash(&f.env, 0xEE)), None);
}

#[test]
fn a_root_cannot_be_anchored_twice() {
    let f = setup();
    f.env.mock_all_auths();
    f.client.anchor_batch(&batch(&f, 0xB3, 5));

    assert_eq!(
        f.client.try_anchor_batch(&batch(&f, 0xB3, 500)),
        Err(Ok(Error::DuplicateBatch))
    );
    assert_eq!(f.client.seller_score(&f.seller).batched_ok, 5);
}

#[test]
fn empty_oversized_zero_root_and_self_dealing_batches_are_rejected() {
    let f = setup();
    f.env.mock_all_auths();

    assert_eq!(f.client.try_anchor_batch(&batch(&f, 0xB4, 0)), Err(Ok(Error::EmptyBatch)));
    assert_eq!(
        f.client.try_anchor_batch(&batch(&f, 0xB4, MAX_BATCH_COUNT + 1)),
        Err(Ok(Error::BatchTooLarge))
    );
    assert_eq!(f.client.try_anchor_batch(&batch(&f, 0, 1)), Err(Ok(Error::ZeroHash)));

    let mut own = batch(&f, 0xB5, 1);
    own.seller = f.buyer.clone();
    assert_eq!(f.client.try_anchor_batch(&own), Err(Ok(Error::SelfDealing)));

    // The cap is inclusive.
    f.client.anchor_batch(&batch(&f, 0xB6, MAX_BATCH_COUNT));
    assert_eq!(f.client.seller_score(&f.seller).batched_ok, MAX_BATCH_COUNT);
}

#[test]
#[should_panic(expected = "Auth, InvalidAction")]
fn only_batch_buyer_can_anchor_it() {
    let f = setup();
    let mallory = Address::generate(&f.env);
    let record = batch(&f, 0xB7, 3);

    f.env.mock_auths(&[MockAuth {
        address: &mallory,
        invoke: &MockAuthInvoke {
            contract: &f.contract_id,
            fn_name: "anchor_batch",
            args: (record.clone(),).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);

    f.client.anchor_batch(&record);
}

#[test]
fn batched_counter_overflow_is_checked() {
    let f = setup();
    f.env.mock_all_auths();
    f.env.as_contract(&f.contract_id, || {
        let key = DataKey::SellerScore(f.seller.clone());
        let maxed = SellerScore {
            batched_ok: u32::MAX,
            ..SellerScore::default()
        };
        f.env.storage().persistent().set(&key, &maxed);
    });

    assert_eq!(
        f.client.try_anchor_batch(&batch(&f, 0xB8, 1)),
        Err(Ok(Error::CounterOverflow))
    );
}

#[test]
fn batch_event_carries_root_and_seller() {
    let f = setup();
    f.env.mock_all_auths();
    let record = batch(&f, 0xB9, 42);
    f.client.anchor_batch(&record);

    let expected = BatchAnchored {
        root: record.root.clone(),
        seller: record.seller.clone(),
        buyer: record.buyer.clone(),
        count: 42,
    };
    assert_eq!(f.env.events().all(), [expected.to_xdr(&f.env, &f.contract_id)]);
}
