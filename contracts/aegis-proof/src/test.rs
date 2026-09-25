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
    let contract_id = env.register(AegisProof, (BytesN::from_array(&env, &[7u8; 32]),));
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
            total: u32::MAX,
            ..SellerScore::default()
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

// ------------------------------------------------------------------ ranges

mod ranges {
    extern crate std;

    use super::*;
    use aegis_account::{
        commitment_digest, AegisAccount, AegisAccountClient, AegisAuth, Config as AccountConfigNative,
        OnChainCommitment, PaymentAuth,
    };
    use aegis_chain::{merkle_root, range_leaf};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use soroban_sdk::{
        auth::{Context, ContractContext},
        vec, Bytes, Symbol, Val, Vec,
    };

    const PRICE: i128 = 10_000;

    pub struct World {
        pub f: Fixture,
        pub account: Address,
        pub asset: Address,
        pub other_seller: Address,
        authority: SigningKey,
        session: SigningKey,
        paid: std::vec::Vec<(u64, BytesN<32>, Address, i128)>,
    }

    fn sign(env: &Env, key: &SigningKey, msg: &[u8]) -> BytesN<64> {
        BytesN::from_array(env, &key.sign(msg).to_bytes())
    }

    pub fn world() -> World {
        let f = setup();
        let owner = SigningKey::generate(&mut OsRng);
        let authority = SigningKey::generate(&mut OsRng);
        let session = SigningKey::generate(&mut OsRng);
        let asset = Address::generate(&f.env);
        let config = AccountConfigNative {
            owner: BytesN::from_array(&f.env, &owner.verifying_key().to_bytes()),
            authority: BytesN::from_array(&f.env, &authority.verifying_key().to_bytes()),
            session: BytesN::from_array(&f.env, &session.verifying_key().to_bytes()),
            allowed_assets: vec![&f.env, asset.clone()],
            registry: Some(f.contract_id.clone()),
        };
        let account = f.env.register(AegisAccount, (config,));
        // Stand-in for create_account, which needs the uploaded wasm.
        f.env.as_contract(&f.contract_id, || {
            f.env.storage().persistent().set(&DataKey::Account(account.clone()), &true);
        });
        let other_seller = Address::generate(&f.env);
        World { f, account, asset, other_seller, authority, session, paid: std::vec::Vec::new() }
    }

    impl World {
        /// A real notarized payment: runs the account's own __check_auth.
        pub fn pay(&mut self, seller: &Address, amount: i128) {
            let env = &self.f.env;
            let n = self.paid.len() as u8 + 1;
            let c = OnChainCommitment {
                commitment_hash: BytesN::from_array(env, &[n; 32]),
                seller: seller.clone(),
                asset: self.asset.clone(),
                max_amount: amount,
                expires_at: NOW + 600,
            };
            let payload: BytesN<32> = env.crypto().sha256(&Bytes::from_array(env, &[n; 32])).to_bytes();
            let digest = commitment_digest(env, &self.account, &c).to_array();
            let auth = AegisAuth::Payment(PaymentAuth {
                authority_sig: sign(env, &self.authority, &digest),
                session_sig: sign(env, &self.session, &payload.to_array()),
                commitment: c.clone(),
            });
            let ctx = Context::Contract(ContractContext {
                contract: self.asset.clone(),
                fn_name: Symbol::new(env, "transfer"),
                args: (self.account.clone(), seller.clone(), amount).into_val(env),
            });
            let signature: Val = auth.into_val(env);
            env.try_invoke_contract_check_auth::<aegis_account::AccError>(&self.account, &payload, signature, &vec![env, ctx])
                .unwrap();
            let seq = AegisAccountClient::new(env, &self.account).head().seq;
            self.paid.push((seq, c.commitment_hash, seller.clone(), amount));
        }

        pub fn leaves(&self, from: u64, to: u64, verdicts: &[Verdict]) -> Vec<RangeLeaf> {
            let env = &self.f.env;
            let mut out = Vec::new(env);
            for (i, (seq, commitment, seller, amount)) in self.paid.iter().enumerate() {
                if *seq < from || *seq > to {
                    continue;
                }
                out.push_back(RangeLeaf {
                    seq: *seq,
                    commitment_hash: commitment.clone(),
                    seller: seller.clone(),
                    amount: *amount,
                    content_hash: BytesN::from_array(env, &[0xC0 + i as u8; 32]),
                    verdict: verdicts[(*seq - from) as usize].clone(),
                });
            }
            out
        }

        pub fn anchor(&self, from: u64, leaves: Vec<RangeLeaf>) -> Result<(), Error> {
            self.f.env.mock_all_auths();
            self.anchor_with_tail(from, leaves, Vec::new(&self.f.env))
        }

        pub fn tail(&self, from: u64, to: u64) -> Vec<ChainStep> {
            let env = &self.f.env;
            let mut out = Vec::new(env);
            for (seq, commitment, seller, amount) in self.paid.iter() {
                if *seq >= from && *seq <= to {
                    out.push_back(ChainStep { commitment_hash: commitment.clone(), seller: seller.clone(), amount: *amount });
                }
            }
            out
        }

        pub fn anchor_with_tail(&self, from: u64, leaves: Vec<RangeLeaf>, tail: Vec<ChainStep>) -> Result<(), Error> {
            self.f.env.mock_all_auths();
            match self.f.client.try_anchor_range(&RangeInput { account: self.account.clone(), from_seq: from, leaves, tail }) {
                Ok(Ok(())) => Ok(()),
                Err(Ok(e)) => Err(e),
                other => panic!("unexpected: {:?}", other),
            }
        }
    }

    #[test]
    fn a_range_of_notarized_payments_is_accepted_and_the_contract_counts() {
        let mut w = world();
        let s1 = w.f.seller.clone();
        let s2 = w.other_seller.clone();
        w.pay(&s1, PRICE);
        w.pay(&s1, PRICE);
        w.pay(&s2, PRICE / 2);
        let leaves = w.leaves(1, 3, &[Verdict::Ok, Verdict::Tainted, Verdict::Ok]);

        assert_eq!(w.anchor(1, leaves.clone()), Ok(()));

        let record = w.f.client.get_range(&w.account, &1).unwrap();
        assert_eq!((record.from_seq, record.to_seq), (1, 3));
        assert_eq!((record.ok, record.tainted, record.mismatch, record.not_delivered), (2, 1, 0, 0));
        let expected: Vec<BytesN<32>> = {
            let env = &w.f.env;
            let mut v = Vec::new(env);
            for l in leaves.iter() {
                let code = match l.verdict { Verdict::Ok => 0, Verdict::Tainted => 1, Verdict::Mismatch => 2, Verdict::NotDelivered => 3 };
                v.push_back(range_leaf(env, l.seq, &l.commitment_hash, &l.seller, l.amount, &l.content_hash, code));
            }
            v
        };
        assert_eq!(record.root, merkle_root(&w.f.env, &expected));

        let checkpoint = w.f.client.checkpoint(&w.account);
        assert_eq!(checkpoint.seq, 3);
        assert_eq!(checkpoint.chain_head, AegisAccountClient::new(&w.f.env, &w.account).head().chain_head);

        let score1 = w.f.client.seller_score(&s1);
        assert_eq!((score1.verified_ok, score1.verified_tainted), (1, 1));
        assert_eq!(score1.ok, 0, "attested counters are untouched by ranges");
        assert_eq!(w.f.client.seller_score(&s2).verified_ok, 1);
    }

    #[test]
    fn the_next_range_continues_from_the_checkpoint() {
        let mut w = world();
        let s = w.f.seller.clone();
        w.pay(&s, PRICE);
        assert_eq!(w.anchor(1, w.leaves(1, 1, &[Verdict::Ok])), Ok(()));
        w.pay(&s, PRICE);
        w.pay(&s, PRICE);
        // Re-anchoring the first payment is refused: it was already counted.
        assert_eq!(w.anchor(1, w.leaves(1, 3, &[Verdict::Ok, Verdict::Ok, Verdict::Ok])), Err(Error::RangeOutOfOrder));
        assert_eq!(w.anchor(2, w.leaves(2, 3, &[Verdict::Ok, Verdict::Mismatch])), Ok(()));
        assert_eq!(w.f.client.checkpoint(&w.account).seq, 3);
        assert_eq!(w.f.client.seller_score(&s).verified_ok, 2);
    }

    #[test]
    fn a_range_that_leaves_out_a_payment_is_refused() {
        let mut w = world();
        let s = w.f.seller.clone();
        w.pay(&s, PRICE);
        w.pay(&s, PRICE);
        w.pay(&s, PRICE);
        // Stops short of the head: the third payment would go uncounted.
        assert_eq!(w.anchor(1, w.leaves(1, 2, &[Verdict::Ok, Verdict::Ok])), Err(Error::RangeNotAtHead));
    }

    #[test]
    fn an_account_far_behind_catches_up_through_the_tail() {
        let mut w = world();
        let s = w.f.seller.clone();
        for _ in 0..3 {
            w.pay(&s, PRICE);
        }
        // Anchor 1..2 now; 3 rides along only to prove the chain reaches the head.
        assert_eq!(w.anchor_with_tail(1, w.leaves(1, 2, &[Verdict::Ok, Verdict::Ok]), w.tail(3, 3)), Ok(()));
        assert_eq!(w.f.client.checkpoint(&w.account).seq, 2);
        assert_eq!(w.f.client.seller_score(&s).verified_ok, 2, "the tail is not counted");
        assert_eq!(w.anchor(3, w.leaves(3, 3, &[Verdict::Ok])), Ok(()));
        assert_eq!(w.f.client.seller_score(&s).verified_ok, 3);
    }

    #[test]
    fn a_tail_that_lies_about_later_payments_is_refused() {
        let mut w = world();
        let s = w.f.seller.clone();
        w.pay(&s, PRICE);
        w.pay(&s, PRICE);
        let mut tail = w.tail(2, 2);
        let mut step = tail.get(0).unwrap();
        step.amount = 1;
        tail.set(0, step);
        assert_eq!(w.anchor_with_tail(1, w.leaves(1, 1, &[Verdict::Ok]), tail), Err(Error::ChainMismatch));
    }

    #[test]
    fn a_skipped_or_reordered_seq_is_refused() {
        let mut w = world();
        let s = w.f.seller.clone();
        w.pay(&s, PRICE);
        w.pay(&s, PRICE);
        let leaves = w.leaves(1, 2, &[Verdict::Ok, Verdict::Ok]);
        let mut swapped = Vec::new(&w.f.env);
        swapped.push_back(leaves.get(1).unwrap());
        swapped.push_back(leaves.get(0).unwrap());
        assert_eq!(w.anchor(1, swapped), Err(Error::RangeOutOfOrder));
        assert_eq!(w.anchor(2, w.leaves(2, 2, &[Verdict::Ok])), Err(Error::RangeOutOfOrder));
    }

    #[test]
    fn an_edited_or_invented_payment_breaks_the_chain() {
        let mut w = world();
        let s = w.f.seller.clone();
        w.pay(&s, PRICE);
        w.pay(&s, PRICE);
        let leaves = w.leaves(1, 2, &[Verdict::Ok, Verdict::Ok]);

        let mut cheaper = leaves.clone();
        let mut leaf = cheaper.get(1).unwrap();
        leaf.amount = PRICE - 1;
        cheaper.set(1, leaf);
        assert_eq!(w.anchor(1, cheaper), Err(Error::ChainMismatch));

        let mut redirected = leaves.clone();
        let mut leaf = redirected.get(0).unwrap();
        leaf.seller = w.other_seller.clone();
        redirected.set(0, leaf);
        assert_eq!(w.anchor(1, redirected), Err(Error::ChainMismatch));

        let mut invented = leaves;
        let mut leaf = invented.get(1).unwrap();
        leaf.commitment_hash = BytesN::from_array(&w.f.env, &[0xEE; 32]);
        invented.set(1, leaf);
        assert_eq!(w.anchor(1, invented), Err(Error::ChainMismatch));
    }

    #[test]
    fn only_registered_accounts_and_bounded_ranges() {
        let mut w = world();
        let s = w.f.seller.clone();
        w.pay(&s, PRICE);
        w.f.env.mock_all_auths();
        let stranger = Address::generate(&w.f.env);
        assert_eq!(
            w.f.client.try_anchor_range(&RangeInput { account: stranger, from_seq: 1, leaves: w.leaves(1, 1, &[Verdict::Ok]), tail: Vec::new(&w.f.env) }),
            Err(Ok(Error::UnknownAccount))
        );
        assert_eq!(w.anchor(1, Vec::new(&w.f.env)), Err(Error::EmptyRange));

        let mut many = Vec::new(&w.f.env);
        let one = w.leaves(1, 1, &[Verdict::Ok]).get(0).unwrap();
        for _ in 0..=MAX_RANGE_LEAVES {
            many.push_back(one.clone());
        }
        assert_eq!(w.anchor(1, many), Err(Error::RangeTooLarge));
    }

    #[test]
    #[should_panic(expected = "Auth, InvalidAction")]
    fn only_the_account_can_anchor_its_range() {
        let mut w = world();
        let s = w.f.seller.clone();
        w.pay(&s, PRICE);
        let input = RangeInput { account: w.account.clone(), from_seq: 1, leaves: w.leaves(1, 1, &[Verdict::Ok]), tail: Vec::new(&w.f.env) };
        let mallory = Address::generate(&w.f.env);
        w.f.env.mock_auths(&[MockAuth {
            address: &mallory,
            invoke: &MockAuthInvoke {
                contract: &w.f.contract_id,
                fn_name: "anchor_range",
                args: (input.clone(),).into_val(&w.f.env),
                sub_invokes: &[],
            },
        }]);
        w.f.client.anchor_range(&input);
    }
}
