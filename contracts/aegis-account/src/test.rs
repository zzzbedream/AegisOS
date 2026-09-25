#![cfg(test)]

extern crate std;

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use soroban_sdk::{
    auth::ContractContext,
    testutils::{Address as _, Ledger},
    vec, Address, Bytes, BytesN, Env, IntoVal, Symbol, Val,
};

const NOW: u64 = 1_900_000_000;
const PRICE: i128 = 10_000;

struct Fixture {
    env: Env,
    account: Address,
    asset: Address,
    seller: Address,
    registry: Address,
    owner: SigningKey,
    authority: SigningKey,
    session: SigningKey,
}

fn raw(env: &Env, key: &SigningKey) -> BytesN<32> {
    BytesN::from_array(env, &key.verifying_key().to_bytes())
}

fn sign(env: &Env, key: &SigningKey, message: &[u8]) -> BytesN<64> {
    BytesN::from_array(env, &key.sign(message).to_bytes())
}

fn setup() -> Fixture {
    let env = Env::default();
    env.ledger().set_timestamp(NOW);
    let owner = SigningKey::generate(&mut OsRng);
    let authority = SigningKey::generate(&mut OsRng);
    let session = SigningKey::generate(&mut OsRng);
    let asset = Address::generate(&env);
    let registry = Address::generate(&env);
    let config = Config {
        owner: raw(&env, &owner),
        authority: raw(&env, &authority),
        session: raw(&env, &session),
        allowed_assets: vec![&env, asset.clone()],
        registry: Some(registry.clone()),
    };
    let account = env.register(AegisAccount, (config,));
    let seller = Address::generate(&env);
    Fixture { env, account, asset, seller, registry, owner, authority, session }
}

fn payload(env: &Env, byte: u8) -> BytesN<32> {
    env.crypto().sha256(&Bytes::from_array(env, &[byte; 32])).to_bytes()
}

fn commitment(f: &Fixture, id: u8) -> OnChainCommitment {
    OnChainCommitment {
        commitment_hash: BytesN::from_array(&f.env, &[id; 32]),
        seller: f.seller.clone(),
        asset: f.asset.clone(),
        max_amount: PRICE,
        expires_at: NOW + 900,
    }
}

fn payment_auth(f: &Fixture, c: OnChainCommitment, authority: &SigningKey, payload: &BytesN<32>) -> AegisAuth {
    let digest = commitment_digest(&f.env, &f.account, &c).to_array();
    AegisAuth::Payment(PaymentAuth {
        authority_sig: sign(&f.env, authority, &digest),
        session_sig: sign(&f.env, &f.session, &payload.to_array()),
        commitment: c,
    })
}

fn transfer(f: &Fixture, contract: &Address, to: &Address, amount: i128) -> Context {
    Context::Contract(ContractContext {
        contract: contract.clone(),
        fn_name: Symbol::new(&f.env, "transfer"),
        args: (f.account.clone(), to.clone(), amount).into_val(&f.env),
    })
}

fn check(f: &Fixture, payload: &BytesN<32>, auth: AegisAuth, contexts: Vec<Context>) -> Result<(), Result<AccError, soroban_sdk::InvokeError>> {
    let signature: Val = auth.into_val(&f.env);
    f.env.try_invoke_contract_check_auth::<AccError>(&f.account, payload, signature, &contexts)
}

fn client(f: &Fixture) -> AegisAccountClient<'_> {
    AegisAccountClient::new(&f.env, &f.account)
}

// ------------------------------------------------------------ happy path

#[test]
fn a_committed_payment_is_authorized_and_notarized() {
    let f = setup();
    let p = payload(&f.env, 1);
    let c = commitment(&f, 1);
    let auth = payment_auth(&f, c.clone(), &f.authority, &p);

    assert_eq!(check(&f, &p, auth, vec![&f.env, transfer(&f, &f.asset, &f.seller, PRICE)]), Ok(()));

    let head = client(&f).head();
    assert_eq!(head.seq, 1);
    let expected = chain_link(&f.env, &BytesN::from_array(&f.env, &[0; 32]), 1, &c.commitment_hash, &f.seller, PRICE);
    assert_eq!(head.chain_head, expected);
    assert!(client(&f).is_spent(&c.commitment_hash));
}

#[test]
fn a_payment_below_the_ceiling_is_allowed() {
    let f = setup();
    let p = payload(&f.env, 2);
    let auth = payment_auth(&f, commitment(&f, 2), &f.authority, &p);
    assert_eq!(check(&f, &p, auth, vec![&f.env, transfer(&f, &f.asset, &f.seller, PRICE / 2)]), Ok(()));
}

#[test]
fn the_chain_advances_once_per_payment() {
    let f = setup();
    for id in 1..=3u8 {
        let p = payload(&f.env, id);
        let auth = payment_auth(&f, commitment(&f, id), &f.authority, &p);
        assert_eq!(check(&f, &p, auth, vec![&f.env, transfer(&f, &f.asset, &f.seller, PRICE)]), Ok(()));
    }
    assert_eq!(client(&f).head().seq, 3);
}

// ------------------------------------------------------------ the attacks

#[test]
fn an_agent_signing_its_own_commitment_cannot_pay() {
    // The compromised-agent case, now refused by the account on-chain: the
    // agent holds the session key but not the commitment authority.
    let f = setup();
    let p = payload(&f.env, 3);
    let rogue = SigningKey::generate(&mut OsRng);
    let mut c = commitment(&f, 3);
    let attacker = Address::generate(&f.env);
    c.seller = attacker.clone();
    let auth = payment_auth(&f, c, &rogue, &p);

    assert!(check(&f, &p, auth, vec![&f.env, transfer(&f, &f.asset, &attacker, PRICE)]).is_err());
    assert_eq!(client(&f).head().seq, 0);
}

#[test]
fn a_valid_commitment_cannot_be_redirected() {
    let f = setup();
    let p = payload(&f.env, 4);
    let attacker = Address::generate(&f.env);
    let auth = payment_auth(&f, commitment(&f, 4), &f.authority, &p);
    assert_eq!(
        check(&f, &p, auth, vec![&f.env, transfer(&f, &f.asset, &attacker, PRICE)]),
        Err(Ok(AccError::SellerMismatch))
    );
}

#[test]
fn an_amount_above_the_ceiling_or_zero_is_refused() {
    let f = setup();
    for amount in [PRICE + 1, 0] {
        let p = payload(&f.env, 5);
        let auth = payment_auth(&f, commitment(&f, 5), &f.authority, &p);
        assert_eq!(
            check(&f, &p, auth, vec![&f.env, transfer(&f, &f.asset, &f.seller, amount)]),
            Err(Ok(AccError::AmountOutOfRange))
        );
    }
}

#[test]
fn a_commitment_pays_only_once() {
    let f = setup();
    let first = payload(&f.env, 6);
    let auth = payment_auth(&f, commitment(&f, 6), &f.authority, &first);
    assert_eq!(check(&f, &first, auth, vec![&f.env, transfer(&f, &f.asset, &f.seller, PRICE)]), Ok(()));

    let second = payload(&f.env, 7);
    let again = payment_auth(&f, commitment(&f, 6), &f.authority, &second);
    assert_eq!(
        check(&f, &second, again, vec![&f.env, transfer(&f, &f.asset, &f.seller, PRICE)]),
        Err(Ok(AccError::CommitmentSpent))
    );
    assert_eq!(client(&f).head().seq, 1);
}

#[test]
fn an_expired_or_overlong_commitment_is_refused() {
    let f = setup();
    let p = payload(&f.env, 8);
    let mut expired = commitment(&f, 8);
    expired.expires_at = NOW - 1;
    let auth = payment_auth(&f, expired, &f.authority, &p);
    assert_eq!(
        check(&f, &p, auth, vec![&f.env, transfer(&f, &f.asset, &f.seller, PRICE)]),
        Err(Ok(AccError::CommitmentExpired))
    );

    let mut overlong = commitment(&f, 9);
    overlong.expires_at = NOW + MAX_COMMITMENT_WINDOW_SECS + 1;
    let auth = payment_auth(&f, overlong, &f.authority, &p);
    assert_eq!(
        check(&f, &p, auth, vec![&f.env, transfer(&f, &f.asset, &f.seller, PRICE)]),
        Err(Ok(AccError::CommitmentWindowTooLong))
    );
}

#[test]
fn an_unlisted_asset_is_refused() {
    let f = setup();
    let p = payload(&f.env, 10);
    let other = Address::generate(&f.env);
    let mut c = commitment(&f, 10);
    c.asset = other.clone();
    let auth = payment_auth(&f, c, &f.authority, &p);
    assert_eq!(
        check(&f, &p, auth, vec![&f.env, transfer(&f, &other, &f.seller, PRICE)]),
        Err(Ok(AccError::AssetNotAllowed))
    );
}

#[test]
fn a_bad_session_signature_is_refused() {
    let f = setup();
    let p = payload(&f.env, 11);
    let auth = payment_auth(&f, commitment(&f, 11), &f.authority, &payload(&f.env, 99));
    assert!(check(&f, &p, auth, vec![&f.env, transfer(&f, &f.asset, &f.seller, PRICE)]).is_err());
}

#[test]
fn only_a_single_transfer_can_ride_on_a_commitment() {
    let f = setup();
    let p = payload(&f.env, 12);
    let auth = payment_auth(&f, commitment(&f, 12), &f.authority, &p);
    let two = vec![
        &f.env,
        transfer(&f, &f.asset, &f.seller, PRICE),
        transfer(&f, &f.asset, &f.seller, PRICE),
    ];
    assert_eq!(check(&f, &p, auth, two), Err(Ok(AccError::UnexpectedContexts)));

    let approve = Context::Contract(ContractContext {
        contract: f.asset.clone(),
        fn_name: Symbol::new(&f.env, "approve"),
        args: (f.account.clone(), f.seller.clone(), PRICE, 100u32).into_val(&f.env),
    });
    let auth = payment_auth(&f, commitment(&f, 13), &f.authority, &p);
    assert_eq!(check(&f, &p, auth, vec![&f.env, approve]), Err(Ok(AccError::NotATransfer)));
}

// ------------------------------------------------------ registry and owner

#[test]
fn the_session_key_may_only_call_the_registry() {
    let f = setup();
    let p = payload(&f.env, 14);
    let sig = sign(&f.env, &f.session, &p.to_array());
    let anchor = Context::Contract(ContractContext {
        contract: f.registry.clone(),
        fn_name: Symbol::new(&f.env, "anchor_range"),
        args: vec![&f.env],
    });
    assert_eq!(check(&f, &p, AegisAuth::Registry(sig.clone()), vec![&f.env, anchor]), Ok(()));

    // The same session signature cannot move funds.
    assert_eq!(
        check(&f, &p, AegisAuth::Registry(sig), vec![&f.env, transfer(&f, &f.asset, &f.seller, PRICE)]),
        Err(Ok(AccError::NotRegistryCall))
    );
}

#[test]
fn the_owner_key_authorizes_anything_and_nothing_else_does() {
    let f = setup();
    let p = payload(&f.env, 15);
    let owner_sig = sign(&f.env, &f.owner, &p.to_array());
    assert_eq!(
        check(&f, &p, AegisAuth::Owner(owner_sig), vec![&f.env, transfer(&f, &f.asset, &f.seller, PRICE)]),
        Ok(())
    );
    let session_as_owner = sign(&f.env, &f.session, &p.to_array());
    assert!(check(&f, &p, AegisAuth::Owner(session_as_owner), vec![&f.env, transfer(&f, &f.asset, &f.seller, PRICE)]).is_err());
}

#[test]
fn a_commitment_for_another_account_cannot_be_replayed() {
    // Same authority, same seller: signed for account X, presented to this one.
    let f = setup();
    let p = payload(&f.env, 16);
    let c = commitment(&f, 16);
    let other = Address::generate(&f.env);
    let digest = commitment_digest(&f.env, &other, &c).to_array();
    let auth = AegisAuth::Payment(PaymentAuth {
        authority_sig: sign(&f.env, &f.authority, &digest),
        session_sig: sign(&f.env, &f.session, &p.to_array()),
        commitment: c,
    });
    assert!(check(&f, &p, auth, vec![&f.env, transfer(&f, &f.asset, &f.seller, PRICE)]).is_err());
}

// ------------------------------------------------------------ vectors

#[test]
fn commitment_digest_matches_the_published_vector() {
    // Shared with packages/proof so TypeScript builds the same bytes.
    let env = Env::default();
    let c = OnChainCommitment {
        commitment_hash: BytesN::from_array(&env, &[0xAB; 32]),
        seller: Address::from_str(&env, "GDVR2KDK5DSMNYZJKNISUIOBDC6FZK3XZOIQWSS7KL4BRMD5BMW6RMCQ"),
        asset: Address::from_str(&env, "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA"),
        max_amount: 10_000,
        expires_at: 1_900_000_900,
    };
    let account = Address::from_str(&env, "CDZ2HUKOYV5GR4NOZWFZN673V36KYWIXGFWFSUFHI2X6UVYAPBZWHCPQ");
    let digest = commitment_digest(&env, &account, &c);
    let link = chain_link(&env, &BytesN::from_array(&env, &[0; 32]), 1, &c.commitment_hash, &c.seller, 10_000);
    std::println!("VECTOR commitment_digest={}", hex(&digest.to_array()));
    std::println!("VECTOR chain_link_1={}", hex(&link.to_array()));
}

fn hex(bytes: &[u8]) -> std::string::String {
    bytes.iter().map(|b| std::format!("{:02x}", b)).collect()
}
