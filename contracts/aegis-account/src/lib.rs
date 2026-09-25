#![no_std]

//! AegisOS buyer account — the wallet notarizes every x402 payment.
//!
//! A Soroban custom account (`__check_auth`) that pays x402 sellers only under
//! a purchase commitment signed by a commitment authority pinned at creation.
//! Because the check runs inside the payment transaction itself, a compromised
//! agent cannot pay outside a signed commitment: the account refuses on-chain,
//! whatever process the agent controls.
//!
//! On every payment it authorizes, atomically with the transfer:
//!   - spends the commitment's nullifier (a commitment pays exactly once),
//!   - advances `seq` and a hash chain over (seq, commitment, seller, amount).
//! If the transaction does not execute, none of this happens — so a `seq` is
//! proof that the corresponding transfer settled.
//!
//! Cost is part of the design: an x402 facilitator rejects payments whose
//! simulated fee exceeds a ceiling (50 000 stroops by default), so this check
//! never creates persistent entries. It updates existing instance state and
//! uses temporary storage for the nullifier. It emits no event: facilitators
//! reject a payment whose simulation carries any contract event other than the
//! SAC `transfer`. The account state is the notarization. It never extends
//! the instance TTL either — that also extends the wasm code entry and cost
//! ~11 XLM of rent on testnet. Keep-alive is `extend_ttl`, called off the
//! payment path.
//!
//! What this does NOT prove: that the delivered content is good, or that the
//! commitment authority chose the seller wisely. It proves the payment was the
//! one the authority committed to.

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Symbol, TryFromVal, Vec,
};

pub const COMMITMENT_DOMAIN: &[u8] = b"aegisos:onchain-commitment:v1";
pub const CHAIN_DOMAIN: &[u8] = b"aegisos:payment-chain:v1";

const DAY_IN_LEDGERS: u32 = 17_280;
const INSTANCE_BUMP: u32 = 30 * DAY_IN_LEDGERS;
/// Longest a commitment may stay payable. Bounded so NULLIFIER_TTL covers it.
pub const MAX_COMMITMENT_WINDOW_SECS: u64 = 3_600;
/// A spent nullifier must outlive the commitment it guards: two hours of
/// ledgers at ~5 s each, for a window of at most one.
const NULLIFIER_TTL: u32 = 1_440;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AccError {
    UnexpectedContexts = 1,
    NotAContractCall = 2,
    AssetNotAllowed = 3,
    NotATransfer = 4,
    WrongPayer = 5,
    SellerMismatch = 6,
    AmountOutOfRange = 7,
    CommitmentExpired = 8,
    CommitmentWindowTooLong = 9,
    CommitmentSpent = 10,
    RegistryNotSet = 11,
    NotRegistryCall = 12,
}

/// The enforceable part of an off-chain purchase commitment. The authority
/// signs `commitment_digest`, which binds the off-chain commitment hash to the
/// fields this contract can check against the transfer.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnChainCommitment {
    pub commitment_hash: BytesN<32>,
    pub seller: Address,
    pub asset: Address,
    pub max_amount: i128,
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentAuth {
    pub commitment: OnChainCommitment,
    /// Commitment authority over `commitment_digest(commitment)`.
    pub authority_sig: BytesN<64>,
    /// Session signer (the isolated signer) over the Soroban signature payload.
    pub session_sig: BytesN<64>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AegisAuth {
    /// Pay a seller under a signed commitment.
    Payment(PaymentAuth),
    /// Session signer, valid only for calls into the AegisOS registry.
    Registry(BytesN<64>),
    /// Owner key: full control, for recovery and administration.
    Owner(BytesN<64>),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// Raw ed25519 public keys.
    pub owner: BytesN<32>,
    pub authority: BytesN<32>,
    pub session: BytesN<32>,
    pub allowed_assets: Vec<Address>,
    pub registry: Option<Address>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Head {
    pub seq: u64,
    pub chain_head: BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config,
    Head,
    Spent(BytesN<32>),
}

/// Digest the authority signs. Fixed byte layout so TypeScript can rebuild it:
/// domain || commitment_hash || seller(ScVal XDR) || asset(ScVal XDR)
///        || max_amount (i128 BE) || expires_at (u64 BE)
pub fn commitment_digest(env: &Env, c: &OnChainCommitment) -> BytesN<32> {
    let mut data = Bytes::from_slice(env, COMMITMENT_DOMAIN);
    data.append(&c.commitment_hash.clone().into());
    data.append(&c.seller.clone().to_xdr(env));
    data.append(&c.asset.clone().to_xdr(env));
    data.append(&Bytes::from_array(env, &c.max_amount.to_be_bytes()));
    data.append(&Bytes::from_array(env, &c.expires_at.to_be_bytes()));
    env.crypto().sha256(&data).to_bytes()
}

/// Next link of the payment chain:
/// sha256(domain || previous || seq (u64 BE) || commitment_hash
///        || seller(ScVal XDR) || amount (i128 BE))
pub fn chain_link(
    env: &Env,
    previous: &BytesN<32>,
    seq: u64,
    commitment_hash: &BytesN<32>,
    seller: &Address,
    amount: i128,
) -> BytesN<32> {
    let mut data = Bytes::from_slice(env, CHAIN_DOMAIN);
    data.append(&previous.clone().into());
    data.append(&Bytes::from_array(env, &seq.to_be_bytes()));
    data.append(&commitment_hash.clone().into());
    data.append(&seller.clone().to_xdr(env));
    data.append(&Bytes::from_array(env, &amount.to_be_bytes()));
    env.crypto().sha256(&data).to_bytes()
}

fn read_config(env: &Env) -> Config {
    env.storage().instance().get(&DataKey::Config).unwrap()
}

fn read_head(env: &Env) -> Head {
    env.storage().instance().get(&DataKey::Head).unwrap()
}

fn verify(env: &Env, key: &BytesN<32>, message: &Bytes, signature: &BytesN<64>) {
    // Panics on a bad signature, which fails the whole authorization.
    env.crypto().ed25519_verify(key, message, signature);
}

fn check_payment(
    env: &Env,
    config: &Config,
    payload: &Bytes,
    auth: PaymentAuth,
    contexts: &Vec<Context>,
) -> Result<(), AccError> {
    if contexts.len() != 1 {
        return Err(AccError::UnexpectedContexts);
    }
    let call = match contexts.get(0).unwrap() {
        Context::Contract(call) => call,
        _ => return Err(AccError::NotAContractCall),
    };
    if call.fn_name != Symbol::new(env, "transfer") || call.args.len() != 3 {
        return Err(AccError::NotATransfer);
    }
    let c = auth.commitment;
    if call.contract != c.asset || !config.allowed_assets.contains(&call.contract) {
        return Err(AccError::AssetNotAllowed);
    }
    let from = Address::try_from_val(env, &call.args.get(0).unwrap())
        .map_err(|_| AccError::NotATransfer)?;
    let to = Address::try_from_val(env, &call.args.get(1).unwrap())
        .map_err(|_| AccError::NotATransfer)?;
    let amount = i128::try_from_val(env, &call.args.get(2).unwrap())
        .map_err(|_| AccError::NotATransfer)?;
    if from != env.current_contract_address() {
        return Err(AccError::WrongPayer);
    }
    if to != c.seller {
        return Err(AccError::SellerMismatch);
    }
    if amount <= 0 || amount > c.max_amount {
        return Err(AccError::AmountOutOfRange);
    }

    let now = env.ledger().timestamp();
    if now > c.expires_at {
        return Err(AccError::CommitmentExpired);
    }
    if c.expires_at - now > MAX_COMMITMENT_WINDOW_SECS {
        return Err(AccError::CommitmentWindowTooLong);
    }

    let digest: Bytes = commitment_digest(env, &c).into();
    verify(env, &config.authority, &digest, &auth.authority_sig);
    verify(env, &config.session, payload, &auth.session_sig);

    let spent = DataKey::Spent(c.commitment_hash.clone());
    if env.storage().temporary().has(&spent) {
        return Err(AccError::CommitmentSpent);
    }
    env.storage().temporary().set(&spent, &true);
    env.storage()
        .temporary()
        .extend_ttl(&spent, NULLIFIER_TTL, NULLIFIER_TTL);

    let head = read_head(env);
    let seq = head.seq + 1;
    let chain_head = chain_link(env, &head.chain_head, seq, &c.commitment_hash, &c.seller, amount);
    env.storage()
        .instance()
        .set(&DataKey::Head, &Head { seq, chain_head });

    Ok(())
}

fn check_registry(
    env: &Env,
    config: &Config,
    payload: &Bytes,
    signature: &BytesN<64>,
    contexts: &Vec<Context>,
) -> Result<(), AccError> {
    let registry = config.registry.clone().ok_or(AccError::RegistryNotSet)?;
    if contexts.is_empty() {
        return Err(AccError::UnexpectedContexts);
    }
    for context in contexts.iter() {
        match context {
            Context::Contract(call) if call.contract == registry => {}
            _ => return Err(AccError::NotRegistryCall),
        }
    }
    verify(env, &config.session, payload, signature);
    Ok(())
}

#[contract]
pub struct AegisAccount;

#[contractimpl]
impl AegisAccount {
    pub fn __constructor(env: Env, config: Config) {
        env.storage().instance().set(&DataKey::Config, &config);
        env.storage().instance().set(
            &DataKey::Head,
            &Head {
                seq: 0,
                chain_head: BytesN::from_array(&env, &[0u8; 32]),
            },
        );
    }

    /// Keep the account (instance and code) alive. Permissionless: it only
    /// pays rent. Deliberately not done inside `__check_auth`, where the rent
    /// would land on every payment and break the facilitator's fee ceiling.
    pub fn extend_ttl(env: Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_BUMP, INSTANCE_BUMP);
    }

    pub fn head(env: Env) -> Head {
        read_head(&env)
    }

    pub fn config(env: Env) -> Config {
        read_config(&env)
    }

    pub fn is_spent(env: Env, commitment_hash: BytesN<32>) -> bool {
        env.storage().temporary().has(&DataKey::Spent(commitment_hash))
    }

    /// Rotate the session signer. Owner only (via `AegisAuth::Owner`).
    pub fn set_session(env: Env, session: BytesN<32>) {
        env.current_contract_address().require_auth();
        let config = Config { session, ..read_config(&env) };
        env.storage().instance().set(&DataKey::Config, &config);
    }

    /// Point the account at the registry it may anchor into. Owner only.
    pub fn set_registry(env: Env, registry: Address) {
        env.current_contract_address().require_auth();
        let config = Config { registry: Some(registry), ..read_config(&env) };
        env.storage().instance().set(&DataKey::Config, &config);
    }
}

#[contractimpl]
impl CustomAccountInterface for AegisAccount {
    type Signature = AegisAuth;
    type Error = AccError;

    #[allow(non_snake_case)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: AegisAuth,
        auth_contexts: Vec<Context>,
    ) -> Result<(), AccError> {
        let config = read_config(&env);
        let payload: Bytes = signature_payload.to_bytes().into();

        match signature {
            AegisAuth::Payment(auth) => check_payment(&env, &config, &payload, auth, &auth_contexts),
            AegisAuth::Registry(sig) => check_registry(&env, &config, &payload, &sig, &auth_contexts),
            AegisAuth::Owner(sig) => {
                verify(&env, &config.owner, &payload, &sig);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod test;
