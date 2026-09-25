#![no_std]

//! Hashing shared by the AegisOS account and registry.
//!
//! - `chain_link`: one link of an account's payment chain. The account advances
//!   it inside `__check_auth`; the registry recomputes it to accept a range.
//! - `range_leaf` + `merkle_root`: the receipts of a range, committed as one
//!   root. Leaves and inner nodes hash under different one-byte prefixes, and
//!   an odd node is promoted unchanged (never paired with itself), so an inner
//!   node cannot pass as a leaf and two leaf lists cannot share a root.
//!
//! TypeScript mirrors every function here byte for byte; the vectors printed
//! by this crate's tests are pinned on the TypeScript side.

use soroban_sdk::{xdr::ToXdr, Address, Bytes, BytesN, Env, Vec};

pub const CHAIN_DOMAIN: &[u8] = b"aegisos:payment-chain:v1";
pub const RANGE_LEAF_DOMAIN: &[u8] = b"aegisos:range-leaf:v1";

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

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

/// Leaf for one payment of a range:
/// sha256(0x00 || sha256(domain || seq || commitment_hash || seller(XDR)
///                       || amount || content_hash || verdict (u32 BE)))
#[allow(clippy::too_many_arguments)]
pub fn range_leaf(
    env: &Env,
    seq: u64,
    commitment_hash: &BytesN<32>,
    seller: &Address,
    amount: i128,
    content_hash: &BytesN<32>,
    verdict_code: u32,
) -> BytesN<32> {
    let mut body = Bytes::from_slice(env, RANGE_LEAF_DOMAIN);
    body.append(&Bytes::from_array(env, &seq.to_be_bytes()));
    body.append(&commitment_hash.clone().into());
    body.append(&seller.clone().to_xdr(env));
    body.append(&Bytes::from_array(env, &amount.to_be_bytes()));
    body.append(&content_hash.clone().into());
    body.append(&Bytes::from_array(env, &verdict_code.to_be_bytes()));
    let inner = env.crypto().sha256(&body).to_bytes();

    let mut leaf = Bytes::from_array(env, &[LEAF_PREFIX]);
    leaf.append(&inner.into());
    env.crypto().sha256(&leaf).to_bytes()
}

fn node(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let mut data = Bytes::from_array(env, &[NODE_PREFIX]);
    data.append(&left.clone().into());
    data.append(&right.clone().into());
    env.crypto().sha256(&data).to_bytes()
}

/// Root over already-prefixed leaves. Panics on an empty list: callers check.
pub fn merkle_root(env: &Env, leaves: &Vec<BytesN<32>>) -> BytesN<32> {
    let mut level = leaves.clone();
    while level.len() > 1 {
        let mut next: Vec<BytesN<32>> = Vec::new(env);
        let mut i = 0;
        while i < level.len() {
            let left = level.get(i).unwrap();
            match level.get(i + 1) {
                Some(right) => next.push_back(node(env, &left, &right)),
                None => next.push_back(left),
            }
            i += 2;
        }
        level = next;
    }
    level.get(0).unwrap()
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use soroban_sdk::{vec, Env};

    fn hex(bytes: &[u8]) -> std::string::String {
        bytes.iter().map(|b| std::format!("{:02x}", b)).collect()
    }

    #[test]
    fn vectors() {
        let env = Env::default();
        let seller = Address::from_str(&env, "GDVR2KDK5DSMNYZJKNISUIOBDC6FZK3XZOIQWSS7KL4BRMD5BMW6RMCQ");
        let commitment = BytesN::from_array(&env, &[0xAB; 32]);
        let content = BytesN::from_array(&env, &[0xCD; 32]);
        let leaf1 = range_leaf(&env, 1, &commitment, &seller, 10_000, &content, 0);
        let leaf2 = range_leaf(&env, 2, &commitment, &seller, 10_000, &content, 1);
        let leaf3 = range_leaf(&env, 3, &commitment, &seller, 10_000, &content, 2);
        let root = merkle_root(&env, &vec![&env, leaf1.clone(), leaf2.clone(), leaf3.clone()]);
        std::println!("VECTOR range_leaf_1={}", hex(&leaf1.to_array()));
        std::println!("VECTOR range_root_3={}", hex(&root.to_array()));

        // A single leaf is its own root; order matters.
        assert_eq!(merkle_root(&env, &vec![&env, leaf1.clone()]), leaf1);
        assert_ne!(
            merkle_root(&env, &vec![&env, leaf1.clone(), leaf2.clone()]),
            merkle_root(&env, &vec![&env, leaf2, leaf1])
        );
    }

    #[test]
    fn chain_link_matches_the_account_vector() {
        let env = Env::default();
        let seller = Address::from_str(&env, "GDVR2KDK5DSMNYZJKNISUIOBDC6FZK3XZOIQWSS7KL4BRMD5BMW6RMCQ");
        let link = chain_link(
            &env,
            &BytesN::from_array(&env, &[0; 32]),
            1,
            &BytesN::from_array(&env, &[0xAB; 32]),
            &seller,
            10_000,
        );
        // Pinned in packages/x402/test/smart-account.test.ts as chainLink1.
        assert_eq!(
            hex(&link.to_array()),
            "8d59d4113fa07fadb6bcc0feeb18d6634441a256657ce31abc4911fe51856137"
        );
    }
}
