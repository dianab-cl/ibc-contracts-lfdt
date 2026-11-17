// SPDX-License-Identifier: Apache-2.0

//! Verification of Ethereum account and storage proofs (`eth_getProof`, EIP-1186).
//!
//! Like the rest of this crate (see its README), this is based on the Ethereum light client of
//! Union (<https://github.com/unionlabs/union>), which is licensed under Apache-2.0 OR MIT.

use alloy_primitives::{Address, B256};
use hash_db::HashDB;
use memory_db::{HashKey, MemoryDB};
use primitive_types::{H160, H256, U256};
use rlp_derive::RlpDecodable;
use trie_db::{Trie, TrieDBBuilder};

use super::{
    layout::{keccak_256, EthLayout, KeccakHasher},
    TrieDBError,
};

/// A smart contract account.
#[derive(Debug, Clone, RlpDecodable)]
pub struct Account {
    /// The nonce of the account.
    pub nonce: u64,
    /// The balance of the account.
    pub balance: U256,
    /// The storage root of the account.
    pub storage_root: H256,
    /// The code hash of the account.
    pub code_hash: H256,
}

/// Verifies against `root`, if the `expected_value` is stored at `key` by using `proof`.
///
/// * `root`: Storage root of a contract.
/// * `key`: Padded slot number that the `expected_value` should be stored at.
/// * `expected_value`: Expected stored value.
/// * `proof`: Proof that is generated to prove the storage.
///
/// NOTE: You must not trust the `root` unless you verified it by calling [`verify_account_storage_root`].
///
/// # Errors
/// Returns an error if the verification fails.
pub fn verify_storage_inclusion_proof(
    root: &[u8; 32],
    key: &[u8; 32],
    expected_value: &[u8],
    proof: impl IntoIterator<Item = impl AsRef<[u8]>>,
) -> Result<(), TrieDBError> {
    match get_node(H256(*root), key, proof)? {
        Some(value) if value == expected_value => Ok(()),
        Some(value) => Err(TrieDBError::ValueMismatch {
            expected: expected_value.into(),
            actual: value,
        })?,
        None => Err(TrieDBError::ValueMissing {
            value: expected_value.into(),
        })?,
    }
}

/// Verifies against `root`, that no value is stored at `key` by using `proof`.
///
/// * `root`: Storage root of a contract.
/// * `key`: Padded slot number that the `expected_value` should be stored at.
/// * `proof`: Proof that is generated to prove the storage.
///
/// NOTE: You must not trust the `root` unless you verified it by calling [`verify_account_storage_root`].
///
/// # Errors
/// Returns an error if the verification fails.
pub fn verify_storage_exclusion_proof(
    root: &[u8; 32],
    key: &[u8; 32],
    proof: impl IntoIterator<Item = impl AsRef<[u8]>>,
) -> Result<(), TrieDBError> {
    match get_node(H256(*root), key, proof)? {
        Some(value) => Err(TrieDBError::ValueShouldBeMissing { value })?,
        None => Ok(()),
    }
}

/// Verifies if the `storage_root` of a contract can be verified against the state `root`.
///
/// * `root`: Light client update's (attested/finalized) execution block's state root.
/// * `address`: Address of the contract.
/// * `proof`: Proof of storage.
/// * `storage_root`: Storage root of the contract.
///
/// WARNING: You must not trust the `root` unless you've verified it.
/// # Errors
/// Returns an error if the verification fails.
pub fn verify_account_storage_root(
    root: B256,
    address: Address,
    proof: impl IntoIterator<Item = impl AsRef<[u8]>>,
    storage_root: B256,
) -> Result<(), TrieDBError> {
    let storage_root: H256 = H256(storage_root.into());
    let address: H160 = H160(address.into());

    match get_node(H256(root.into()), address.as_ref(), proof)? {
        Some(account) => {
            let account =
                rlp::decode::<Account>(account.as_ref()).map_err(TrieDBError::RlpDecode)?;
            if account.storage_root != storage_root {
                return Err(TrieDBError::ValueMismatch {
                    expected: storage_root.as_ref().into(),
                    actual: account.storage_root.as_ref().into(),
                });
            }
            Ok(())
        }
        None => Err(TrieDBError::ValueMissing {
            value: address.as_ref().into(),
        })?,
    }
}

fn get_node(
    root: H256,
    key: impl AsRef<[u8]>,
    proof: impl IntoIterator<Item = impl AsRef<[u8]>>,
) -> Result<Option<Vec<u8>>, TrieDBError> {
    let mut db = MemoryDB::<KeccakHasher, HashKey<_>, Vec<u8>>::default();
    proof.into_iter().for_each(|n| {
        db.insert(hash_db::EMPTY_PREFIX, n.as_ref());
    });

    let trie = TrieDBBuilder::<EthLayout>::new(&db, &root).build();
    trie.get(&keccak_256(key.as_ref()))
        .map_err(|e| TrieDBError::GetTrieNodeFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{b256, keccak256, Bytes, U256};
    use alloy_rlp::Encodable;
    use rlp::{Rlp, RlpStream};
    use trie_db::{trie_visit, Recorder, TrieBuilder};

    use super::*;
    use crate::mpt::test_layout::TestLayout;

    /// The fields of an account, with alloy types, to build the test tries.
    #[derive(Debug, Clone)]
    struct Account {
        nonce: u64,
        balance: U256,
        storage_root: B256,
        code_hash: B256,
    }

    fn encode_account(account: &Account) -> Vec<u8> {
        let fields: [&dyn Encodable; 4] = [
            &account.nonce,
            &account.balance,
            &account.storage_root,
            &account.code_hash,
        ];
        let mut out = Vec::new();
        alloy_rlp::encode_list::<_, dyn Encodable>(&fields, &mut out);
        out
    }

    /// Builds a secure trie (keys hashed with keccak256) from `entries` and returns its root and
    /// the proof for `target`: the nodes that a lookup of `target` reads, from the root node, as
    /// `eth_getProof` returns them.
    fn build_trie(entries: &[(Vec<u8>, Vec<u8>)], target: &[u8]) -> (B256, Vec<Bytes>) {
        let mut leaves: Vec<_> = entries
            .iter()
            .map(|(key, value)| (keccak256(key), value.clone()))
            .collect();
        leaves.sort();

        let mut db = MemoryDB::<KeccakHasher, HashKey<_>, Vec<u8>>::default();
        let mut builder = TrieBuilder::<TestLayout, _>::new(&mut db);
        trie_visit::<TestLayout, _, _, _, _>(leaves, &mut builder);
        let root = builder.root.expect("the trie is not empty");

        let mut recorder = Recorder::<TestLayout>::new();
        {
            let trie = TrieDBBuilder::<TestLayout>::new(&db, &root)
                .with_recorder(&mut recorder)
                .build();
            trie.get(keccak256(target).as_slice()).unwrap();
        }
        let proof = recorder
            .drain()
            .into_iter()
            .map(|record| record.data.into())
            .collect();
        (B256::from(root.0), proof)
    }

    fn slot(n: u64) -> [u8; 32] {
        U256::from(n).to_be_bytes()
    }

    fn storage_value(n: u64) -> Vec<u8> {
        alloy_rlp::encode(U256::from(n))
    }

    fn storage_entries() -> Vec<(Vec<u8>, Vec<u8>)> {
        (1..=64)
            .map(|n| (slot(n).to_vec(), storage_value(n * 1000)))
            .collect()
    }

    fn account(n: u64) -> Account {
        Account {
            nonce: n,
            balance: U256::from(n) * U256::from(1_000_000_000u64),
            storage_root: keccak256(n.to_be_bytes()),
            code_hash: keccak256(b"code"),
        }
    }

    fn account_entries() -> Vec<(Vec<u8>, Vec<u8>)> {
        (1..=64)
            .map(|n| {
                (
                    Address::with_last_byte(u8::try_from(n).unwrap()).to_vec(),
                    encode_account(&account(n)),
                )
            })
            .collect()
    }

    #[test]
    fn storage_inclusion() {
        let (root, proof) = build_trie(&storage_entries(), &slot(7));
        verify_storage_inclusion_proof(&root, &slot(7), &storage_value(7000), &proof).unwrap();
    }

    #[test]
    fn storage_inclusion_wrong_value() {
        let (root, proof) = build_trie(&storage_entries(), &slot(7));
        let err =
            verify_storage_inclusion_proof(&root, &slot(7), &storage_value(1), &proof).unwrap_err();
        assert_eq!(
            err,
            TrieDBError::ValueMismatch {
                expected: storage_value(1),
                actual: storage_value(7000),
            }
        );
    }

    #[test]
    fn storage_inclusion_of_absent_key() {
        let (root, proof) = build_trie(&storage_entries(), &slot(100));
        let err = verify_storage_inclusion_proof(&root, &slot(100), &storage_value(1), &proof)
            .unwrap_err();
        assert_eq!(
            err,
            TrieDBError::ValueMissing {
                value: storage_value(1)
            }
        );
    }

    #[test]
    fn storage_exclusion() {
        let (root, proof) = build_trie(&storage_entries(), &slot(100));
        verify_storage_exclusion_proof(&root, &slot(100), &proof).unwrap();
    }

    #[test]
    fn storage_exclusion_of_present_key() {
        let (root, proof) = build_trie(&storage_entries(), &slot(7));
        let err = verify_storage_exclusion_proof(&root, &slot(7), &proof).unwrap_err();
        assert_eq!(
            err,
            TrieDBError::ValueShouldBeMissing {
                value: storage_value(7000)
            }
        );
    }

    #[test]
    fn storage_proof_for_other_key_is_rejected() {
        // A valid proof for slot 7 must not prove anything about slot 8.
        let (root, proof) = build_trie(&storage_entries(), &slot(7));
        assert!(
            verify_storage_inclusion_proof(&root, &slot(8), &storage_value(7000), &proof).is_err()
        );
        assert!(
            verify_storage_inclusion_proof(&root, &slot(8), &storage_value(8000), &proof).is_err()
        );
    }

    #[test]
    fn storage_wrong_root() {
        let (_, proof) = build_trie(&storage_entries(), &slot(7));
        let err =
            verify_storage_inclusion_proof(&[0xab; 32], &slot(7), &storage_value(7000), &proof)
                .unwrap_err();
        assert!(matches!(err, TrieDBError::GetTrieNodeFailed(_)), "{err:?}");
    }

    #[test]
    fn storage_tampered_proof() {
        let (root, mut proof) = build_trie(&storage_entries(), &slot(7));
        assert!(proof.len() > 1);
        let mut node = proof[1].to_vec();
        let last = node.len() - 1;
        node[last] ^= 1;
        proof[1] = node.into();
        let err = verify_storage_inclusion_proof(&root, &slot(7), &storage_value(7000), &proof)
            .unwrap_err();
        assert!(matches!(err, TrieDBError::GetTrieNodeFailed(_)), "{err:?}");
    }

    #[test]
    fn storage_truncated_proof() {
        let (root, mut proof) = build_trie(&storage_entries(), &slot(7));
        proof.pop();
        assert!(
            verify_storage_inclusion_proof(&root, &slot(7), &storage_value(7000), &proof).is_err()
        );
        assert!(verify_storage_exclusion_proof(&root, &slot(7), &proof).is_err());
    }

    #[test]
    fn account_storage_root() {
        let address = Address::with_last_byte(9);
        let (root, proof) = build_trie(&account_entries(), address.as_slice());
        verify_account_storage_root(root, address, &proof, account(9).storage_root).unwrap();
    }

    #[test]
    fn account_storage_root_mismatch() {
        let address = Address::with_last_byte(9);
        let (root, proof) = build_trie(&account_entries(), address.as_slice());
        let err = verify_account_storage_root(root, address, &proof, account(10).storage_root)
            .unwrap_err();
        assert_eq!(
            err,
            TrieDBError::ValueMismatch {
                expected: account(10).storage_root.to_vec(),
                actual: account(9).storage_root.to_vec(),
            }
        );
    }

    #[test]
    fn account_missing() {
        let address = Address::with_last_byte(200);
        let (root, proof) = build_trie(&account_entries(), address.as_slice());
        let err = verify_account_storage_root(root, address, &proof, account(9).storage_root)
            .unwrap_err();
        assert_eq!(
            err,
            TrieDBError::ValueMissing {
                value: address.to_vec()
            }
        );
    }

    #[test]
    fn account_proof_for_other_account_is_rejected() {
        let address = Address::with_last_byte(9);
        let (root, proof) = build_trie(&account_entries(), address.as_slice());
        let other = Address::with_last_byte(10);
        assert!(verify_account_storage_root(root, other, &proof, account(9).storage_root).is_err());
    }

    #[test]
    fn account_tampered_leaf() {
        let address = Address::with_last_byte(9);
        let (root, mut proof) = build_trie(&account_entries(), address.as_slice());
        // Swap the leaf for one that claims a different storage root.
        let leaf_index = proof.len() - 1;
        let leaf = Rlp::new(&proof[leaf_index]);
        assert_eq!(leaf.item_count().unwrap(), 2);
        let path = leaf.at(0).unwrap().data().unwrap().to_vec();
        assert_eq!(path[0] & 0x20, 0x20, "expected a leaf node");
        let mut forged = account(9);
        forged.storage_root = B256::repeat_byte(0x11);
        let mut stream = RlpStream::new_list(2);
        stream
            .append(&path.as_slice())
            .append(&encode_account(&forged).as_slice());
        proof[leaf_index] = stream.out().to_vec().into();
        let err =
            verify_account_storage_root(root, address, &proof, forged.storage_root).unwrap_err();
        assert!(matches!(err, TrieDBError::GetTrieNodeFailed(_)), "{err:?}");
    }

    #[test]
    fn empty_proof() {
        let address = Address::with_last_byte(9);
        let (root, _) = build_trie(&account_entries(), address.as_slice());
        assert!(
            verify_account_storage_root(root, address, Vec::<Bytes>::new(), B256::ZERO).is_err()
        );
        assert!(verify_storage_exclusion_proof(&root, &slot(1), Vec::<Bytes>::new()).is_err());
    }

    #[test]
    fn test_tries_match_alloy_trie() {
        // Roots of the test tries computed with alloy-trie, an independent implementation of
        // the Ethereum trie.
        assert_eq!(
            build_trie(&storage_entries(), &slot(7)).0,
            b256!("46252802c87ba998fd8ebbe7652805c613a9612a13a9d79d1dc3e15ecf9ee64c")
        );
        assert_eq!(
            build_trie(&account_entries(), &slot(7)).0,
            b256!("9b164c4455c71585f69e367ac6522154f257e44bfd29f8233d76c1b00f0dace1")
        );
    }
}
