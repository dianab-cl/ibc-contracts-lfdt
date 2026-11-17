// SPDX-License-Identifier: Apache-2.0

//! Ethereum Merkle Patricia trie proofs: verifies that a value is, or is not, stored under a key
//! of the state trie or of a contract's storage trie.

mod error;
pub mod layout;
pub mod proof;
#[cfg(test)]
mod test_layout;

pub use error::TrieDBError;
pub use proof::{
    verify_account_storage_root, verify_storage_exclusion_proof, verify_storage_inclusion_proof,
};
