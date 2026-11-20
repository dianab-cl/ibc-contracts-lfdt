// SPDX-License-Identifier: Apache-2.0

//! The layout of Ethereum's Merkle Patricia tries, for the [`trie_db`] crate.
//!
//! Every node is RLP encoded (Ethereum Yellow Paper, Appendix D):
//! - the empty node is the empty string, `0x80`;
//! - a leaf is `[HP(path, leaf), value]` and an extension is `[HP(path, extension), child]`,
//!   where `HP` is the hex-prefix encoding of the remaining key nibbles;
//! - a branch is `[child_0, ..., child_15, value]`, with the empty string for a missing child
//!   or value.
//!
//! A child is referenced by the Keccak-256 hash of its encoding, or embedded as is when its
//! encoding is shorter than 32 bytes.
//!
//! # Compatibility
//!
//! [`RlpNodeCodec`] decodes nodes as the codec of the `ethereum-trie-db` crate it replaces,
//! except that it rejects an embedded child whose encoding is 32 bytes or longer. Every other
//! proof is accepted or rejected as before, with the same error. That includes encodings no
//! Ethereum client produces, which are decoded leniently:
//! - Bytes after the empty node are ignored, and bytes after a list are read as more items of
//!   it.
//! - A path is read from the payload of its item, whether a string or a list. An empty string
//!   or list is an extension with no nibbles.
//! - Of the hex-prefix flag nibble only the leaf and odd bits are read, and the padding nibble
//!   of an even path is ignored.
//! - A leaf or branch value is the payload of its item, whether a string or a list.
//! - An empty string or list as a branch child or value means none.
//! - A child that is a 32-byte string is a hash. Anything else shorter than 32 bytes is an
//!   embedded node, which fails to decode only if a lookup reaches it.
//!
//! The tests below pin each of these down.

use std::{borrow::Borrow, ops::Range};

use hash_db::Hasher;
use primitive_types::H256;
use rlp::{DecoderError, Prototype, Rlp};
use sha3::{Digest, Keccak256};
use trie_db::{
    node::{NibbleSlicePlan, NodeHandlePlan, NodePlan, Value, ValuePlan},
    ChildReference, NodeCodec, TrieLayout,
};

/// Encoding of the empty node: the RLP empty string.
static EMPTY_NODE: [u8; 1] = rlp::NULL_RLP;

/// Hex-prefix flag of a path that ends in a leaf.
pub(super) const HP_LEAF: u8 = 0x20;
/// Hex-prefix flag of a path with an odd number of nibbles.
pub(super) const HP_ODD: u8 = 0x10;

/// Length of a Keccak-256 hash, and the size from which a child is referenced by its hash.
const HASH_LENGTH: usize = 32;

/// Returns the Keccak-256 hash of `data`.
#[must_use]
pub fn keccak_256(data: &[u8]) -> [u8; HASH_LENGTH] {
    Keccak256::digest(data).into()
}

/// The [`Hasher`] of Ethereum tries: Keccak-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeccakHasher;

impl Hasher for KeccakHasher {
    type Out = H256;
    type StdHasher = hash256_std_hasher::Hash256StdHasher;
    const LENGTH: usize = HASH_LENGTH;

    fn hash(data: &[u8]) -> Self::Out {
        H256(keccak_256(data))
    }
}

/// The [`TrieLayout`] of Ethereum's state and storage tries: extension nodes, Keccak-256, and
/// values always stored in their node.
#[derive(Debug, Clone, Copy, Default)]
pub struct EthLayout;

impl TrieLayout for EthLayout {
    const USE_EXTENSION: bool = true;
    const ALLOW_EMPTY: bool = false;
    const MAX_INLINE_VALUE: Option<u32> = None;

    type Hash = KeccakHasher;
    type Codec = RlpNodeCodec;
}

/// The error for RLP that is not a trie node; the message is the one `ethereum-trie-db` used.
const NOT_A_NODE: DecoderError = DecoderError::Custom("Rlp is not valid.");

/// The error for an embedded child whose encoding is too long to be embedded: a child of
/// [`HASH_LENGTH`] bytes or more must be referenced by its hash.
const EMBEDDED_NODE_TOO_LONG: DecoderError =
    DecoderError::Custom("Embedded node is not shorter than a hash.");

/// Number of children of a branch.
const BRANCH_CHILDREN: usize = 16;

/// Number of items of a branch node: its children and its value.
const BRANCH_ITEMS: usize = BRANCH_CHILDREN + 1;

/// The [`NodeCodec`] of Ethereum tries; see the module documentation for the encoding.
#[derive(Debug, Clone, Copy, Default)]
pub struct RlpNodeCodec;

/// Returns the range of `item`'s payload in the node, given the offset of `item` in the node.
fn payload_range(item: &Rlp<'_>, offset: usize) -> Result<Range<usize>, DecoderError> {
    let info = item.payload_info()?;
    let start = offset + info.header_len;
    Ok(start..start + info.value_len)
}

/// Decodes the hex-prefix encoded path of a leaf or extension. Returns whether the path ends in
/// a leaf, and where its nibbles are in the node.
fn decode_path(item: &Rlp<'_>, offset: usize) -> Result<(bool, NibbleSlicePlan), DecoderError> {
    let range = payload_range(item, offset)?;
    // The payload of a string or a list.
    let Some(&flags) = item.data()?.first() else {
        // An empty string or list: an extension with no nibbles.
        return Ok((false, NibbleSlicePlan::new(range.start..range.start, 0)));
    };
    let plan = if flags & HP_ODD != 0 {
        // An odd path starts in the low nibble of the flag byte.
        NibbleSlicePlan::new(range, 1)
    } else {
        NibbleSlicePlan::new(range.start + 1..range.end, 0)
    };
    let is_leaf = flags & HP_LEAF != 0;
    Ok((is_leaf, plan))
}

/// Decodes the item of a child of a branch or extension: a hash if it is a 32-byte string, and
/// an embedded node if its encoding is shorter than a hash.
fn decode_child(item: &Rlp<'_>, offset: usize) -> Result<NodeHandlePlan, DecoderError> {
    if item.is_data() && item.size() == HASH_LENGTH {
        return Ok(NodeHandlePlan::Hash(payload_range(item, offset)?));
    }

    let len = item.as_raw().len();
    if len >= HASH_LENGTH {
        return Err(EMBEDDED_NODE_TOO_LONG);
    }
    Ok(NodeHandlePlan::Inline(offset..offset + len))
}

impl NodeCodec for RlpNodeCodec {
    type Error = DecoderError;
    type HashOut = H256;

    fn hashed_null_node() -> Self::HashOut {
        KeccakHasher::hash(&EMPTY_NODE)
    }

    fn decode_plan(data: &[u8]) -> Result<NodePlan, Self::Error> {
        // `prototype` counts the items of a list up to the end of `data`, not of the list, and
        // reads a malformed string as an empty one (see the module documentation).
        let node = Rlp::new(data);
        match node.prototype()? {
            Prototype::Data(0) => Ok(NodePlan::Empty),
            Prototype::List(2) => {
                let (path, path_offset) = node.at_with_offset(0)?;
                let (is_leaf, partial) = decode_path(&path, path_offset)?;
                let (second, second_offset) = node.at_with_offset(1)?;
                if is_leaf {
                    let value = ValuePlan::Inline(payload_range(&second, second_offset)?);
                    Ok(NodePlan::Leaf { partial, value })
                } else {
                    let child = decode_child(&second, second_offset)?;
                    Ok(NodePlan::Extension { partial, child })
                }
            }
            Prototype::List(BRANCH_ITEMS) => {
                let mut children: [Option<NodeHandlePlan>; BRANCH_CHILDREN] = Default::default();
                for (index, child) in children.iter_mut().enumerate() {
                    let (item, offset) = node.at_with_offset(index)?;
                    if !item.is_empty() {
                        *child = Some(decode_child(&item, offset)?);
                    }
                }
                let (value, value_offset) = node.at_with_offset(BRANCH_CHILDREN)?;
                let value = if value.is_empty() {
                    None
                } else {
                    Some(ValuePlan::Inline(payload_range(&value, value_offset)?))
                };
                Ok(NodePlan::Branch { value, children })
            }
            _ => Err(NOT_A_NODE),
        }
    }

    fn is_empty_node(data: &[u8]) -> bool {
        // Like `ethereum-trie-db`: anything starting with an empty string or list.
        Rlp::new(data).is_empty()
    }

    fn empty_node() -> &'static [u8] {
        &EMPTY_NODE
    }

    // Proof verification only decodes nodes; the tests encode them with `test_layout`.

    fn leaf_node(_: impl Iterator<Item = u8>, _: usize, _: Value) -> Vec<u8> {
        unreachable!("proof verification does not encode nodes")
    }

    fn extension_node(
        _: impl Iterator<Item = u8>,
        _: usize,
        _: ChildReference<Self::HashOut>,
    ) -> Vec<u8> {
        unreachable!("proof verification does not encode nodes")
    }

    fn branch_node(
        _: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
        _: Option<Value>,
    ) -> Vec<u8> {
        unreachable!("proof verification does not encode nodes")
    }

    fn branch_node_nibbled(
        _partial: impl Iterator<Item = u8>,
        _number_nibble: usize,
        _children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
        _value: Option<Value>,
    ) -> Vec<u8> {
        unreachable!("EthLayout uses extension nodes, not nibbled branches")
    }
}

#[cfg(test)]
mod tests {
    use rlp::RlpStream;
    use trie_db::{trie_visit, TrieRoot};

    use super::*;
    use crate::mpt::test_layout::{TestCodec, TestLayout};

    /// Root of a trie built by `trie_db` with this codec, from unhashed keys.
    fn root(entries: &[(&[u8], &[u8])]) -> H256 {
        let mut entries = entries.to_vec();
        entries.sort();
        let mut cb = TrieRoot::<TestLayout>::default();
        trie_visit::<TestLayout, _, _, _, _>(entries, &mut cb);
        cb.root.unwrap_or_else(RlpNodeCodec::hashed_null_node)
    }

    #[test]
    fn empty_trie_root() {
        // keccak256(rlp("")), the root of every empty Ethereum trie.
        assert_eq!(
            hex::encode(RlpNodeCodec::hashed_null_node()),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn roots_match_alloy_trie() {
        // The expected roots were computed with alloy-trie, an independent implementation of
        // the same trie. Keys within a case have the same length, as in Ethereum's tries
        // (alloy-trie does not support a key that is a prefix of another).
        type Entries = Vec<(Vec<u8>, Vec<u8>)>;
        let cases: Vec<(Entries, &str)> = vec![
            // A single leaf.
            (
                vec![(b"doe".to_vec(), b"reindeer".to_vec())],
                "11a0327cfcc5b7689b6b6d727e1f5f8846c1137caaa9fc871ba31b7cce1b703e",
            ),
            // Short keys and values: nodes under 32 bytes are embedded in their parent.
            (
                (0u8..4)
                    .flat_map(|i| (0u8..40).step_by(3).map(move |j| (vec![i, j], vec![j])))
                    .collect(),
                "bb32d1f5751fa4adc29bd1bc60b49e5bfb690b9cd884e78826921f97ae7d4bc2",
            ),
            // A long shared prefix: an extension node above a branch.
            (
                (0u8..5)
                    .map(|i| ([[0xaa; 20].as_slice(), &[i]].concat(), vec![i; 40]))
                    .collect(),
                "2bd7685455748c32dae45f31762916a896859ba436a7f4a405858f432953be76",
            ),
            // Hashed keys, as in the state and storage tries, with values of varying length.
            (
                (0u8..=200)
                    .map(|i| (keccak_256(&[i]).to_vec(), vec![i; usize::from(i % 40) + 1]))
                    .collect(),
                "7923cb386df58f5fa8afa537ceaec1ff11d6783c9905eebd5f79a2007bbf6529",
            ),
        ];
        for (entries, expected) in cases {
            let ours = root(
                &entries
                    .iter()
                    .map(|(k, v)| (k.as_slice(), v.as_slice()))
                    .collect::<Vec<_>>(),
            );
            assert_eq!(hex::encode(ours), expected, "{entries:?}");
        }
    }

    #[test]
    fn decode_roundtrip() {
        let path = [0x1u8, 0x23, 0x45];
        let leaf =
            TestCodec::leaf_node(path.iter().copied(), 5, Value::Inline(b"value of the leaf"));
        let NodePlan::Leaf { partial, value } = RlpNodeCodec::decode_plan(&leaf).unwrap() else {
            panic!("expected a leaf");
        };
        let nibbles: Vec<u8> = partial.build(&leaf).iter().collect();
        assert_eq!(nibbles, [1, 2, 3, 4, 5]);
        assert_eq!(value.build(&leaf), Value::Inline(b"value of the leaf"));
    }

    // The tests below pin down how nodes are decoded, including the encodings that no Ethereum
    // client produces but that `ethereum-trie-db` accepted (see the module documentation).

    /// A child reference to a hashed node.
    const HASH: [u8; 32] = [0x11; 32];

    /// The RLP encoding of the string `data`.
    fn string(data: &[u8]) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream.append(&data);
        stream.out().to_vec()
    }

    /// An RLP list of already encoded `items`.
    fn list(items: &[&[u8]]) -> Vec<u8> {
        let mut stream = RlpStream::new_list(items.len());
        for item in items {
            stream.append_raw(item, 1);
        }
        stream.out().to_vec()
    }

    /// A branch with `first` as its first child, no other children, and `value`; both encoded.
    fn branch(first: &[u8], value: &[u8]) -> Vec<u8> {
        let empty = string(&[]);
        let mut items = vec![first];
        items.extend(std::iter::repeat_n(empty.as_slice(), 15));
        items.push(value);
        list(&items)
    }

    /// An extension over the nibbles `1, 2` to the encoded `child`.
    fn extension(child: &[u8]) -> Vec<u8> {
        list(&[&string(&[0x00, 0x12]), child])
    }

    fn decode(node: &[u8]) -> NodePlan {
        RlpNodeCodec::decode_plan(node).unwrap_or_else(|e| panic!("{}: {e:?}", hex::encode(node)))
    }

    fn rejects(node: &[u8]) -> bool {
        RlpNodeCodec::decode_plan(node).is_err()
    }

    /// The nibbles of a leaf or extension path.
    fn nibbles(node: &[u8]) -> Vec<u8> {
        match decode(node) {
            NodePlan::Leaf { partial, .. } | NodePlan::Extension { partial, .. } => {
                partial.build(node).iter().collect()
            }
            plan => panic!("not a leaf or extension: {plan:?}"),
        }
    }

    fn leaf_value(node: &[u8]) -> Vec<u8> {
        let NodePlan::Leaf { value, .. } = decode(node) else {
            panic!("expected a leaf");
        };
        let Value::Inline(value) = value.build(node) else {
            panic!("expected an inline value");
        };
        value.to_vec()
    }

    fn branch_value(node: &[u8]) -> Option<Vec<u8>> {
        let NodePlan::Branch { value, .. } = decode(node) else {
            panic!("expected a branch");
        };
        value.map(|value| match value.build(node) {
            Value::Inline(value) => value.to_vec(),
            Value::Node(_) => panic!("expected an inline value"),
        })
    }

    fn first_child(node: &[u8]) -> Option<NodeHandlePlan> {
        match decode(node) {
            NodePlan::Branch { children, .. } => children[0].clone(),
            NodePlan::Extension { child, .. } => Some(child),
            plan => panic!("not a branch or extension: {plan:?}"),
        }
    }

    #[test]
    fn rejects_rlp_that_is_not_a_node() {
        assert!(rejects(&[]));
        assert!(rejects(&[0xc0]));
        assert!(rejects(&string(&[0x11])));
        assert!(rejects(&list(&[
            &string(b"a"),
            &string(b"b"),
            &string(b"c")
        ])));
        assert!(rejects(&list(&[&string(&[0x20])])));
        // Bytes after a list are read as more items of it: here a third item.
        let mut trailing = list(&[&string(&[0x20]), &string(b"v")]);
        assert!(!rejects(&trailing));
        trailing.push(0x00);
        assert!(rejects(&trailing));
    }

    #[test]
    fn bytes_after_a_list_are_more_items() {
        let mut node = list(&[&string(&[0x20])]);
        node.extend(string(b"v"));
        assert_eq!(leaf_value(&node), b"v");
    }

    #[test]
    fn empty_node_ignores_trailing_bytes() {
        assert!(matches!(decode(&[0x80]), NodePlan::Empty));
        assert!(matches!(decode(&[0x80, 0x00]), NodePlan::Empty));
        assert!(RlpNodeCodec::is_empty_node(&[0x80]));
        assert!(RlpNodeCodec::is_empty_node(&[0xc0, 0x00]));
        assert!(!RlpNodeCodec::is_empty_node(&[]));
    }

    #[test]
    fn empty_path_is_an_extension_without_nibbles() {
        let hash = string(&HASH);
        for path in [string(&[]), vec![0xc0], string(&[0x00])] {
            let node = list(&[&path, &hash]);
            assert!(matches!(decode(&node), NodePlan::Extension { .. }));
            assert!(nibbles(&node).is_empty());
        }
    }

    #[test]
    fn reads_only_the_leaf_and_odd_flag_bits() {
        let v = string(b"v");
        // Odd leaf, odd extension, even leaf and even extension.
        assert_eq!(nibbles(&list(&[&string(&[0x31, 0x23]), &v])), [1, 2, 3]);
        assert_eq!(leaf_value(&list(&[&string(&[0x31, 0x23]), &v])), b"v");
        assert!(matches!(
            decode(&list(&[&string(&[0x11]), &v])),
            NodePlan::Extension { .. }
        ));
        assert_eq!(nibbles(&list(&[&string(&[0x20, 0x12]), &v])), [1, 2]);
        assert!(matches!(
            decode(&list(&[&string(&[0x00, 0x12]), &v])),
            NodePlan::Extension { .. }
        ));
        // Higher flag bits are ignored: 0x7_ is an odd leaf, 0x4_ an even extension.
        assert_eq!(leaf_value(&list(&[&string(&[0x71, 0x23]), &v])), b"v");
        assert_eq!(nibbles(&list(&[&string(&[0x71, 0x23]), &v])), [1, 2, 3]);
        assert!(matches!(
            decode(&list(&[&string(&[0x40, 0x12]), &v])),
            NodePlan::Extension { .. }
        ));
        assert_eq!(nibbles(&list(&[&string(&[0x40, 0x12]), &v])), [1, 2]);
        // The padding nibble of an even path is ignored.
        assert_eq!(nibbles(&list(&[&string(&[0x2f, 0x12]), &v])), [1, 2]);
    }

    #[test]
    fn path_is_read_from_the_payload_of_a_list() {
        // The payload of `[0x20, 0x12]` is the bytes `20 12`: an even leaf path over `1, 2`.
        let path = list(&[&string(&[0x20]), &string(&[0x12])]);
        let node = list(&[&path, &string(b"v")]);
        assert_eq!(nibbles(&node), [1, 2]);
        assert_eq!(leaf_value(&node), b"v");
    }

    #[test]
    fn value_is_the_payload_of_a_string_or_list() {
        let hash = string(&HASH);
        let listed = list(&[&string(b"v")]);
        assert_eq!(leaf_value(&list(&[&string(&[0x20]), &listed])), b"v");
        assert_eq!(leaf_value(&list(&[&string(&[0x20]), &string(&[])])), b"");
        assert_eq!(
            branch_value(&branch(&hash, &string(b"v"))),
            Some(b"v".to_vec())
        );
        assert_eq!(branch_value(&branch(&hash, &listed)), Some(b"v".to_vec()));
        assert_eq!(branch_value(&branch(&hash, &string(&[]))), None);
        assert_eq!(branch_value(&branch(&hash, &[0xc0])), None);
    }

    #[test]
    fn empty_branch_child_is_none() {
        assert!(first_child(&branch(&string(&[]), &string(&[]))).is_none());
        assert!(first_child(&branch(&[0xc0], &string(&[]))).is_none());
    }

    #[test]
    fn child_is_a_hash_only_if_a_32_byte_string() {
        let hash = string(&HASH);
        assert_eq!(
            first_child(&branch(&hash, &string(&[]))),
            Some(NodeHandlePlan::Hash(2..34))
        );
        assert_eq!(
            first_child(&extension(&hash)),
            Some(NodeHandlePlan::Hash(5..37))
        );
        // Anything else shorter than a hash is an embedded node.
        let short_node = list(&[&string(&[0x20]), &string(&[7; 20])]);
        for child in [string(&[0x11]), string(&[0x11; 30]), short_node.clone()] {
            assert!(child.len() < HASH_LENGTH);
            for node in [branch(&child, &string(&[])), extension(&child)] {
                let Some(NodeHandlePlan::Inline(range)) = first_child(&node) else {
                    panic!("expected an embedded node: {}", hex::encode(&node));
                };
                assert_eq!(node[range], child);
            }
        }
        // An embedded node is decoded only when a lookup reaches it.
        assert!(rejects(&string(&[0x11; 30])));
        assert!(!rejects(&short_node));
    }

    #[test]
    fn rejects_embedded_child_not_shorter_than_a_hash() {
        let long_node = list(&[&string(&[0x20]), &string(&[7; 40])]);
        // A 31-byte string encodes to exactly 32 bytes, the smallest rejected length.
        for child in [string(&[0x11; 31]), string(&[0x11; 33]), long_node] {
            assert!(child.len() >= HASH_LENGTH);
            for node in [branch(&child, &string(&[])), extension(&child)] {
                assert_eq!(
                    RlpNodeCodec::decode_plan(&node),
                    Err(EMBEDDED_NODE_TOO_LONG),
                    "{}",
                    hex::encode(&node)
                );
            }
        }
    }

    #[test]
    fn extension_to_the_empty_string_embeds_the_empty_node() {
        let node = extension(&string(&[]));
        assert_eq!(first_child(&node), Some(NodeHandlePlan::Inline(4..5)));
        assert!(matches!(decode(&[0x80]), NodePlan::Empty));
        assert_eq!(
            first_child(&extension(&[0xc0])),
            Some(NodeHandlePlan::Inline(4..5))
        );
        assert!(rejects(&[0xc0]));
    }
}
