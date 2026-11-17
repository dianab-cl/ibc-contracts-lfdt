// SPDX-License-Identifier: Apache-2.0

//! The layout of Ethereum's Merkle Patricia tries, for the [`trie_db`] crate.
//!
//! Written from the node encoding in the Ethereum Yellow Paper (Appendix D, "Modified Merkle
//! Patricia Tree") against the [`NodeCodec`] and [`TrieLayout`] traits of `trie_db`.
//!
//! Every node is RLP encoded:
//! - the empty node is the empty string, `0x80`;
//! - a leaf is `[HP(path, leaf), value]` and an extension is `[HP(path, extension), child]`,
//!   where `HP` is the hex-prefix encoding of the remaining key nibbles;
//! - a branch is `[child_0, ..., child_15, value]`, with the empty string for a missing child
//!   or value.
//!
//! A child is referenced by the Keccak-256 hash of its encoding, or embedded as is when its
//! encoding is shorter than 32 bytes.

use std::{borrow::Borrow, ops::Range};

use hash_db::Hasher;
use primitive_types::H256;
use rlp::{Rlp, RlpStream};
use sha3::{Digest, Keccak256};
use trie_db::{
    node::{NibbleSlicePlan, NodeHandlePlan, NodePlan, Value, ValuePlan},
    ChildReference, NodeCodec, TrieLayout,
};

/// Encoding of the empty node: the RLP empty string.
static EMPTY_NODE: [u8; 1] = rlp::NULL_RLP;

/// Hex-prefix flag of a path that ends in a leaf.
const HP_LEAF: u8 = 0x20;
/// Hex-prefix flag of a path with an odd number of nibbles.
const HP_ODD: u8 = 0x10;

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

/// An error decoding a trie node.
#[derive(Debug, thiserror::Error)]
pub enum NodeCodecError {
    /// The node is not valid RLP.
    #[error("invalid rlp: {0}")]
    Rlp(#[from] rlp::DecoderError),
    /// The node is valid RLP, but not a valid trie node.
    #[error("invalid trie node: {0}")]
    InvalidNode(&'static str),
}

/// The [`NodeCodec`] of Ethereum tries; see the module documentation for the encoding.
#[derive(Debug, Clone, Copy, Default)]
pub struct RlpNodeCodec;

/// Returns the range of `item`'s payload in the node, given the offset of `item` in the node.
fn payload_range(item: &Rlp<'_>, offset: usize) -> Result<Range<usize>, NodeCodecError> {
    let info = item.payload_info()?;
    let start = offset + info.header_len;
    Ok(start..start + info.value_len)
}

/// Decodes the hex-prefix encoded path of a leaf or extension. Returns whether the path ends in
/// a leaf, and where its nibbles are in the node.
fn decode_path(item: &Rlp<'_>, offset: usize) -> Result<(bool, NibbleSlicePlan), NodeCodecError> {
    if !item.is_data() {
        return Err(NodeCodecError::InvalidNode("path is not a string"));
    }
    let range = payload_range(item, offset)?;
    let first = *item
        .data()?
        .first()
        .ok_or(NodeCodecError::InvalidNode("empty path"))?;
    let flags = first >> 4;
    if flags > 3 {
        return Err(NodeCodecError::InvalidNode("invalid hex-prefix flags"));
    }
    let is_leaf = flags & (HP_LEAF >> 4) != 0;
    let plan = if flags & (HP_ODD >> 4) != 0 {
        // An odd path starts in the low nibble of the flag byte.
        NibbleSlicePlan::new(range, 1)
    } else {
        if first & 0x0f != 0 {
            return Err(NodeCodecError::InvalidNode("non-zero hex-prefix padding"));
        }
        NibbleSlicePlan::new(range.start + 1..range.end, 0)
    };
    Ok((is_leaf, plan))
}

/// Decodes a child reference of a branch or extension: `None` for the empty string.
fn decode_child(item: &Rlp<'_>, offset: usize) -> Result<Option<NodeHandlePlan>, NodeCodecError> {
    if item.is_list() {
        // An embedded node is stored as its own encoding, which is shorter than a hash.
        let len = item.as_raw().len();
        if len >= HASH_LENGTH {
            return Err(NodeCodecError::InvalidNode(
                "embedded node is not shorter than a hash",
            ));
        }
        return Ok(Some(NodeHandlePlan::Inline(offset..offset + len)));
    }
    let range = payload_range(item, offset)?;
    match range.len() {
        0 => Ok(None),
        HASH_LENGTH => Ok(Some(NodeHandlePlan::Hash(range))),
        _ => Err(NodeCodecError::InvalidNode(
            "child is neither empty, a hash nor an embedded node",
        )),
    }
}

/// Hex-prefix encodes a path of `number_nibble` nibbles, given as `trie_db` provides it: packed
/// two nibbles per byte, with an odd first nibble alone in the low half of the first byte.
fn encode_path(partial: impl Iterator<Item = u8>, number_nibble: usize, leaf: bool) -> Vec<u8> {
    let flag = if leaf { HP_LEAF } else { 0 };
    let mut partial = partial;
    let mut path = Vec::with_capacity(number_nibble / 2 + 1);
    if number_nibble % 2 == 1 {
        let first = partial.next().unwrap_or_default();
        path.push(flag | HP_ODD | (first & 0x0f));
    } else {
        path.push(flag);
    }
    path.extend(partial);
    path
}

/// Appends a child reference to a branch or extension being encoded.
fn append_child(stream: &mut RlpStream, child: Option<&ChildReference<H256>>) {
    match child {
        Some(ChildReference::Hash(hash)) => {
            stream.append(&hash.as_bytes());
        }
        Some(ChildReference::Inline(data, len)) => {
            stream.append_raw(&data.as_bytes()[..*len], 1);
        }
        None => {
            stream.append_empty_data();
        }
    }
}

/// Returns the bytes of a value. [`EthLayout`] stores every value in its node.
fn inline_value<'a>(value: &Value<'a>) -> &'a [u8] {
    match *value {
        Value::Inline(data) => data,
        Value::Node(_) => unreachable!("EthLayout stores every value inline"),
    }
}

impl NodeCodec for RlpNodeCodec {
    type Error = NodeCodecError;
    type HashOut = H256;

    fn hashed_null_node() -> Self::HashOut {
        KeccakHasher::hash(&EMPTY_NODE)
    }

    fn decode_plan(data: &[u8]) -> Result<NodePlan, Self::Error> {
        if Self::is_empty_node(data) {
            return Ok(NodePlan::Empty);
        }

        let node = Rlp::new(data);
        if !node.is_list() || node.payload_info()?.total() != data.len() {
            return Err(NodeCodecError::InvalidNode("not a single RLP list"));
        }
        let items = (0..node.item_count()?)
            .map(|i| node.at_with_offset(i))
            .collect::<Result<Vec<_>, _>>()?;
        // The items must take up the whole list, with nothing after the last one.
        let end = items
            .last()
            .map_or(Ok(node.payload_info()?.header_len), |(item, offset)| {
                item.payload_info().map(|info| offset + info.total())
            })?;
        if end != data.len() {
            return Err(NodeCodecError::InvalidNode("trailing bytes in list"));
        }

        match items.as_slice() {
            [(path, path_offset), (second, second_offset)] => {
                let (is_leaf, partial) = decode_path(path, *path_offset)?;
                if is_leaf {
                    if !second.is_data() {
                        return Err(NodeCodecError::InvalidNode("leaf value is not a string"));
                    }
                    let value = ValuePlan::Inline(payload_range(second, *second_offset)?);
                    Ok(NodePlan::Leaf { partial, value })
                } else {
                    if partial.len() == 0 {
                        return Err(NodeCodecError::InvalidNode("extension with an empty path"));
                    }
                    let child = decode_child(second, *second_offset)?
                        .ok_or(NodeCodecError::InvalidNode("extension without a child"))?;
                    Ok(NodePlan::Extension { partial, child })
                }
            }
            [branch_children @ .., (value, value_offset)] if branch_children.len() == 16 => {
                let mut children: [Option<NodeHandlePlan>; 16] = Default::default();
                for (child, (item, offset)) in children.iter_mut().zip(branch_children) {
                    *child = decode_child(item, *offset)?;
                }
                if !value.is_data() {
                    return Err(NodeCodecError::InvalidNode("branch value is not a string"));
                }
                let range = payload_range(value, *value_offset)?;
                let value = (!range.is_empty()).then_some(ValuePlan::Inline(range));
                Ok(NodePlan::Branch { value, children })
            }
            _ => Err(NodeCodecError::InvalidNode(
                "list is neither a leaf, an extension nor a branch",
            )),
        }
    }

    fn is_empty_node(data: &[u8]) -> bool {
        data == EMPTY_NODE
    }

    fn empty_node() -> &'static [u8] {
        &EMPTY_NODE
    }

    fn leaf_node(partial: impl Iterator<Item = u8>, number_nibble: usize, value: Value) -> Vec<u8> {
        let mut stream = RlpStream::new_list(2);
        stream.append(&encode_path(partial, number_nibble, true).as_slice());
        stream.append(&inline_value(&value));
        stream.out().to_vec()
    }

    fn extension_node(
        partial: impl Iterator<Item = u8>,
        number_nibble: usize,
        child_ref: ChildReference<Self::HashOut>,
    ) -> Vec<u8> {
        let mut stream = RlpStream::new_list(2);
        stream.append(&encode_path(partial, number_nibble, false).as_slice());
        append_child(&mut stream, Some(&child_ref));
        stream.out().to_vec()
    }

    fn branch_node(
        children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
        value: Option<Value>,
    ) -> Vec<u8> {
        let mut stream = RlpStream::new_list(17);
        for child in children {
            append_child(&mut stream, child.borrow().as_ref());
        }
        match value {
            Some(value) => stream.append(&inline_value(&value)),
            None => stream.append_empty_data(),
        };
        stream.out().to_vec()
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
    use trie_db::{trie_visit, TrieRoot};

    use super::*;

    /// Root of a trie built by `trie_db` with this codec, from unhashed keys.
    fn root(entries: &[(&[u8], &[u8])]) -> H256 {
        let mut entries = entries.to_vec();
        entries.sort();
        let mut cb = TrieRoot::<EthLayout>::default();
        trie_visit::<EthLayout, _, _, _, _>(entries, &mut cb);
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
        // alloy-trie is an independent implementation of the same trie; both must produce the
        // same root. Keys within a case have the same length, as in Ethereum's tries (alloy-trie
        // does not support a key that is a prefix of another).
        let cases: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
            // A single leaf.
            vec![(b"doe".to_vec(), b"reindeer".to_vec())],
            // Short keys and values: nodes under 32 bytes are embedded in their parent.
            (0u8..4)
                .flat_map(|i| (0u8..40).step_by(3).map(move |j| (vec![i, j], vec![j])))
                .collect(),
            // A long shared prefix: an extension node above a branch.
            (0u8..5)
                .map(|i| ([[0xaa; 20].as_slice(), &[i]].concat(), vec![i; 40]))
                .collect(),
            // Hashed keys, as in the state and storage tries, with values of varying length.
            (0u8..=200)
                .map(|i| (keccak_256(&[i]).to_vec(), vec![i; usize::from(i % 40) + 1]))
                .collect(),
        ];
        for entries in cases {
            let ours = root(
                &entries
                    .iter()
                    .map(|(k, v)| (k.as_slice(), v.as_slice()))
                    .collect::<Vec<_>>(),
            );
            let mut sorted = entries.clone();
            sorted.sort();
            let mut builder = alloy_trie::HashBuilder::default();
            for (key, value) in &sorted {
                builder.add_leaf(alloy_trie::Nibbles::unpack(key), value);
            }
            assert_eq!(ours.as_bytes(), builder.root().as_slice(), "{entries:?}");
        }
    }

    #[test]
    fn decode_roundtrip() {
        let path = [0x1u8, 0x23, 0x45];
        let leaf =
            RlpNodeCodec::leaf_node(path.iter().copied(), 5, Value::Inline(b"value of the leaf"));
        let NodePlan::Leaf { partial, value } = RlpNodeCodec::decode_plan(&leaf).unwrap() else {
            panic!("expected a leaf");
        };
        let nibbles: Vec<u8> = partial.build(&leaf).iter().collect();
        assert_eq!(nibbles, [1, 2, 3, 4, 5]);
        assert_eq!(value.build(&leaf), Value::Inline(b"value of the leaf"));
    }

    #[test]
    fn rejects_malformed_nodes() {
        let leaf = RlpNodeCodec::leaf_node([0x12u8].into_iter(), 2, Value::Inline(b"v"));
        // Trailing bytes after the node.
        let mut trailing = leaf.clone();
        trailing.push(0x00);
        assert!(RlpNodeCodec::decode_plan(&leaf).is_ok());
        assert!(RlpNodeCodec::decode_plan(&trailing).is_err());
        // A list of three items.
        let mut stream = RlpStream::new_list(3);
        stream.append(&"a").append(&"b").append(&"c");
        assert!(RlpNodeCodec::decode_plan(&stream.out()).is_err());
        // Invalid hex-prefix flags.
        let mut stream = RlpStream::new_list(2);
        stream.append(&[0x40u8].as_slice()).append(&"v");
        assert!(RlpNodeCodec::decode_plan(&stream.out()).is_err());
        // Non-zero padding in an even path.
        let mut stream = RlpStream::new_list(2);
        stream.append(&[0x21u8].as_slice()).append(&"v");
        assert!(RlpNodeCodec::decode_plan(&stream.out()).is_err());
        // A branch child that is neither empty nor a hash.
        let mut stream = RlpStream::new_list(17);
        stream.append(&[0u8; 31].as_slice());
        for _ in 0..16 {
            stream.append_empty_data();
        }
        assert!(RlpNodeCodec::decode_plan(&stream.out()).is_err());
    }
}
