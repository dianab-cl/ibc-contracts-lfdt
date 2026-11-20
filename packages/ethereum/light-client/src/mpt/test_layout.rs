// SPDX-License-Identifier: Apache-2.0

//! A [`TrieLayout`] for tests that build Ethereum tries.
//!
//! [`RlpNodeCodec`] only decodes nodes, as proof verification never encodes them. To build test
//! tries and proofs, [`TestCodec`] decodes with [`RlpNodeCodec`] and also encodes nodes, in the
//! encoding described in the documentation of [`super::layout`].

use std::borrow::Borrow;

use primitive_types::H256;
use rlp::{DecoderError, RlpStream};
use trie_db::{
    node::{NodePlan, Value},
    ChildReference, NodeCodec, TrieLayout,
};

use super::layout::{EthLayout, KeccakHasher, RlpNodeCodec, HP_LEAF, HP_ODD};

/// [`EthLayout`] with a codec that can also encode nodes.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestLayout;

impl TrieLayout for TestLayout {
    const USE_EXTENSION: bool = EthLayout::USE_EXTENSION;
    const ALLOW_EMPTY: bool = EthLayout::ALLOW_EMPTY;
    const MAX_INLINE_VALUE: Option<u32> = EthLayout::MAX_INLINE_VALUE;

    type Hash = KeccakHasher;
    type Codec = TestCodec;
}

/// [`RlpNodeCodec`], plus encoding.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestCodec;

/// Hex-prefix encodes a path of `number_nibble` nibbles, given as `trie_db` provides it: packed
/// two nibbles per byte, with an odd first nibble alone in the low half of the first byte.
fn encode_path(mut partial: impl Iterator<Item = u8>, number_nibble: usize, leaf: bool) -> Vec<u8> {
    let flag = if leaf { HP_LEAF } else { 0 };
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

impl NodeCodec for TestCodec {
    type Error = DecoderError;
    type HashOut = H256;

    fn hashed_null_node() -> Self::HashOut {
        RlpNodeCodec::hashed_null_node()
    }

    fn decode_plan(data: &[u8]) -> Result<NodePlan, Self::Error> {
        RlpNodeCodec::decode_plan(data)
    }

    fn is_empty_node(data: &[u8]) -> bool {
        RlpNodeCodec::is_empty_node(data)
    }

    fn empty_node() -> &'static [u8] {
        RlpNodeCodec::empty_node()
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
