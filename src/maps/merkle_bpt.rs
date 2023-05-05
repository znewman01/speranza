//! Merkle binary prefix tree (trie) for representing a dictionary.
//!
//! Follows CONIKS.
use digest::Output;
use std::{collections::HashMap, fmt::Debug, marker::PhantomData};
use thiserror::Error;

pub use digest::Digest as Hasher;

use crate::util::{bit_twiddling::*, FixedSizedBytes, SizedBytes};
use crate::util::{hash_canonical, Canonicalize};

const NONCE: [u8; 4] = [0, 0, 0, 0];
const NODE_TYPE_EMPTY: [u8; 4] = [0, 0, 0, 1];
const NODE_TYPE_LEAF: [u8; 4] = [0, 0, 0, 2];

/// A direction in the tree.
#[derive(Debug, Clone, Copy)]
enum Direction {
    Left,
    Right,
}

use Direction::*;

impl From<bool> for Direction {
    fn from(value: bool) -> Self {
        match value {
            false => Left,
            true => Right,
        }
    }
}

#[derive(Debug, Clone)]
struct LeafData<H: Hasher> {
    /// H(key)
    key_index: Output<H>,
    /// How deep in the prefix tree? (0-indexed)
    depth: usize,
    /// H(value).
    value_hash: Output<H>,
}

impl<H: Hasher> LeafData<H> {
    fn new(index: Output<H>, depth: usize, value: Output<H>) -> Self {
        Self {
            key_index: index,
            depth,
            value_hash: value,
        }
    }

    fn hash(&self) -> Output<H> {
        let mut hasher = H::new();
        hasher.update(NODE_TYPE_LEAF);
        hasher.update(NONCE);
        hasher.update(&self.key_index);
        hasher.update(self.depth.to_le_bytes());
        hasher.update(&self.value_hash);
        hasher.finalize()
    }

    fn from_key_value<K: Canonicalize, V: Canonicalize>(depth: usize, key: &K, value: &V) -> Self {
        Self::new(
            hash_canonical::<_, H>(key),
            depth,
            hash_canonical::<_, H>(value),
        )
    }
}

impl<H: Hasher> FixedSizedBytes for LeafData<H> {
    fn fixed_size_bytes() -> usize {
        usize::try_from(usize::BITS / 8).unwrap() + H::output_size() * 2
    }
}

#[derive(Debug, Clone)]
struct EmptyData<H: Hasher> {
    /// How deep in the prefix tree?
    depth: usize,
    /// The unique prefix.
    prefix: Output<H>,
}

impl<H: Hasher> FixedSizedBytes for EmptyData<H> {
    fn fixed_size_bytes() -> usize {
        usize::try_from(usize::BITS / 8).unwrap() + H::output_size()
    }
}

impl<H: Hasher> EmptyData<H> {
    fn new(depth: usize, prefix: Output<H>) -> Self {
        debug_assert_eq!(mask(&prefix, depth), prefix);
        Self { depth, prefix }
    }

    fn hash(&self) -> Output<H> {
        let mut hasher = H::new();
        hasher.update(NODE_TYPE_EMPTY);
        hasher.update(NONCE);
        hasher.update(&self.prefix);
        hasher.update(self.depth.to_le_bytes());
        hasher.finalize()
    }
}

fn hash_interior<H: Hasher>(left: &Output<H>, right: &Output<H>) -> Output<H> {
    let mut hasher = H::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

#[derive(Debug, Clone)]
struct InteriorData<H: Hasher> {
    left: Box<Node<H>>,
    right: Box<Node<H>>,
}

impl<H: Hasher> FixedSizedBytes for InteriorData<H> {
    fn fixed_size_bytes() -> usize {
        usize::try_from(usize::BITS / 8).unwrap() * 2
    }
}

impl<H: Hasher> InteriorData<H> {
    fn new(left: Box<Node<H>>, right: Box<Node<H>>) -> Self {
        Self { left, right }
    }

    #[allow(clippy::borrowed_box)]
    fn child(&self, direction: Direction) -> &Box<Node<H>> {
        match direction {
            Left => &self.left,
            Right => &self.right,
        }
    }

    fn child_mut(&mut self, direction: Direction) -> &mut Node<H> {
        match direction {
            Left => self.left.as_mut(),
            Right => self.right.as_mut(),
        }
    }

    fn sibling(&self, direction: Direction) -> &Node<H> {
        match direction {
            Left => &self.right,
            Right => &self.left,
        }
    }
}

impl<H: Hasher> InteriorData<H> {
    fn hash(&self) -> Output<H> {
        hash_interior::<H>(&self.left.hash, &self.right.hash)
    }
}

#[derive(Debug, Clone)]
enum NodeData<H: Hasher> {
    Leaf(LeafData<H>),
    Empty(EmptyData<H>),
    Interior(InteriorData<H>),
}

#[derive(Debug, Clone)]
struct Node<H: Hasher> {
    inner: NodeData<H>,
    hash: Output<H>,
}

impl<H: Hasher> From<LeafData<H>> for Node<H> {
    fn from(data: LeafData<H>) -> Self {
        let hash = data.hash();
        let inner = NodeData::Leaf(data);
        Self { inner, hash }
    }
}

impl<H: Hasher> From<EmptyData<H>> for Node<H> {
    fn from(data: EmptyData<H>) -> Self {
        let hash = data.hash();
        let inner = NodeData::Empty(data);
        Self { inner, hash }
    }
}

impl<H: Hasher> From<InteriorData<H>> for Node<H> {
    fn from(inner: InteriorData<H>) -> Self {
        let hash = hash_interior::<H>(&inner.left.hash, &inner.right.hash);
        let inner = NodeData::Interior(inner);
        Self { inner, hash }
    }
}

impl<H: Hasher> Node<H> {
    fn leaf(index: Output<H>, depth: usize, value: Output<H>) -> Self {
        LeafData::new(index, depth, value).into()
    }

    fn empty(depth: usize, prefix: Output<H>) -> Self {
        EmptyData::new(depth, prefix).into()
    }

    fn interior(left: Box<Node<H>>, right: Box<Node<H>>) -> Self {
        InteriorData::new(left, right).into()
    }

    fn interior_for_direction(
        child: Box<Node<H>>,
        sibling: Box<Node<H>>,
        direction: Direction,
    ) -> Self {
        match direction {
            Left => Self::interior(child, sibling),
            Right => Self::interior(sibling, child),
        }
    }

    fn rehash(&mut self) {
        self.hash = match &self.inner {
            NodeData::Leaf(data) => data.hash(),
            NodeData::Empty(data) => data.hash(),
            NodeData::Interior(inner) => inner.hash(),
        };
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
struct NodeCounts {
    interior: isize,
    leaf: isize,
    empty: isize,
}

impl NodeCounts {
    fn interior_unsigned(&self) -> usize {
        self.interior.try_into().unwrap()
    }

    fn leaf_unsigned(&self) -> usize {
        self.leaf.try_into().unwrap()
    }

    fn empty_unsigned(&self) -> usize {
        self.empty.try_into().unwrap()
    }
}

impl std::ops::AddAssign for NodeCounts {
    fn add_assign(&mut self, rhs: Self) {
        self.interior += rhs.interior;
        self.leaf += rhs.leaf;
        self.empty += rhs.empty;
    }
}

impl std::ops::Add for NodeCounts {
    type Output = NodeCounts;

    fn add(self, rhs: Self) -> Self::Output {
        NodeCounts {
            interior: self.interior + rhs.interior,
            leaf: self.leaf + rhs.leaf,
            empty: self.empty + rhs.empty,
        }
    }
}

/// Binary Merkle Prefix Tree.
#[derive(Debug, Clone)]
pub struct Tree<K: Canonicalize, V: Canonicalize, H: Hasher> {
    /// The root node of a Merkle prefix tree for the given keys/values.
    root: Box<Node<H>>,
    /// This is where the actual keys and values are stored.
    values: HashMap<K, V>,
    node_counts: NodeCounts,
}

impl<K: Canonicalize, V: Canonicalize, H: Hasher> Tree<K, V, H> {
    pub fn values(&self) -> &HashMap<K, V> {
        &self.values
    }
}

impl<K: Canonicalize, V: Canonicalize, H: Hasher> Default for Tree<K, V, H> {
    fn default() -> Self {
        let root = Box::new(Node::empty(0, Default::default()));
        let node_counts = NodeCounts {
            interior: 0,
            leaf: 0,
            empty: 1,
        };
        Self {
            root,
            values: Default::default(),
            node_counts,
        }
    }
}

#[derive(Debug, Clone)]
enum ProofInner<V, H: Hasher> {
    Member(V),
    NonMemberEmpty(Output<H>),
    NonMemberLeaf {
        leaf_index: Output<H>,
        value_hash: Output<H>,
    },
}

impl<V, H: Hasher> SizedBytes for ProofInner<V, H>
where
    V: SizedBytes,
{
    fn size_bytes(&self) -> usize {
        match self {
            Member(v) => v.size_bytes(),
            NonMemberEmpty(_) => H::output_size(),
            NonMemberLeaf { .. } => H::output_size() * 2,
        }
    }
}

use ProofInner::*;

use super::Map;

#[derive(Debug, Clone)]
pub struct Proof<V, H: Hasher> {
    /// Root to leaf.
    sibling_hashes: Vec<Output<H>>,
    /// H(key)
    key_index: Output<H>,
    inner: ProofInner<V, H>,
}

impl<V, H: Hasher> Proof<V, H> {
    pub fn get_unverified(&self) -> Option<&V> {
        match &self.inner {
            Member(value) => Some(value),
            NonMemberEmpty(_) => None,
            NonMemberLeaf { .. } => None,
        }
    }
}

impl<V: Clone, H: Hasher> Proof<&V, H> {
    pub fn cloned(self) -> Proof<V, H> {
        use ProofInner::*;

        let inner = match self.inner {
            Member(value) => Member(value.clone()),
            NonMemberEmpty(x) => NonMemberEmpty(x),
            NonMemberLeaf {
                leaf_index,
                value_hash,
            } => NonMemberLeaf {
                leaf_index,
                value_hash,
            },
        };
        Proof {
            inner,
            sibling_hashes: self.sibling_hashes,
            key_index: self.key_index,
        }
    }
}

impl<V, H: Hasher> SizedBytes for Proof<V, H>
where
    ProofInner<V, H>: SizedBytes,
{
    fn size_bytes(&self) -> usize {
        self.sibling_hashes
            .iter()
            .map(|_| H::output_size())
            .sum::<usize>()
            + H::output_size()
            + self.inner.size_bytes()
    }
}

#[derive(Debug, Clone)]
pub struct Digest<K, H: Hasher> {
    value: Output<H>,
    _key: PhantomData<K>,
}

impl<K, H: Hasher> SizedBytes for Digest<K, H> {
    fn size_bytes(&self) -> usize {
        H::output_size()
    }
}

/// Insert a node recursively into the tree rooted at `current_node`.
///
/// Returns the *change* to the node counts.
fn insert_recursive<H: Hasher>(
    current_node: &mut Node<H>,
    depth: usize,
    index: Output<H>,
    value_hash: Output<H>,
) -> NodeCounts
where
    Output<H>: Copy,
{
    let mut delta_node_counts = NodeCounts::default();
    let new_node = match &mut current_node.inner {
        NodeData::Leaf(data) => {
            debug_assert_eq!(data.depth, depth);
            if data.key_index == index {
                // We already had this key; just update its value (by replacing the leaf node).
                Some(Node::leaf(index, depth, value_hash))
            } else {
                // There's already a leaf there. Need to prepare interior nodes.
                debug_assert_eq!(mask(&data.key_index, depth), mask(&index, depth));

                // The existing leaf and the new leaf share a prefix (possibly
                // beyond `depth`). Find it.
                //
                // existing:  0 1 0 1 0 1 0 1
                // new_leaf:  0 1 0 1 0 0 0 1
                //                      ^shared_prefix_len
                let shared_prefix_len = shared_prefix_length(data.key_index, index);

                // There will be interior nodes from `depth` until
                // `shared_prefix_len`, at which point there will be the two
                // leaf nodes.
                delta_node_counts.leaf += 2;
                let mut child = Box::new(Node::leaf(index, shared_prefix_len + 1, value_hash));
                let mut sibling = Box::new(Node::leaf(
                    data.key_index,
                    shared_prefix_len + 1,
                    data.value_hash,
                ));
                for i in ((depth + 1)..=shared_prefix_len).rev() {
                    let direction = Direction::from(get_bit_i(&index, i));
                    delta_node_counts.interior += 1;
                    child = Box::new(Node::interior_for_direction(child, sibling, direction));

                    // Make the empty leaf for the next level up. It should
                    // differ from `index` at bit `i - 1`.
                    let mut other_index = mask(&index, i);
                    flip_bit_i(&mut other_index, i - 1);
                    delta_node_counts.empty += 1;
                    sibling = Box::new(Node::empty(i, other_index));
                }

                // Create the interior node that will replace the existing leaf.
                let direction = Direction::from(get_bit_i(&index, depth));

                delta_node_counts.leaf += -1;
                delta_node_counts.interior += 1;
                Some(Node::interior_for_direction(child, sibling, direction))
            }
        }
        NodeData::Empty(data) => {
            // Replace the empty node with a leaf node.
            debug_assert_eq!(data.depth, depth);
            debug_assert_eq!(mask(&data.prefix, depth), mask(&index, depth));
            delta_node_counts.empty -= 1;
            delta_node_counts.leaf += 1;
            Some(Node::leaf(index, depth, value_hash))
        }
        NodeData::Interior(inner) => {
            // Recurse down the tree. This node is unchanged (but will need to be rehashed).
            let direction = Direction::from(get_bit_i(&index, depth));
            delta_node_counts =
                insert_recursive(inner.child_mut(direction), depth + 1, index, value_hash);
            None
        }
    };

    // Replace the current node with `new_node`, if applicable.
    if let Some(new_node) = new_node {
        *current_node = new_node;
    }
    current_node.rehash();

    delta_node_counts
}

/// Verification of a Merkle BPT proof failed.
#[derive(Error, PartialEq, Debug)]
pub enum VerificationError {
    #[error(
        "index of leaf {leaf_index:?} did not match given key index {key_index:?} (depth {depth})"
    )]
    IndexMismatch {
        leaf_index: Vec<u8>,
        key_index: Vec<u8>,
        depth: usize,
    },
    #[error("non-member proof provided, but indexes match completely: {0:?}")]
    UnexpectedIndexMatch(Vec<u8>),
    #[error("computed hash {computed:?} doesn't match expected hash {expected:?}")]
    HashMismatch {
        computed: Vec<u8>,
        expected: Vec<u8>,
    },
}

/// Checks that `leaf_index` is a valid leaf-node nonmembership proof for
/// `key_index` at `depth`.
fn check_valid_non_member_leaf<H: Hasher>(
    leaf_index: Output<H>,
    key_index: Output<H>,
    depth: usize,
) -> Result<(), VerificationError> {
    // A leaf node with a matching prefix (up to `depth`) but *not* a
    // matching key convinces us that the key is missing.
    if mask(&leaf_index, depth) != mask(&key_index, depth) {
        return Err(VerificationError::IndexMismatch {
            leaf_index: leaf_index.to_vec(),
            key_index: key_index.to_vec(),
            depth,
        });
    }
    if leaf_index == key_index {
        return Err(VerificationError::UnexpectedIndexMatch(key_index.to_vec()));
    }
    Ok(())
}

/// Check that `leaf_index` is the index of a valid empty-node nonmembership
/// proof for `key_index` at `depth`.
fn check_valid_non_member_empty<H: Hasher>(
    leaf_index: Output<H>,
    key_index: Output<H>,
    depth: usize,
) -> Result<(), VerificationError> {
    // An empty node with a matching prefix (up to depth) convinces
    // us that the key is missing.
    if mask(&leaf_index, depth) != mask(&key_index, depth) {
        return Err(VerificationError::IndexMismatch {
            leaf_index: leaf_index.to_vec(),
            key_index: key_index.to_vec(),
            depth,
        });
    }
    Ok(())
}

impl<K, V, H: Hasher> Map for Tree<K, V, H>
where
    K: Canonicalize + Eq + std::hash::Hash + Debug,
    V: Canonicalize + Debug + Clone,
    Output<H>: Copy,
{
    type Key = K;
    type Value = V;
    type Digest = Digest<K, H>;
    type LookupProof = Proof<V, H>;
    type VerificationError = VerificationError;

    fn digest(&self) -> Self::Digest {
        Digest {
            value: self.root.hash,
            _key: PhantomData,
        }
    }

    fn lookup(&self, key: &Self::Key) -> Self::LookupProof {
        let key_index = hash_canonical::<_, H>(key);
        let mut sibling_hashes = Vec::<Output<H>>::new();
        let mut depth = 0usize;
        let mut current_node = &self.root;

        loop {
            match &current_node.inner {
                NodeData::Leaf(data) => {
                    let inner = if data.key_index == key_index {
                        Member(self.values.get(key).expect("found!").clone())
                    } else {
                        NonMemberLeaf {
                            leaf_index: data.key_index,
                            value_hash: data.value_hash,
                        }
                    };
                    return Proof {
                        sibling_hashes,
                        key_index,
                        inner,
                    };
                }
                NodeData::Empty(data) => {
                    // Terminate: a membership proof for the Empty node convinces
                    debug_assert_eq!(mask(&data.prefix, depth), mask(&key_index, depth));
                    let inner = NonMemberEmpty(data.prefix);
                    return Proof {
                        sibling_hashes,
                        key_index,
                        inner,
                    };
                }
                NodeData::Interior(inner) => {
                    // Push a new sibling hash and go depeer.
                    let direction = Direction::from(get_bit_i(&key_index, depth));
                    sibling_hashes.push(inner.sibling(direction).hash);
                    current_node = inner.child(direction);
                }
            }
            depth += 1;
        }
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) {
        let index = hash_canonical::<_, H>(&key);
        let value_hash = hash_canonical::<_, H>(&value);

        let delta_node_counts = insert_recursive(&mut self.root, 0usize, index, value_hash);
        self.node_counts += delta_node_counts;

        self.values.insert(key, value);
    }

    fn verify(
        digest: &Self::Digest,
        key: &Self::Key,
        result: Self::LookupProof,
    ) -> Result<Option<Self::Value>, Self::VerificationError> {
        let mut depth = result.sibling_hashes.len();
        let key_index = hash_canonical::<_, H>(key);

        // Compute the hash of the "leaf" node, and check that the purported result makes sense.
        let (mut current_hash, value) = match result.inner {
            ProofInner::Member(value) => {
                let data = LeafData::<H>::new(key_index, depth, hash_canonical::<_, H>(&value));
                (data.hash(), Some(value))
            }
            ProofInner::NonMemberLeaf {
                leaf_index,
                value_hash,
            } => {
                check_valid_non_member_leaf::<H>(leaf_index, key_index, depth)?;
                let data = LeafData::<H>::new(leaf_index, depth, value_hash);
                (data.hash(), None)
            }
            ProofInner::NonMemberEmpty(leaf_index) => {
                check_valid_non_member_empty::<H>(leaf_index, key_index, depth)?;
                let data = EmptyData::<H>::new(depth, leaf_index);
                (data.hash(), None)
            }
        };

        // Recompute the hash from leaf to root.
        for sibling_hash in result.sibling_hashes.iter().rev() {
            depth -= 1;
            let direction = Direction::from(get_bit_i(&result.key_index, depth));
            current_hash = match direction {
                Left => hash_interior::<H>(&current_hash, sibling_hash),
                Right => hash_interior::<H>(sibling_hash, &current_hash),
            };
        }
        debug_assert_eq!(depth, 0);

        if current_hash != digest.value {
            return Err(VerificationError::HashMismatch {
                computed: current_hash.to_vec(),
                expected: digest.value.to_vec(),
            });
        }

        Ok(value)
    }

    fn lookup_unchecked(&self, key: &Self::Key) -> Option<&Self::Value> {
        self.values.get(key)
    }
}

impl<K, V, H> SizedBytes for Tree<K, V, H>
where
    K: Canonicalize + SizedBytes,
    V: Canonicalize + SizedBytes,
    H: Hasher,
{
    fn size_bytes(&self) -> usize {
        let mut size: usize = self
            .values
            .iter()
            .map(|(k, v)| k.size_bytes() + v.size_bytes())
            .sum();
        let hash_size = H::output_size();
        let interior_size = InteriorData::<H>::fixed_size_bytes() + hash_size;
        size += interior_size * self.node_counts.interior_unsigned();
        let leaf_size = LeafData::<H>::fixed_size_bytes() + hash_size;
        size += leaf_size * self.node_counts.leaf_unsigned();
        let empty_size = EmptyData::<H>::fixed_size_bytes() + hash_size;
        size += empty_size * self.node_counts.empty_unsigned();
        size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::sample::Index;

    type Key = u8;
    type Value = u8;
    type CRHF = sha2::Sha256;
    type TestTree = Tree<u8, u8, sha2::Sha256>;

    use crate::maps::tests::{check_map, insertions};

    check_map!(TestTree);

    proptest! {
        /// Tests that verification fails if any bit in the tree digest is perturbed.
        #[test]
        fn test_tree_bad_digest(insertions in insertions(), key: Key, index: Index) {
            let mut map = TestTree::default();
            let mut reference = HashMap::<Key, Value>::default();

            for (key, value) in insertions {
                map.insert(key, value);
                reference.insert(key, value);
            }

            let mut digest = map.digest();
            let bit = index.index(<CRHF as digest::Digest>::output_size() * 8);
            flip_bit_i(&mut digest.value, bit);

            let proof = map.lookup(&key);
            assert!(TestTree::verify(&digest, &key, proof).is_err());
        }

        /// Tests that verification fails if a correct proof is given for an incorrect key.
        #[test]
        fn test_tree_wrong_key(insertions in insertions(), index: Index, other_key: Key) {
            prop_assume!(!insertions.is_empty());
            let key = insertions[index.index(insertions.len())].0;
            prop_assume!(key != other_key);

            let mut map = TestTree::default();
            let mut reference = HashMap::<Key, Value>::default();

            for (key, value) in insertions {
                map.insert(key, value);
                reference.insert(key, value);
            }

            let digest = map.digest();
            let proof = map.lookup(&key);
            assert!(TestTree::verify(&digest, &other_key, proof).is_err());
        }

        /// Tests that verification fails if the wrong value is included in the proof.
        #[test]
        fn test_tree_wrong_value(insertions in insertions(), index: Index, value_offset: Value) {
            prop_assume!(value_offset != 0);
            prop_assume!(!insertions.is_empty());
            let key = insertions[index.index(insertions.len())].0;

            let mut map = Tree::<Key, Value, CRHF>::default();
            let mut reference = HashMap::<Key, Value>::default();

            for (key, value) in insertions {
                map.insert(key, value);
                reference.insert(key, value);
            }

            let digest = map.digest();
            let mut proof = map.lookup(&key);
            let mut new_value = value_offset;
            if let ProofInner::Member(value) = proof.inner {
                new_value = u8::wrapping_add(new_value, value);
                proof.inner = ProofInner::Member(new_value);
            }
            assert!(TestTree::verify(&digest, &key, proof).is_err());
        }

        /// Tests that the manually-updated `NodeCounts` are the same as the
        /// ones we get by actually counting the nodes.
        #[test]
        fn test_tree_node_counts(insertions in insertions()) {
            let mut map = Tree::<Key, Value, CRHF>::default();
            let mut reference = HashMap::<Key, Value>::default();

            for (key, value) in insertions {
                map.insert(key, value);
                reference.insert(key, value);
            }

            fn count_nodes<H: Hasher>(node: &Node<H>) -> NodeCounts {
                match &node.inner {
                    NodeData::Leaf(_) => NodeCounts {
                        leaf: 1,
                        ..Default::default()
                    },
                    NodeData::Empty(_) => NodeCounts {
                        empty: 1,
                        ..Default::default()
                    },
                    NodeData::Interior(data) => {
                        count_nodes(&data.left)
                            + count_nodes(&data.right)
                            + NodeCounts {
                                interior: 1,
                                ..Default::default()
                            }
                    }
                }
            }

            dbg!(&map);
            assert_eq!(map.node_counts.leaf, isize::try_from(reference.len()).unwrap());
            let node_counts = count_nodes(&map.root);
            assert_eq!(map.node_counts, node_counts);
        }
    }
}
