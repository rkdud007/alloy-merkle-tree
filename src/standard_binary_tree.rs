//! This module contains the [StandardMerkleTree], an implementation of the standard Merkle Tree data structure.
//!
//! Check out [StandardMerkleTree](https://github.com/OpenZeppelin/merkle-tree) for more details.
//!
//! # Examples
//!
//! ```rust
//! use alloy_merkle_tree::standard_binary_tree::StandardMerkleTree;
//! use alloy_dyn_abi::DynSolValue;
//!
//! let num_leaves = 1000;
//! let mut leaves = Vec::new();
//! for i in 0..num_leaves {
//!     leaves.push(DynSolValue::String(i.to_string()));
//! }
//! let tree = StandardMerkleTree::of_sorted(&leaves);
//!
//! for leaf in leaves.iter() {
//!     let proof = tree.get_proof(leaf).unwrap();
//!     let is_valid = tree.verify_proof(leaf, proof);
//!     assert!(is_valid);
//! }
//! ```
//!
use core::panic;

use crate::alloc::string::ToString;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{keccak256, Keccak256, B256};

use hashbrown::HashMap;

/// The error type for the [StandardMerkleTree].
#[derive(Debug)]
pub enum MerkleTreeError {
    /// The specified leaf was not found in the tree.
    LeafNotFound,
    /// An invalid check occurred during tree operations.
    InvalidCheck,
    /// The root node does not have any siblings.
    RootHaveNoSiblings,
    /// The leaf type is not supported by the tree.
    NotSupportedType,
}

/// Represents a standard Merkle tree with methods for proof generation and verification.
#[derive(Debug)]
pub struct StandardMerkleTree {
    /// The internal representation of the tree as a flat vector.
    tree: Vec<B256>,
    /// A mapping from serialized leaf values to their indices in the tree.
    tree_values: HashMap<String, usize>,
}

impl Default for StandardMerkleTree {
    /// Creates a new, empty `StandardMerkleTree`.
    fn default() -> Self {
        Self::new(Vec::new(), Vec::new())
    }
}

impl StandardMerkleTree {
    /// Creates a new [`StandardMerkleTree`] with the given tree nodes and values.
    pub fn new(tree: Vec<B256>, values: Vec<(&DynSolValue, usize)>) -> Self {
        let mut tree_values = HashMap::new();
        for (tree_key, tree_value) in values.into_iter() {
            let tree_key_str = Self::check_valid_value_type(tree_key);
            tree_values.insert(tree_key_str, tree_value);
        }
        Self { tree, tree_values }
    }

    pub fn of(values: &[DynSolValue]) -> Self {
        Self::create(values, false)
    }

    pub fn of_sorted(values: &[DynSolValue]) -> Self {
        Self::create(values, true)
    }

    /// Constructs a [`StandardMerkleTree`] from a slice of dynamic Solidity values.
    fn create(values: &[DynSolValue], sort_leaves: bool) -> Self {
        // Hash each value and associate it with its index and leaf hash.
        let mut hashed_values: Vec<(&DynSolValue, usize, B256)> = values
            .iter()
            .enumerate()
            .map(|(i, value)| (value, i, standard_leaf_hash(value)))
            .collect();

        // Sort the hashed values by their hash.
        if sort_leaves {
            hashed_values.sort_by(|(_, _, a), (_, _, b)| a.cmp(b));
        }
        // Collect the leaf hashes into a vector.
        let hashed_values_hash = hashed_values
            .iter()
            .map(|(_, _, hash)| *hash)
            .collect::<Vec<B256>>();

        // Build the Merkle tree from the leaf hashes.
        let tree = make_merkle_tree(hashed_values_hash);

        // Map each value to its corresponding index in the tree.
        let mut indexed_values: Vec<(&DynSolValue, usize)> =
            values.iter().map(|value| (value, 0)).collect();

        for (leaf_index, (_, value_index, _)) in hashed_values.iter().enumerate() {
            indexed_values[*value_index].1 = tree.len() - leaf_index - 1;
        }

        Self::new(tree, indexed_values)
    }

    /// Retrieves the root hash of the Merkle tree.
    pub fn root(&self) -> B256 {
        self.tree[0]
    }

    /// Generates a Merkle proof for a given leaf value.
    pub fn get_proof(&self, value: &DynSolValue) -> Result<Vec<B256>, MerkleTreeError> {
        let tree_key = Self::check_valid_value_type(value);

        let tree_index = self
            .tree_values
            .get(&tree_key)
            .ok_or(MerkleTreeError::LeafNotFound)?;

        make_proof(&self.tree, *tree_index)
    }

    /// Computes the hash of a leaf node.
    fn get_leaf_hash(&self, leaf: &DynSolValue) -> B256 {
        standard_leaf_hash(leaf)
    }

    /// Verifies a Merkle proof for a given leaf value.
    pub fn verify_proof(&self, leaf: &DynSolValue, proof: Vec<B256>) -> bool {
        let leaf_hash = self.get_leaf_hash(leaf);
        let implied_root = process_proof(leaf_hash, proof);
        self.tree[0] == implied_root
    }

    /// Validates and serializes a [`DynSolValue`] into a [`String`].
    fn check_valid_value_type(value: &DynSolValue) -> String {
        match value {
            DynSolValue::String(inner_value) => inner_value.to_string(),
            DynSolValue::FixedBytes(inner_value, _) => inner_value.to_string(),
            _ => panic!("Not supported value type"),
        }
    }
}

/// Computes the standard leaf hash for a given value..
fn standard_leaf_hash(value: &DynSolValue) -> B256 {
    let encoded = match value {
        DynSolValue::String(inner_value) => inner_value.as_bytes(),
        DynSolValue::FixedBytes(inner_value, _) => inner_value.as_ref(),
        _ => panic!("Not supported value type for leaf"),
    };
    keccak256(keccak256(encoded))
}

/// Calculates the index of the left child for a given parent index..
fn left_child_index(index: usize) -> usize {
    2 * index + 1
}

/// Calculates the index of the right child for a given parent index.
fn right_child_index(index: usize) -> usize {
    2 * index + 2
}

/// Determines the sibling index for a given node index..
fn sibling_index(index: usize) -> Result<usize, MerkleTreeError> {
    if index == 0 {
        return Err(MerkleTreeError::RootHaveNoSiblings);
    }

    if index % 2 == 0 {
        Ok(index - 1)
    } else {
        Ok(index + 1)
    }
}

/// Calculates the parent index for a given child index.
fn parent_index(index: usize) -> usize {
    (index - 1) / 2
}

/// Checks if a given index corresponds to a node within the tree.
fn is_tree_node(tree: &[B256], index: usize) -> bool {
    index < tree.len()
}

/// Checks if a given index corresponds to an internal node (non-leaf).
fn is_internal_node(tree: &[B256], index: usize) -> bool {
    is_tree_node(tree, left_child_index(index))
}

/// Checks if a given index corresponds to a leaf node.
fn is_leaf_node(tree: &[B256], index: usize) -> bool {
    !is_internal_node(tree, index) && is_tree_node(tree, index)
}

/// Validates that a given index corresponds to a leaf node.
fn check_leaf_node(tree: &[B256], index: usize) -> Result<(), MerkleTreeError> {
    if !is_leaf_node(tree, index) {
        Err(MerkleTreeError::InvalidCheck)
    } else {
        Ok(())
    }
}

/// Constructs a Merkle tree from a vector of leaf hashes.
fn make_merkle_tree(leaves: Vec<B256>) -> Vec<B256> {
    let tree_len = 2 * leaves.len() - 1;
    let mut tree = vec![B256::default(); tree_len];
    let leaves_len = leaves.len();

    // Place leaves at the end of the tree array.
    for (i, leaf) in leaves.into_iter().enumerate() {
        tree[tree_len - 1 - i] = leaf;
    }

    // Build the tree by hashing pairs of nodes from the leaves up to the root.
    for i in (0..tree_len - leaves_len).rev() {
        let left = tree[left_child_index(i)];
        let right = tree[right_child_index(i)];

        tree[i] = hash_pair(left, right);
    }

    tree
}

/// Generates a Merkle proof for a leaf at a given index.
fn make_proof(tree: &[B256], index: usize) -> Result<Vec<B256>, MerkleTreeError> {
    check_leaf_node(tree, index)?;

    let mut proof = Vec::new();
    let mut current_index = index;
    while current_index > 0 {
        let sibling = sibling_index(current_index)?;

        if sibling < tree.len() {
            proof.push(tree[sibling]);
        }
        current_index = parent_index(current_index);
    }

    Ok(proof)
}

/// Processes a Merkle proof to compute the implied root hash.
///
/// Returns `B256` hash of the implied Merkle root.
fn process_proof(leaf: B256, proof: Vec<B256>) -> B256 {
    proof.into_iter().fold(leaf, hash_pair)
}

/// Hashes a pair of `B256` values to compute their parent hash.
fn hash_pair(left: B256, right: B256) -> B256 {
    let combined = if left <= right { left } else { right };
    let second = if left <= right { right } else { left };

    let mut hasher = Keccak256::new();
    hasher.update(combined);
    hasher.update(second);
    hasher.finalize()
}

#[cfg(test)]
mod test {
    use crate::alloc::string::ToString;
    use crate::standard_binary_tree::StandardMerkleTree;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;
    use alloy_dyn_abi::DynSolValue;
    use alloy_primitives::{address, hex, hex::FromHex, FixedBytes, U256};

    /// Tests the [`StandardMerkleTree`] with string-type leaves.
    #[test]
    fn test_tree_string_type() {
        let num_leaves = 1000;
        let mut leaves = Vec::new();
        for i in 0..num_leaves {
            leaves.push(DynSolValue::String(i.to_string()));
        }
        let tree = StandardMerkleTree::of(&leaves);

        for leaf in leaves.into_iter() {
            let proof = tree.get_proof(&leaf).unwrap();
            let is_valid = tree.verify_proof(&leaf, proof);
            assert!(is_valid);
        }
    }

    /// Tests the `StandardMerkleTree` with bytes32-type leaves.
    #[test]
    fn test_tree_bytes32_type() {
        let mut leaves = Vec::new();

        let leaf = DynSolValue::FixedBytes(
            FixedBytes::<32>::from_hex(
                "0x46296bc9cb11408bfa46c5c31a542f12242db2412ee2217b4e8add2bc1927d0b",
            )
            .unwrap(),
            32,
        );

        leaves.push(leaf);

        let tree = StandardMerkleTree::of(&leaves);

        for leaf in leaves.into_iter() {
            let proof = tree.get_proof(&leaf).unwrap();
            let is_valid = tree.verify_proof(&leaf, proof);
            assert!(is_valid);
        }
    }

    /// Tests the [`StandardMerkleTree`] with a tuple leaves of hardhat addresses and amounts.
    /// Equivalent to JS: const tree = StandardMerkleTree.of(values, ["address", "uint256"]);
    #[test]
    fn test_hardhat_tuples() {
        let mut leaves = Vec::new();

        vec![
            (
                address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
                U256::from(10000),
            ),
            (
                address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
                U256::from(1000),
            ),
            (
                address!("3c44cdddb6a900fa2b585dd299e03d12fa4293bc"),
                U256::from(100),
            ),
            (
                address!("90f79bf6eb2c4f870365e785982e1f101e93b906"),
                U256::from(10),
            ),
            (
                address!("15d34aaf54267db7d7c367839aaf71a00a2c6a65"),
                U256::from(1),
            ),
        ]
        .iter()
        .for_each(|(address, amount)| {
            leaves.push(unsafe {
                DynSolValue::String(String::from_utf8_unchecked(
                    DynSolValue::Tuple(vec![
                        DynSolValue::Address(*address),
                        DynSolValue::Uint(*amount, 256),
                    ])
                    .abi_encode(),
                ))
            });
        });

        let tree = StandardMerkleTree::of_sorted(&leaves);

        let proof = tree.get_proof(leaves.first().unwrap()).unwrap();
        let is_valid = tree.verify_proof(leaves.first().unwrap(), proof.clone());
        assert!(is_valid);
        assert_eq!(
            proof,
            vec![
                hex!("8ee56d16226ff6684927054c33cd505c4eee1ebabbffe198460d00cb083aaebd"),
                hex!("fa31eb8d65ff2307b7026df667a06a19aade0151ed701ed2307295ae4fa48364"),
                hex!("f0768f444c5a27a6bb7c9203b0b5b147e501ff7b7784e0363e5751590962b034"),
            ]
        );

        let root = tree.root();
        assert_eq!(
            root,
            hex!("2b4b963c699c531f94ca8f8a0ef76c5d28f067d79927c035a44296190c2d8029")
        );
    }
}
