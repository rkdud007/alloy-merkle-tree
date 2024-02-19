//! This module contains the [StandardMerkleTree], an implementation of the standard Merkle Tree data structure
//! Checkout [StandardMerkleTree](https://github.com/OpenZeppelin/merkle-tree) for more details.

use alloc::vec;
use alloc::vec::Vec;
use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{keccak256, Keccak256, B256};

use hashbrown::HashMap;

#[derive(Debug)]
enum MerkleTreeError {
    LeafNotFound,
    InvalidCheck,
}

#[derive(Debug)]
pub struct MerkleProof {
    pub leaf: B256,
    pub siblings: Vec<B256>,
    pub path_indices: Vec<usize>,
    pub root: B256,
}

#[derive(Debug)]
pub struct StandardMerkleTree {
    tree: Vec<B256>,
    tree_values: HashMap<B256, usize>,
}

impl Default for StandardMerkleTree {
    fn default() -> Self {
        Self::new(Vec::new(), Vec::new())
    }
}

impl StandardMerkleTree {
    pub fn new(tree: Vec<B256>, values: Vec<(B256, usize)>) -> Self {
        let mut tree_values = HashMap::new();
        for value in values.iter() {
            tree_values.insert(value.0, value.1);
        }
        Self { tree, tree_values }
    }

    pub fn of(values: Vec<B256>) -> Self {
        let hashed_values: Vec<(B256, usize, B256)> = values
            .iter()
            .enumerate()
            .map(|(i, value)| (*value, i, standard_leaf_hash(value)))
            .collect();

        let hashed_values_hash = hashed_values
            .iter()
            .map(|(_, _, hash)| *hash)
            .collect::<Vec<B256>>();

        let tree = make_merkle_tree(hashed_values_hash);

        let mut indexed_values: Vec<(B256, usize)> = values
            .iter()
            .enumerate()
            .map(|(_, value)| (*value, 0))
            .collect();

        for (leaf_index, (_, value_index, _)) in hashed_values.iter().enumerate() {
            indexed_values[*value_index].1 = tree.len() - leaf_index - 1;
        }

        Self::new(tree, indexed_values)
    }

    pub fn root(&self) -> B256 {
        self.tree[0]
    }

    pub fn get_proof(&self, value: &B256) -> Vec<B256> {
        let tree_index = self
            .tree_values
            .get(value)
            .ok_or(MerkleTreeError::LeafNotFound)
            .unwrap();
        make_proof(self.tree.clone(), *tree_index)
    }

    fn get_leaf_hash(&self, leaf: B256) -> B256 {
        standard_leaf_hash(&leaf)
    }

    pub fn verify_proof(&self, leaf: B256, proof: Vec<B256>) -> bool {
        let leaf_hash = self.get_leaf_hash(leaf);

        let implied_root = process_proof(leaf_hash, proof);

        self.tree[0] == implied_root
    }
}

fn standard_leaf_hash(value: &B256) -> B256 {
    let abi_value: DynSolValue = DynSolValue::FixedBytes(*value, 32);
    let encoded = abi_value.abi_encode();
    keccak256(keccak256(encoded))
}

fn left_child_index(index: usize) -> usize {
    2 * index + 1
}

fn right_child_index(index: usize) -> usize {
    2 * index + 2
}

fn sibling_index(index: usize) -> usize {
    if index == 0 {
        panic!("Root has no siblings"); // Panicking since throwError is not available in Rust
    } else if index % 2 == 0 {
        index - 1
    } else {
        index + 1
    }
}
fn parent_index(index: usize) -> usize {
    (index - 1) / 2
}

fn is_tree_node(tree: &[B256], index: usize) -> bool {
    index < tree.len()
}

fn is_internal_node(tree: &[B256], index: usize) -> bool {
    is_tree_node(tree, left_child_index(index))
}

fn is_leaf_node(tree: &[B256], index: usize) -> bool {
    !is_internal_node(tree, index) && is_tree_node(tree, index)
}

fn check_leaf_node(tree: &[B256], index: usize) -> Result<(), MerkleTreeError> {
    if !is_leaf_node(tree, index) {
        Err(MerkleTreeError::InvalidCheck)
    } else {
        Ok(())
    }
}

fn make_merkle_tree(leaves: Vec<B256>) -> Vec<B256> {
    let tree_len = 2 * leaves.len() - 1;
    let mut tree = vec![B256::default(); tree_len];
    let leaves_len = leaves.len();

    for (i, leaf) in leaves.into_iter().enumerate() {
        tree[tree_len - 1 - i] = leaf;
    }

    for i in (0..tree_len - leaves_len).rev() {
        let left = tree[left_child_index(i)];
        let right = tree[right_child_index(i)];

        tree[i] = hash_pair(left, right);
    }

    tree
}

fn make_proof(tree: Vec<B256>, index: usize) -> Vec<B256> {
    check_leaf_node(&tree, index).unwrap();

    let mut proof = Vec::new();
    let mut current_index = index;
    while current_index > 0 {
        let sibling = sibling_index(current_index);

        if sibling < tree.len() {
            proof.push(tree[sibling]);
        }
        current_index = parent_index(current_index);
    }

    proof
}

fn process_proof(leaf: B256, proof: Vec<B256>) -> B256 {
    proof.iter().fold(leaf, |acc, item| hash_pair(acc, *item))
}

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
    use crate::standard_binary_tree::StandardMerkleTree;
    use alloc::vec::Vec;
    use alloy_primitives::{B256, U256};

    #[test]
    fn test_tree() {
        // Should be 2 ^ N leaves
        let num_leaves = 4;
        let mut leaves = Vec::new();
        for i in 0..num_leaves {
            leaves.push(B256::from(U256::from(i)));
        }
        let tree = StandardMerkleTree::of(leaves.clone());

        for leaf in leaves.iter() {
            let proof = tree.get_proof(leaf);
            let bool = tree.verify_proof(*leaf, proof);
            assert!(bool);
        }
    }
}
