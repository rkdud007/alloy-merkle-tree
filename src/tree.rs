//! This module contains the [MerkleTree], an implementation of a perfect binary Merkle tree.
//!
//! # Examples
//!
//! ```rust
//! use alloy_merkle_tree::tree::MerkleTree;
//! use alloy_primitives::{B256, U256};
//!
//! let mut tree = MerkleTree::new();
//! // Number of leaves should be a power of 2 for a perfect binary tree
//! let num_leaves = 16;
//! for i in 0..num_leaves {
//!     tree.insert(B256::from(U256::from(i)));
//! }
//! tree.finish();
//!
//! for i in 0..num_leaves {
//!     let proof = tree.create_proof(&B256::from(U256::from(i))).unwrap();
//!     assert!(MerkleTree::verify_proof(&proof));
//! }
//! ```
//!

use alloc::vec::Vec;
use alloy_primitives::{Keccak256, B256};

/// Represents a Merkle proof for a specific leaf in the Merkle tree.
#[derive(Debug)]
pub struct MerkleProof {
    /// The leaf node for which the proof is generated.
    pub leaf: B256,
    /// The sibling hashes required to reconstruct the root.
    pub siblings: Vec<B256>,
    /// The path indices indicating the position (left/right) at each level.
    pub path_indices: Vec<usize>,
    /// The Merkle root of the tree.
    pub root: B256,
}

/// A Merkle tree implementation supporting insertion of leaves,
/// tree construction, proof generation, and proof verification.
#[derive(Debug)]
pub struct MerkleTree {
    /// The list of leaf nodes in the tree.
    leaves: Vec<B256>,
    /// Indicates whether the leaves should be sorted before tree construction.
    is_sort: bool,
    /// Indicates whether the tree has been constructed.
    is_tree_ready: bool,
    /// Layers of the tree, where each layer is a vector of hashes.
    layers: Vec<Vec<B256>>,
    /// The depth of the tree (number of layers).
    depth: u64,
    /// The root hash of the Merkle tree.
    pub root: B256,
}

impl Default for MerkleTree {
    /// Creates a new empty [`MerkleTree`] with default values.
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    /// Creates a new empty [`MerkleTree`].
    pub fn new() -> Self {
        MerkleTree {
            leaves: Vec::new(),
            is_sort: false,
            is_tree_ready: false,
            layers: Vec::new(),
            depth: 0,
            root: B256::default(),
        }
    }

    /// Sets whether the leaves should be sorted before tree construction.
    pub fn set_sort(&mut self, sort: bool) {
        self.is_sort = sort;
    }

    /// Checks if the leaves are set to be sorted.
    pub fn is_sorted(&self) -> bool {
        self.is_sort
    }

    /// Inserts a new leaf into the Merkle tree.
    pub fn insert(&mut self, leaf: B256) {
        self.leaves.push(leaf);
    }

    /// Hashes two nodes together using Keccak256.
    fn hash(left: &B256, right: &B256) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(left);
        hasher.update(right);
        let result = hasher.finalize();
        B256::from(result)
    }

    /// Finalizes the tree construction by building all layers and computing the root hash.
    ///
    /// If the tree has already been constructed, this method will do nothing.
    pub fn finish(&mut self) {
        if self.is_tree_ready {
            return;
        }

        // Sort leaves if sorting is enabled and not already sorted
        if self.is_sort {
            self.leaves.sort();
            self.is_sort = true;
        }

        self.depth = 1;
        self.layers.push(self.leaves.clone());

        // Build the tree layers from the leaves up to the root
        while self.layers.last().unwrap().len() > 1 {
            let mut new_layer = Vec::new();
            let mut i = 0;
            while i < self.layers.last().unwrap().len() {
                let left = &self.layers.last().unwrap()[i];
                i += 1;
                let right = if i < self.layers.last().unwrap().len() {
                    &self.layers.last().unwrap()[i]
                } else {
                    // Duplicate the last node if the number of nodes is odd
                    left
                };
                i += 1;
                new_layer.push(Self::hash(left, right));
            }
            self.layers.push(new_layer);
            self.depth += 1;
        }

        // The root is the only element in the last layer
        self.root = self.layers.last().unwrap()[0];
        self.is_tree_ready = true;
    }

    /// Generates a Merkle proof for a given leaf.
    ///
    /// An `Option` containing the `MerkleProof` if the leaf is found, or `None` if not.
    pub fn create_proof(&self, leaf: &B256) -> Option<MerkleProof> {
        // Find the index of the leaf in the list of leaves
        let mut index = self.leaves.iter().position(|x| x == leaf)?;

        let mut proof = MerkleProof {
            leaf: *leaf,
            siblings: Vec::new(),
            path_indices: Vec::new(),
            root: self.root,
        };

        // Traverse from the leaf to the root, collecting sibling hashes
        for layer in &self.layers {
            if index % 2 == 0 {
                if index + 1 < layer.len() {
                    // If the current node is a left child, add the right sibling
                    proof.siblings.push(layer[index + 1]);
                    proof.path_indices.push(1);
                }
            } else {
                // If the current node is a right child, add the left sibling
                proof.siblings.push(layer[index - 1]);
                proof.path_indices.push(0);
            }
            index /= 2; // Move up to the parent index
        }

        Some(proof)
    }

    /// Verifies a Merkle proof against the root hash.
    ///
    /// # Parameters
    ///
    /// - `proof`: The `MerkleProof` to verify.
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid and corresponds to the root hash; otherwise, `false`.
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut hash = proof.leaf;
        // Reconstruct the hash from the leaf using the proof
        for (i, sibling) in proof.siblings.iter().enumerate() {
            hash = if proof.path_indices[i] == 0 {
                // Left sibling
                Self::hash(sibling, &hash)
            } else {
                // Right sibling
                Self::hash(&hash, sibling)
            };
        }
        // Check if the reconstructed hash matches the root
        hash == proof.root
    }
}

#[cfg(test)]
mod test {
    use crate::tree::MerkleTree;
    use alloy_primitives::{B256, U256};

    /// Tests the basic functionality of the [`MerkleTree`].
    #[test]
    fn test_tree() {
        let mut tree = MerkleTree::new();
        // Number of leaves (should be 2^N for full binary tree)
        let num_leaves = 16;
        for i in 0..num_leaves {
            tree.insert(B256::from(U256::from(i)));
        }
        tree.finish();

        // Verify proofs for each leaf
        for i in 0..num_leaves {
            let proof = tree.create_proof(&B256::from(U256::from(i))).unwrap();
            assert!(MerkleTree::verify_proof(&proof));
        }
    }

    /// Tests the [`MerkleTree`] with sorting enabled.
    #[test]
    fn test_tree_sorted() {
        let mut tree = MerkleTree::new();
        tree.set_sort(true);

        // Number of leaves (should be 2^N for full binary tree)
        let num_leaves = 16;
        // Insert leaves in reverse order
        for i in (0..num_leaves).rev() {
            tree.insert(B256::from(U256::from(i)));
        }
        tree.finish();

        // Verify that the tree is sorted
        assert!(tree.is_sorted());

        // Check if the leaves are actually sorted
        let sorted_leaves = tree.leaves.clone();
        assert!(sorted_leaves.windows(2).all(|w| w[0] <= w[1]));

        // Verify proofs for each leaf
        for i in 0..num_leaves {
            let leaf = B256::from(U256::from(i));
            let proof = tree.create_proof(&leaf).unwrap();
            assert!(MerkleTree::verify_proof(&proof));
        }
    }
}
