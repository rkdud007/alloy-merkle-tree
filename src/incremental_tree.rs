//! This module contains the [IncrementalMerkleTree], an implementation of the incremental Merkle Tree data structure
//! used in the [ETH2 Deposit Contract](https://etherscan.io/address/0x00000000219ab540356cbb839cbe05303d7705fa).

use alloc::{vec, vec::Vec};
use alloy::primitives::{keccak256, B256};

/// The error type for the [IncrementalMerkleTree].
#[derive(Debug)]
pub enum IncrementalMerkleTreeError {
    /// The tree is full and cannot accept any more leaves.
    TreeFull,
    /// The loop did not terminate after at most `height` iterations in the `append` function.
    LoopDidNotTerminate,
    /// Index out of bounds.
    IndexOutOfBounds,
}

/// [IncrementalMerkleTree] is an append-only merkle tree of generic height, using `keccak256` as the
/// hash function.
pub struct IncrementalMerkleTree<const HEIGHT: usize> {
    /// The zero hashes
    zero_hashes: [B256; HEIGHT],
    /// The active branch of the tree, used to calculate the root hash
    active_branch: [B256; HEIGHT],
    /// The number of leaves that have been added to the tree.
    size: usize,
    /// The intermediate cache for the tree, indexed by `generalized_index + 1`. The intermediates are
    /// only valid if `cache_valid` is true.
    intermediates: Vec<B256>,
    /// Signals whether the intermediate cache is valid. Cache validation is global, and all levels above
    /// the leaves will be recomputed during proof generation if it is invalid.
    cache_valid: bool,
}

impl<const HEIGHT: usize> Default for IncrementalMerkleTree<HEIGHT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const HEIGHT: usize> IncrementalMerkleTree<HEIGHT> {
    /// Create a new [IncrementalMerkleTree] with a height of `height`. This function will precompute the zero hashes
    /// for the tree.
    pub fn new() -> Self {
        let mut zero_hashes = [B256::default(); HEIGHT];
        let mut hash_buf = [0u8; 64];
        (1..HEIGHT).for_each(|height| {
            hash_buf[..32].copy_from_slice(zero_hashes[height - 1].as_slice());
            hash_buf[32..].copy_from_slice(zero_hashes[height - 1].as_slice());
            zero_hashes[height] = keccak256(hash_buf);
        });
        let intermediates = vec![B256::default(); (1 << (HEIGHT as u32 + 1)) - 1];

        Self {
            zero_hashes,
            active_branch: [B256::default(); HEIGHT],
            size: 0,
            intermediates,
            cache_valid: false,
        }
    }

    /// Compute the root hash of the tree from the active branch.
    ///
    /// # Returns
    /// - The root hash of the tree.
    pub fn root(&self) -> B256 {
        let mut size = self.size;
        let mut hash_buf = [0u8; 64];
        (0..HEIGHT).fold(B256::default(), |tree_root, height| {
            if size & 1 == 1 {
                hash_buf[..32].copy_from_slice(self.active_branch[height].as_slice());
                hash_buf[32..].copy_from_slice(tree_root.as_slice());
            } else {
                hash_buf[..32].copy_from_slice(tree_root.as_slice());
                hash_buf[32..].copy_from_slice(self.zero_hashes[height].as_slice());
            }
            size >>= 1;
            keccak256(hash_buf)
        })
    }

    /// Appends a new leaf to the tree by recomputing the active branch.
    ///
    /// # Returns
    /// - `Ok(())` - If the leaf was successfully appended.
    /// - `Err(IncrementalMerkleTreeError::TreeFull)` - If the tree is full and cannot accept any more leaves.
    /// - `Err(IncrementalMerkleTreeError::LoopDidNotTerminate)` - If the loop did not terminate after at most `height` iterations.
    pub fn append(&mut self, leaf: B256) -> Result<(), IncrementalMerkleTreeError> {
        // Increment the leaves by 1 prior to appending the leaf.
        self.size += 1;
        let mut size = self.size;

        // Do not allow for appending more leaves than the merkle tree can support. The incremental merkle tree
        // algorithm only supports 2**HEIGHT - 1 leaves, the right most leaf must always be kept empty.
        // Reference: https://daejunpark.github.io/papers/deposit.pdf - Page 10, Section 5.1.
        if size > (1 << HEIGHT) - 1 {
            return Err(IncrementalMerkleTreeError::TreeFull);
        }

        // Append the leaf by computing the new active branch.
        let mut intermediate = leaf;
        let mut hash_buf = [0u8; 64];
        for height in 0..HEIGHT {
            if size & 1 == 1 {
                // Set the branch value at the current height to the intermediate hash and return.
                self.active_branch[height] = intermediate;

                // Add the leaf to the intermediates and invalidate the global cache.
                self.intermediates[(1 << HEIGHT) + self.size - 2] = leaf;
                self.cache_valid = false;

                return Ok(());
            }

            hash_buf[..32].copy_from_slice(self.active_branch[height].as_slice());
            hash_buf[32..].copy_from_slice(intermediate.as_slice());
            intermediate = keccak256(hash_buf);
            size >>= 1;
        }

        Err(IncrementalMerkleTreeError::LoopDidNotTerminate)
    }

    /// Verifies a merkle proof against the tree's root hash for a leaf at a given index within the tree.
    /// Reference: <https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#is_valid_merkle_branch>
    ///
    /// # Returns
    /// - `true` - If the proof is valid.
    /// - `false` - If the proof is invalid.
    pub fn verify_proof(&self, leaf: B256, index: usize, proof: &[B256; HEIGHT]) -> bool {
        let mut hash_buf = [0u8; 64];
        (0..HEIGHT).fold(leaf, |value, height| {
            if ((index >> height) & 1) == 1 {
                hash_buf[..32].copy_from_slice(proof[height].as_slice());
                hash_buf[32..].copy_from_slice(value.as_slice());
            } else {
                hash_buf[..32].copy_from_slice(value.as_slice());
                hash_buf[32..].copy_from_slice(proof[height].as_slice());
            }
            keccak256(hash_buf)
        }) == self.root()
    }

    /// Generate a merkle proof for a leaf at a given index within the tree.
    ///
    /// # Returns
    /// - `Ok([B256; HEIGHT])` - The merkle proof for the leaf at the given index.
    /// - `Err(IncrementalMerkleTreeError::IndexOutOfBounds)` - If the passed index is out of bounds.
    pub fn proof_at_index(
        &mut self,
        mut index: usize,
    ) -> Result<[B256; HEIGHT], IncrementalMerkleTreeError> {
        if index >= (1 << HEIGHT) - 1 {
            return Err(IncrementalMerkleTreeError::IndexOutOfBounds);
        }

        // Compute the intermediates if the cache is not already valid.
        self.compute_intermediates();

        // Generate the proof by copying the sibling of each node on the path to the root.
        let mut proof = [B256::default(); HEIGHT];
        (0..HEIGHT).for_each(|height| {
            // Determine the sibling's generalized index.
            let sibling_gindex = (1 << (HEIGHT - height)) + (index ^ 1);
            // Copy the sibling into the proof.
            proof[height] = self.intermediates[sibling_gindex - 1];
            // Move up the tree.
            index >>= 1;
        });

        Ok(proof)
    }

    /// Compute all intermediate nodes in the merkle tree, if the cache is not already valid.
    fn compute_intermediates(&mut self) {
        if self.cache_valid {
            return;
        }

        // Compute the intermediate hashes for the sub-trees that contain appended leaves.
        let mut hash_buf = [0u8; 64];
        (1..=HEIGHT).for_each(|height| {
            // The first generalized index of the current level is `1 << (HEIGHT - height)`
            let start_gindex = 1 << (HEIGHT - height);
            // The final generalized index of the current level is `(1 << (HEIGHT - height + 1)) - 1`
            let end_gindex = (1 << (HEIGHT - height + 1)) - 1;

            for i in start_gindex..=end_gindex {
                // If the left most leaf index is greater than the size, the rest of the level is filled with the precomputed
                // zero hashes. No need to compute these intermediates, we already have them cached.
                let left_most_idx = (i << height) - (1 << HEIGHT);
                if left_most_idx >= self.size {
                    (i..=end_gindex)
                        .for_each(|j| self.intermediates[j - 1] = self.zero_hashes[height]);
                    break;
                }

                hash_buf[..32].copy_from_slice(self.intermediates[(i << 1) - 1].as_slice());
                hash_buf[32..].copy_from_slice(self.intermediates[i << 1].as_slice());
                self.intermediates[i - 1] = keccak256(hash_buf);
            }
        });
        self.cache_valid = true;
    }
}

#[cfg(test)]
mod test {
    use super::IncrementalMerkleTree;
    use alloy::primitives::{keccak256, B256};

    #[test]
    fn test_static_tree_root() {
        let mut tree = IncrementalMerkleTree::<2>::new();
        tree.append([1u8; 32].into()).unwrap();

        // Compute the root manually to compare against the tree's root.
        let manual_root = {
            let mut hash_buf = [0u8; 64];
            hash_buf[..32].copy_from_slice([1u8; 32].as_slice());
            hash_buf[32..].copy_from_slice([0u8; 32].as_slice());
            let left = keccak256(hash_buf);
            let right = tree.zero_hashes[1];
            hash_buf[..32].copy_from_slice(left.as_slice());
            hash_buf[32..].copy_from_slice(right.as_slice());
            keccak256(hash_buf)
        };

        assert_eq!(tree.size, 1);
        assert_eq!(tree.root(), manual_root);
    }

    #[test]
    fn test_static_tree_proof() {
        let mut tree = IncrementalMerkleTree::<2>::new();
        tree.append([1u8; 32].into()).unwrap();

        // Compute the proof manually to verify.
        let manual_proof = {
            let mut proof = [B256::default(); 2];
            proof[0] = tree.zero_hashes[0];
            proof[1] = tree.zero_hashes[1];
            proof
        };

        assert_eq!(tree.size, 1);
        assert!(tree.verify_proof([1u8; 32].into(), 0, &manual_proof));
    }

    #[test]
    fn test_gen_proof() {
        let mut tree = IncrementalMerkleTree::<8>::new();
        for i in 0..1 << (8 - 1) {
            tree.append([i as u8; 32].into()).unwrap();
        }
        for i in 0..1 << (8 - 1) {
            let leaf = [i as u8; 32].into();
            let proof = tree.proof_at_index(i).unwrap();
            assert!(tree.verify_proof(leaf, i, &proof));
        }
    }

    #[test]
    fn test_tree_overflow() {
        let mut tree = IncrementalMerkleTree::<2>::new();
        for _ in 0..3 {
            tree.append([1u8; 32].into()).unwrap();
        }
        assert!(tree.append([1u8; 32].into()).is_err());
    }
}
