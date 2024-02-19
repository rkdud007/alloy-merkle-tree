use alloy_primitives::{Keccak256, B256};

#[derive(Debug)]
pub struct MerkleProof {
    pub leaf: B256,
    pub siblings: Vec<B256>,
    pub path_indices: Vec<usize>,
    pub root: B256,
}

#[derive(Debug)]
pub struct MerkleTree {
    leaves: Vec<B256>,
    is_tree_ready: bool,
    layers: Vec<Vec<B256>>,
    depth: u64,
    pub root: B256,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    pub fn new() -> Self {
        MerkleTree {
            leaves: Vec::new(),
            is_tree_ready: false,
            layers: Vec::new(),
            depth: 0,
            root: B256::default(),
        }
    }

    pub fn insert(&mut self, leaf: B256) {
        self.leaves.push(leaf);
    }

    fn hash(left: &B256, right: &B256) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(left);
        hasher.update(right);
        let result = hasher.finalize();
        B256::from(result)
    }

    pub fn finish(&mut self) {
        if self.is_tree_ready {
            return;
        }

        self.depth = 1;
        self.layers.push(self.leaves.clone());

        while self.layers.last().unwrap().len() > 1 {
            let mut new_layer = Vec::new();
            let mut i = 0;
            while i < self.layers.last().unwrap().len() {
                let left = &self.layers.last().unwrap()[i];
                i += 1;
                let right = if i < self.layers.last().unwrap().len() {
                    &self.layers.last().unwrap()[i]
                } else {
                    left
                };
                i += 1;
                new_layer.push(Self::hash(left, right));
            }
            self.layers.push(new_layer);
            self.depth += 1;
        }

        self.root = self.layers.last().unwrap()[0];
        self.is_tree_ready = true;
    }

    pub fn create_proof(&self, leaf: &B256) -> Option<MerkleProof> {
        let mut index = match self.leaves.iter().position(|x| x == leaf) {
            Some(index) => index,
            None => return None,
        };

        let mut proof = MerkleProof {
            leaf: *leaf,
            siblings: Vec::new(),
            path_indices: Vec::new(),
            root: self.root,
        };

        for layer in &self.layers {
            if index % 2 == 0 {
                if index + 1 < layer.len() {
                    proof.siblings.push(layer[index + 1]);
                    proof.path_indices.push(1);
                }
            } else {
                proof.siblings.push(layer[index - 1]);
                proof.path_indices.push(0);
            }
            index /= 2;
        }

        Some(proof)
    }

    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut hash = proof.leaf;
        for (i, sibling) in proof.siblings.iter().enumerate() {
            hash = if proof.path_indices[i] == 0 {
                Self::hash(sibling, &hash)
            } else {
                Self::hash(&hash, sibling)
            };
        }
        hash == proof.root
    }
}

#[test]

fn test_tree() {
    use alloy_primitives::Uint;

    let mut tree = MerkleTree::new();
    // Should be 2 ^ N leaves
    let num_leaves = 16;
    for i in 0..num_leaves {
        tree.insert(B256::from(Uint::from(i)));
    }
    tree.finish();

    for i in 0..num_leaves {
        let proof = tree.create_proof(&B256::from(Uint::from(i))).unwrap();
        assert!(MerkleTree::verify_proof(&proof));
    }
}
