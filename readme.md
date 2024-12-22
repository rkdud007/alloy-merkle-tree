# alloy-merkle-tree

![CI](https://img.shields.io/github/actions/workflow/status/rkdud007/alloy-merkle-tree/ci.yml?style=flat-square&logo=githubactions&logoColor=white&label=CI)
[![Crates.io](https://img.shields.io/crates/v/alloy-merkle-tree?style=flat-square&logo=lootcrate)](https://crates.io/crates/alloy-merkle-tree)
[![Documentation](https://img.shields.io/docsrs/alloy-merkle-tree)](https://docs.rs/alloy-merkle-tree)

Minimal Merkle Tree implementation

- various tree implementation
  - PerfectBinaryMerkleTree
  - IncrementalMerkleTree
  - StandardBinaryTree
- type compatible with alloy-primitives
- keccak hash as native hash
- support features: insert, proof, verify

## Install

```bash
❯ cargo add alloy-merkle-tree
```

## Support

### MerkleTree

Perfect Binary Merkle Tree

```rust
let mut tree = MerkleTree::new();
// Should be 2 ^ N leaves
let num_leaves = 16;
for i in 0..num_leaves {
    tree.insert(B256::from(U256::from(i)));
}
tree.finish();

for i in 0..num_leaves {
    let proof = tree.create_proof(&B256::from(U256::from(i))).unwrap();
    assert!(MerkleTree::verify_proof(&proof));
}
```

### IncrementalMerkleTree

used in the [ETH2 Deposit Contract](https://etherscan.io/address/0x00000000219ab540356cbb839cbe05303d7705fa)

```rust
 let mut tree = IncrementalMerkleTree::<8>::new();
for i in 0..1 << (8 - 1) {
    tree.append([i as u8; 32].into()).unwrap();
}
for i in 0..1 << (8 - 1) {
    let leaf = [i as u8; 32].into();
    let proof = tree.proof_at_index(i).unwrap();
    assert!(tree.verify_proof(leaf, i, &proof));
}
```

### StandardBinaryMerkleTree

[StandardMerkleTree](https://github.com/OpenZeppelin/merkle-tree)

```rust
let num_leaves = 1000;
let mut leaves = Vec::new();
for i in 0..num_leaves {
    leaves.push(i.to_string());
}
let tree = StandardMerkleTree::of_sorted(leaves.clone());

for leaf in leaves.iter() {
    let proof = tree.get_proof(leaf);
    let bool = tree.verify_proof(leaf.to_string(), proof);
    assert!(bool);
}

```

### reference

- [merkle-tree](https://github.com/personaelabs/merkle-tree)
- [StandardMerkleTree](https://github.com/OpenZeppelin/merkle-tree)
