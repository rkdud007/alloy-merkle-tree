# alloy-merkle-tree

Minimal Merkle Tree implementation

- type compatible with alloy-primitives
- keccak hash as native hash
- support features: insert, proof, verify

## Quick Start

```rust
alloy-merkle-tree = { version = "0.1.0" }
```

## Example

- Insert

```rust
 let mut tree = MerkleTree::new();
// Should be 2 ^ N leaves
let num_leaves = 16;
for i in 0..num_leaves {
    tree.insert(B256::from(Uint::from(i)));
}
```

- Finish
  finalize tree, meaning calculate root and layers

```rust
let mut tree = MerkleTree::new();
// fill elements with insertion
tree.finish();
```

- Create Proof & Verify

Create proof is base on layer, so tree need to be finalized before.

```rust
let mut tree = MerkleTree::new();
// fill elements with insertion
tree.finish();
for i in 0..num_leaves {
    let proof = tree.create_proof(&B256::from(Uint::from(i))).unwrap();
    assert!(MerkleTree::verify_proof(&proof));
}

```

### reference

- [merkle-tree](https://github.com/personaelabs/merkle-tree)
