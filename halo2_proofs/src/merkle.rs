//! This module provides merkle tree related functions.

use ff::PrimeField;
use rs_merkle::{MerkleTree, Hasher};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, Copy)]
struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    type Hash = [u8; 32];
    fn hash(data: &[u8]) -> [u8; 32] {
        let hash = Sha3_256::digest(data);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }
    
    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
        let mut concatenated: Vec<u8> = (*left).into();
    
        match right {
            Some(right_node) => {
                let mut right_node_clone: Vec<u8> = (*right_node).into();
                concatenated.append(&mut right_node_clone);
                Self::hash(&concatenated)
            }
            None => *left,
        }
    }
    
    fn hash_size() -> usize {
        std::mem::size_of::<Self::Hash>()
    }
}

/// Compute the Merkle root hash of a list of data.
pub fn merkle_hash<F: PrimeField>(data: Vec<F>) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = data.iter()
        .map(|d| Sha256Hasher::hash(d.to_repr().as_ref()))
        .collect();

    let merkle_tree = MerkleTree::<Sha256Hasher>::from_leaves(&leaves);
    merkle_tree.root().unwrap()
}

// fn main() {
//     let data = vec!["data1", "data2", "data3", "data4"];
//     let leaves: Vec<[u8; 32]> = data.iter()
//         .map(|d| Sha256Hasher::hash(d.as_bytes()))
//         .collect();

//     let merkle_tree = MerkleTree::<Sha256Hasher>::from_leaves(&leaves);
//     let root = merkle_tree.root().unwrap();
//     println!("Merkle Root: {:?}", root);
// }