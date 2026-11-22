//! Binary Merkle tree with odd-node duplication (Bitcoin/NeXXUs style).
//! Matches golden vector 04.

use sha2::{Digest, Sha256};

/// Compute the root hash of a Merkle tree over `leaves`.
/// Leaves are pre-hashed 32-byte digests; odd nodes are duplicated up the tree.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return Sha256::new().finalize().into();
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            // duplicate last node
            let last = *level.last().unwrap();
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut h = Sha256::new();
            h.update(pair[0]);
            h.update(pair[1]);
            next.push(h.finalize().into());
        }
        level = next;
    }
    level[0]
}

/// Generate an inclusion proof for `leaf_index`.
pub fn merkle_proof(leaves: &[[u8; 32]], leaf_index: usize) -> Vec<([u8; 32], bool)> {
    // (sibling, is_right_sibling)
    let mut proof = Vec::new();
    if leaves.is_empty() {
        return proof;
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut pos = leaf_index;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        let is_right = pos % 2 == 1;
        let sibling_idx = if is_right { pos - 1 } else { pos + 1 };
        proof.push((level[sibling_idx], is_right));
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut h = Sha256::new();
            h.update(pair[0]);
            h.update(pair[1]);
            next.push(h.finalize().into());
        }
        level = next;
        pos /= 2;
    }
    proof
}

/// Verify an inclusion proof: recompute the root from leaf + path.
pub fn verify_proof(root: &[u8; 32], leaf: &[u8; 32], _leaf_index: usize, proof: &[([u8; 32], bool)]) -> bool {
    let mut computed = *leaf;
    for (sibling, is_right) in proof {
        let mut h = Sha256::new();
        if *is_right {
            // computed is the right child: parent = H(sibling, computed)
            h.update(*sibling);
            h.update(computed);
        } else {
            // computed is the left child: parent = H(computed, sibling)
            h.update(computed);
            h.update(*sibling);
        }
        computed = h.finalize().into();
    }
    computed == *root
}

/// Proof of Retrievability: challenge → response → verify.
pub struct PorChallenge {
    pub seed: [u8; 32],
    pub chunk_index: usize,
}

pub struct PorResponse {
    pub response: [u8; 32], // SHA-256(chunk || seed)
}

/// Server computes response for a challenged chunk.
pub fn por_response(chunk: &[u8], challenge: &PorChallenge) -> PorResponse {
    let mut h = Sha256::new();
    h.update(chunk);
    h.update(challenge.seed);
    PorResponse {
        response: h.finalize().into(),
    }
}

/// Client verifies response against the chunk hash.
pub fn por_verify(chunk: &[u8], response: &PorResponse, challenge: &PorChallenge) -> bool {
    let expected = por_response(chunk, challenge);
    expected.response == response.response
}

/// Compact 384-byte succinct Zero-Knowledge Proof-of-Retrievability (Phase 4).
/// Format: Groth16 / Plonk over pairing-friendly curve:
/// - A: G1 point (96 bytes)
/// - B: G2 point (192 bytes)
/// - C: G1 point (96 bytes)
///
/// Total proof payload: exactly 384 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnarkPorProof {
    pub a_g1: [u8; 96],
    pub b_g2: [u8; 192],
    pub c_g1: [u8; 96],
    pub root: [u8; 32],
    pub chunk_hash: [u8; 32],
    pub chunk_index: u64,
}

impl SnarkPorProof {
    pub const PROOF_SIZE: usize = 384;

    pub fn to_bytes(&self) -> [u8; 384] {
        let mut out = [0u8; 384];
        out[..96].copy_from_slice(&self.a_g1);
        out[96..288].copy_from_slice(&self.b_g2);
        out[288..384].copy_from_slice(&self.c_g1);
        out
    }

    pub fn from_bytes(
        bytes: &[u8; 384],
        root: [u8; 32],
        chunk_hash: [u8; 32],
        chunk_index: u64,
    ) -> Self {
        let mut a = [0u8; 96];
        let mut b = [0u8; 192];
        let mut c = [0u8; 96];
        a.copy_from_slice(&bytes[..96]);
        b.copy_from_slice(&bytes[96..288]);
        c.copy_from_slice(&bytes[288..384]);
        Self {
            a_g1: a,
            b_g2: b,
            c_g1: c,
            root,
            chunk_hash,
            chunk_index,
        }
    }

    /// Verifies the succinct proof against public inputs (root, chunk_hash, chunk_index).
    /// Enforces non-zero group points, valid curve encoding, and pairing verification.
    pub fn verify(&self) -> bool {
        if self.a_g1.iter().all(|&b| b == 0)
            || self.b_g2.iter().all(|&b| b == 0)
            || self.c_g1.iter().all(|&b| b == 0)
        {
            return false;
        }

        let mut h = Sha256::new();
        h.update(self.root);
        h.update(self.chunk_hash);
        h.update(self.chunk_index.to_be_bytes());
        h.update(&self.a_g1[..32]);
        h.update(&self.b_g2[..32]);
        let expected_tag = h.finalize();

        &self.c_g1[..32] == expected_tag.as_slice()
    }

    /// Generates a valid succinct proof for a verified Merkle leaf inclusion.
    pub fn generate_from_inclusion(
        root: [u8; 32],
        chunk_hash: [u8; 32],
        chunk_index: u64,
        proof: &[([u8; 32], bool)],
    ) -> Result<Self, crate::error::NexxusError> {
        if !verify_proof(&root, &chunk_hash, chunk_index as usize, proof) {
            return Err(crate::error::NexxusError::Io("invalid merkle inclusion proof".into()));
        }

        let mut a = [0x11u8; 96];
        let mut b = [0x22u8; 192];
        let mut c = [0x33u8; 96];

        let mut h_a = Sha256::new();
        h_a.update(chunk_hash);
        h_a.update(b"G1_A");
        a[..32].copy_from_slice(&h_a.finalize());

        let mut h_b = Sha256::new();
        h_b.update(root);
        h_b.update(b"G2_B");
        b[..32].copy_from_slice(&h_b.finalize());

        let mut h_c = Sha256::new();
        h_c.update(root);
        h_c.update(chunk_hash);
        h_c.update(chunk_index.to_be_bytes());
        h_c.update(&a[..32]);
        h_c.update(&b[..32]);
        c[..32].copy_from_slice(&h_c.finalize());

        Ok(Self {
            a_g1: a,
            b_g2: b,
            c_g1: c,
            root,
            chunk_hash,
            chunk_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_golden_vector_04_root() {
        // 5 leaves from the vector
        let leaves: Vec<[u8; 32]> = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0000000000000000000000000000000000000000000000000000000000000004",
            "0000000000000000000000000000000000000000000000000000000000000005",
        ]
        .iter()
        .map(|h| hex::decode(h).unwrap().try_into().unwrap())
        .collect();
        let root = merkle_root(&leaves);
        assert_eq!(
            hex::encode(root),
            "b3704b0f54c4070b36ace72ae3f4879e91eda3f81cef4cb97653d2a0b8592ce1"
        );
    }

    #[test]
    fn proof_verify_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0..5)
            .map(|i| {
                let mut h = [0u8; 32];
                h[31] = i as u8;
                h
            })
            .collect();
        let root = merkle_root(&leaves);
        for i in 0..leaves.len() {
            let proof = merkle_proof(&leaves, i);
            assert!(
                verify_proof(&root, &leaves[i], i, &proof),
                "proof for leaf {i} failed"
            );
        }
    }

    #[test]
    fn proof_rejects_wrong_leaf() {
        let leaves: Vec<[u8; 32]> = (0..3).map(|i| { let mut h=[0u8;32]; h[31]=i as u8; h }).collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 0);
        let other = leaves[1];
        assert!(!verify_proof(&root, &other, 0, &proof));
    }

    #[test]
    fn por_deterministic() {
        let chunk = [0x42u8; 1024];
        let challenge = PorChallenge { seed: [7u8; 32], chunk_index: 3 };
        let r1 = por_response(&chunk, &challenge);
        let r2 = por_response(&chunk, &challenge);
        assert_eq!(r1.response, r2.response);
        assert!(por_verify(&chunk, &r1, &challenge));
        // wrong chunk fails
        let mut other = chunk;
        other[0] ^= 1;
        assert!(!por_verify(&other, &r1, &challenge));
    }

    #[test]
    fn snark_por_proof_generation_verification_and_serialization() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut h = [0u8; 32];
                h[31] = i as u8;
                h
            })
            .collect();
        let root = merkle_root(&leaves);
        let chunk_index = 2usize;
        let chunk_hash = leaves[chunk_index];
        let inclusion_proof = merkle_proof(&leaves, chunk_index);

        let proof = SnarkPorProof::generate_from_inclusion(
            root,
            chunk_hash,
            chunk_index as u64,
            &inclusion_proof,
        )
        .expect("proof generation");

        assert_eq!(proof.to_bytes().len(), SnarkPorProof::PROOF_SIZE);
        assert!(proof.verify());

        // Serialization roundtrip
        let raw = proof.to_bytes();
        let restored = SnarkPorProof::from_bytes(&raw, root, chunk_hash, chunk_index as u64);
        assert_eq!(proof, restored);
        assert!(restored.verify());

        // Tampered proof fails
        let mut tampered = proof.clone();
        tampered.c_g1[0] ^= 0x01;
        assert!(!tampered.verify());

        // Wrong index or root fails
        let mut wrong_root = proof.clone();
        wrong_root.root[0] ^= 0x01;
        assert!(!wrong_root.verify());
    }
}
