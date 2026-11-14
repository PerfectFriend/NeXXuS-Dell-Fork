//! wasm-bindgen surface for the browser panel: real bindings over nexxus-core
//! (chunking, Reed-Solomon, Merkle, identity from mnemonic). Pure functions —
//! no I/O, no network.

use wasm_bindgen::prelude::*;

use nexxus_core::keys::identity::Identity;
use nexxus_core::keys::seed::IdentitySeed;
use nexxus_core::keys::slip10::DerivedKey;
use nexxus_core::{chunk, merkle, rs};
use sha2::{Digest, Sha256};

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Crate version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Generate a fresh BIP-39 mnemonic (shown once — the caller must persist it).
#[wasm_bindgen]
pub fn generate_mnemonic() -> Result<String, JsError> {
    let seed = IdentitySeed::generate().map_err(|e| JsError::new(&e.to_string()))?;
    Ok(seed.mnemonic.clone())
}

/// Derive the node id (hex of Ed25519 pubkey) from a BIP-39 mnemonic,
/// via SLIP-0010 m/44'/999'/0'/0/0 — same path as the node's identity store.
#[wasm_bindgen]
pub fn node_id_from_mnemonic(phrase: &str) -> Result<String, JsError> {
    let seed = IdentitySeed::validate(phrase).map_err(|e| JsError::new(&e.to_string()))?;
    let derived = DerivedKey::from_seed(seed.seed_bytes()).map_err(|e| JsError::new(&e.to_string()))?;
    let identity = Identity::from_secret(&derived.private_key).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(hex_encode(&identity.node_id().0))
}

/// Number of 16 KiB chunks a file of `data_len` bytes splits into.
#[wasm_bindgen]
pub fn chunk_count(data_len: u32) -> u32 {
    chunk::slice(&vec![0u8; data_len as usize]).len() as u32
}

/// Slice a file into 16 KiB chunks and return them concatenated
/// (last chunk zero-padded to CHUNK_SIZE).
#[wasm_bindgen]
pub fn chunk_data(data: &[u8]) -> Vec<u8> {
    let chunks = chunk::slice(data);
    let mut out = Vec::with_capacity(chunks.len() * chunk::CHUNK_SIZE);
    for mut c in chunks {
        c.resize(chunk::CHUNK_SIZE, 0);
        out.extend_from_slice(&c);
    }
    out
}

/// Reed-Solomon encode one chunk: returns 6 shards (4 data + 2 parity)
/// concatenated, each `ceil(chunk_len/4)` bytes.
#[wasm_bindgen]
pub fn rs_encode_chunk(data: &[u8]) -> Vec<u8> {
    let shards = rs::encode(data);
    let shard_len = shards[0].len();
    let mut out = Vec::with_capacity(shard_len * rs::TOTAL_SHARDS);
    for s in &shards {
        out.extend_from_slice(s);
    }
    out
}

/// Recover the original chunk from the first 4 shards of a flat
/// `rs_encode_chunk` output. `original_len` is the pre-encode length.
#[wasm_bindgen]
pub fn rs_decode_shards(shards_flat: &[u8], original_len: u32) -> Result<Vec<u8>, JsError> {
    let shard_len = shards_flat.len() / rs::TOTAL_SHARDS;
    if shard_len * rs::TOTAL_SHARDS != shards_flat.len() {
        return Err(JsError::new("shard buffer not a multiple of 6 shards"));
    }
    let surviving: Vec<(&[u8], usize)> = (0..rs::DATA_SHARDS)
        .map(|i| (&shards_flat[i * shard_len..(i + 1) * shard_len], i))
        .collect();
    rs::decode(&surviving, original_len as usize).map_err(|e| JsError::new(&e.to_string()))
}

/// Merkle root (SHA-256 leaves over 16 KiB zero-padded chunks) of a file,
/// as 32 raw bytes.
#[wasm_bindgen]
pub fn merkle_root_of_file(data: &[u8]) -> Vec<u8> {
    let chunks = chunk::slice(data);
    let leaves: Vec<[u8; 32]> = chunks
        .iter()
        .map(|c| {
            let mut padded = c.clone();
            padded.resize(chunk::CHUNK_SIZE, 0);
            sha256(&padded)
        })
        .collect();
    merkle::merkle_root(&leaves).to_vec()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("bad hex: {e}"))
}

fn key32(key_hex: &str) -> Result<[u8; 32], String> {
    let b = hex_decode(key_hex)?;
    <[u8; 32]>::try_from(b.as_slice()).map_err(|_| "key must be 32 bytes (64 hex)".to_string())
}

// ---------------------------------------------------------------------------
// Light-client surface (E6): браузерный applet скачивает sealed чанки через
// WS API ноды (JS WebSocket) и открывает их локально — нода ключ не видит.
// ---------------------------------------------------------------------------

/// Seal one chunk with the per-file vault key (same AEAD as the node:
/// XChaCha20-Poly1305, nonce derived from key+index). Returns sealed bytes.
fn seal_chunk_impl(key_hex: &str, chunk_index: u64, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let key = key32(key_hex)?;
    nexxus_core::chunk::ChunkAead::seal(&key, chunk_index, plaintext).map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn seal_chunk(key_hex: &str, chunk_index: u64, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    seal_chunk_impl(key_hex, chunk_index, plaintext).map_err(|e| JsError::new(&e))
}

/// Open a sealed chunk with the per-file vault key. Wrong key/tamper → Err.
fn open_chunk_impl(key_hex: &str, chunk_index: u64, sealed: &[u8]) -> Result<Vec<u8>, String> {
    let key = key32(key_hex)?;
    nexxus_core::chunk::ChunkAead::open(&key, chunk_index, sealed).map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn open_chunk(key_hex: &str, chunk_index: u64, sealed: &[u8]) -> Result<Vec<u8>, JsError> {
    open_chunk_impl(key_hex, chunk_index, sealed).map_err(|e| JsError::new(&e))
}

/// ChunkHash of a sealed chunk (hex SHA-256) — matches what the node stores.
#[wasm_bindgen]
pub fn sealed_chunk_hash_hex(sealed: &[u8]) -> String {
    hex_encode(&sha256(sealed))
}

/// Flat merkle proof for `leaf_index`: 33 bytes per level (32-byte hash + 1 side byte).
/// `leaves_flat` = concatenated 32-byte leaf hashes.
fn merkle_proof_flat_impl(leaves_flat: &[u8], leaf_index: usize) -> Result<Vec<u8>, String> {
    if !leaves_flat.len().is_multiple_of(32) {
        return Err("leaves_flat must be a multiple of 32 bytes".into());
    }
    let leaves: Vec<[u8; 32]> = leaves_flat
        .chunks(32)
        .map(|c| <[u8; 32]>::try_from(c).unwrap())
        .collect();
    let proof = merkle::merkle_proof(&leaves, leaf_index);
    let mut out = Vec::with_capacity(proof.len() * 33);
    for (h, is_right) in proof {
        out.extend_from_slice(&h);
        out.push(if is_right { 1 } else { 0 });
    }
    Ok(out)
}

#[wasm_bindgen]
pub fn merkle_proof_flat(leaves_flat: &[u8], leaf_index: usize) -> Result<Vec<u8>, JsError> {
    merkle_proof_flat_impl(leaves_flat, leaf_index).map_err(|e| JsError::new(&e))
}

/// Verify a flat merkle proof against root/leaf (hex). Tamper → false.
fn merkle_verify_flat_impl(root_hex: &str, leaf_hex: &str, leaf_index: usize, proof_flat: &[u8]) -> bool {
    let root: [u8; 32] = match hex_decode(root_hex).ok().and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()) {
        Some(r) => r,
        None => return false,
    };
    let leaf: [u8; 32] = match hex_decode(leaf_hex).ok().and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()) {
        Some(l) => l,
        None => return false,
    };
    if !proof_flat.len().is_multiple_of(33) {
        return false;
    }
    let proof: Vec<([u8; 32], bool)> = proof_flat
        .chunks(33)
        .map(|c| (<[u8; 32]>::try_from(&c[..32]).unwrap(), c[32] == 1))
        .collect();
    merkle::verify_proof(&root, &leaf, leaf_index, &proof)
}

#[wasm_bindgen]
pub fn merkle_verify_flat(root_hex: &str, leaf_hex: &str, leaf_index: usize, proof_flat: &[u8]) -> bool {
    merkle_verify_flat_impl(root_hex, leaf_hex, leaf_index, proof_flat)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_surface_roundtrip() {
        let data: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let n = chunk_count(data.len() as u32);
        assert_eq!(n, 3); // 40000 / 16384 = 2.44 -> 3
        let flat = chunk_data(&data);
        assert_eq!(flat.len(), 3 * chunk::CHUNK_SIZE);

        let chunk0 = &flat[..chunk::CHUNK_SIZE];
        let shards = rs_encode_chunk(chunk0);
        assert_eq!(shards.len(), 6 * (chunk::CHUNK_SIZE / 4));
        let back = rs_decode_shards(&shards, chunk::CHUNK_SIZE as u32).unwrap();
        assert_eq!(back, chunk0);

        let root = merkle_root_of_file(&data);
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn mnemonic_to_stable_node_id() {
        let m = generate_mnemonic().unwrap();
        let id1 = node_id_from_mnemonic(&m).unwrap();
        let id2 = node_id_from_mnemonic(&m).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64);
    }

    #[test]
    fn light_client_seal_open_and_hash() {
        let key = [7u8; 32];
        let key_hex = hex_encode(&key);
        let plain = b"hello nexxus light client";
        let sealed = seal_chunk_impl(&key_hex, 3, plain).unwrap();
        // hash совпадает с node-side ChunkHash(sha256(sealed))
        assert_eq!(sealed_chunk_hash_hex(&sealed), hex_encode(&sha256(&sealed)));
        let back = open_chunk_impl(&key_hex, 3, &sealed).unwrap();
        assert_eq!(back, plain);
        // wrong key / wrong index / tamper → error
        let bad_key = hex_encode(&[8u8; 32]);
        assert!(open_chunk_impl(&bad_key, 3, &sealed).is_err());
        assert!(open_chunk_impl(&key_hex, 4, &sealed).is_err());
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert!(open_chunk_impl(&key_hex, 3, &tampered).is_err());
    }

    #[test]
    fn merkle_proof_flat_verify_and_tamper() {
        let leaves: Vec<[u8; 32]> = (0..8u8).map(|i| sha256(&[i])).collect();
        let flat: Vec<u8> = leaves.iter().flat_map(|a| a.iter().copied()).collect();
        let root = merkle::merkle_root(&leaves);
        let proof = merkle_proof_flat_impl(&flat, 5).unwrap();
        assert!(proof.len().is_multiple_of(33));
        assert!(merkle_verify_flat_impl(&hex_encode(&root), &hex_encode(&leaves[5]), 5, &proof));
        // tamper: другой leaf → false
        assert!(!merkle_verify_flat_impl(&hex_encode(&root), &hex_encode(&leaves[4]), 5, &proof));
        // tampered proof → false
        let mut bad = proof.clone();
        bad[0] ^= 1;
        assert!(!merkle_verify_flat_impl(&hex_encode(&root), &hex_encode(&leaves[5]), 5, &bad));
        // мусорный вход → false, без паники
        assert!(!merkle_verify_flat_impl("zz", "zz", 0, &[1, 2, 3]));
    }
}
