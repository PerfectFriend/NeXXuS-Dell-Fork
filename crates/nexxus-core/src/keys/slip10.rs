//! SLIP-0010: hierarchical deterministic derivation on ed25519.
//! Path: m / 44' / 999' / 0' / 0 / 0 (coin type 999, last two indexes unhardened per spec §2.1).

use crate::error::NexxusError;
use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

const CURVE: &[u8] = b"ed25519 seed";
const HARDENED: u32 = 0x8000_0000;

/// Derive a child private key from a parent using SLIP-0010.
fn ckd_private(parent_key: &[u8; 64], cc: &[u8; 32], index: u32) -> Result<([u8; 64], [u8; 32]), NexxusError> {
    let mut mac = HmacSha512::new_from_slice(cc)
        .map_err(|_| NexxusError::Io("hmac init failed".into()))?;
    mac.update(&[0u8]); // 0x00 = private key derivation
    mac.update(parent_key);
    mac.update(&index.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut il = [0u8; 32];
    let mut ir = [0u8; 32];
    il.copy_from_slice(&out[..32]);
    ir.copy_from_slice(&out[32..]);

    let mut new_key = [0u8; 64];
    new_key[..32].copy_from_slice(&il);
    new_key[32..].copy_from_slice(&cc[..]);
    Ok((new_key, ir))
}

/// Derive from seed: master = HMAC-SHA512("ed25519 seed", seed).
fn master_from_seed(seed: &[u8; 64]) -> Result<([u8; 64], [u8; 32]), NexxusError> {
    let mut mac = HmacSha512::new_from_slice(CURVE)
        .map_err(|_| NexxusError::Io("hmac init failed".into()))?;
    mac.update(seed);
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 64];
    let mut cc = [0u8; 32];
    key[..32].copy_from_slice(&out[..32]);
    cc.copy_from_slice(&out[32..]);
    Ok((key, cc))
}

/// SLIP-0010 derivation path for NeXXUs: m / 44' / 999' / 0' / 0 / <host_index>
/// Matches NEXXUS_SPECIFICATION_V2.md §2.1 (coin type 999, last two indexes
/// unhardened). Последний индекс — **host_index**: у каждого физического
/// хоста одного владельца (один и тот же BIP-39) свой ключ/node_id, а
/// cluster_tag при этом общий (считается от мастер-seed, см. discovery).
/// host_index = 0 даёт прежний путь m/44'/999'/0'/0/0 (совместимость).
pub const DERIVATION_PATH: &[u32] = &[
    44 | HARDENED,
    999 | HARDENED,
    HARDENED,
    0,
    0,
];

/// Путь с заданным host_index (последний, unhardened, элемент).
pub fn path_with_host_index(host_index: u32) -> [u32; 5] {
    [
        DERIVATION_PATH[0],
        DERIVATION_PATH[1],
        DERIVATION_PATH[2],
        DERIVATION_PATH[3],
        host_index,
    ]
}

pub struct DerivedKey {
    pub private_key: [u8; 32], // ed25519 secret
    pub chain_code: [u8; 32],
    pub path: Vec<u32>,
}

impl DerivedKey {
    pub fn from_seed(seed: &[u8; 64]) -> Result<Self, NexxusError> {
        Self::from_seed_at(seed, path_with_host_index(0))
    }

    /// Деривация по пути с заданным host_index (ADR-0011: пул одного
    /// владельца = много хостов с разными ключами из одного seed).
    pub fn from_seed_host(seed: &[u8; 64], host_index: u32) -> Result<Self, NexxusError> {
        Self::from_seed_at(seed, path_with_host_index(host_index))
    }

    fn from_seed_at(seed: &[u8; 64], path: [u32; 5]) -> Result<Self, NexxusError> {
        let (mut key, mut cc) = master_from_seed(seed)?;
        let mut vpath = Vec::with_capacity(path.len());
        for &index in &path {
            vpath.push(index);
            let (next, next_cc) = ckd_private(&key, &cc, index)?;
            key = next;
            cc = next_cc;
        }
        Ok(DerivedKey {
            private_key: key[..32].try_into().expect("32 bytes"),
            chain_code: cc,
            path: vpath,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let seed = [42u8; 64];
        let k1 = DerivedKey::from_seed(&seed).unwrap();
        let k2 = DerivedKey::from_seed(&seed).unwrap();
        assert_eq!(k1.private_key, k2.private_key);
        assert_eq!(k1.chain_code, k2.chain_code);
    }

    #[test]
    fn path_is_all_hardened() {
        // First three indexes are hardened; last two (0, 0) are not per spec §2.1.
        assert!(DERIVATION_PATH[0] & HARDENED != 0);
        assert!(DERIVATION_PATH[1] & HARDENED != 0);
        assert!(DERIVATION_PATH[2] & HARDENED != 0);
        assert!(DERIVATION_PATH[3] & HARDENED == 0);
        assert!(DERIVATION_PATH[4] & HARDENED == 0);
        assert_eq!(DERIVATION_PATH, &[44 | HARDENED, 999 | HARDENED, HARDENED, 0, 0]);
    }

    #[test]
    fn host_index_zero_matches_default_path() {
        let seed = [7u8; 64];
        let a = DerivedKey::from_seed(&seed).unwrap();
        let b = DerivedKey::from_seed_host(&seed, 0).unwrap();
        assert_eq!(a.private_key, b.private_key);
        assert_eq!(a.chain_code, b.chain_code);
        assert_eq!(b.path, DERIVATION_PATH);
    }

    #[test]
    fn different_host_index_gives_different_key() {
        let seed = [7u8; 64];
        let h0 = DerivedKey::from_seed_host(&seed, 0).unwrap();
        let h1 = DerivedKey::from_seed_host(&seed, 1).unwrap();
        assert_ne!(h0.private_key, h1.private_key);
        assert_eq!(h1.path[4], 1);
        assert_eq!(h1.path[..4], DERIVATION_PATH[..4]);
    }
}
