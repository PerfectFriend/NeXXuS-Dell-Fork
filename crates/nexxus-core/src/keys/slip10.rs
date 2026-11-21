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

/// SLIP-0010 derivation path for NeXXUs: m / 44' / 999' / 0' / 0 / 0
/// Matches NEXXUS_SPECIFICATION_V2.md §2.1 (coin type 999, last two indexes unhardened).
pub const DERIVATION_PATH: &[u32] = &[
    44 | HARDENED,
    999 | HARDENED,
    HARDENED,
    0,
    0,
];

pub struct DerivedKey {
    pub private_key: [u8; 32], // ed25519 secret
    pub chain_code: [u8; 32],
    pub path: Vec<u32>,
}

impl DerivedKey {
    /// Derive key using a custom SLIP-0010 derivation path.
    pub fn derive_custom_path(seed: &[u8; 64], path: &[u32]) -> Result<Self, NexxusError> {
        let (mut key, mut cc) = master_from_seed(seed)?;
        for &index in path {
            let (next, next_cc) = ckd_private(&key, &cc, index)?;
            key = next;
            cc = next_cc;
        }
        Ok(DerivedKey {
            private_key: key[..32].try_into().expect("32 bytes"),
            chain_code: cc,
            path: path.to_vec(),
        })
    }

    pub fn from_seed(seed: &[u8; 64]) -> Result<Self, NexxusError> {
        Self::derive_custom_path(seed, DERIVATION_PATH)
    }

    /// Phase 3 dApp isolated key derivation: m / 44' / 999' / app_id' / 0 / 0
    /// Ensures apps only access their own derived key pair and cannot read the master seed or other apps.
    pub fn for_dapp(seed: &[u8; 64], app_id: u32) -> Result<Self, NexxusError> {
        let path = [
            44 | HARDENED,
            999 | HARDENED,
            app_id | HARDENED,
            0,
            0,
        ];
        Self::derive_custom_path(seed, &path)
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
    fn dapp_key_isolation_is_unique_per_app_id() {
        let seed = [99u8; 64];
        let master = DerivedKey::from_seed(&seed).unwrap();
        let app1 = DerivedKey::for_dapp(&seed, 1).unwrap();
        let app2 = DerivedKey::for_dapp(&seed, 2).unwrap();

        // App keys are strictly distinct from each other and master
        assert_ne!(app1.private_key, app2.private_key);
        assert_ne!(app1.private_key, master.private_key);
        assert_ne!(app2.private_key, master.private_key);

        // Derivation for same app_id is deterministic
        let app1_again = DerivedKey::for_dapp(&seed, 1).unwrap();
        assert_eq!(app1.private_key, app1_again.private_key);
    }
}
