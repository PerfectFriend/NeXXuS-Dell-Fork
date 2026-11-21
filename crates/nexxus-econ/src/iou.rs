//! ADR-0009: off-chain signed IOU (`nexxus-iou/v1`). Accounting only — no payments,
//! no wire v3 changes. Transport: local API / SMP (opcode family 0x2x — отдельным ADR).
//!
//! Каноническая сериализация: JSON, ключи по алфавиту, compact separators,
//! `amount_micro` — строка. Подпись — ed25519 ключа должника поверх канонического
//! JSON без поля `sig`. node_id = SHA-256(pubkey), поэтому verify сверяет и то, и другое.

use nexxus_core::keys::identity::Identity;
use nexxus_core::types::{Money, NodeId};
use sha2::{Digest, Sha256};

pub const IOU_KIND: &str = "nexxus-iou/v1";
/// Default IOU lifetime: 30 days (ADR-0009 §3).
pub const DEFAULT_IOU_TTL_SECS: u64 = 30 * 24 * 60 * 60;
/// Minimum amount to fight spam-griefing (ADR-0009 §5): 0.001 NEXX.
pub const MIN_IOU_MICRO: i64 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Iou {
    pub debtor: NodeId,
    pub creditor: NodeId,
    pub amount_micro: i64,
    pub epoch: u64,
    pub nonce: [u8; 32],
    pub issued_unix: u64,
    pub expiry_unix: u64,
    pub sig: [u8; 64],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IouError {
    #[error("debtor node_id is not SHA-256 of the given pubkey")]
    DebtorMismatch,
    #[error("bad signature")]
    BadSignature,
    #[error("iou expired at {expiry_unix}, now {now}")]
    Expired { now: u64, expiry_unix: u64 },
    #[error("amount {0} below minimum {MIN_IOU_MICRO}")]
    BelowMinimum(i64),
    #[error("amount overflow")]
    Overflow,
}

fn to_hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 0xf) as usize] as char);
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for pair in b.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

pub fn node_id_of(pubkey: &[u8; 32]) -> NodeId {
    NodeId(Sha256::digest(pubkey).into())
}

impl Iou {
    pub fn new(
        debtor: &Identity,
        creditor: NodeId,
        amount: Money,
        epoch: u64,
        nonce: [u8; 32],
        now_unix: u64,
    ) -> Result<Self, IouError> {
        if amount.0 < MIN_IOU_MICRO {
            return Err(IouError::BelowMinimum(amount.0));
        }
        let mut iou = Iou {
            debtor: debtor.node_id(),
            creditor,
            amount_micro: amount.0,
            epoch,
            nonce,
            issued_unix: now_unix,
            expiry_unix: now_unix.checked_add(DEFAULT_IOU_TTL_SECS).ok_or(IouError::Overflow)?,
            sig: [0u8; 64],
        };
        iou.sig = debtor.sign(&iou.canonical_bytes());
        Ok(iou)
    }

    /// Canonical JSON without `sig`: keys sorted, compact, amount as string.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{{\"amount_micro\":\"{}\",\"creditor\":\"{}\",\"debtor\":\"{}\",\"epoch\":{},\"expiry_unix\":{},\"issued_unix\":{},\"kind\":\"{}\",\"nonce\":\"{}\"}}",
            self.amount_micro,
            to_hex(&self.creditor.0),
            to_hex(&self.debtor.0),
            self.epoch,
            self.expiry_unix,
            self.issued_unix,
            IOU_KIND,
            to_hex(&self.nonce),
        )
        .into_bytes()
    }

    /// Full JSON including `sig` (for transport/storage).
    pub fn to_json(&self) -> String {
        let mut c = String::from_utf8(self.canonical_bytes()).unwrap();
        c.pop(); // remove trailing '}'
        format!(
            "{},\"sig\":\"{}\"}}",
            c,
            to_hex(&self.sig)
        )
    }

    pub fn from_json(s: &str) -> Result<Self, IouError> {
        // Minimal parser for OUR canonical shape — not a general JSON parser.
        let get_str = |key: &str| -> Option<String> {
            let pat = format!("\"{key}\":\"");
            let i = s.find(&pat)? + pat.len();
            let rest = &s[i..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        };
        let get_num = |key: &str| -> Option<u64> {
            let pat = format!("\"{key}\":");
            let i = s.find(&pat)? + pat.len();
            let rest = &s[i..];
            let end = rest.find([',', '}']).unwrap_or(rest.len());
            rest[..end].trim_matches('"').parse().ok()
        };
        let debtor = from_hex(&get_str("debtor").ok_or(IouError::BadSignature)?)
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
            .ok_or(IouError::BadSignature)?;
        let creditor = from_hex(&get_str("creditor").ok_or(IouError::BadSignature)?)
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
            .ok_or(IouError::BadSignature)?;
        let nonce = from_hex(&get_str("nonce").ok_or(IouError::BadSignature)?)
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
            .ok_or(IouError::BadSignature)?;
        let sig = from_hex(&get_str("sig").ok_or(IouError::BadSignature)?)
            .and_then(|v| <[u8; 64]>::try_from(v.as_slice()).ok())
            .ok_or(IouError::BadSignature)?;
        let amount_str = get_str("amount_micro").ok_or(IouError::BadSignature)?;
        let amount_micro = amount_str.parse::<i64>().map_err(|_| IouError::Overflow)?;
        if get_str("kind").as_deref() != Some(IOU_KIND) {
            return Err(IouError::BadSignature);
        }
        Ok(Iou {
            debtor: NodeId(debtor),
            creditor: NodeId(creditor),
            amount_micro,
            epoch: get_num("epoch").ok_or(IouError::BadSignature)?,
            nonce,
            issued_unix: get_num("issued_unix").ok_or(IouError::BadSignature)?,
            expiry_unix: get_num("expiry_unix").ok_or(IouError::BadSignature)?,
            sig,
        })
    }

    /// Verify: debtor node_id == SHA-256(pubkey), sig valid, not expired, amount sane.
    pub fn verify(&self, debtor_pubkey: &[u8; 32], now_unix: u64) -> Result<(), IouError> {
        if node_id_of(debtor_pubkey) != self.debtor {
            return Err(IouError::DebtorMismatch);
        }
        if self.amount_micro < MIN_IOU_MICRO {
            return Err(IouError::BelowMinimum(self.amount_micro));
        }
        if now_unix > self.expiry_unix {
            return Err(IouError::Expired { now: now_unix, expiry_unix: self.expiry_unix });
        }
        let vk = ed25519_dalek::VerifyingKey::from_bytes(debtor_pubkey)
            .map_err(|_| IouError::BadSignature)?;
        if !Identity::verify(&vk, &self.canonical_bytes(), &self.sig) {
            return Err(IouError::BadSignature);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Identity, Identity) {
        (Identity::generate(), Identity::generate())
    }

    #[test]
    fn sign_verify_roundtrip_and_json_roundtrip() {
        let (debtor, creditor_id) = pair();
        let creditor = creditor_id.node_id();
        let iou = Iou::new(&debtor, creditor, Money(1_500_000), 42, [7u8; 32], 1_794_659_095).unwrap();
        let vk = debtor.verifying_key.to_bytes();
        iou.verify(&vk, 1_794_659_096).unwrap();
        let parsed = Iou::from_json(&iou.to_json()).unwrap();
        assert_eq!(parsed, iou);
        parsed.verify(&vk, 1_794_659_096).unwrap();
    }

    #[test]
    fn tamper_detected() {
        let (debtor, creditor_id) = pair();
        let mut iou = Iou::new(&debtor, creditor_id.node_id(), Money(2_000_000), 1, [1u8; 32], 100).unwrap();
        iou.amount_micro += 1;
        let vk = debtor.verifying_key.to_bytes();
        assert_eq!(iou.verify(&vk, 101), Err(IouError::BadSignature));
    }

    #[test]
    fn wrong_pubkey_rejected() {
        let (debtor, creditor_id) = pair();
        let (_, other) = pair();
        let iou = Iou::new(&debtor, creditor_id.node_id(), Money(2_000_000), 1, [1u8; 32], 100).unwrap();
        let other_vk = other.verifying_key.to_bytes();
        assert_eq!(iou.verify(&other_vk, 101), Err(IouError::DebtorMismatch));
    }

    #[test]
    fn expired_rejected() {
        let (debtor, creditor_id) = pair();
        let iou = Iou::new(&debtor, creditor_id.node_id(), Money(2_000_000), 1, [1u8; 32], 100).unwrap();
        let vk = debtor.verifying_key.to_bytes();
        assert!(matches!(iou.verify(&vk, 100 + DEFAULT_IOU_TTL_SECS + 1), Err(IouError::Expired { .. })));
    }

    #[test]
    fn below_minimum_rejected() {
        let (debtor, creditor_id) = pair();
        assert!(matches!(
            Iou::new(&debtor, creditor_id.node_id(), Money(MIN_IOU_MICRO - 1), 1, [1u8; 32], 100),
            Err(IouError::BelowMinimum(_))
        ));
    }
}
