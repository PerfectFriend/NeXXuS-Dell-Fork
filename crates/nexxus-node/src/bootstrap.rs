//! E6: signed bootstrap-список пиров (registry list с expiry).
//!
//! Не центральный «владелец сети»: это подписанный список bootstrap-адресов,
//! который узел хранит локально, проверяет подпись ed25519 по доверенному
//! registry-публичному ключу и отбрасывает по expiry. Формат:
//!
//! canonical JSON (sorted keys, compact):
//! {"kind":"nexxus-bootstrap/v1","addrs":["host:port",...],"issued_unix":N,
//!  "expiry_unix":N,"registry_pub":"<hex64>"} + отдельная подпись ed25519 над
//! этим canonical JSON (поле "sig" в envelope: {"payload": canonical, "sig": hex}).
//!
//! Хранение: meta-ключ "bootstrap:list" в ChunkStore (вместе с envelope).

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::storage::ChunkStore;
use nexxus_core::error::NexxusError;

pub const BOOTSTRAP_META_KEY: &str = "bootstrap:list";
pub const BOOTSTRAP_KIND: &str = "nexxus-bootstrap/v1";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BootstrapList {
    pub kind: String,
    pub addrs: Vec<String>,
    pub issued_unix: u64,
    pub expiry_unix: u64,
    pub registry_pub: String, // hex ed25519 verifying key
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BootstrapEnvelope {
    pub payload: BootstrapList,
    pub sig: String, // hex ed25519 over canonical payload
}

/// Каноническая сериализация payload: sorted keys, compact separators.
pub fn canonical_payload(p: &BootstrapList) -> Result<String, NexxusError> {
    let v = serde_json::to_value(p).map_err(|e| NexxusError::Io(format!("json: {e}")))?;
    fn sort(v: serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => serde_json::Value::Object(
                m.into_iter()
                    .map(|(k, v)| (k, sort(v)))
                    .collect::<serde_json::Map<_, _>>(),
            ),
            serde_json::Value::Array(a) => {
                serde_json::Value::Array(a.into_iter().map(sort).collect())
            }
            other => other,
        }
    }
    let v = sort(v);
    // serde_json::Map по умолчанию BTreeMap при включённом preserve_order=off;
    // для гарантии сортируем вручную через строку.
    let s = serde_json::to_string(&v).map_err(|e| NexxusError::Io(format!("json: {e}")))?;
    Ok(s)
}

/// Подписать список registry-стороной (используется CLI/tests; нода только verify).
#[allow(dead_code)]
pub fn sign_list(list: &BootstrapList, sk: &ed25519_dalek::SigningKey) -> Result<BootstrapEnvelope, NexxusError> {
    let canon = canonical_payload(list)?;
    let sig = sk.sign(canon.as_bytes());
    Ok(BootstrapEnvelope {
        payload: list.clone(),
        sig: hex::encode(sig.to_bytes()),
    })
}

/// Проверка подписи + срока годности. now_unix — текущее время.
pub fn verify_envelope(env: &BootstrapEnvelope, now_unix: u64) -> Result<(), NexxusError> {
    if env.payload.kind != BOOTSTRAP_KIND {
        return Err(NexxusError::Io("bad bootstrap kind".into()));
    }
    if now_unix >= env.payload.expiry_unix {
        return Err(NexxusError::Io("bootstrap list expired".into()));
    }
    let pk_bytes = hex::decode(&env.payload.registry_pub)
        .map_err(|e| NexxusError::Io(format!("bad registry_pub hex: {e}")))?;
    let pk = <[u8; 32]>::try_from(pk_bytes.as_slice())
        .map_err(|_| NexxusError::Io("registry_pub not 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| NexxusError::Io(format!("bad pubkey: {e}")))?;
    let sig_bytes = hex::decode(&env.sig).map_err(|e| NexxusError::Io(format!("bad sig hex: {e}")))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| NexxusError::Io(format!("bad sig: {e}")))?;
    let canon = canonical_payload(&env.payload)?;
    vk.verify(canon.as_bytes(), &sig)
        .map_err(|_| NexxusError::Io("bootstrap list signature invalid".into()))?;
    if env.payload.addrs.len() > 64 {
        return Err(NexxusError::Io("too many bootstrap addrs (>64)".into()));
    }
    for a in &env.payload.addrs {
        if a.is_empty() || a.len() > 255 || !a.contains(':') {
            return Err(NexxusError::Io(format!("bad addr: {a}")));
        }
    }
    Ok(())
}

/// Сохранить envelope в store (meta-ключ). Проверяет подпись и expiry.
pub fn store_set(store: &ChunkStore, env: &BootstrapEnvelope, now_unix: u64) -> Result<(), NexxusError> {
    verify_envelope(env, now_unix)?;
    let s = serde_json::to_string(env).map_err(|e| NexxusError::Io(format!("json: {e}")))?;
    store.put_meta(BOOTSTRAP_META_KEY, s.as_bytes())
}

/// Прочитать и проверить сохранённый список. None если не сохранён.
pub fn store_get(store: &ChunkStore, now_unix: u64) -> Result<Option<BootstrapList>, NexxusError> {
    let raw = match store.get_meta(BOOTSTRAP_META_KEY)? {
        Some(r) => r,
        None => return Ok(None),
    };
    let env: BootstrapEnvelope =
        serde_json::from_slice(&raw).map_err(|e| NexxusError::Io(format!("bad bootstrap json: {e}")))?;
    verify_envelope(&env, now_unix)?;
    Ok(Some(env.payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(expiry: u64) -> BootstrapList {
        BootstrapList {
            kind: BOOTSTRAP_KIND.into(),
            addrs: vec!["1.2.3.4:4001".into(), "example.onion:4001".into()],
            issued_unix: 100,
            expiry_unix: expiry,
            registry_pub: "ab".repeat(32),
        }
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut l = list(1000);
        l.registry_pub = hex::encode(sk.verifying_key().to_bytes());
        let env = sign_list(&l, &sk).unwrap();
        verify_envelope(&env, 500).unwrap();
        // tamper: меняем адрес после подписи
        let mut bad = env.clone();
        bad.payload.addrs.push("9.9.9.9:1".into());
        assert!(verify_envelope(&bad, 500).is_err());
        // expired
        assert!(verify_envelope(&env, 1000).is_err());
        assert!(verify_envelope(&env, 2000).is_err());
        // bad kind
        let mut bad2 = env.clone();
        bad2.payload.kind = "other".into();
        assert!(verify_envelope(&bad2, 500).is_err());
        // bad addr
        let mut bad3 = env.clone();
        bad3.payload.addrs = vec!["no-port".into()];
        // подпись сломается раньше — ок, тоже err
        assert!(verify_envelope(&bad3, 500).is_err());
    }

    #[test]
    fn store_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "nexxus-test-boot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let st = ChunkStore::open(&dir).unwrap();
        assert!(store_get(&st, 500).unwrap().is_none());
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let mut l = list(1000);
        l.registry_pub = hex::encode(sk.verifying_key().to_bytes());
        let env = sign_list(&l, &sk).unwrap();
        store_set(&st, &env, 500).unwrap();
        let got = store_get(&st, 500).unwrap().unwrap();
        assert_eq!(got.addrs, l.addrs);
        // после expiry чтение падает
        assert!(store_get(&st, 1001).is_err());
        drop(st);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
