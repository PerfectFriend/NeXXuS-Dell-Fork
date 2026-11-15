//! Formal bits (E6 plan): property-доказательства критичных инвариантов.
//!
//! 1. **Session nonce binding (wire v3):** подпись фрейма валидна ТОЛЬКО под
//!    тем session_nonce, который вошёл в signing bytes. Подмена nonce, payload,
//!    request_id или opcode → verify = false. Replay фрейма из одной сессии в
//!    другую (другой peer nonce) отклоняется.
//! 2. **Vault KDF:** derive детерминирован, разный salt → другой ключ,
//!    seal/open roundtrip, wrong PIN не открывает, tamper не открывает.

use nexxus_core::keys::identity::Identity;
use nexxus_core::keys::vault::{
    check_pin, decrypt_vault_payload, encrypt_vault_payload_rounds, PinCheck,
};
use nexxus_core::wire::header::{encode_v3, v3_signing_bytes};
use nexxus_core::wire::opcode::Opcode;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Nonce binding: подпись верна только под «своим» nonce и содержимым.
    #[test]
    fn v3_signature_binds_nonce_payload_req_opcode(
        op in 0u8..=0xFF,
        req in any::<u32>(),
        payload in proptest::collection::vec(any::<u8>(), 0..128),
        nonce_a in any::<[u8; 32]>(),
        nonce_b in any::<[u8; 32]>(),
        req2 in any::<u32>(),
        op2 in 0u8..=0xFF,
    ) {
        let id = Identity::generate();
        let op = Opcode::from_u8(op).unwrap_or(Opcode::ErrorResponse);
        let op2 = Opcode::from_u8(op2).unwrap_or(Opcode::ErrorResponse);
        let msg = v3_signing_bytes(op, req, &payload, &nonce_a);
        let sig = id.sign(&msg);
        // эталон: верно
        prop_assert!(Identity::verify(&id.verifying_key, &msg, &sig));
        // nonce подменён → false (session binding)
        if nonce_a != nonce_b {
            let msg_b = v3_signing_bytes(op, req, &payload, &nonce_b);
            prop_assert!(!Identity::verify(&id.verifying_key, &msg_b, &sig));
        }
        // payload tamper → false
        let mut p2 = payload.clone();
        if p2.is_empty() { p2.push(0); } else { p2[0] ^= 1; }
        prop_assert!(!Identity::verify(&id.verifying_key, &v3_signing_bytes(op, req, &p2, &nonce_a), &sig));
        // request_id другой → false
        if req != req2 {
            prop_assert!(!Identity::verify(&id.verifying_key, &v3_signing_bytes(op, req2, &payload, &nonce_a), &sig));
        }
        // opcode другой → false
        if op != op2 {
            prop_assert!(!Identity::verify(&id.verifying_key, &v3_signing_bytes(op2, req, &payload, &nonce_a), &sig));
        }
        // replay в другую сессию: тот же фрейм, но peer_nonce другой → false
        let frame = encode_v3(op, req, &payload, &sig);
        let parsed = nexxus_core::wire::header::parse_v3(&frame).unwrap();
        let replay_msg = v3_signing_bytes(parsed.opcode, parsed.request_id, &parsed.payload, &nonce_b);
        if nonce_a != nonce_b {
            prop_assert!(!Identity::verify(&id.verifying_key, &replay_msg, &parsed.signature));
        }
        // ed25519 детерминирован: та же msg → та же подпись
        prop_assert_eq!(id.sign(&msg), sig);
    }

    /// Vault KDF/encryption: roundtrip, wrong PIN, tamper, per-salt uniqueness.
    #[test]
    fn vault_seal_open_properties(
        pin in "[0-9]{4,12}",
        wrong_pin in "[0-9]{4,12}",
        secret in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let rounds = 1_000u32; // тестовые раунды, не 600k
        let v = encrypt_vault_payload_rounds(&secret, &pin, None, rounds).unwrap();
        // roundtrip своим PIN
        let d = decrypt_vault_payload(&v, &pin).unwrap();
        prop_assert!(d.decrypted_bytes == secret);
        prop_assert!(!d.is_duress);
        prop_assert!(matches!(check_pin(&v, &pin), Ok(PinCheck::Ok)));
        // два шифрования одного секрета → разные salt/iv (KDF per-salt, random nonce)
        let v2 = encrypt_vault_payload_rounds(&secret, &pin, None, rounds).unwrap();
        prop_assert_ne!(&v, &v2);
        let salt_of = |j: &str| serde_json::from_str::<serde_json::Value>(j).unwrap()["salt_hex"].as_str().unwrap().to_string();
        prop_assert_ne!(salt_of(&v), salt_of(&v2));
        // wrong PIN: check_pin = Wrong, decrypt → ошибка
        if pin != wrong_pin {
            prop_assert!(matches!(check_pin(&v, &wrong_pin), Ok(PinCheck::Wrong)));
            prop_assert!(decrypt_vault_payload(&v, &wrong_pin).is_err());
        }
        // tamper ciphertext → ошибка
        let mut t = v.clone().into_bytes();
        let n = t.len();
        t[n / 2] ^= 1;
        if let Ok(tampered) = String::from_utf8(t) {
            prop_assert!(decrypt_vault_payload(&tampered, &pin).is_err());
        }
    }
}
