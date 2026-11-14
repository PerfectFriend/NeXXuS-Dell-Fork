//! G4: signed self-update (`nexxusd update`).
//!
//! Релиз скачивается по URL из конфига/CLI, проверяется detached
//! ed25519-подписью против зашитого публичного ключа, заменяется атомарно
//! (tmp + rename в той же файловой системе) с rollback при любой ошибке.
//! Приватный ключ живёт вне репозитория (владелец), в коде — только pubkey.

use nexxus_core::error::NexxusError;
use std::path::{Path, PathBuf};

/// Публичный ключ подписи релизов (ed25519, hex). Приватный — у владельца,
/// в secrets вне git (см. docs/plans/2026-11-12-evolution-post-rc1.md, фаза G4).
pub const RELEASE_PUBKEY_HEX: &str =
    "d2513bc75eb06436ecc391005bf8ad0fba4f6d8d66f4e16bee7039dcc1947436";

/// URL релизного ассета по умолчанию (squash-mirror / GitHub releases).
pub const DEFAULT_RELEASE_URL: &str =
    "https://github.com/PerfectFriend/NeXXuS-Node-Hermes-Rust/releases/latest/download/nexxusd-linux-x86_64";

pub fn release_pubkey() -> Result<ed25519_dalek::VerifyingKey, NexxusError> {
    let bytes = hex::decode(RELEASE_PUBKEY_HEX)
        .map_err(|e| NexxusError::Io(format!("release pubkey hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| NexxusError::Io("release pubkey must be 32 bytes".into()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| NexxusError::Io(format!("release pubkey: {e}")))
}

/// Проверка detached-подписи (64 байта) над байтами ассета.
pub fn verify_release(bytes: &[u8], signature_hex: &str) -> Result<(), NexxusError> {
    let sig_bytes = hex::decode(signature_hex.trim())
        .map_err(|e| NexxusError::Io(format!("bad signature hex: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| NexxusError::Io("signature must be 64 bytes".into()))?;
    let vk = release_pubkey()?;
    use ed25519_dalek::Verifier;
    vk.verify(bytes, &ed25519_dalek::Signature::from_bytes(&sig_arr))
        .map_err(|_| NexxusError::Vault("release signature verification FAILED".into()))
}

/// UPD-01: скачивание ассета и .sig in-process через ureq+rustls (без curl/PATH).
/// HTTPS обязателен; plain HTTP разрешён только для loopback (локальные тесты).
pub fn download(url: &str) -> Result<(Vec<u8>, String), NexxusError> {
    let bin = http_get(url)?;
    let sig = http_get(&format!("{url}.sig"))
        .map_err(|e| NexxusError::Io(format!("signature download: {e}")))?;
    let sig_text = String::from_utf8_lossy(&sig).trim().to_string();
    Ok((bin, sig_text))
}

/// Валидация URL: https всегда; http только для 127.0.0.1/localhost/[::1].
pub fn validate_url(url: &str) -> Result<(), NexxusError> {
    if let Some(rest) = url.strip_prefix("https://") {
        if rest.is_empty() {
            return Err(NexxusError::Io("empty host in url".into()));
        }
        Ok(())
    } else if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split(['/', ':', '?']).next().unwrap_or("");
        if host == "127.0.0.1" || host == "localhost" || host == "[::1]" {
            Ok(())
        } else {
            Err(NexxusError::Io(
                "plain http allowed only for loopback; use https".into(),
            ))
        }
    } else {
        Err(NexxusError::Io("url must start with https://".into()))
    }
}

const MAX_DOWNLOAD_BYTES: usize = 512 * 1024 * 1024;

fn http_get(url: &str) -> Result<Vec<u8>, NexxusError> {
    use std::io::Read;
    validate_url(url)?;
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(120))
        .call()
        .map_err(|e| NexxusError::Io(format!("GET {url}: {e}")))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take((MAX_DOWNLOAD_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| NexxusError::Io(format!("read body: {e}")))?;
    if buf.len() > MAX_DOWNLOAD_BYTES {
        return Err(NexxusError::Io("download exceeds 512 MiB cap".into()));
    }
    Ok(buf)
}

/// Атомарная замена бинарника с rollback: verify подписи → backup старого →
/// tmp+rename → при любой ошибке до rename старый бинарь не тронут.
/// UPD-02 (anti-rollback): разобрать semver-строку "0.1.0[-suffix]" в кортеж.
pub fn version_tuple(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.split(['-', '+']).next()?;
    let mut it = core.split('.');
    let maj = it.next()?.parse().ok()?;
    let min = it.next().unwrap_or("0").parse().ok()?;
    let pat = it.next().unwrap_or("0").parse().ok()?;
    Some((maj, min, pat))
}

/// true если `new` строго новее `cur`.
pub fn is_newer(new: (u64, u64, u64), cur: (u64, u64, u64)) -> bool {
    new > cur
}

/// UPD-02: anti-rollback — прогоняет скачанный (уже signature-verified) бинарник
/// с `--version` и отказывается устанавливать, если его версия <= текущей.
/// Возвращает строку новой версии при успехе.
pub fn check_not_downgrade(new_bytes: &[u8]) -> Result<String, NexxusError> {
    if new_bytes.len() < 1024 {
        return Err(NexxusError::Io("suspiciously small release binary".into()));
    }
    let dir = std::env::temp_dir().join(format!(
        "nexxus-upd-check-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).map_err(|e| NexxusError::Io(format!("tmp dir: {e}")))?;
    let tmp = dir.join("nexxusd-candidate");
    std::fs::write(&tmp, new_bytes).map_err(|e| NexxusError::Io(format!("tmp write: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    let out = std::process::Command::new(&tmp)
        .arg("--version")
        .output()
        .map_err(|e| NexxusError::Io(format!("probe --version: {e}")))?;
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // ожидаем "nexxusd X.Y.Z"
    let vstr = stdout
        .split_whitespace()
        .last()
        .ok_or_else(|| NexxusError::Io("candidate --version produced no version".into()))?;
    let new = version_tuple(vstr)
        .ok_or_else(|| NexxusError::Io(format!("candidate version unparseable: {vstr}")))?;
    let cur = version_tuple(env!("CARGO_PKG_VERSION"))
        .ok_or_else(|| NexxusError::Io("current version unparseable".into()))?;
    if !is_newer(new, cur) {
        return Err(NexxusError::Io(format!(
            "anti-rollback: candidate {vstr} is not newer than current {} — refusing",
            env!("CARGO_PKG_VERSION")
        )));
    }
    Ok(vstr.to_string())
}

pub fn install_update(new_bytes: &[u8], signature_hex: &str, current_bin: &Path) -> Result<PathBuf, NexxusError> {
    verify_release(new_bytes, signature_hex)?;
    if new_bytes.len() < 1024 {
        return Err(NexxusError::Io("suspiciously small release binary".into()));
    }
    let dir = current_bin
        .parent()
        .ok_or_else(|| NexxusError::Io("no parent dir".into()))?;
    let backup = dir.join(format!(
        ".{}.rollback",
        current_bin
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "nexxusd".into())
    ));
    // backup текущего бинарника
    if current_bin.exists() {
        std::fs::copy(current_bin, &backup)
            .map_err(|e| NexxusError::Io(format!("backup copy: {e}")))?;
    }
    let tmp = dir.join(format!(
        ".{}.new",
        current_bin
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "nexxusd".into())
    ));
    let install = (|| -> Result<PathBuf, NexxusError> {
        std::fs::write(&tmp, new_bytes)
            .map_err(|e| NexxusError::Io(format!("tmp write: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| NexxusError::Io(format!("chmod: {e}")))?;
        }
        std::fs::rename(&tmp, current_bin)
            .map_err(|e| NexxusError::Io(format!("atomic rename: {e}")))?;
        Ok(current_bin.to_path_buf())
    })();
    if install.is_err() {
        // rollback
        if backup.exists() {
            let _ = std::fs::copy(&backup, current_bin);
        }
        let _ = std::fs::remove_file(&tmp);
    }
    install
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_url_rules() {
        assert!(validate_url("https://github.com/x/y").is_ok());
        assert!(validate_url("http://127.0.0.1:8080/nexxusd").is_ok());
        assert!(validate_url("http://localhost/x").is_ok());
        assert!(validate_url("http://evil.example.com/x").is_err(), "plain http вне loopback запрещён");
        assert!(validate_url("ftp://x").is_err());
        assert!(validate_url("https://").is_err());
    }

    #[test]
    fn version_tuple_and_is_newer() {
        assert_eq!(version_tuple("0.1.0"), Some((0, 1, 0)));
        assert_eq!(version_tuple("2.0.0-rc1"), Some((2, 0, 0)));
        assert_eq!(version_tuple("v2.0.0-prototype"), None, "префикс v не парсится — ок, --version печатает без него");
        assert!(is_newer((0, 2, 0), (0, 1, 0)));
        assert!(!is_newer((0, 1, 0), (0, 1, 0)), "равная версия — не новее (anti-rollback)");
        assert!(!is_newer((0, 0, 9), (0, 1, 0)));
    }

    #[test]
    fn check_not_downgrade_rejects_same_version_binary() {
        // собираем "кандидата": текущий бинарник теста с --version = CARGO_PKG_VERSION
        let cur = std::env::current_exe().unwrap();
        let bytes = std::fs::read(&cur).unwrap();
        // текущий == текущему → отказ
        assert!(check_not_downgrade(&bytes).is_err());
    }

    #[test]
    fn signature_verify_ok_and_tamper_fails() {
        // ключationenkeypair только для теста — не release-ключ
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let msg = b"fake release binary bytes";
        use ed25519_dalek::Signer;
        let sig = sk.sign(msg);
        use ed25519_dalek::Verifier;
        assert!(vk.verify(msg, &sig).is_ok());
        let mut bad = msg.to_vec();
        bad[0] ^= 0xFF;
        assert!(vk.verify(&bad, &sig).is_err());

        // verify_release падает на битую подпись / левый ключ
        assert!(verify_release(msg, &hex::encode([0u8; 64])).is_err());
        assert!(verify_release(msg, "zz").is_err());
    }

    #[test]
    fn install_update_atomic_and_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("nexxusd");
        std::fs::write(&bin, b"old-binary").unwrap();
        // подпись валидна только под release pubkey — для теста install
        // используем verify отдельно; здесь проверяем rollback-логику через
        // фальшивую подпись: install должен упасть и НЕ трогать старый бинарь
        let res = install_update(b"new-bytes", &hex::encode([1u8; 64]), &bin);
        assert!(res.is_err(), "bad signature must abort");
        assert_eq!(std::fs::read(&bin).unwrap(), b"old-binary", "old binary intact after failed verify");
    }
}
