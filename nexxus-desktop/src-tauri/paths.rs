//! Единый резолвер путей монитора и ноды (P0-B).
//!
//! До этого пути считались в трёх местах: `guardian.rs` (`~/.nexxus/...`),
//! `node_unit.rs` (`/home/thomas/...` — хардкод машины сборки) и
//! `api_client.rs` (`~/.nexxus/api.token`). Юнит и гардиан могли смотреть на
//! разные бинарники — тот же дрейф, что был в M-8 (список CLI-команд).
//!
//! Правило: **все** пути ноды считаются здесь. Переопределения — через env,
//! чтобы тесты и стенды не зависели от домашнего каталога:
//!   * `NEXXUSD_BIN` — бинарь ноды;
//!   * `NEXXUS_STORE` — хранилище;
//!   * `NEXXUS_DATA_DIR` — каталог данных (по умолчанию `~/.nexxus`);
//!   * `NEXXUS_CONFIG_DIR` — каталог конфигурации (по умолчанию `~/.nexxus`);
//!   * `NEXXUS_API_TOKEN_FILE` — файл токена API;
//!   * `NEXXUS_LOG_FILE` — лог ноды.

use std::path::PathBuf;

/// Каталог данных ноды (хранилище, лог, токен).
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("NEXXUS_DATA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".nexxus")
}

/// Путь к бинарю ноды: env → рядом с текущим exe → системные каталоги → PATH.
pub fn nexxusd_bin() -> String {
    if let Ok(p) = std::env::var("NEXXUSD_BIN") {
        if !p.is_empty() && std::path::Path::new(&p).exists() {
            return p;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join("nexxusd");
            if cand.exists() {
                return cand.to_string_lossy().into_owned();
            }
        }
    }
    for p in ["/usr/local/bin/nexxusd", "/usr/bin/nexxusd"] {
        if std::path::Path::new(p).exists() {
            return p.to_string();
        }
    }
    "nexxusd".to_string() // надежда на PATH
}

/// Путь к хранилищу ноды (store.redb).
pub fn nexxusd_store() -> String {
    if let Ok(p) = std::env::var("NEXXUS_STORE") {
        if !p.is_empty() {
            return p;
        }
    }
    data_dir()
        .join("store.redb")
        .to_string_lossy()
        .into_owned()
}

/// Путь к лог-файлу ноды.
pub fn nexxusd_log() -> String {
    if let Ok(p) = std::env::var("NEXXUS_LOG_FILE") {
        if !p.is_empty() {
            return p;
        }
    }
    data_dir().join("nexxusd.log").to_string_lossy().into_owned()
}

/// Путь к файлу токена локального API.
pub fn api_token_path() -> String {
    if let Ok(p) = std::env::var("NEXXUS_API_TOKEN_FILE") {
        if !p.is_empty() {
            return p;
        }
    }
    crate::node_config::config_dir()
        .join("api.token")
        .to_string_lossy()
        .into_owned()
}
