//! Единый конфиг ноды и монитора: `<NEXXUS_CONFIG_DIR|~/.nexxus>/node.conf`.
//!
//! Формат — тот же key=value, что пишет монитор (nexxus-desktop/src-tauri/node_config.rs),
//! чтобы нода и монитор **всегда слушали одни и те же порты**. Приоритет:
//! env-переменная > node.conf > дефолт. Это убирает класс рассинхрона
//! «нода на 4010, монитор стучится в 5010 → все кнопки мёртвые».

use std::collections::HashMap;
use std::path::PathBuf;

pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("NEXXUS_CONFIG_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".nexxus")
}

pub fn config_path() -> PathBuf {
    config_dir().join("node.conf")
}

/// Прочитать node.conf в карту (пустая карта, если файла нет).
pub fn load_file() -> HashMap<String, String> {
    load_file_from(&config_path())
}

pub fn load_file_from(path: &std::path::Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(content) = std::fs::read_to_string(path) else {
        return out;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

/// env > conf > дефолт.
pub fn cfg_or_env(conf: &HashMap<String, String>, conf_key: &str, env_key: &str, default: &str) -> String {
    if let Ok(v) = std::env::var(env_key) {
        if !v.is_empty() {
            return v;
        }
    }
    conf.get(conf_key).cloned().unwrap_or_else(|| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_overrides_default_env_overrides_file() {
        let dir = std::env::temp_dir().join(format!(
            "nexxus-test-cfg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("node.conf");
        std::fs::write(&p, "# comment\napi=127.0.0.1:5010\nlisten=0.0.0.0:4001\n\n").unwrap();
        let conf = load_file_from(&p);
        assert_eq!(conf.get("api").unwrap(), "127.0.0.1:5010");
        // дефолт
        assert_eq!(cfg_or_env(&conf, "tor", "NEXXUS_TOR_TEST_UNSET", "0"), "0");
        // файл перекрывает дефолт
        assert_eq!(cfg_or_env(&conf, "api", "NEXXUS_API_ADDR_TEST_UNSET", "127.0.0.1:4010"), "127.0.0.1:5010");
        // env перекрывает файл
        std::env::set_var("NEXXUS_API_ADDR_TEST_SET", "127.0.0.1:9999");
        assert_eq!(cfg_or_env(&conf, "api", "NEXXUS_API_ADDR_TEST_SET", "127.0.0.1:4010"), "127.0.0.1:9999");
        std::env::remove_var("NEXXUS_API_ADDR_TEST_SET");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
