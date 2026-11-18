//! systemd-юнит ноды, которым управляет монитор.
//!
//! Монитор ставится первым и сам создаёт юнит ноды: нода запускается
//! системой как отдельная служба (а не дочерним процессом монитора), поэтому
//! переживает перезапуск монитора и стартует при загрузке ОС.

use crate::node_config::NodeConfig;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Имя юнита ноды.
pub const NODE_UNIT_NAME: &str = "nexxus-node.service";
/// Имя юнита монитора (в нём живёт нода по умолчанию, см. fallback).
pub const MONITOR_UNIT_NAME: &str = "nexxus-monitor.service";

/// Путь к user-юниту ноды.
pub fn node_unit_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user")
        .join(NODE_UNIT_NAME)
}

/// Путь к исполняемому файлу ноды.
pub fn node_binary_path() -> PathBuf {
    PathBuf::from(crate::paths::nexxusd_bin())
}

/// Путь к хранилищу ноды.
pub fn node_store_path() -> PathBuf {
    PathBuf::from(crate::paths::nexxusd_store())
}

/// Экранирует значение для unit-файла systemd.
///
/// Инвариант (P0-B): пользовательское значение **не может** дописать в юнит
/// свои директивы и не может вызвать подстановку systemd:
///   * управляющий символ (в т.ч. перевод строки) — отказ, а не экранирование;
///   * обратный слэш и кавычка — экранируются внутри кавычек;
///   * `%` — спецификатор systemd (`%h`, `%i`), удваивается;
///   * `$` — подстановка переменной в ExecStart, удваивается.
pub fn unit_quote(v: &str) -> Result<String, String> {
    if v.chars().any(|c| c.is_control()) {
        return Err("управляющий символ в значении юнита".into());
    }
    Ok(v
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$"))
}

/// Имя переменной окружения допустимо для unit-файла: только префикс
/// NEXXUS_ и верхний регистр/цифры/подчёркивание.
pub fn valid_env_key(k: &str) -> bool {
    k.starts_with("NEXXUS_")
        && k.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Директивы, которые unit-файл вообще может содержать (белый список для
/// property-теста: ни одна пользовательская строка не должна породить
/// директиву вне списка).
#[cfg_attr(not(test), allow(dead_code))]
pub const ALLOWED_UNIT_DIRECTIVES: &[&str] = &[
    "Description",
    "After",
    "Wants",
    "Type",
    "WorkingDirectory",
    "Environment",
    "ExecStart",
    "Restart",
    "RestartSec",
    "TimeoutStopSec",
    "StartLimitIntervalSec",
    "StartLimitBurst",
    "NoNewPrivileges",
    "PrivateTmp",
    "WantedBy",
];

/// Собирает текст user-юнита ноды из конфигурации.
///
/// Возвращает `Err`, если значение конфига содержит управляющие символы или
/// недопустимое имя переменной: unit-файл не пишется «как получилось».
pub fn render_unit(cfg: &NodeConfig, bin: &Path, store: &Path) -> Result<String, String> {
    let mut env_lines = String::new();
    for (k, v) in crate::node_config::to_env(cfg) {
        if !valid_env_key(&k) {
            return Err(format!("недопустимое имя переменной окружения: {k}"));
        }
        env_lines.push_str(&format!("Environment=\"{k}={}\"\n", unit_quote(&v)?));
    }

    let dir = store
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());

    Ok(format!(
        "[Unit]\n\
         Description=NeXXus Storage Node (daemon nexxusd)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         StartLimitIntervalSec=300\n\
         StartLimitBurst=5\n\
         \n\
         [Service]\n\
         Type=simple\n\
         WorkingDirectory=\"{dir}\"\n\
         {env_lines}\n\
         ExecStart=\"{bin}\" \"{store}\"\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         TimeoutStopSec=30\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        dir = unit_quote(&dir)?,
        env_lines = env_lines,
        bin = unit_quote(&bin.to_string_lossy())?,
        store = unit_quote(&store.to_string_lossy())?,
    ))
}

/// Устанавливает (создаёт/обновляет) user-юнит ноды и перечитывает
/// конфигурацию systemd. Возвращает путь к записанному файлу.
pub fn install_unit(cfg: &NodeConfig) -> Result<PathBuf, String> {
    let path = node_unit_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Не удалось создать {}: {e}", parent.display()))?;
    }
    let content = render_unit(cfg, &node_binary_path(), &node_store_path())?;
    std::fs::write(&path, content).map_err(|e| format!("Не удалось записать {}: {e}", path.display()))?;
    daemon_reload()?;
    Ok(path)
}

/// `systemctl --user daemon-reload`.
pub fn daemon_reload() -> Result<(), String> {
    let status = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()
        .map_err(|e| format!("Не удалось выполнить systemctl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl daemon-reload завершился с кодом {}", status.code().unwrap_or(-1)))
    }
}

/// Включает и запускает юнит ноды (`systemctl --user enable --now`).
pub fn enable_and_start() -> Result<(), String> {
    let status = Command::new("systemctl")
        .args(["--user", "enable", "--now", NODE_UNIT_NAME])
        .status()
        .map_err(|e| format!("Не удалось выполнить systemctl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl enable --now {} завершился с кодом {}", NODE_UNIT_NAME, status.code().unwrap_or(-1)))
    }
}

/// Останавливает и выключает юнит ноды (`systemctl --user disable --now`).
pub fn disable_and_stop() -> Result<(), String> {
    let status = Command::new("systemctl")
        .args(["--user", "disable", "--now", NODE_UNIT_NAME])
        .status()
        .map_err(|e| format!("Не удалось выполнить systemctl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl disable --now {} завершился с кодом {}", NODE_UNIT_NAME, status.code().unwrap_or(-1)))
    }
}

/// Состояние юнита ноды: active / inactive / failed / not-found.
pub fn unit_state() -> String {
    let Ok(out) = Command::new("systemctl")
        .args(["--user", "is-active", NODE_UNIT_NAME])
        .output()
    else {
        return "unknown".into();
    };
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        "unknown".into()
    } else {
        text
    }
}

/// Установлен ли юнит ноды.
pub fn is_installed() -> bool {
    node_unit_path().exists()
}

/// Состояние юнита монитора: active / inactive / not-found.
///
/// Нужно, чтобы «полное отключение» понимало: если монитор под systemd,
/// его корректно останавливать через `systemctl --user stop`, а не просто
/// завершать процесс.
pub fn monitor_unit_state() -> String {
    let Ok(out) = Command::new("systemctl")
        .args(["--user", "is-active", MONITOR_UNIT_NAME])
        .output()
    else {
        return "unknown".into();
    };
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        "unknown".into()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P0-B: значение поля конфига не должно уметь дописать в unit-файл свои
    /// директивы. Управляющий символ (перевод строки) — это отказ, а не тихая
    /// подстановка: юнит в таком случае просто не пишется.
    #[test]
    fn unit_rejects_injection_via_config_value() {
        let cfg = NodeConfig {
            log_path: "/tmp/x\nExecStartPre=/bin/sh -c \"id> /tmp/pwned\"".into(),
            ..NodeConfig::default()
        };
        let res = render_unit(&cfg, Path::new("/usr/bin/nexxusd"), Path::new("/tmp/s.redb"));
        assert!(
            res.is_err(),
            "инъекция через значение конфига не отклонена:\n{}",
            res.unwrap_or_default()
        );
        assert!(
            !res.unwrap_or_default().contains("ExecStartPre"),
            "инъекция попала в unit"
        );
    }

    /// P0-B: управляющий символ отклоняется на уровне экранирования.
    #[test]
    fn unit_quote_rejects_control_chars() {
        assert!(unit_quote("a\nb").is_err());
        assert!(unit_quote("a\u{0}b").is_err());
        assert!(unit_quote("a\tb").is_err());
        assert!(unit_quote("обычное значение").is_ok());
    }

    /// P0-B: имя переменной окружения — только NEXXUS_* в верхнем регистре.
    #[test]
    fn env_key_validation() {
        assert!(valid_env_key("NEXXUS_LISTEN"));
        assert!(valid_env_key("NEXXUS_AUDITORS"));
        assert!(!valid_env_key("PATH"));
        assert!(!valid_env_key("nexxus_listen"));
        assert!(!valid_env_key("NEXXUS_EVIL;rm -rf /"));
        assert!(!valid_env_key("NEXXUS_LISTEN=x"));
    }

    /// P0-B: спецификаторы systemd (`%h`) и `$` экранируются, а не остаются
    /// живыми подстановками.
    #[test]
    fn unit_escapes_systemd_specifiers_and_dollar() {
        let cfg = NodeConfig {
            log_path: "/tmp/%h/$HOME.log".into(),
            ..NodeConfig::default()
        };
        let unit = render_unit(&cfg, Path::new("/usr/bin/nexxusd"), Path::new("/tmp/s.redb"))
            .expect("unit должен собираться");
        assert!(
            unit.contains("%%h") && unit.contains("$$HOME"),
            "спецификатор/переменная не экранированы:\n{unit}"
        );
        // «живой» `%h` (не %%h) и «живая» `$HOME` (не $$HOME) отсутствуют
        assert!(!unit.contains("=%h"), "живой спецификатор в юните:\n{unit}");
        assert!(!unit.contains("=$HOME"), "живая переменная в юните:\n{unit}");
    }

    /// P0-B property-тест: для ЛЮБОГО значения конфига unit-файл либо
    /// отклоняется (Err), либо содержит ровно одну ExecStart и ни одной
    /// директивы вне белого списка. Детерминированный цикл вместо proptest
    /// (proptest офлайн недоступен в этом workspace).
    #[test]
    fn unit_property_no_injection_for_arbitrary_values() {
        // простой LCG, чтобы не тянуть rand
        let mut seed: u64 = 0x243F_6A88_85A3_08D3;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };
        let alphabet: Vec<char> = "\n\r\t\0%h$HOME\"'\\;ExecStartPre=/bin/sh #abcXYZ019".chars().collect();
        for _ in 0..10_000 {
            let len = rnd() % 40;
            let evil: String = (0..len).map(|_| alphabet[rnd() % alphabet.len()]).collect();
            let cfg = NodeConfig {
                log_path: evil.clone(),
                spec_version: evil.clone(),
                ..NodeConfig::default()
            };
            match render_unit(&cfg, Path::new("/usr/bin/nexxusd"), Path::new("/tmp/s.redb")) {
                Err(_) => {} // управляющие символы — отказ, это норма
                Ok(unit) => {
                    let exec = unit.lines().filter(|l| l.starts_with("ExecStart=")).count();
                    assert_eq!(exec, 1, "не ровно одна ExecStart при значении {evil:?}:\n{unit}");
                    for line in unit.lines() {
                        let line = line.trim_end();
                        if line.is_empty() || line.starts_with('[') {
                            continue;
                        }
                        let directive = line.split('=').next().unwrap_or("");
                        assert!(
                            ALLOWED_UNIT_DIRECTIVES.contains(&directive),
                            "директива вне белого списка {directive:?} при значении {evil:?}:\n{unit}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn unit_file_contains_env_and_exec() {
        let cfg = NodeConfig {
            listen: "127.0.0.1:4001".into(),
            api: "127.0.0.1:4010".into(),
            auditors: vec!["aa".into(), "bb".into()],
            threshold: 1,
            tor: false,
            ..NodeConfig::default()
        };
        // Пути передаются явно: тест не закрепляет машину сборки.
        let bin = Path::new("/opt/nexxus/bin/nexxusd");
        let store = Path::new("/var/lib/nexxus/store.redb");
        let unit = render_unit(&cfg, bin, store).expect("unit");

        assert!(
            unit.contains("ExecStart=\"/opt/nexxus/bin/nexxusd\" \"/var/lib/nexxus/store.redb\""),
            "ExecStart не собран с кавычками:\n{unit}"
        );
        assert!(unit.contains("WorkingDirectory=\"/var/lib/nexxus\""));
        assert!(unit.contains("Environment=\"NEXXUS_LISTEN=127.0.0.1:4001\""));
        assert!(unit.contains("Environment=\"NEXXUS_API_ADDR=127.0.0.1:4010\""));
        assert!(unit.contains("Environment=\"NEXXUS_AUDITORS=aa,bb\""));
        assert!(unit.contains("Environment=\"NEXXUS_THRESHOLD=1\""));
        assert!(unit.contains("Environment=\"NEXXUS_TOR=0\""));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn unit_contains_every_node_env_var() {
        let unit = render_unit(&NodeConfig::default(), &node_binary_path(), &node_store_path()).expect("unit");
        for key in [
            "NEXXUS_LISTEN",
            "NEXXUS_API_ADDR",
            "NEXXUS_AUDITORS",
            "NEXXUS_THRESHOLD",
            "NEXXUS_EPOCH_SECS",
            "NEXXUS_TOR",
            "NEXXUS_LOG",
            "NEXXUS_SPECIFICATION_V",
        ] {
            assert!(unit.contains(&format!("Environment=\"{key}=")), "нет {key} в юните");
        }
    }
}
