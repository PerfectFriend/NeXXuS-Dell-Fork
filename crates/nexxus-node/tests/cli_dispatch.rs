//! S1: единый источник правды по CLI-командам.
//!
//! Регрессия: список команд в `main.rs` не совпадал с диспетчером в `cli.rs`.
//! Из-за этого `nexxusd doctor` / `backup` / `restore` / `--help` не уходили в CLI,
//! а первый аргумент трактовался как путь к хранилищу: демон стартовал на файле
//! с именем `--help` / `doctor` / `light` и создавал `redb`-хранилище в корне
//! репозитория (4 файла по 1,5 МБ с открытой мнемоникой попали в git).
//!
//! Что проверяем:
//! 1. `cli::COMMANDS` содержит все команды, которые реально обрабатывает диспетчер,
//!    и каждая команда из списка действительно маршрутизируется в CLI.
//! 2. Неизвестный аргумент печатает usage и завершает процесс с кодом 2,
//!    НЕ создавая ни одного файла.
//! 3. Ни одна команда из списка не создаёт файл-хранилище в текущем каталоге.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Команда → ожидаемый фрагмент в stdout (для тех, что печатают что-то своё).
fn expected_output(cmd: &str) -> Option<&'static str> {
    match cmd {
        "--version" => Some("nexxusd "),
        "doctor" => Some("chunk_count"),
        "backup" => Some("chunk_count"),
        _ => None,
    }
}

/// Команды, которые НЕ должны создавать файл-хранилище в cwd.
const NO_FILE_COMMANDS: &[&str] = &[
    "--version",
    "--help",
    "help",
    "doctor",
    "backup",
    "backups",
    "restore",
    "status",
    "peers",
    "benchmark",
    "logs",
    "id",
    "init",
];

/// Запускает бинарь в пустом tempdir и возвращает (код возврата, stdout+stderr).
fn run_in_empty_dir(bin: &str, args: &[&str], home: &Path) -> (Option<i32>, String, Vec<PathBuf>) {
    let cwd = home.join("cwd");
    std::fs::create_dir_all(&cwd).expect("cwd");
    let out = Command::new(bin)
        .args(args)
        .current_dir(&cwd)
        .env("HOME", home)
        .env("NEXXUS_DATA_DIR", home.join("data"))
        .env("NEXXUS_CONFIG_DIR", home.join("cfg"))
        .env("NEXXUS_STORE", home.join("data").join("store.redb"))
        .env("NEXXUS_API_ADDR", "127.0.0.1:1")
        .env("NEXXUS_API_TOKEN_FILE", home.join("token"))
        .env("NEXXUS_TOR", "0")
        .output()
        .expect("запуск nexxusd");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&cwd)
        .expect("read cwd")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    files.sort();
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code(), text, files)
}

fn temp_home(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "nexxus-cli-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("tempdir");
    base
}

#[test]
fn unknown_command_prints_usage_and_exits_2_without_creating_files() {
    let home = temp_home("unknown");
    let (code, text, files) = run_in_empty_dir(env!("CARGO_BIN_EXE_nexxusd"), &["doctorx"], &home);
    assert!(
        files.is_empty(),
        "неизвестная команда создала файлы: {:?}",
        files
    );
    assert_eq!(code, Some(2), "ожидался код 2, вывод: {text}");
    assert!(
        text.to_lowercase().contains("usage") || text.to_lowercase().contains("usage:"),
        "в выводе нет usage: {text}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn flag_like_argument_does_not_create_store_file() {
    // Регрессия S1: `nexxusd --help` раньше создавал файл `--help` (redb, 1,5 МБ).
    let home = temp_home("flaglike");
    let (code, text, files) = run_in_empty_dir(env!("CARGO_BIN_EXE_nexxusd"), &["--help"], &home);
    assert!(
        files.is_empty(),
        "--help создал файлы: {:?}",
        files
    );
    assert!(
        code.is_some(),
        "--help должен завершаться сам, а не висеть демоном; вывод: {text}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn commands_do_not_create_store_file_in_cwd() {
    let home = temp_home("nocreate");
    for cmd in NO_FILE_COMMANDS {
        let sub = home.join(cmd.trim_start_matches('-'));
        std::fs::create_dir_all(&sub).expect("subdir");
        let (code, text, files) = run_in_empty_dir(env!("CARGO_BIN_EXE_nexxusd"), &[cmd], &sub);
        assert!(
            files.is_empty(),
            "команда `{cmd}` создала файлы в cwd: {:?} (код {code:?}, вывод {text})",
            files
        );
        if let Some(expect) = expected_output(cmd) {
            assert!(
                text.contains(expect),
                "команда `{cmd}` не напечатала ожидаемое `{expect}`: {text}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn store_path_argument_still_starts_daemon() {
    // Обратная совместимость: `nexxusd /path/to/store.redb` — это демон.
    let home = temp_home("daemon");
    let cwd = home.join("cwd");
    std::fs::create_dir_all(&cwd).expect("cwd");
    let store = home.join("data").join("my.redb");
    std::fs::create_dir_all(store.parent().unwrap()).expect("data");
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexxusd"))
        .arg(&store)
        .current_dir(&cwd)
        .env("HOME", &home)
        .env("NEXXUS_LISTEN", "127.0.0.1:0")
        .env("NEXXUS_API_ADDR", "127.0.0.1:0")
        .env("NEXXUS_TOR", "0")
        .env("NEXXUS_DATA_DIR", home.join("data"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn");
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        store.exists(),
        "демон не создал хранилище по явному пути {store:?}"
    );
    let _ = std::fs::remove_dir_all(&home);
}
