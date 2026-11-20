//! CLI subcommands (plan phase 6). Hand-rolled arg parsing — no extra deps.
//!
//!   nexxusd serve [store-path]        — daemon (default subcommand)
//!   nexxusd init [--mnemonic "..."] [store-path]
//!   nexxusd id [store-path]
//!   nexxusd status | peers | peer add <IP:PORT>
//!   nexxusd upload <file> | download <root-hex> <out>
//!   nexxusd test-por | test-interhost <IP:PORT>
//!   nexxusd logs [-n N] | benchmark

use std::env;
use std::path::PathBuf;
use std::process;
use std::time::Instant;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Единый источник правды по CLI-командам (аудит S1).
///
/// Раньше список команд жил в `main.rs` (`CLI_CMDS`) и не совпадал с
/// диспетчером ниже: `doctor`, `backup`, `backups`, `restore`, `--help`
/// в него не попадали. Первый аргумент вне списка трактовался как путь к
/// хранилищу, и демон стартовал на файле с именем команды — в репозиторий
/// попали четыре `redb`-хранилища (`--help`, `light`, `update`, `doctor`)
/// с открытой мнемоникой внутри.
///
/// Теперь `main.rs` берёт список отсюда, а неизвестный аргумент печатает
/// usage и завершает процесс с кодом 2.
pub const COMMANDS: &[&str] = &[
    "init",
    "id",
    "status",
    "peers",
    "peer",
    "upload",
    "download",
    "test-por",
    "test-interhost",
    "logs",
    "benchmark",
    "update",
    "light",
    "doctor",
    "backup",
    "backups",
    "restore",
    "--version",
    "--help",
    "help",
];

/// Usage-текст CLI (печатается на неизвестную команду и на `--help`).
pub fn usage() -> String {
    let mut s = String::from("Usage: nexxusd <command> [args]\n\nCommands:\n");
    for c in COMMANDS {
        s.push_str("  ");
        s.push_str(c);
        s.push('\n');
    }
    s.push_str("\nStore path: nexxusd serve [store-path] (по умолчанию ~/.nexxus/store.redb)\n");
    s
}

pub fn default_store() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".nexxus").join("store.redb")
}

fn api_addr() -> String {
    env::var("NEXXUS_API_ADDR").unwrap_or_else(|_| "127.0.0.1:4010".to_string())
}

/// Merkle root файла локально: 16 KiB чанки, zero-pad, SHA-256 leaves.
/// Тот же алгоритм, что в ноде и в nexxus-wasm — light client сверяет root сам.
fn merkle_root_of_file(data: &[u8]) -> [u8; 32] {
    let chunks = nexxus_core::chunk::slice(data);
    let leaves: Vec<[u8; 32]> = chunks
        .iter()
        .map(|c| {
            let mut padded = c.clone();
            padded.resize(nexxus_core::chunk::CHUNK_SIZE, 0);
            Sha256::digest(&padded).into()
        })
        .collect();
    nexxus_core::merkle::merkle_root(&leaves)
}

/// Двухуровневый root как у ноды (vault.rs): чанк → seal(key, i, chunk) целиком
/// (случайный nonce) → RS(shifротекст) → sha256(shard) → chunk_root;
/// root = merkle(chunk_roots). Нужен per-file ключ из манифеста.
fn merkle_root_of_file_sealed(data: &[u8], key: &[u8; 32]) -> Result<[u8; 32], String> {
    let chunks = nexxus_core::chunk::slice(data);
    let mut chunk_roots = Vec::with_capacity(chunks.len());
    for (i, plain) in chunks.iter().enumerate() {
        let sealed = nexxus_core::chunk::ChunkAead::seal(key, i as u64, plain)
            .map_err(|e| e.to_string())?;
        let shards = nexxus_core::rs::encode(&sealed);
        let mut shard_hashes = Vec::with_capacity(shards.len());
        for shard in shards.iter() {
            shard_hashes.push(Sha256::digest(shard).into());
        }
        chunk_roots.push(nexxus_core::merkle::merkle_root(&shard_hashes));
    }
    Ok(nexxus_core::merkle::merkle_root(&chunk_roots))
}

/// One JSON-RPC call over WebSocket to the local daemon.
///
/// Сначала выполняет `auth` с токеном из `~/.nexxus/api.token`
/// (или `NEXXUS_API_TOKEN_FILE`), затем — сам запрос на том же соединении.
pub async fn ws_call(method: &str, params: Value) -> Result<Value, String> {
    let url = format!("ws://{}", api_addr());
    let (ws, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .map_err(|e| format!("connect {url}: {e} (is `nexxusd serve` running?)"))?;
    let (mut write, mut read) = ws.split();

    // --- auth handshake ---
    let token = crate::api_auth::load_token(&crate::api_auth::token_file_path())
        .map_err(|e| format!("read API token: {e}"))?
        .ok_or_else(|| "API token file is empty/missing — restart nexxusd".to_string())?;
    let auth_req = serde_json::to_string(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "auth", "params": {"token": token},
    }))
    .unwrap();
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(auth_req))
        .await
        .map_err(|e| format!("send auth: {e}"))?;
    while let Some(msg) = read.next().await {
        if let Ok(tokio_tungstenite::tungstenite::Message::Text(t)) = msg {
            let v: Value = serde_json::from_str(&t).map_err(|e| format!("bad json: {e}"))?;
            if let Some(err) = v.get("error") {
                if !err.is_null() {
                    return Err(format!("auth failed: {err}"));
                }
            }
            break;
        }
    }

    let req = serde_json::to_string(&json!({
        "jsonrpc": "2.0", "id": 2, "method": method, "params": params,
    }))
    .unwrap();
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(req))
        .await
        .map_err(|e| format!("send: {e}"))?;
    while let Some(msg) = read.next().await {
        if let Ok(tokio_tungstenite::tungstenite::Message::Text(t)) = msg {
            let v: Value = serde_json::from_str(&t).map_err(|e| format!("bad json: {e}"))?;
            if let Some(err) = v.get("error") {
                if !err.is_null() {
                    return Err(err.to_string());
                }
            }
            return Ok(v.get("result").cloned().unwrap_or(Value::Null));
        }
    }
    Err("connection closed before response".to_string())
}

/// E6 light client: тонкий CLI без запуска демона.
/// Поддерживает --api host:port и --token-file path (иначе env/дефолты).
async fn cmd_light(rest: &[String]) -> i32 {
    // парсим флаги
    let mut api: Option<String> = None;
    let mut token_file: Option<String> = None;
    let mut key_hex: Option<String> = None;
    let mut pos = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--api" => {
                if let Some(v) = rest.get(i + 1) {
                    api = Some(v.clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--token-file" => {
                if let Some(v) = rest.get(i + 1) {
                    token_file = Some(v.clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--key" => {
                if let Some(v) = rest.get(i + 1) {
                    key_hex = Some(v.clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            other => {
                pos.push(other.to_string());
                i += 1;
            }
        }
    }
    if let Some(a) = api {
        env::set_var("NEXXUS_API_ADDR", a);
    }
    if let Some(t) = token_file {
        env::set_var("NEXXUS_API_TOKEN_FILE", t);
    }
    match pos.first().map(|s| s.as_str()) {
        Some("status") => print_result(ws_call("node_status", json!({})).await),
        Some("chunks") => print_result(ws_call("node_chunks", json!({})).await),
        Some("peers") => print_result(ws_call("node_peers", json!({})).await),
        Some("get") => match (pos.get(1), pos.get(2)) {
            (Some(root), Some(out)) => {
                // E6 light client: скачиваем через ноду, затем САМИ проверяем
                // merkle root файла локально — нода не является доверенным
                // источником целостности.
                let res = ws_call("node_download", json!({ "root": root, "out": out })).await;
                match res {
                    Ok(v) if v.get("error").is_none() => {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                        match std::fs::read(out) {
                            Ok(data) => {
                                // Верификация: с --key — двухуровневый root как у ноды;
                                // без ключа — одноуровневый (должен совпасть, если нода
                                // считает root так же; иначе FAIL — честно).
                                let local_hex = match &key_hex {
                                    Some(kh) => match hex::decode(kh) {
                                        Ok(kb) if kb.len() == 32 => {
                                            let key: [u8; 32] = kb.try_into().unwrap();
                                            match merkle_root_of_file_sealed(&data, &key) {
                                                Ok(r) => hex::encode(r),
                                                Err(e) => {
                                                    eprintln!("light verify: seal error: {e}");
                                                    return 3;
                                                }
                                            }
                                        }
                                        _ => {
                                            eprintln!("light verify: --key должен быть 64 hex-символа");
                                            return 3;
                                        }
                                    },
                                    None => hex::encode(merkle_root_of_file(&data)),
                                };
                                if local_hex == root.to_lowercase() {
                                    println!("light verify: OK — merkle root {} совпадает", local_hex);
                                    0
                                } else {
                                    eprintln!(
                                        "light verify: FAIL — локальный root {} != запрошенный {}",
                                        local_hex, root
                                    );
                                    3
                                }
                            }
                            Err(e) => {
                                eprintln!("light verify: не удалось прочитать {out}: {e}");
                                3
                            }
                        }
                    }
                    other => {
                        println!("{}", serde_json::to_string_pretty(&other).unwrap_or_default());
                        1
                    }
                }
            }
            _ => {
                eprintln!("usage: nexxusd light get <root-hex> <out-file> [--key <hex64>]");
                2
            }
        },
        Some("pin") => match pos.get(1) {
            Some(h) => print_result(ws_call("node_chunk_pin", json!({ "hash": h })).await),
            None => {
                eprintln!("usage: nexxusd light pin <hash-hex>");
                2
            }
        },
        Some("manifest") => match pos.get(1) {
            Some(root) => print_result(ws_call("node_manifest_get", json!({ "root": root })).await),
            None => {
                eprintln!("usage: nexxusd light manifest <root-hex>");
                2
            }
        },
        _ => {
            eprintln!("usage: nexxusd light status | chunks | peers | get <root-hex> <out> [--key hex64] | pin <hash> | manifest <root>  [--api host:port] [--token-file path]");
            2
        }
    }
}

fn print_result(r: Result<Value, String>) -> i32 {
    match r {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            0
        }
        Err(e) => fail(&e),
    }
}

/// S1: путь к хранилищу распознаётся строго — только `*.redb` или путь с `/`.
/// Всё остальное считается командой; неизвестная команда → usage + код 2.
pub fn looks_like_store_path(arg: &str) -> bool {
    arg.ends_with(".redb") || arg.contains('/')
}

fn fail(msg: &str) -> i32 {
    eprintln!("error: {msg}");
    1
}

/// Entry point for CLI subcommands. Builds its own tokio runtime.
pub fn run(args: Vec<String>) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let code = rt.block_on(async_main(args));
    process::exit(code);
}

async fn async_main(args: Vec<String>) -> i32 {
    let cmd = args[0].clone();
    let rest: Vec<String> = args[1..].to_vec();
    match cmd.as_str() {
        "init" => cmd_init(&rest),
        "id" => cmd_id(&rest).await,
        "status" => print_result(ws_call("node_status", json!({})).await),
        // E6 light client: тонкий режим без демона — только WS к ноде.
        // nexxusd light status | get <root-hex> <out> | pin <hash> | chunks
        // api/token: --api host:port / --token-file path, либо NEXXUS_API_ADDR / NEXXUS_API_TOKEN_FILE
        "light" => cmd_light(&rest).await,
        "--version" => {
            println!("nexxusd {}", env!("CARGO_PKG_VERSION"));
            0
        }
        "--help" => {
            print!("{}", usage());
            0
        }
        "help" => {
            print!("{}", usage());
            0
        }
        "peers" => print_result(ws_call("node_peers", json!({})).await),
        "peer" => match rest.first().map(|s| s.as_str()) {
            Some("add") => match rest.get(1) {
                Some(addr) => print_result(ws_call("node_connect", json!({ "addr": addr })).await),
                None => {
                    eprintln!("usage: nexxusd peer add <IP:PORT>");
                    2
                }
            },
            Some("dial-onion") => match rest.get(1) {
                Some(addr) => {
                    print_result(ws_call("node_dial_onion", json!({ "addr": addr })).await)
                }
                None => {
                    eprintln!("usage: nexxusd peer dial-onion <xxxx.onion:PORT>");
                    2
                }
            },
            _ => {
                eprintln!("usage: nexxusd peer add <IP:PORT> | nexxusd peer dial-onion <xxxx.onion:PORT>");
                2
            }
        },
        "upload" => match rest.first() {
            Some(f) => {
                let abs = std::fs::canonicalize(f).unwrap_or_else(|_| PathBuf::from(f));
                print_result(ws_call("node_upload", json!({ "path": abs.display().to_string() })).await)
            }
            None => {
                eprintln!("usage: nexxusd upload <file>");
                2
            }
        },
        "download" => match (rest.first(), rest.get(1)) {
            (Some(root), Some(out)) => {
                print_result(ws_call("node_download", json!({ "root": root, "out": out })).await)
            }
            _ => {
                eprintln!("usage: nexxusd download <root-hex> <out-file>");
                2
            }
        },
        "test-por" => print_result(ws_call("node_por", json!({})).await),
        "test-interhost" => match rest.first() {
            Some(addr) => {
                print_result(ws_call("node_test_interhost", json!({ "addr": addr })).await)
            }
            None => {
                eprintln!("usage: nexxusd test-interhost <IP:PORT>");
                2
            }
        },
        "logs" => cmd_logs(&rest),
        "benchmark" => cmd_benchmark(),
        "doctor" => cmd_doctor(&rest),
        "update" => cmd_update(&rest),
        "backup" => cmd_backup(&rest),
        "backups" => cmd_backups(&rest),
        "restore" => cmd_restore(&rest),
        other => {
            eprintln!("unknown command: {other}");
            2
        }
    }
}

fn cmd_update(rest: &[String]) -> i32 {
    // G4: nexxusd update [--check] [--url <release-url>]
    // --check: скачать и проверить подпись, не заменяя бинарник.
    let mut check_only = false;
    let mut url = crate::update::DEFAULT_RELEASE_URL.to_string();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--check" => check_only = true,
            "--url" => {
                if let Some(u) = rest.get(i + 1) {
                    url = u.clone();
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    println!("nexxusd update: downloading {url} …");
    let (bytes, sig) = match crate::update::download(&url) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("update: download failed: {e}");
            return 1;
        }
    };
    if let Err(e) = crate::update::verify_release(&bytes, &sig) {
        eprintln!("update: {e} — бинарник НЕ заменён");
        return 1;
    }
    println!("update: signature OK ({} bytes)", bytes.len());
    // UPD-02: anti-rollback — кандидат должен быть строго новее текущей версии.
    match crate::update::check_not_downgrade(&bytes) {
        Ok(v) => println!("update: candidate version {v} > current {} — OK", env!("CARGO_PKG_VERSION")),
        Err(e) => {
            eprintln!("update: {e} — бинарник НЕ заменён");
            return 1;
        }
    }
    if check_only {
        println!("update --check: OK, бинарник не менялся");
        return 0;
    }
    let current = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("nexxusd"));
    match crate::update::install_update(&bytes, &sig, &current) {
        Ok(p) => {
            println!("update: installed to {} — перезапустите демон", p.display());
            0
        }
        Err(e) => {
            eprintln!("update: install failed (rollback выполнен): {e}");
            1
        }
    }
}

fn open_store(rest: &[String]) -> Result<(PathBuf, crate::storage::ChunkStore), String> {
    let path = rest
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .unwrap_or_else(default_store);
    if let Some(p) = path.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let db = crate::storage::ChunkStore::open(&path).map_err(|e| e.to_string())?;
    Ok((path, db))
}

/// `nexxusd doctor [store]` — health report: perms, chunks, merkle root,
/// encryption flag, identity, seed vault, backup count, problems.
fn cmd_doctor(rest: &[String]) -> i32 {
    let positional: Vec<String> = rest.iter().filter(|a| !a.starts_with('-')).cloned().collect();
    // Чек-лист аудита (п.3): doctor НЕ должен ничего создавать — открываем
    // только существующий стор, иначе reported problem + exit 1.
    let path = positional
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(default_store);
    let (_path, db) = match crate::storage::ChunkStore::open_existing(&path) {
        Ok(db) => (path, db),
        Err(e) => {
            eprintln!("nexxusd doctor: {e} (файл не создан)");
            return 1;
        }
    };
    let report = crate::backup::doctor(&db);
    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
    if report.problems.is_empty() {
        0
    } else {
        eprintln!("problems: {}", report.problems.len());
        1
    }
}

/// `nexxusd backup [store]` — snapshot the store into <dir>/backups/<ts>/.
fn cmd_backup(rest: &[String]) -> i32 {
    let positional: Vec<String> = rest.iter().filter(|a| !a.starts_with('-')).cloned().collect();
    let (_path, db) = match open_store(&positional) {
        Ok(x) => x,
        Err(e) => return fail(&e),
    };
    match crate::backup::backup_store(&db) {
        Ok(m) => {
            println!("{}", serde_json::to_string_pretty(&m).unwrap_or_default());
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

/// `nexxusd backups [store]` — list backups with verification status.
fn cmd_backups(rest: &[String]) -> i32 {
    let positional: Vec<String> = rest.iter().filter(|a| !a.starts_with('-')).cloned().collect();
    let (_path, db) = match open_store(&positional) {
        Ok(x) => x,
        Err(e) => return fail(&e),
    };
    match crate::backup::list_backups(&db) {
        Ok(list) => {
            for m in &list {
                let (_, ok, detail) = crate::backup::verify_backup(&db, &m.name).unwrap_or((m.clone(), false, "err".into()));
                println!("{}  chunks={}  sha256={}  verified={}  {}", m.name, m.chunk_count, &m.sha256[..12], ok, detail);
            }
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

/// `nexxusd restore <name> [store]` — VERIFIED swap of a backup over the store.
/// Only safe with the daemon stopped (the API never overwrites a live store).
fn cmd_restore(rest: &[String]) -> i32 {
    let positional: Vec<String> = rest.iter().filter(|a| !a.starts_with('-')).cloned().collect();
    let Some(name) = positional.first() else {
        eprintln!("usage: nexxusd restore <backup-name> [store-path]");
        eprintln!("warning: stop the daemon first — this overwrites the live store file");
        return 2;
    };
    let store_pos: Vec<String> = positional[1..].to_vec();
    let (path, _db) = match open_store(&store_pos) {
        Ok(x) => x,
        Err(e) => return fail(&e),
    };
    drop(_db);
    match crate::backup::swap_backup(&path, name) {
        Ok(p) => {
            println!("restored {name} -> {}", p.display());
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_init(rest: &[String]) -> i32 {
    let mut mnemonic: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let a = &rest[i];
        if a == "--mnemonic" {
            mnemonic = rest.get(i + 1).cloned();
            i += 2;
        } else if let Some(v) = a.strip_prefix("--mnemonic=") {
            mnemonic = Some(v.to_string());
            i += 1;
        } else if !a.starts_with('-') {
            positional.push(a.clone());
            i += 1;
        } else {
            i += 1;
        }
    }
    let (path, db) = match open_store(&positional) {
        Ok(x) => x,
        Err(e) => return fail(&e),
    };
    match crate::identity_store::init_identity(&db, mnemonic.as_deref(), crate::vault_pin_from_env_or_credential().as_ref().map(|z| z.as_str())) {
        Ok((iden, created)) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "store": path.display().to_string(),
                    "node_id": hex::encode(iden.node_id.0),
                    "ed25519_pub": hex::encode(iden.identity.verifying_key.to_bytes()),
                    "x25519_pub": hex::encode(crate::identity_store::x25519_pub(&iden.x25519_secret)),
                    "mnemonic": created.as_ref().map(|z| z.as_str()),
                }))
                .unwrap()
            );
            if created.is_some() {
                eprintln!("note: the mnemonic is shown once — back it up; it lives in the redb meta table");
            }
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

async fn cmd_id(rest: &[String]) -> i32 {
    let path = rest
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .unwrap_or_else(default_store);
    match crate::storage::ChunkStore::open(&path) {
        Ok(db) => match crate::identity_store::load_or_create_identity(&db, crate::vault_pin_from_env_or_credential().as_ref().map(|z| z.as_str())) {
            Ok((iden, _)) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "store": path.display().to_string(),
                        "source": "store",
                        "node_id": hex::encode(iden.node_id.0),
                        "ed25519_pub": hex::encode(iden.identity.verifying_key.to_bytes()),
                        "x25519_pub": hex::encode(crate::identity_store::x25519_pub(&iden.x25519_secret)),
                    }))
                    .unwrap()
                );
                0
            }
            Err(e) => fail(&e.to_string()),
        },
        Err(e) => {
            // Store is locked (a daemon holds it) — ask the running daemon.
            match ws_call("node_status", json!({})).await {
                Ok(s) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "store": path.display().to_string(),
                            "source": "daemon (store locked: daemon is running)",
                            "note": e.to_string(),
                            "node_id": s["node_id"],
                            "ed25519_pub": s["ed25519_pub"],
                            "x25519_pub": s["x25519_pub"],
                        }))
                        .unwrap()
                    );
                    0
                }
                Err(e2) => fail(&format!(
                    "cannot open {}: {e}; daemon not reachable either: {e2}",
                    path.display()
                )),
            }
        }
    }
}

fn cmd_logs(rest: &[String]) -> i32 {
    let mut n = 50usize;
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == "-n" {
            if let Some(v) = rest.get(i + 1) {
                n = v.parse().unwrap_or(n);
            }
            i += 2;
        } else if let Some(v) = rest[i].strip_prefix("-n") {
            n = v.parse().unwrap_or(n);
            i += 1;
        } else {
            i += 1;
        }
    }
    let log = env::var("NEXXUS_LOG")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".nexxus").join("nexxusd.log")
        });
    match std::fs::read_to_string(&log) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(n);
            for l in &lines[start..] {
                println!("{l}");
            }
            0
        }
        Err(_) => fail(&format!(
            "no log file at {} — run the daemon with output redirected, e.g. `nexxusd serve 2>>{}`",
            log.display(),
            log.display()
        )),
    }
}

fn cmd_benchmark() -> i32 {
    let dir = default_store()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(".nexxus-bench.tmp");
    let mb: usize = 64;
    let block = vec![0xABu8; 1024 * 1024];
    let t = Instant::now();
    {
        use std::io::Write;
        let mut f = match std::fs::File::create(&path) {
            Ok(f) => f,
            Err(e) => return fail(&e.to_string()),
        };
        for _ in 0..mb {
            if let Err(e) = f.write_all(&block) {
                return fail(&e.to_string());
            }
        }
        if let Err(e) = f.sync_all() {
            return fail(&e.to_string());
        }
    }
    let write_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    if let Err(e) = std::fs::read(&path) {
        return fail(&e.to_string());
    }
    let read_s = t.elapsed().as_secs_f64();
    let _ = std::fs::remove_file(&path);
    let leaves: Vec<[u8; 32]> = (0..4096u32)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(i.to_be_bytes());
            h.finalize().into()
        })
        .collect();
    let t = Instant::now();
    let root = nexxus_core::merkle::merkle_root(&leaves);
    let merkle_ms = t.elapsed().as_millis() as u64;
    let total = (mb * 1024 * 1024) as f64;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "bytes": mb * 1024 * 1024,
            "write_mbps": (total / write_s / 1e6) as u64,
            "read_mbps": (total / read_s / 1e6) as u64,
            "merkle_4096_leaves_ms": merkle_ms,
            "merkle_root": hex::encode(root),
        }))
        .unwrap()
    );
    0
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;

    /// S1: список COMMANDS и диспетчер не должны разъезжаться.
    /// Иначе неизвестный аргумент снова станет путём к хранилищу.
    #[test]
    fn commands_list_covers_dispatcher() {
        let src = include_str!("cli.rs");
        for cmd in COMMANDS {
            assert!(
                src.contains(&format!("\"{cmd}\" =>")),
                "команда `{cmd}` есть в COMMANDS, но её нет в диспетчере"
            );
        }
    }

    /// S1: неизвестный первый аргумент не должен выглядеть как путь к хранилищу.
    #[test]
    fn store_path_detection_is_strict() {
        assert!(looks_like_store_path("/home/u/store.redb"));
        assert!(looks_like_store_path("store.redb"));
        assert!(looks_like_store_path("data/store.redb"));
        assert!(!looks_like_store_path("doctor"));
        assert!(!looks_like_store_path("--help"));
        assert!(!looks_like_store_path("light"));
        assert!(!looks_like_store_path("update"));
        assert!(!looks_like_store_path("backup"));
        assert!(!looks_like_store_path("backups"));
        assert!(!looks_like_store_path("restore"));
    }
}
