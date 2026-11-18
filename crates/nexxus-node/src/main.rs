//! NeXXUs storage daemon (nexxusd).
//! Phase 8: full network protocol daemon — redb persistent chunk index,
//! P2P network listener (wire v3), NodeAnnounce/SmpEnvelope/EpochFinalize/PoR handlers.
//!
//! Запуск:
//!   nexxusd <store-path>
//! Переменные окружения:
//!   NEXXUS_LISTEN       — адрес P2P слушателя (по умолчанию 127.0.0.1:4001)
//!   NEXXUS_API_ADDR     — адрес локального WebSocket API (по умолчанию 127.0.0.1:4010)

use std::env;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;

use hex::encode as hex_encode;
use tokio::signal::unix::{signal, SignalKind};

mod net;
mod storage;
mod tor;
mod local_api;
mod api_auth;
mod at_rest;
mod panic;
mod identity_store;
mod cli;
mod vault;
mod seed_vault;
mod backup;
mod bundle;
mod update;
mod logging;
mod bootstrap;
mod node_config;

use crate::net::P2pNetwork;
use crate::storage::ChunkStore;
use crate::local_api::LocalApi;
use crate::identity_store::load_or_create_identity;

/// Запрет core dumps (RLIMIT_CORE=0): seed/ключи не должны попадать в дампы
/// памяти процесса на диск. Safe-обёртка `rlimit` (workspace forbids unsafe).
#[cfg(unix)]
pub fn disable_core_dumps() {
    if let Err(e) = rlimit::setrlimit(rlimit::Resource::CORE, 0, 0) {
        eprintln!("nexxusd: WARNING: setrlimit(RLIMIT_CORE, 0) failed: {e}");
    }
}

#[cfg(not(unix))]
pub fn disable_core_dumps() {}

/// S4: PIN для seed vault: `NEXXUS_SEED_PIN` env → systemd-credential `seed.pin`
/// (`$CREDENTIALS_DIRECTORY`). Возвращает None, если нигде не задан.
pub fn vault_pin_from_env_or_credential() -> Option<zeroize::Zeroizing<String>> {
    if let Ok(p) = std::env::var("NEXXUS_SEED_PIN") {
        if !p.is_empty() {
            return Some(zeroize::Zeroizing::new(p));
        }
    }
    if let Ok(dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        let p = std::path::Path::new(&dir).join("seed.pin");
        if let Ok(s) = std::fs::read_to_string(&p) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(zeroize::Zeroizing::new(t.to_string()));
            }
        }
    }
    None
}


fn main() {
    disable_core_dumps();
    // Логи arti/Tor по RUST_LOG (по умолчанию — только предупреждения nexxusd).
    #[cfg(feature = "tor")]
    {
        use tracing_subscriber::EnvFilter;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("warn,arti_client=info,tor_hsservice=info")),
            )
            .with_writer(std::io::stderr)
            .try_init();
    }
    // --- Аргументы командной строки ---
    // Подкоманды CLI (фаза 6): init/id/status/peers/peer/upload/download/
    // test-por/test-interhost/logs/benchmark — обрабатываются в cli::run.
    // Всё остальное (или `serve`) — запуск демона; позиционный аргумент —
    // путь к файлу хранилища redb (по умолчанию ~/.nexxus/store.redb).
    // S1: список команд — единый источник правды в cli::COMMANDS.
    // Неизвестный аргумент больше НЕ трактуется как путь к хранилищу:
    // демон стартовал на файле с именем команды и создавал redb-хранилище
    // (4 таких файла с открытой мнемоникой попали в репозиторий).
    let args: Vec<String> = env::args().skip(1).collect();
    let first = args.first().map(|s| s.as_str());
    if let Some(cmd) = first {
        if cli::COMMANDS.contains(&cmd) {
            cli::run(args);
            return;
        }
        // `serve` — явный запуск демона, остальные позиционные аргументы
        // допускаются только как явный путь к хранилищу.
        if cmd != "serve" && !cli::looks_like_store_path(cmd) {
            eprint!("{}", cli::usage());
            eprintln!("nexxusd: unknown command `{cmd}`");
            process::exit(2);
        }
    }
    let path = match first {
        Some("serve") => args.get(1).cloned(),
        other => other.map(|s| s.to_string()),
    }
    .unwrap_or_else(|| cli::default_store().to_string_lossy().into_owned());

    // --- Адреса слушателей ---
    // Единый конфиг с монитором: ~/.nexxus/node.conf (env перекрывает файл).
    let conf = crate::node_config::load_file();
    // NEXXUS_LISTEN — адрес для P2P соединений (не для API).
    // P1: тихий откат на дефолт при нечитаемом адресе давал монитору неверный порт —
    // логируем warn с именем ключа (значение НЕ логируем).
    let listen_addr: SocketAddr = {
        let raw = crate::node_config::cfg_or_env(&conf, "listen", "NEXXUS_LISTEN", "127.0.0.1:4001");
        raw.parse().unwrap_or_else(|_| {
            eprintln!("warn: listen (NEXXUS_LISTEN) не распарсен как SocketAddr — дефолт 127.0.0.1:4001 (значение не логируется)");
            "127.0.0.1:4001".parse().unwrap()
        })
    };

    // NEXXUS_API_ADDR — адрес для локального WebSocket API (для nexxus-desktop).
    // Дефолт 4010 единый для ноды и монитора.
    let api_addr: SocketAddr = {
        let raw = crate::node_config::cfg_or_env(
            &conf,
            "api",
            "NEXXUS_API_ADDR",
            crate::local_api::DEFAULT_API_ADDR,
        );
        raw.parse().unwrap_or_else(|_| {
            eprintln!("warn: api (NEXXUS_API_ADDR) не распарсен как SocketAddr — дефолт {} (значение не логируется)", crate::local_api::DEFAULT_API_ADDR);
            crate::local_api::DEFAULT_API_ADDR.parse().unwrap()
        })
    };

    // --- Комитет аудиторов (фаза 4): NEXXUS_AUDITORS=hex,hex,... NEXXUS_THRESHOLD=M ---
    // Без реестра и порога кворум не достигается никогда (deny-by-default).
    let auditor_keys: Vec<ed25519_dalek::VerifyingKey> = crate::node_config::cfg_or_env(&conf, "auditors", "NEXXUS_AUDITORS", "")
        .split(',')
        .filter_map(|s| hex::decode(s.trim()).ok())
        .filter_map(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .filter_map(|a| ed25519_dalek::VerifyingKey::from_bytes(&a).ok())
        .collect();
    let threshold: usize = crate::node_config::cfg_or_env(&conf, "threshold", "NEXXUS_THRESHOLD", "0")
        .parse()
        .unwrap_or(0);
    // Период epoch-цикла (секунды), для тестов можно уменьшить.
    let epoch_secs: u64 = crate::node_config::cfg_or_env(&conf, "epoch_secs", "NEXXUS_EPOCH_SECS", "300")
        .parse()
        .unwrap_or(300);

    // --- Tokio runtime ---
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    rt.block_on(async {
        // --- Хранилище чанков (redb) ---
        // Открываем persistent базу данных по указанному пути.
        let store = match ChunkStore::open(&path) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("nexxusd: failed to open store: {e}");
                process::exit(1);
            }
        };

        // NEXXUS_MAX_STORE_BYTES — user-defined disk cap стора (E2 quick win).
        // 0 (дефолт) = без лимита; put_chunk всё равно проверяет free space.
        if let Ok(v) = env::var("NEXXUS_MAX_STORE_BYTES") {
            if let Ok(bytes) = v.parse::<u64>() {
                store.set_max_store_bytes(bytes);
                if bytes > 0 {
                    eprintln!("nexxusd: store cap set to {bytes} bytes");
                }
            }
        }

        // --- Персистентная идентичность узла (фаза 2 плана) ---
        // Seed хранится в redb (таблица meta, ключ identity_mnemonic); Ed25519
        // ключ деривируется по SLIP-0010, X25519 — из seed с domain separator.
        // NodeId = SHA-256(pubkey) и поэтому стабилен между перезапусками.
        // Mnemonic печатается ровно один раз — при первом создании.
        // S4/ADR-0010: PIN для seed vault — из env или systemd-credential.
        let seed_pin = vault_pin_from_env_or_credential();
        let (node_iden, fresh_mnemonic) = load_or_create_identity(&store, seed_pin.as_ref().map(|z| z.as_str())).unwrap_or_else(|e| {
            eprintln!("nexxusd: identity load failed: {e}");
            process::exit(1);
        });
        if let Some(phrase) = &fresh_mnemonic {
            eprintln!("nexxusd: NEW identity created. Write down this 12-word mnemonic (shown only once):");
            eprintln!("  {}", phrase.as_str());
        }
        let our_id = node_iden.node_id;

        // --- Шифрование стора at rest (Phase A2): ключ из seed через HKDF ---
        // Если стор уже зашифрован — ключ валидируется; если открыт — миграция
        // всех чанков в один проход. При неверном ключе/повреждении — exit.
        let store_key = at_rest::StoreKey::derive(&node_iden.seed[..]);
        match store.enable_encryption(store_key) {
            Ok(0) => println!("nexxusd: store encryption at rest enabled (already encrypted)"),
            Ok(n) => println!("nexxusd: store encrypted at rest, {n} chunks migrated"),
            Err(e) => {
                eprintln!("nexxusd: FATAL: cannot enable store encryption: {e}");
                process::exit(1);
            }
        }

        // --- P2P сеть ---
        // Используем персистентную идентичность из стора (детерминированные
        // node_id / Ed25519 / X25519 от seed), а не случайный identity.
        // Плюс реестр аудиторов и порог M-of-N из env (deny-by-default).
        let epoch_identity = node_iden.identity.clone();
        let net = if auditor_keys.is_empty() {
            Arc::new(P2pNetwork::with_keys(
                our_id,
                node_iden.identity,
                *node_iden.x25519_secret,
                listen_addr,
                Arc::clone(&store),
            ))
        } else {
            Arc::new(P2pNetwork::with_keys_and_auditors(
                our_id,
                node_iden.identity,
                *node_iden.x25519_secret,
                listen_addr,
                Arc::clone(&store),
                auditor_keys.clone(),
                threshold,
            ))
        };

        // --- Локальное WebSocket API ---
        let api = Arc::new(LocalApi::new(Arc::clone(&net), Arc::clone(&store)));

        // BS-01: опциональный pin registry_pub для signed bootstrap-списков
        // (node.conf: bootstrap_registry_pub / env: NEXXUS_BOOTSTRAP_REGISTRY_PUB).
        let reg_pin = crate::node_config::cfg_or_env(&conf, "bootstrap_registry_pub", "NEXXUS_BOOTSTRAP_REGISTRY_PUB", "");
        if !reg_pin.is_empty() {
            api.set_bootstrap_registry_pin(Some(reg_pin));
            println!("nexxusd: bootstrap registry_pub pinned");
        }

        // --- Токен доступа к API (fail-closed): без токена API не стартует ---
        let token_path = api_auth::token_file_path();
        match api_auth::load_or_create_token(&token_path) {
            Ok(token) => {
                api.set_api_token(token);
                println!("nexxusd: API token загружен/создан, файл {}", token_path.display());
            }
            Err(e) => {
                eprintln!(
                    "nexxusd: FATAL: не удалось загрузить/создать API-токен {}: {e}. API не запускается (fail-closed).",
                    token_path.display()
                );
                process::exit(1);
            }
        }

        // --- Tor (feature `tor`, NEXXUS_TOR=0 чтобы выключить): bootstrap arti
        // и публикация onion v3 hidden service на P2P-порту; статус — в node_tor.
        //
        // Бутстрап выполняется в фоновой задаче: он занимает десятки секунд
        // (а при проблемах с сетью — минуты), и раньше блокировал запуск
        // слушателей, из-за чего порт 4010 не поднимался и монитор получал
        // "connection refused". Теперь P2P и API стартуют сразу, а статус Tor
        // обновляется асинхронно (node_tor).
        #[cfg(feature = "tor")]
        if std::env::var("NEXXUS_TOR")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true)
        {
            let api_tor = Arc::clone(&api);
            let listen_addr_tor = listen_addr;
            tokio::spawn(async move {
                match tor::TorSession::new().await {
                    Ok(mut ts) => {
                        match ts.publish_onion(listen_addr_tor).await {
                            Ok(onion) => {
                                eprintln!("nexxusd: tor onion v3 published: {onion}");
                                api_tor.set_tor_status(crate::local_api::TorStatus {
                                    enabled: true,
                                    onion_address: Some(onion),
                                    api_onion: None,
                                    connected: true,
                                })
                                .await;
                            }
                            Err(e) => {
                                eprintln!("nexxusd: tor onion publish failed: {e}");
                                api_tor.set_tor_status(crate::local_api::TorStatus {
                                    enabled: true,
                                    onion_address: None,
                                    api_onion: None,
                                    connected: false,
                                })
                                .await;
                            }
                        }
                        // F3: второй onion v3 сервис на локальный API-порт —
                        // только при явном NEXXUS_API_ONION=1 (API наружу по умолчанию закрыт).
                        let api_onion_enabled = std::env::var("NEXXUS_API_ONION")
                            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                            .unwrap_or(false);
                        if api_onion_enabled {
                            match ts.publish_api_onion(api_addr).await {
                                Ok(onion) => {
                                    eprintln!("nexxusd: tor onion v3 published for API: {onion}");
                                    api_tor.set_tor_api_onion(onion).await;
                                }
                                Err(e) => {
                                    eprintln!("nexxusd: tor api onion publish failed: {e}");
                                }
                            }
                        }
                        // Сессия живёт в API (для node_dial_onion) и в отдельной задаче до конца процесса.
                        let ts = Arc::new(ts);
                        api_tor.set_tor_session(Arc::clone(&ts)).await;
                        tokio::spawn(async move {
                            let _session = ts;
                            std::future::pending::<()>().await;
                        });
                    }
                    Err(e) => {
                        eprintln!("nexxusd: tor bootstrap failed: {e}");
                        api_tor.set_tor_status(crate::local_api::TorStatus {
                            enabled: false,
                            onion_address: None,
                            api_onion: None,
                            connected: false,
                        })
                        .await;
                    }
                }
            });
        }
        #[cfg(not(feature = "tor"))]
        {
            let _ = &api; // без feature tor статус остаётся enabled:false
        }
        // Привязываем API к сети, чтобы сеть могла регистрировать пиров в API.
        net.set_local_api(Arc::clone(&api)).await;

        println!(
            "nexxusd {} — node {} listening on {}",
            env!("CARGO_PKG_VERSION"),
            hex_encode(our_id.0),
            listen_addr
        );

        // --- Запуск задач ---
        // P2P сеть: принимает входящие соединения, обрабатывает опкоды.
        let net_clone = Arc::clone(&net);
        let p2p_task = tokio::spawn(async move {
            if let Err(e) = net_clone.run().await {
                eprintln!("nexxusd: network error: {e}");
                process::exit(1);
            }
        });

        // Локальное WebSocket API: принимает соединения от nexxus-desktop.
        let epoch_api = Arc::clone(&api);
        let api_task = tokio::spawn(async move {
            if let Err(e) = api.run(api_addr).await {
                eprintln!("nexxusd: API error: {e}");
                process::exit(1);
            }
        });

        // --- Epoch-цикл (фаза 4): строим merkle root по сторy, подписываем
        // EpochFinalize, рассылаем известным пирам и обновляем node_epoch.
        let epoch_store = Arc::clone(&store);
        let epoch_net = Arc::clone(&net);
        let epoch_task = tokio::spawn(async move {
            let mut epoch_number: u64 = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(epoch_secs)).await;
                epoch_number += 1;
                let hashes = epoch_store.list_chunk_hashes().unwrap_or_default();
                let leaves: Vec<[u8; 32]> = hashes.iter().map(|h| h.0).collect();
                let root = nexxus_core::merkle::merkle_root(&leaves);
                let total_bytes: u64 = hashes.len() as u64 * 16384;
                let msg = nexxus_core::epoch::epoch_signing_bytes(epoch_number, &root, total_bytes);
                let sig = epoch_identity.sign(&msg);
                let finalize = nexxus_core::wire::payloads::EpochFinalize {
                    epoch_number,
                    merkle_root: root,
                    total_bytes,
                    signatures: vec![nexxus_core::wire::payloads::CommitteeSig {
                        pubkey: epoch_identity.verifying_key.to_bytes(),
                        signature: sig,
                    }],
                };
                if let Ok(vr) =
                    nexxus_core::epoch::verify_epoch_finalize(&finalize, &auditor_keys, threshold)
                {
                    epoch_api
                        .set_epoch_info(crate::local_api::EpochInfo {
                            epoch_number,
                            merkle_root: hex_encode(root),
                            total_bytes,
                            signature_count: vr.signatures_valid,
                            threshold,
                            quorum_met: vr.quorum_met,
                        })
                        .await;
                    if vr.quorum_met {
                        let _ = epoch_store.put_meta(
                            "last_epoch",
                            format!("{{\"epoch_number\":{epoch_number}}}").as_bytes(),
                        );
                    }
                }
                for p in epoch_net.known_peers().await {
                    let _ = epoch_net.send_epoch_finalize(p.addr, &finalize).await;
                }
            }
        });

        // --- Обработка сигналов завершения ---
        // Корректно завершаем по SIGINT (Ctrl+C) или SIGTERM.
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT");
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM");

        tokio::select! {
            _ = p2p_task => {
                eprintln!("nexxusd: P2P task exited");
            }
            _ = api_task => {
                eprintln!("nexxusd: API task exited");
            }
            _ = epoch_task => {
                eprintln!("nexxusd: epoch task exited");
            }
            _ = sigint.recv() => {
                eprintln!("nexxusd: received SIGINT, shutting down");
            }
            _ = sigterm.recv() => {
                eprintln!("nexxusd: received SIGTERM, shutting down");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn core_dumps_disabled() {
        super::disable_core_dumps();
        let (cur, _max) = rlimit::getrlimit(rlimit::Resource::CORE).unwrap();
        assert_eq!(cur, 0, "RLIMIT_CORE должен быть 0 после disable_core_dumps");
    }
}
