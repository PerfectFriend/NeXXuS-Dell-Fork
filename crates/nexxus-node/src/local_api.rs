//! Local WebSocket API for the NeXXus desktop monitor application.
//! Listens on 127.0.0.1:4010 (configurable via NEXXUS_API_ADDR) and speaks
//! JSON-RPC 2.0 over WebSocket so `nexxus-desktop` can query node status,
//! peers, chunks, SMP history, Epoch finalize, and Tor state.
//
//! Протокол:
//!   - Клиент подключается по ws://127.0.0.1:4010
//!   - Отправляет JSON-RPC 2.0 запрос в виде текстового WebSocket сообщения
//!   - Сервер отвечает JSON-RPC 2.0 ответом и закрывает соединение
//!   - Каждый запрос = новое соединение (простая модель для MVP)

use crate::identity_store::{identity_status, import_mnemonic, read_mnemonic};
use crate::net::network::{InboundSmp, P2pNetwork};
use crate::storage::ChunkStore;
use curve25519_dalek::MontgomeryPoint;
use nexxus_core::{
    error::NexxusError,
    types::{ChunkHash, NodeId},
    wire::payloads::SmpEnvelope,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::accept_async_with_config;
use tokio_tungstenite::tungstenite::Message;

/// Default bind address for the local API WebSocket server.
///
/// API-01 hardening: hard caps on WebSocket frame/message sizes (a local
/// client must not be able to exhaust memory with one giant frame) and on
/// the number of concurrent WS connections.
pub const MAX_WS_MESSAGE_SIZE: usize = 1 << 20; // 1 MiB per message
pub const MAX_WS_FRAME_SIZE: usize = 1 << 20; // 1 MiB per frame
pub const MAX_WS_CONNECTIONS: usize = 16;
pub const DEFAULT_API_ADDR: &str = "127.0.0.1:4010";

/// Information about a connected peer (for the local API).
#[derive(Debug, Clone, Serialize)]
pub struct ConnectedPeerInfo {
    pub node_id: String,
    pub addr: String,
    pub direction: String, // "inbound" or "outbound"
    pub connected_at: u64, // unix seconds
}

/// Information about an SMP message (for the local API).
#[derive(Debug, Clone, Serialize)]
pub struct SmpMessageInfo {
    pub id: String,
    pub direction: String, // "sent" or "received"
    pub sender_node_id: String, // hex; empty for "sent"
    pub recipient_node_id: String,
    pub payload_size: usize,
    pub status: String, // "sent", "delivered", "failed", "pending"
    pub timestamp: u64,
}

/// Epoch finalize status (for the local API).
#[derive(Debug, Clone, Serialize)]
pub struct EpochInfo {
    pub epoch_number: u64,
    pub merkle_root: String,
    pub total_bytes: u64,
    pub signature_count: usize,
    pub threshold: usize,
    pub quorum_met: bool,
}

/// Node status (for the local API).
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub node_id: String,
    pub version: String,
    pub listen_addr: String,
    pub bound_addr: Option<String>,
    pub uptime_ms: u128,
    pub peer_count: usize,
    pub tor_enabled: bool,
    pub paused: bool,
    pub x25519_pub: String,
    pub ed25519_pub: String,
}

/// Chunk store stats (for the local API).
#[derive(Debug, Clone, Serialize)]
pub struct ChunkStats {
    pub total_chunks: usize,
    pub chunk_size_bytes: usize,
    pub used_bytes: u64,
    pub free_gb: u64,
}

/// Tor status (for the local API).
#[derive(Debug, Clone, Serialize)]
pub struct TorStatus {
    pub enabled: bool,
    pub onion_address: Option<String>,
    /// F3: onion v3 адрес локального API (NEXXUS_API_ONION=1), если опубликован.
    pub api_onion: Option<String>,
    pub connected: bool,
}

/// JSON-RPC 2.0 request.
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: Option<String>,
    method: String,
    params: Option<Value>,
    id: Option<Value>,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error.
#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

const ERR_INVALID_REQUEST: i32 = -32600;
const ERR_METHOD_NOT_FOUND: i32 = -32601;
const ERR_INTERNAL_ERROR: i32 = -32603;

fn error_response(id: Option<Value>, code: i32, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message,
            data: None,
        }),
    }
}

fn ok_response(id: Option<Value>, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: Some(result),
        error: None,
    }
}

/// Local API server state, shared with P2pNetwork.
///
/// Все Mutex-поля защищают разделяемое состояние между задачами WebSocket.
pub struct LocalApi {
    /// Ссылка на P2P сеть (для node_id, bound_addr, отправки SMP).
    network: Arc<P2pNetwork>,
    /// Ссылка на хранилище чанков (для статистики).
    store: Arc<ChunkStore>,
    /// Время запуска daemon (для расчёта uptime).
    start_time: SystemTime,
    /// Подключённые пиры: адрес -> информация о пире.
    connected_peers: Arc<Mutex<HashMap<SocketAddr, ConnectedPeerInfo>>>,
    /// История SMP сообщений (последние 500 записей).
    smp_history: Arc<Mutex<Vec<SmpMessageInfo>>>,
    /// Inbound SMP channel: sender side goes to P2pNetwork, receiver is
    /// drained into smp_history by a task spawned in run().
    smp_inbox_tx: mpsc::UnboundedSender<InboundSmp>,
    smp_inbox_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<InboundSmp>>>>,
    /// Статус финализации эпохи (кворум, merkle_root и т.д.).
    epoch_info: Arc<Mutex<EpochInfo>>,
    /// Статус Tor (включен, onion адрес, подключён).
    tor_status: Arc<Mutex<TorStatus>>,
    /// Живая Tor-сессия (feature `tor`) — для dial_onion через чужие .onion.
    #[cfg(feature = "tor")]
    tor_session: Arc<Mutex<Option<Arc<crate::tor::TorSession>>>>,
    /// Токен доступа к API (api_auth). None = fail-closed: кроме ping ничего не доступно.
    api_token: std::sync::Mutex<Option<String>>,
    /// Panic PIN менеджер (Phase A3): состояние в panic.state рядом со store.
    panic: Arc<std::sync::Mutex<crate::panic::PanicManager>>,
    /// Выставляется при duress-PIN: после отправки ответа — wipe стора + выход.
    duress_wipe: std::sync::atomic::AtomicBool,
    /// API-01: семафор на число одновременных WebSocket соединений.
    ws_conns: std::sync::Arc<tokio::sync::Semaphore>,
    /// BS-01: опциональный pin ожидаемого registry_pub (hex) для bootstrap-списков.
    /// Если задан — envelope с другим registry_pub отклоняется (trust-on-first-use закрыт).
    bootstrap_registry_pin: std::sync::Mutex<Option<String>>,
    /// ADR-0009: IOU journal + anti-replay set (подключается из main после open).
    iou_journal: std::sync::Mutex<Option<crate::iou_journal::IouJournal>>,
    iou_seen: std::sync::Mutex<crate::iou_journal::Seen>,
}

/// JSON-RPC error code: не пройдена аутентификация.
pub const ERR_UNAUTHORIZED: i32 = -32001;

/// RSS текущего процесса в байтах (Linux: /proc/self/statm). Для /metrics.
fn rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(resident_pages * 4096)
}

/// Parse params.hash (64 hex chars) into a ChunkHash.
fn parse_hash_param(params: Option<Value>) -> Result<ChunkHash, NexxusError> {
    let s = params
        .as_ref()
        .and_then(|p| p.get("hash"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| NexxusError::Io("param 'hash' required".into()))?;
    let bytes = hex::decode(s).map_err(|e| NexxusError::Io(format!("bad hash hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| NexxusError::Io("hash must be 32 bytes".into()))?;
    Ok(ChunkHash(arr))
}

/// Гейт аутентификации: вызывается до диспетчеризации метода.
///
/// Возвращает `Some((response, close_after))`, если запрос обработан
/// самим гейтом (ping / auth / отказ), и `None`, если надо диспетчить
/// обычным образом (соединение уже аутентифицировано).
///
/// Fail-closed: без настроенного токена (`expected == None`) доступен
/// только `ping`.
fn auth_gate(
    expected: Option<&str>,
    req: &JsonRpcRequest,
    authenticated: &mut bool,
) -> Option<(JsonRpcResponse, bool)> {
    if *authenticated {
        return None;
    }
    match req.method.as_str() {
        "ping" => Some((
            ok_response(req.id.clone(), serde_json::json!({"pong": true})),
            false, // соединение остаётся открытым
        )),
        "auth" => {
            let supplied = req
                .params
                .as_ref()
                .and_then(|p| p.get("token"))
                .and_then(|t| t.as_str())
                .unwrap_or("");
            match expected {
                // Constant-time compare: token is a 256-bit secret, do not leak
                // prefix length via an early-exit == on strings.
                Some(expected)
                    if !supplied.is_empty()
                        && supplied.len() == expected.len()
                        && bool::from(
                            subtle::ConstantTimeEq::ct_eq(
                                supplied.as_bytes(),
                                expected.as_bytes(),
                            ),
                        ) =>
                {
                    *authenticated = true;
                    Some((
                        ok_response(req.id.clone(), serde_json::json!({"authenticated": true})),
                        false, // после успешного auth ждём настоящий запрос на этом же соединении
                    ))
                }
                _ => Some((
                    error_response(req.id.clone(), ERR_UNAUTHORIZED, "invalid or missing token".into()),
                    true, // закрываем соединение
                )),
            }
        }
        _ => Some((
            error_response(
                req.id.clone(),
                ERR_UNAUTHORIZED,
                format!("method '{}' requires auth", req.method),
            ),
            true,
        )),
    }
}

impl LocalApi {
    pub fn new(network: Arc<P2pNetwork>, store: Arc<ChunkStore>) -> Self {
        let (smp_inbox_tx, smp_inbox_rx) = mpsc::unbounded_channel();
        let panic_path = crate::panic::PanicManager::default_path(store.path());
        Self {
            network,
            store,
            start_time: SystemTime::now(),
            connected_peers: Arc::new(Mutex::new(HashMap::new())),
            smp_history: Arc::new(Mutex::new(Vec::new())),
            smp_inbox_tx,
            smp_inbox_rx: Arc::new(Mutex::new(Some(smp_inbox_rx))),
            api_token: std::sync::Mutex::new(None),
            panic: Arc::new(std::sync::Mutex::new(
                crate::panic::PanicManager::load(panic_path)
                .unwrap_or_else(|_| {
                    // Невалидный panic.state — fail-closed: панику нельзя обойти
                    // молча. Создаём "не armed" менеджер и пишем ошибку в лог.
                    eprintln!("nexxusd: WARNING: panic.state unreadable, panic disabled");
                    crate::panic::PanicManager::load(
                        std::env::temp_dir().join("nexxus-panic-unreadable.state"),
                    )
                    .expect("temp panic state must load")
                }),
            )),
            duress_wipe: std::sync::atomic::AtomicBool::new(false),
            ws_conns: std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_WS_CONNECTIONS)),
            bootstrap_registry_pin: std::sync::Mutex::new(None),
            iou_journal: std::sync::Mutex::new(None),
            iou_seen: std::sync::Mutex::new(std::collections::HashSet::new()),
            epoch_info: Arc::new(Mutex::new(EpochInfo {
                epoch_number: 0,
                merkle_root: hex::encode([0u8; 32]),
                total_bytes: 0,
                signature_count: 0,
                threshold: 0,
                quorum_met: false,
            })),
            tor_status: Arc::new(Mutex::new(TorStatus {
                enabled: false,
                onion_address: None,
                api_onion: None,
                connected: false,
            })),
            #[cfg(feature = "tor")]
            tor_session: Arc::new(Mutex::new(None)),
        }
    }

    /// ADR-0009: подключить IOU journal (вызывается из main после открытия стора).
    pub fn set_iou_journal(&self, j: crate::iou_journal::IouJournal, seen: crate::iou_journal::Seen) {
        *self.iou_seen.lock().unwrap() = seen;
        *self.iou_journal.lock().unwrap() = Some(j);
    }

    /// Register a connected peer (called from handle_connection).
    pub async fn register_peer(&self, addr: SocketAddr, node_id: Option<NodeId>, direction: &str) {
        let mut peers = self.connected_peers.lock().await;
        peers.insert(
            addr,
            ConnectedPeerInfo {
                node_id: node_id
                    .map(|n| hex::encode(n.0))
                    .unwrap_or_else(|| "unknown".into()),
                addr: addr.to_string(),
                direction: direction.into(),
                connected_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            },
        );
    }

    /// Unregister a disconnected peer.
    pub async fn unregister_peer(&self, addr: &SocketAddr) {
        self.connected_peers.lock().await.remove(addr);
    }

    /// Record an SMP message in history.
    pub async fn record_smp(&self, direction: &str, recipient: &str, payload_size: usize, status: &str) {
        self.record_smp_full(direction, "", recipient, payload_size, status).await;
    }

    /// Record an inbound (delivered) SMP message in history.
    pub async fn record_smp_inbound(&self, sender: &str, recipient: &str, payload_size: usize, status: &str) {
        self.record_smp_full("received", sender, recipient, payload_size, status).await;
    }

    async fn record_smp_full(&self, direction: &str, sender: &str, recipient: &str, payload_size: usize, status: &str) {
        let mut history = self.smp_history.lock().await;
        let id = format!("smp-{}", history.len() + 1);
        history.push(SmpMessageInfo {
            id,
            direction: direction.into(),
            sender_node_id: sender.into(),
            recipient_node_id: recipient.into(),
            payload_size,
            status: status.into(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        });
        // keep only last 500 entries
        if history.len() > 500 {
            let drain_count = history.len() - 500;
            history.drain(0..drain_count);
        }
    }

    /// Update epoch finalize status.
    pub async fn set_epoch_info(&self, info: EpochInfo) {
        *self.epoch_info.lock().await = info;
    }

    /// Устанавливает токен доступа к API (из api_auth::load_or_create_token).
    pub fn set_api_token(&self, token: String) {
        *self.api_token.lock().unwrap() = Some(token);
    }

    #[cfg(feature = "tor")]
    pub async fn set_tor_status(&self, status: TorStatus) {
        *self.tor_status.lock().await = status;
    }

    /// F3: записать api_onion адрес (не трогая остальной статус).
    pub async fn set_tor_api_onion(&self, onion: String) {
        self.tor_status.lock().await.api_onion = Some(onion);
    }

    /// Attach the live Tor session so `node_dial_onion` can reach .onion peers.
    #[cfg(feature = "tor")]
    pub async fn set_tor_session(&self, ts: Arc<crate::tor::TorSession>) {
        *self.tor_session.lock().await = Some(ts);
    }

    /// Handle a single JSON-RPC request and return a response value.
    async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let id = req.id.clone();
        // JSON-RPC 2.0: если поле jsonrpc присутствует, оно обязано быть "2.0".
        if let Some(v) = &req.jsonrpc {
            if v != "2.0" {
                return error_response(
                    id,
                    ERR_INVALID_REQUEST,
                    format!("unsupported jsonrpc version: {v}"),
                );
            }
        }
        let result = match req.method.as_str() {
            "ping" => Ok(serde_json::json!({"pong": true})),
            "node_status" => self.handle_node_status().await,
            "node_metrics" => self.handle_node_metrics(),
            "node_peers" => self.handle_node_peers().await,
            "node_ping_peer" => self.handle_node_ping_peer(req.params).await,
            "node_chunks" => self.handle_node_chunks().await,
            "node_chunk_pin" => self.handle_node_chunk_pin(req.params, true),
            "node_chunk_unpin" => self.handle_node_chunk_pin(req.params, false),
            "node_chunk_ttl" => self.handle_node_chunk_ttl(req.params),
            "node_name_set" => self.handle_node_name_set(req.params),
            "node_name_get" => self.handle_node_name_get(req.params),
            "node_manifest_get" => self.handle_node_manifest_get(req.params),
            "node_rehydrate_manifest" => self.handle_node_rehydrate_manifest(req.params).await,
            "node_name_history" => self.handle_node_name_history(req.params),
            "node_name_list" => self.handle_node_name_list(),
            "node_bootstrap_set" => self.handle_node_bootstrap_set(req.params),
            "node_bootstrap_get" => self.handle_node_bootstrap_get(),
            "node_chunk_onion_only" => self.handle_node_chunk_onion_only(req.params),
            "node_onion_only_list" => self.handle_node_onion_only_list(),
            "node_replicate_onion" => self.handle_node_replicate_onion().await,
            "node_policy_set" => self.handle_node_policy_set(req.params),
            "node_policy_list" => self.handle_node_policy_list(),
            "node_policy_delete" => self.handle_node_policy_delete(req.params),
            "node_policy_apply" => self.handle_node_policy_apply(req.params),
            "node_gc" => self.handle_node_gc(req.params),            "node_export_bundle" => self.handle_node_export_bundle(req.params).await,
            "node_import_bundle" => self.handle_node_import_bundle(req.params).await,
            "node_smp" => self.handle_node_smp().await,
            "node_smp_send" => self.handle_node_smp_send(req.params).await,
            "node_contact_link" => self.handle_node_contact_link(req.params).await,
            "node_contact_parse" => self.handle_node_contact_parse(req.params),
            "node_epoch" => self.handle_node_epoch().await,
            "node_tor" => self.handle_node_tor().await,
            "send_smp_envelope" => self.handle_send_smp_envelope(req.params).await,
            "node_pause" => self.handle_node_pause().await,
            "node_resume" => self.handle_node_resume().await,
            "node_connect" => self.handle_node_connect(req.params).await,
            "node_dial_onion" => self.handle_node_dial_onion(req.params).await,
            "node_upload" => self.handle_node_upload(req.params).await,
            "node_download" => self.handle_node_download(req.params).await,
            "node_sync_scan" => self.handle_node_sync_scan(req.params).await,
            "node_sync_status" => self.handle_node_sync_status(req.params),
            "node_provider_pin" => self.handle_node_provider_pin(req.params),
            "node_provider_status" => self.handle_node_provider_status(),
            "node_provider_list" => self.handle_node_provider_list(),
            "node_por" => self.handle_node_por().await,
            "node_audit_peer" => self.handle_node_audit_peer(req.params).await,
            "node_test_interhost" => self.handle_node_test_interhost(req.params).await,
            "panic_status" => self.handle_panic_status(),
            "panic_arm" => self.handle_panic_arm(req.params),
            "panic_enter" => self.handle_panic_enter(req.params),
            "node_identity_status" => self.handle_node_identity_status(),
            "node_identity_export" => self.handle_node_identity_export(req.params),
            "node_identity_import" => self.handle_node_identity_import(req.params),
            "node_seed_vault_status" => self.handle_seed_vault_status(),
            "node_seed_backup" => self.handle_seed_backup(req.params),
            "node_seed_restore" => self.handle_seed_restore(req.params),
            "node_backup" => self.handle_node_backup(),
            "node_backup_list" => self.handle_node_backup_list(),
            "node_backup_verify" => self.handle_node_backup_verify(req.params),
            "node_backup_restore" => self.handle_node_backup_restore(req.params),
            "node_backup_delete" => self.handle_node_backup_delete(req.params),
            "node_doctor" => self.handle_node_doctor(),
            "node_econ" => self.handle_node_econ(),
            "node_econ_export" => self.handle_node_econ_export().await,
            "iou_issue" => self.handle_iou_issue(req.params),
            "iou_list" => self.handle_iou_list(),
            "iou_balance" => self.handle_iou_balance(req.params),
            "iou_redeem" => self.handle_iou_redeem(req.params),
            _ => return error_response(id, ERR_METHOD_NOT_FOUND, format!("method '{}' not found", req.method)),
        };
        match result {
            Ok(v) => ok_response(id, v),
            Err(e) => error_response(id, ERR_INTERNAL_ERROR, e.to_string()),
        }
    }

    // --- ADR-0009: IOU (off-chain signed, local journal) ---

    fn iou_journal_ref(&self) -> Result<std::sync::MutexGuard<'_, Option<crate::iou_journal::IouJournal>>, NexxusError> {
        self.iou_journal.lock().map_err(|_| NexxusError::Io("iou journal lock poisoned".into()))
    }

    fn parse_node_id_param(params: Option<Value>, key: &str) -> Result<NodeId, NexxusError> {
        let s = params.as_ref().and_then(|p| p.get(key)).and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io(format!("param '{key}' (64 hex) required")))?;
        let b = hex::decode(s).map_err(|e| NexxusError::Io(format!("param '{key}' not hex: {e}")))?;
        let arr: [u8; 32] = b.try_into().map_err(|_| NexxusError::Io(format!("param '{key}' must be 64 hex chars")))?;
        Ok(NodeId(arr))
    }

    /// Выписать IOU: мы — debtor, подписываем своим identity.
    fn handle_iou_issue(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let creditor = Self::parse_node_id_param(params.clone(), "creditor")?;
        let amount_micro = params.as_ref().and_then(|p| p.get("amount_micro")).and_then(|v| v.as_i64())
            .ok_or_else(|| NexxusError::Io("param 'amount_micro' (i64) required".into()))?;
        let epoch = params.as_ref().and_then(|p| p.get("epoch")).and_then(|v| v.as_u64())
            .unwrap_or_else(|| self.epoch_info.try_lock().map(|e| e.epoch_number).unwrap_or(0));
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|e| NexxusError::Io(e.to_string()))?.as_secs();
        let nonce: [u8; 32] = rand::random();
        let iou = nexxus_econ::iou::Iou::new(self.network.identity(), creditor, nexxus_core::types::Money(amount_micro), epoch, nonce, now)
            .map_err(|e| NexxusError::Io(format!("iou issue: {e}")))?;
        Ok(serde_json::json!({"iou": iou.to_json(), "debtor": hex::encode(self.network.node_id().0), "debtor_pubkey": hex::encode(self.network.identity_pubkey())}))
    }

    fn handle_iou_list(&self) -> Result<Value, NexxusError> {
        let guard = self.iou_journal_ref()?;
        let j = guard.as_ref().ok_or_else(|| NexxusError::Io("iou journal not initialized".into()))?;
        let (ious, _seen, bad) = j.load().map_err(|e| NexxusError::Io(e.to_string()))?;
        Ok(serde_json::json!({"ious": ious.iter().map(|i| i.to_json()).collect::<Vec<_>>(), "bad_lines": bad}))
    }

    fn handle_iou_balance(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let creditor = Self::parse_node_id_param(params, "creditor")?;
        let guard = self.iou_journal_ref()?;
        let j = guard.as_ref().ok_or_else(|| NexxusError::Io("iou journal not initialized".into()))?;
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|e| NexxusError::Io(e.to_string()))?.as_secs();
        let bal = j.balance_owed(&creditor, now).map_err(|e| NexxusError::Io(e.to_string()))?;
        Ok(serde_json::json!({"creditor": hex::encode(creditor.0), "owed_micro": bal}))
    }

    /// Redeem: принимаем IOU от должника, верифицируем подпись по его pubkey, append в journal (anti-replay).
    fn handle_iou_redeem(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let iou_str = params.as_ref().and_then(|p| p.get("iou")).and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'iou' (json string) required".into()))?;
        let pk_hex = params.as_ref().and_then(|p| p.get("debtor_pubkey")).and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'debtor_pubkey' (64 hex) required".into()))?;
        let pk_b = hex::decode(pk_hex).map_err(|e| NexxusError::Io(format!("debtor_pubkey not hex: {e}")))?;
        let pk: [u8; 32] = pk_b.try_into().map_err(|_| NexxusError::Io("debtor_pubkey must be 64 hex chars".into()))?;
        let iou = nexxus_econ::iou::Iou::from_json(iou_str).map_err(|e| NexxusError::Io(format!("iou parse: {e}")))?;
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|e| NexxusError::Io(e.to_string()))?.as_secs();
        iou.verify(&pk, now).map_err(|e| NexxusError::Io(format!("iou verify: {e}")))?;
        let guard = self.iou_journal_ref()?;
        let j = guard.as_ref().ok_or_else(|| NexxusError::Io("iou journal not initialized".into()))?;
        let mut seen = self.iou_seen.lock().map_err(|_| NexxusError::Io("iou seen lock poisoned".into()))?;
        match j.append(&iou, &mut seen) {
            Ok(()) => Ok(serde_json::json!({"ok": true, "debtor": hex::encode(iou.debtor.0), "amount_micro": iou.amount_micro})),
            Err(e) => Err(NexxusError::Io(format!("iou redeem: {e}"))),
        }
    }

    /// Identity status for the monitor UI: is a BIP-39 identity persisted,
    /// how many words it has, and the resulting node_id.
    fn handle_node_identity_status(&self) -> Result<Value, NexxusError> {
        let (initialized, word_count) = identity_status(&self.store)?;
        Ok(serde_json::json!({
            "initialized": initialized,
            "word_count": word_count,
            "node_id": hex::encode(self.network.node_id().0),
        }))
    }

    /// One-time export of the mnemonic. Requires params.confirm == true.
    /// The mnemonic is returned in the RPC response only — it is never
    /// written to logs by this handler.
    fn handle_node_identity_export(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let confirm = params
            .as_ref()
            .and_then(|p| p.get("confirm"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !confirm {
            return Err(NexxusError::Vault(
                "param 'confirm' must be true to export the mnemonic".into(),
            ));
        }
        // S4: после миграции мнемоника живёт только в vault — для export нужен PIN из запроса.
        let pin = params.as_ref().and_then(|p| p.get("pin")).and_then(|p| p.as_str());
        match read_mnemonic(&self.store, pin)? {
            Some(phrase) => Ok(serde_json::json!({
                "mnemonic": phrase.as_str(),
                "word_count": phrase.split_whitespace().count(),
            })),
            None => Err(NexxusError::Io("identity not initialized".into())),
        }
    }

    /// Import a mnemonic. Refuses on a store already initialized with a
    /// different seed (store key is derived from the seed). On a live daemon
    /// the identity is already loaded, so a matching phrase returns "already".
    fn handle_node_identity_import(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let phrase = params
            .as_ref()
            .and_then(|p| p.get("mnemonic"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Vault("param 'mnemonic' required".into()))?;
        let (node_id, status) = import_mnemonic(&self.store, phrase)?;
        Ok(serde_json::json!({
            "status": status,
            "node_id": hex::encode(node_id.0),
        }))
    }

    /// Seed vault (encrypted BIP39 backup) metadata — no secrets, no decryption.
    fn handle_seed_vault_status(&self) -> Result<Value, NexxusError> {
        match crate::seed_vault::seed_vault_status(&self.store)? {
            Some(st) => Ok(serde_json::json!({
                "exists": true,
                "path": st.path.to_string_lossy(),
                "created_at": st.created_at,
                "has_duress_pin": st.has_duress_pin,
                "kdf_rounds": st.kdf_rounds,
            })),
            None => Ok(serde_json::json!({"exists": false})),
        }
    }

    /// Create/overwrite the encrypted seed vault. Params: pin (required, >=4),
    /// duress_pin (optional). The mnemonic never leaves the process in plaintext
    /// except into the encrypted vault file (0600).
    fn handle_seed_backup(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let pin = params
            .as_ref()
            .and_then(|p| p.get("pin"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Vault("param 'pin' required".into()))?;
        let duress = params
            .as_ref()
            .and_then(|p| p.get("duress_pin"))
            .and_then(|v| v.as_str());
        let path = crate::seed_vault::backup_seed(&self.store, pin, duress)?;
        Ok(serde_json::json!({
            "ok": true,
            "path": path.to_string_lossy(),
        }))
    }

    /// Restore the seed from the vault with a PIN. Returns one of:
    /// "imported" | "already" | "duress" | "wrong_pin" (+ node_id when applicable).
    /// On "duress" the real seed is NOT imported — the monitor must alert, not celebrate.
    fn handle_seed_restore(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let pin = params
            .as_ref()
            .and_then(|p| p.get("pin"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Vault("param 'pin' required".into()))?;
        use crate::seed_vault::RestoreOutcome;
        let r = match crate::seed_vault::restore_seed(&self.store, pin)? {
            RestoreOutcome::Imported(id) => serde_json::json!({"status": "imported", "node_id": hex::encode(id.0)}),
            RestoreOutcome::Already(id) => serde_json::json!({"status": "already", "node_id": hex::encode(id.0)}),
            RestoreOutcome::Duress => serde_json::json!({"status": "duress"}),
            RestoreOutcome::WrongPin => serde_json::json!({"status": "wrong_pin"}),
        };
        Ok(r)
    }

    /// Store backup (R3): file-level copy + manifest. Safe on a running node.
    fn handle_node_backup(&self) -> Result<Value, NexxusError> {
        let r = crate::backup::backup_store(&self.store);
        match &r {
            Ok(m) => {
                self.network.metrics.backup_ok.fetch_add(1, Ordering::Relaxed);
                crate::log_ev!("info", "backup.ok", "name" => m.name.clone(), "chunks" => m.chunk_count);
            }
            Err(e) => {
                self.network.metrics.backup_fail.fetch_add(1, Ordering::Relaxed);
                crate::log_ev!("error", "backup.fail", "err" => e.to_string());
            }
        }
        let m = r?;
        serde_json::to_value(m).map_err(|e| NexxusError::Io(e.to_string()))
    }

    fn handle_node_backup_list(&self) -> Result<Value, NexxusError> {
        let list = crate::backup::list_backups(&self.store)?;
        serde_json::to_value(list).map_err(|e| NexxusError::Io(e.to_string()))
    }

    fn handle_node_backup_verify(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let name = params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'name' required".into()))?;
        let (m, ok, detail) = crate::backup::verify_backup(&self.store, name)?;
        Ok(serde_json::json!({
            "name": m.name,
            "ok": ok,
            "detail": detail,
            "sha256": m.sha256,
            "chunk_count": m.chunk_count,
            "created_at": m.created_at,
        }))
    }

    /// D2: delete one backup by name (rotation from the guardian scheduler).
    /// AB-02: требует явный confirm=true — симметрия с node_backup_restore.
    fn handle_node_backup_delete(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let name = params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'name' required".into()))?;
        let confirm = params
            .as_ref()
            .and_then(|p| p.get("confirm"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !confirm {
            return Err(NexxusError::Vault(
                "param 'confirm' must be true to delete a backup".into(),
            ));
        }
        crate::backup::delete_backup(&self.store, name)?;
        Ok(serde_json::json!({ "deleted": name }))
    }

    /// Restore = verify + write a *.restore-candidate.redb next to the live
    /// store. The live store is never overwritten via API; swap happens via
    /// `nexxusd restore <name>` with the daemon stopped.
    fn handle_node_backup_restore(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let name = params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'name' required".into()))?;
        let confirm = params
            .as_ref()
            .and_then(|p| p.get("confirm"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !confirm {
            return Err(NexxusError::Vault(
                "param 'confirm' must be true to stage a restore candidate".into(),
            ));
        }
        let cand = crate::backup::restore_candidate(&self.store, name)?;
        Ok(serde_json::json!({
            "status": "staged",
            "candidate": cand.to_string_lossy(),
            "note": "live store untouched; swap with `nexxusd restore <name>` while stopped",
        }))
    }

    /// Health report (R3 doctor) as JSON.
    fn handle_node_doctor(&self) -> Result<Value, NexxusError> {
        let r = crate::backup::doctor(&self.store);
        serde_json::to_value(r).map_err(|e| NexxusError::Io(e.to_string()))
    }

    /// Economics panel (R4): storage GB, section split, daily reward/cost,
    /// anti-loop invariant, 56-day vesting progress, health.
    fn handle_node_econ(&self) -> Result<Value, NexxusError> {
        use nexxus_econ::degradation::{health_from_offline, Health};
        use nexxus_econ::sections::{
            anti_loop_invariant_holds, daily_storer_reward, daily_subscription_cost,
            split_into_sections,
        };
        use nexxus_econ::vesting::VestingSchedule;
        use nexxus_econ::{VESTING_LOCK_DAYS, DAILY_NEXX_RATE_PER_GB, SUBSCRIPTION_DAILY_COST_PER_GB};

        const META_VESTING_START: &str = "econ_vesting_start_ts";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Vesting start: зафиксировать при первом вызове.
        let start_ts = match self.store.get_meta(META_VESTING_START)? {
            Some(b) => String::from_utf8_lossy(&b).parse::<u64>().unwrap_or(now),
            None => {
                self.store.put_meta(META_VESTING_START, now.to_string().as_bytes())?;
                now
            }
        };
        let hashes = self.store.list_chunk_hashes()?;
        let used_bytes: u64 = hashes
            .iter()
            .filter_map(|h| self.store.get_chunk(h).ok().flatten())
            .map(|d| d.len() as u64)
            .sum();
        let free_gb = fs2::available_space(self.store.path())
            .map(|b| b / (1u64 << 30))
            .unwrap_or(0);
        let used_gb = used_bytes / 1_000_000_000;
        let split = split_into_sections(free_gb);
        let daily_reward = daily_storer_reward(used_gb);
        let daily_cost = daily_subscription_cost(used_gb);
        let days_elapsed = now.saturating_sub(start_ts) / 86_400;
        let mut vest = VestingSchedule::new(nexxus_core::types::Money(daily_reward.0 * VESTING_LOCK_DAYS as i64));
        vest.advance(days_elapsed.min(VESTING_LOCK_DAYS));
        let health = health_from_offline(0); // нода online, пока API отвечает
        let health_str = match health {
            Health::Online => "online",
            Health::RewardsFrozen => "rewards_frozen",
            Health::Warning14d => "warning_14d",
            Health::Degraded28d => "degraded_28d",
        };
        Ok(serde_json::json!({
            "used_gb": used_gb,
            "free_gb": free_gb,
            "sections": {
                "sections_16gb": split.sections_16gb,
                "remainder_gb": split.remainder_gb,
                "vault_quota_gb": split.vault_quota_gb,
            },
            "daily": {
                "reward_per_gb_micro": DAILY_NEXX_RATE_PER_GB,
                "cost_per_gb_micro": SUBSCRIPTION_DAILY_COST_PER_GB,
                "reward_total_micro": daily_reward.0,
                "cost_total_micro": daily_cost.0,
                "anti_loop_ok": anti_loop_invariant_holds(),
            },
            "vesting": {
                "lock_days": VESTING_LOCK_DAYS,
                "start_ts": start_ts,
                "days_elapsed": days_elapsed.min(VESTING_LOCK_DAYS),
                "total_micro": vest.total.0,
                "vested_micro": vest.vested().0,
                "unvested_micro": vest.unvested().0,
                "fully_vested": vest.is_fully_vested(),
            },
            "health": health_str,
        }))
    }

    /// E3 quick win: signed accounting export (still NO payments — the report
    /// explicitly says "accounting only"). Canonical JSON of the report is
    /// signed with the node's Ed25519 identity; the monitor can hand the
    /// {report, signature, pubkey} triple to anyone for verification.
    async fn handle_node_econ_export(&self) -> Result<Value, NexxusError> {
        let econ = self.handle_node_econ()?;
        let m = self.network.metrics.snapshot();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let uptime_ms = self.start_time.elapsed().map(|d| d.as_millis()).unwrap_or(0);
        let store_used = self.network.store().store_size().unwrap_or(0);
        let disk_free = self.network.store().available_space().unwrap_or(0);
        let report = serde_json::json!({
            "kind": "nexxus_accounting_export",
            "version": 1,
            "disclaimer": "accounting only — not payments, not on-chain settlement",
            "node_id": hex::encode(self.network.node_id().0),
            "ed25519_pub": hex::encode(self.network.identity_pubkey()),
            "exported_at_unix": now,
            "uptime_ms": uptime_ms,
            "peers_connected": self.connected_peers.lock().await.len(),
            "store": {
                "used_bytes": store_used,
                "cap_bytes": self.network.store().max_store_bytes(),
                "disk_free_bytes": disk_free,
                "chunks": self.store.list_chunk_hashes()?.len(),
            },
            "metrics": m,
            "econ": econ,
        });
        let canonical = serde_json::to_string(&report)
            .map_err(|e| NexxusError::Io(format!("canonical json: {e}")))?;
        let sig = self.network.identity().sign(canonical.as_bytes());
        Ok(serde_json::json!({
            "report": report,
            "canonical": canonical,
            "signature": hex::encode(sig),
            "pubkey": hex::encode(self.network.identity_pubkey()),
        }))
    }

    fn handle_panic_status(&self) -> Result<Value, NexxusError> {
        let st = self.panic.lock().unwrap().status();
        Ok(serde_json::json!({
            "armed": st.armed,
            "fail_count": st.fail_count,
            "cooldown_remaining_secs": st.cooldown_remaining_secs,
        }))
    }

    fn handle_panic_arm(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let pin = params
            .as_ref()
            .and_then(|p| p.get("pin"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Vault("param 'pin' required".into()))?;
        let duress = params
            .as_ref()
            .and_then(|p| p.get("duress_pin"))
            .and_then(|v| v.as_str());
        self.panic.lock().unwrap().arm(pin, duress)?;
        Ok(serde_json::json!({"armed": true}))
    }

    fn handle_panic_enter(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        use crate::panic::EnterOutcome;
        let pin = params
            .as_ref()
            .and_then(|p| p.get("pin"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Vault("param 'pin' required".into()))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        match self.panic.lock().unwrap().enter(pin, now)? {
            EnterOutcome::Ok => Ok(serde_json::json!({"ok": true})),
            EnterOutcome::Duress => {
                // Ложный успех: снаружи неотличимо от Ok. После отправки
                // ответа handle_ws затрёт стор и завершит процесс.
                self.duress_wipe
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(serde_json::json!({"ok": true}))
            }
            EnterOutcome::Wrong { cooldown_secs } => {
                Ok(serde_json::json!({"ok": false, "cooldown_secs": cooldown_secs}))
            }
            EnterOutcome::Cooldown { remaining_secs } => {
                Ok(serde_json::json!({"ok": false, "cooldown_remaining_secs": remaining_secs}))
            }
        }
    }

    async fn handle_node_status(&self) -> Result<Value, NexxusError> {
        let bound = self.network.bound_addr().await;
        let peers = self.connected_peers.lock().await.len();
        let uptime = self
            .start_time
            .elapsed()
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let tor = self.tor_status.lock().await.clone();
        serde_json::to_value(NodeStatus {
            node_id: hex::encode(self.network.node_id().0),
            version: env!("CARGO_PKG_VERSION").into(),
            listen_addr: self.network.listen_addr_str().to_string(),
            bound_addr: bound.map(|a| a.to_string()),
            uptime_ms: uptime,
            peer_count: peers,
            tor_enabled: tor.enabled,
            paused: self.network.is_paused(),
            x25519_pub: hex::encode(self.network.x25519_pub().0),
            ed25519_pub: hex::encode(self.network.identity_pubkey()),
        }).map_err(|e| NexxusError::Io(e.to_string()))
    }

    /// E1: node-level P2P counters (JSON + Prometheus text in `prom`).
    fn handle_node_metrics(&self) -> Result<Value, NexxusError> {
        let m = self.network.snapshot_with_rl();
        let mut v = serde_json::json!({ "metrics": m, "peers_scored": self.network.peer_scores_snapshot().len() });
        v["prom"] = Value::String(self.network.metrics.prom());
        // E0: prod-observability — uptime и RSS процесса (unix: /proc/self).
        v["uptime_secs"] = Value::from(
            crate::START_TIME
                .get()
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0),
        );
        #[cfg(unix)]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if let Some(rest) = line.strip_prefix("VmRSS:") {
                        let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
                        v["rss_kb"] = Value::from(kb);
                        break;
                    }
                }
            }
        }
        // E2: storage capacity visibility (cap, used, free).
        if let Ok(used) = self.network.store().store_size() {
            v["store_used_bytes"] = Value::from(used);
        }
        v["store_cap_bytes"] = Value::from(self.network.store().max_store_bytes());
        if let Ok(avail) = self.network.store().available_space() {
            v["disk_free_bytes"] = Value::from(avail);
        }
        Ok(v)
    }

    /// E1 connection-quality hint: ping one peer, record EWMA RTT into its
    /// PeerScore (surfaced via node_peers score_detail.rtt_ms).
    async fn handle_node_ping_peer(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let addr_s = params
            .as_ref()
            .and_then(|p| p.get("addr"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'addr' required".into()))?;
        let addr: SocketAddr = addr_s
            .parse()
            .map_err(|e| NexxusError::Io(format!("bad addr '{addr_s}': {e}")))?;
        let rtt = self.network.ping(addr).await?;
        self.network.note_peer_rtt(addr, rtt);
        Ok(serde_json::json!({
            "addr": addr_s,
            "rtt_ms": rtt.as_millis() as u64,
        }))
    }

    async fn handle_node_peers(&self) -> Result<Value, NexxusError> {
        let peers = self.connected_peers.lock().await.clone();
        let scores: std::collections::HashMap<String, crate::net::network::PeerScore> = self
            .network
            .peer_scores_snapshot()
            .into_iter()
            .collect();
        let mut list: Vec<Value> = peers
            .into_values()
            .map(|p| {
                let mut v = serde_json::to_value(p).unwrap_or(Value::Null);
                if let Some(addr) = v.get("addr").and_then(|a| a.as_str()) {
                    if let Some(s) = scores.get(addr) {
                        v["score"] = serde_json::json!(s.score());
                        v["score_detail"] = serde_json::to_value(s).unwrap_or(Value::Null);
                    }
                }
                v
            })
            .collect();
        // Merge in routing-table peers (known by address even if not
        // holding a live connection right now).
        for p in self.network.known_peers().await {
            let addr = p.addr.to_string();
            if !list
                .iter()
                .any(|v| v.get("addr").and_then(|a| a.as_str()) == Some(addr.as_str()))
            {
                list.push(serde_json::json!({
                    "node_id": hex::encode(p.node_id.0),
                    "addr": addr,
                    "connected": false,
                }));
            }
        }
        Ok(serde_json::json!({ "peers": list }))
    }

    /// E2 retention: pin/unpin a chunk (params: hash hex).
    fn handle_node_chunk_pin(&self, params: Option<Value>, pin: bool) -> Result<Value, NexxusError> {
        let hash = parse_hash_param(params)?;
        if pin {
            self.store.pin_chunk(&hash)?;
        } else {
            self.store.unpin_chunk(&hash)?;
        }
        Ok(serde_json::json!({ "hash": hex::encode(hash.0), "pinned": pin }))
    }

    /// E2 retention: set chunk TTL in seconds (params: hash hex, ttl_secs; 0 = clear).
    fn handle_node_chunk_ttl(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let hash = parse_hash_param(params.clone())?;
        let ttl = params
            .as_ref()
            .and_then(|p| p.get("ttl_secs"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| NexxusError::Io("param 'ttl_secs' required".into()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let exp = self.store.set_chunk_ttl(&hash, ttl, now)?;
        Ok(serde_json::json!({ "hash": hex::encode(hash.0), "ttl_secs": ttl, "expires_unix": exp }))
    }

    /// E2 versioning: name_set — указатель name → hash, запись в историю.
    fn handle_node_name_set(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let name = params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'name' required".into()))?;
        let hash = parse_hash_param(params.clone())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        self.store.name_set(name, &hash, now)?;
        Ok(serde_json::json!({ "name": name, "hash": hex::encode(hash.0), "ts_ns": now }))
    }

    /// E2 versioning: текущий указатель name.
    fn handle_node_name_get(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let name = params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'name' required".into()))?;
        let h = self.store.name_get(name)?;
        Ok(serde_json::json!({
            "name": name,
            "hash": h.map(|h| hex::encode(h.0)),
        }))
    }

    /// E2 versioning: история указаний name [(ts, hash)].
    fn handle_node_name_history(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let name = params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'name' required".into()))?;
        let hist = self
            .store
            .name_history(name)?
            .into_iter()
            .map(|(ts, h)| serde_json::json!({ "ts_ns": ts, "hash": hex::encode(h.0) }))
            .collect::<Vec<_>>();
        Ok(serde_json::json!({ "name": name, "history": hist }))
    }

    /// Манифест файла по root (владелец ноды, token-gated): содержит per-file
    /// key — нужен light-клиенту для локальной merkle-верификации скачанного.
    fn handle_node_manifest_get(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let root = params
            .and_then(|p| p.get("root").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .ok_or_else(|| NexxusError::Io("param 'root'".into()))?;
        let raw = self
            .store
            .get_meta(&format!("manifest_{root}"))?
            .ok_or_else(|| NexxusError::Io(format!("no manifest for root {root}")))?;
        serde_json::from_slice(&raw)
            .map_err(|e| NexxusError::Io(format!("bad manifest json: {e}")))
    }

    /// PROD-RESTORE-01 / Phase 2: Дотянуть недостающие шарды манифеста из Mesh-сети.
    async fn handle_node_rehydrate_manifest(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let p = params.ok_or_else(|| NexxusError::Io("params required (root or manifest)".into()))?;
        let manifest = if let Some(root) = p.get("root").and_then(|v| v.as_str()) {
            let raw = self
                .store
                .get_meta(&format!("manifest_{root}"))?
                .ok_or_else(|| NexxusError::Io(format!("no local manifest for root {root}")))?;
            serde_json::from_slice(&raw)
                .map_err(|e| NexxusError::Io(format!("bad manifest json: {e}")))?
        } else if p.get("chunks").is_some() {
            p
        } else {
            return Err(NexxusError::Io("param 'root' or 'manifest' required".into()));
        };

        crate::vault::rehydrate_manifest_from_mesh(&self.network, &self.store, &manifest).await
    }

    /// E2 versioning: список всех имён.
    fn handle_node_name_list(&self) -> Result<Value, NexxusError> {
        Ok(serde_json::json!({ "names": self.store.name_list()? }))
    }

    /// E6: принять signed bootstrap-список (envelope {payload, sig}).
    /// Проверка подписи ed25519 и expiry — внутри bootstrap::store_set.
    fn handle_node_bootstrap_set(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let env: crate::bootstrap::BootstrapEnvelope = serde_json::from_value(
            params.ok_or_else(|| NexxusError::Io("params required".into()))?,
        )
        .map_err(|e| NexxusError::Io(format!("bad envelope: {e}")))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // BS-01: если в конфиге задан pin registry_pub — проверяем до store_set.
        if let Some(pin) = self.bootstrap_registry_pin.lock().unwrap().clone() {
            if env.payload.registry_pub.to_lowercase() != pin {
                crate::log_ev!("warn", "bootstrap.list.rejected_pin", "got" => &env.payload.registry_pub.chars().take(16).collect::<String>());
                return Err(NexxusError::Io(
                    "bootstrap registry_pub does not match pinned bootstrap_registry_pub".into(),
                ));
            }
        }
        crate::bootstrap::store_set(&self.store, &env, now)?;
        crate::log_ev!("info", "bootstrap.list.accepted", "addrs" => env.payload.addrs.len(), "expiry_unix" => env.payload.expiry_unix);
        Ok(serde_json::json!({
            "ok": true, "addrs": env.payload.addrs.len(), "expiry_unix": env.payload.expiry_unix
        }))
    }

    /// BS-01: установить pin registry_pub (hex64, lowercase). None = без pin.
    pub fn set_bootstrap_registry_pin(&self, hex: Option<String>) {
        *self.bootstrap_registry_pin.lock().unwrap() = hex.map(|h| h.to_lowercase());
    }

    /// E6 onion-only: установить/снять флаг chunk'а вручную. params: {hash:<hex64>, on:bool}
    fn handle_node_chunk_onion_only(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let p = params.ok_or_else(|| NexxusError::Io("params required".into()))?;
        let hexstr = p.get("hash").and_then(|v| v.as_str()).ok_or_else(|| NexxusError::Io("param 'hash'".into()))?;
        let on = p.get("on").and_then(|v| v.as_bool()).unwrap_or(true);
        let h = parse_hash_param(Some(serde_json::json!({ "hash": hexstr })))?;
        self.store.set_onion_only(&h, on)?;
        if on {
            self.store.pin_chunk(&h)?;
        }
        crate::log_ev!("info", "chunk.onion_only", "hash" => &hexstr[..16.min(hexstr.len())], "on" => on);
        Ok(serde_json::json!({ "ok": true, "hash": hexstr, "on": on }))
    }

    /// E6: список чанков с флагом onion-only.
    fn handle_node_onion_only_list(&self) -> Result<Value, NexxusError> {
        let list = self
            .store
            .onion_only_list()?
            .into_iter()
            .map(|h| hex::encode(h.0))
            .collect::<Vec<_>>();
        Ok(serde_json::json!({ "onion_only": list }))
    }

    /// E6: репликация всех onion-only чанков на .onion-адреса из signed
    /// bootstrap-списка (через Tor). Требует NEXXUS_TOR=1 и валидный список.
    #[cfg(feature = "tor")]
    async fn handle_node_replicate_onion(&self) -> Result<Value, NexxusError> {
        let ts = self
            .tor_session
            .lock()
            .await
            .clone()
            .ok_or_else(|| NexxusError::Io("tor session not running (NEXXUS_TOR=0?)".into()))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let boot = crate::bootstrap::store_get(&self.store, now)?
            .ok_or_else(|| NexxusError::Io("no bootstrap list installed (node_bootstrap_set)".into()))?;
        let onion_addrs: Vec<&String> = boot.addrs.iter().filter(|a| crate::net::network::P2pNetwork::is_onion_addr(a)).collect();
        if onion_addrs.is_empty() {
            return Err(NexxusError::Io("bootstrap list has no .onion addrs".into()));
        }
        let chunks = self.store.onion_only_list()?;
        let mut sent = 0usize;
        let mut errors = Vec::new();
        for h in &chunks {
            let data = match self.store.get_chunk(h)? {
                Some(d) => d,
                None => continue,
            };
            let sc = nexxus_core::wire::payloads::StoreChunk {
                chunk_hash: *h,
                file_id: 0,
                chunk_index: 0,
                data,
            };
            for addr in &onion_addrs {
                match self.network.send_store_chunk_onion(&ts, addr, &sc).await {
                    Ok(_) => sent += 1,
                    Err(e) => errors.push(format!("{addr}: {e}")),
                }
            }
        }
        crate::log_ev!("info", "chunk.replicate_onion", "chunks" => chunks.len(), "sent" => sent, "errors" => errors.len());
        Ok(serde_json::json!({
            "chunks": chunks.len(), "targets": onion_addrs.len(), "sent": sent,
            "errors": errors.iter().take(5).collect::<Vec<_>>(),
        }))
    }

    #[cfg(not(feature = "tor"))]
    async fn handle_node_replicate_onion(&self) -> Result<Value, NexxusError> {
        Err(NexxusError::Io("built without tor feature".into()))
    }

    /// E6 policies: установить правило {id, name_prefix, action=pin|ttl:<secs>}.
    fn handle_node_policy_set(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let p = params.ok_or_else(|| NexxusError::Io("params required".into()))?;
        let id = p.get("id").and_then(|v| v.as_str()).ok_or_else(|| NexxusError::Io("param 'id'".into()))?;
        let prefix = p.get("name_prefix").and_then(|v| v.as_str()).ok_or_else(|| NexxusError::Io("param 'name_prefix'".into()))?;
        let action = p.get("action").and_then(|v| v.as_str()).ok_or_else(|| NexxusError::Io("param 'action'".into()))?;
        self.store.policy_set(id, prefix, action)?;
        Ok(serde_json::json!({ "ok": true, "id": id }))
    }

    /// E6 policies: список правил.
    fn handle_node_policy_list(&self) -> Result<Value, NexxusError> {
        let list = self
            .store
            .policy_list()?
            .into_iter()
            .map(|(id, prefix, action)| serde_json::json!({ "id": id, "name_prefix": prefix, "action": action }))
            .collect::<Vec<_>>();
        Ok(serde_json::json!({ "policies": list }))
    }

    /// E6 policies: удалить правило по id.
    fn handle_node_policy_delete(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let id = params
            .and_then(|p| p.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .ok_or_else(|| NexxusError::Io("param 'id'".into()))?;
        self.store.policy_delete(&id)?;
        Ok(serde_json::json!({ "ok": true, "id": id }))
    }

    /// E6 policies: применить все правила к существующим именам (pin/ttl chancей).
    /// POL-01: bulk-операция, требует confirm=true.
    fn handle_node_policy_apply(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let confirmed = params
            .as_ref()
            .and_then(|p| p.get("confirm").and_then(|v| v.as_bool()))
            .unwrap_or(false);
        if !confirmed {
            return Err(NexxusError::Io(
                "policy_apply is bulk: pass {\"confirm\": true}".into(),
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let applied = self.store.policy_apply(now)?;
        crate::log_ev!("info", "policy.applied", "count" => applied);
        Ok(serde_json::json!({ "applied": applied }))
    }

    /// E6: текущий bootstrap-список (с проверкой подписи/expiry). null если нет.
    fn handle_node_bootstrap_get(&self) -> Result<Value, NexxusError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let list = crate::bootstrap::store_get(&self.store, now)?;
        Ok(serde_json::json!({
            "bootstrap": list.map(|l| serde_json::json!({
                "addrs": l.addrs, "issued_unix": l.issued_unix,
                "expiry_unix": l.expiry_unix, "registry_pub": l.registry_pub,
            })),
        }))
    }

    /// E2 retention: delete all expired unpinned chunks now.
    /// POL-01: GC — bulk-удаление, требует confirm=true (симметрия с backup_delete).
    fn handle_node_gc(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let confirmed = params
            .as_ref()
            .and_then(|p| p.get("confirm").and_then(|v| v.as_bool()))
            .unwrap_or(false);
        if !confirmed {
            return Err(NexxusError::Io(
                "gc is destructive: pass {\"confirm\": true}".into(),
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let deleted = self.store.gc_expired(now)?;
        crate::log_ev!("warn", "gc.run", "deleted" => deleted);
        Ok(serde_json::json!({ "deleted": deleted }))
    }

    /// E2: экспорт cold-backup bundle (зашифрован PIN'ом) в `<data>/bundles/`.
    /// params: pin (обязателен, затирается), опционально name.
    async fn handle_node_export_bundle(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let pin = params
            .as_ref()
            .and_then(|p| p.get("pin"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| NexxusError::Vault("param 'pin' required".into()))?
            .to_string();
        let node_id = hex::encode(self.network.node_id().0);
        // PBKDF2 600k — тяжёлый KDF; в spawn_blocking, чтобы не блокировать
        // tokio-воркер и не ронять WS-ответы (e2e smoke ловил таймаут).
        let store = Arc::clone(&self.store);
        let (vault, total, nmeta) = tokio::task::spawn_blocking(move || {
            crate::bundle::export_bundle(&store, &node_id, &pin)
        })
        .await
        .map_err(|e| NexxusError::Io(format!("bundle task join: {e}")))??;
        let dir = self
            .store
            .path()
            .parent()
            .map(|p| p.join("bundles"))
            .ok_or_else(|| NexxusError::Io("no data dir".into()))?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| NexxusError::Io(format!("bundles dir: {e}")))?;
        let name = format!(
            "bundle-{}.json",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        let path = dir.join(&name);
        // bundle уже зашифрован; временный файл + rename, права 0600.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &vault)
            .map_err(|e| NexxusError::Io(format!("bundle write: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &path)
            .map_err(|e| NexxusError::Io(format!("bundle rename: {e}")))?;
        Ok(serde_json::json!({
            "path": path.to_string_lossy(),
            "chunks_total": total,
            "meta_entries": nmeta,
            "encrypted": true,
        }))
    }

    /// E2: импорт bundle из файла. params: path, pin, confirm=true (симметрия
    /// с restore/delete — импорт пишет в живой стор).
    async fn handle_node_import_bundle(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let path = params
            .as_ref()
            .and_then(|p| p.get("path"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'path' required".into()))?;
        let confirm = params
            .as_ref()
            .and_then(|p| p.get("confirm"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !confirm {
            return Err(NexxusError::Vault(
                "param 'confirm' must be true to import a bundle".into(),
            ));
        }
        let pin = params
            .as_ref()
            .and_then(|p| p.get("pin"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| NexxusError::Vault("param 'pin' required".into()))?;
        // path traversal guard: только внутри bundles/ каталога стора
        let base = self
            .store
            .path()
            .parent()
            .map(|p| p.join("bundles"))
            .ok_or_else(|| NexxusError::Io("no data dir".into()))?;
        let canon = std::fs::canonicalize(path)
            .map_err(|e| NexxusError::Io(format!("bundle path: {e}")))?;
        let base_canon = std::fs::canonicalize(&base)
            .map_err(|e| NexxusError::Io(format!("bundles dir: {e}")))?;
        if !canon.starts_with(&base_canon) {
            return Err(NexxusError::Io("bundle path outside bundles/ dir".into()));
        }
        let vault = std::fs::read_to_string(&canon)
            .map_err(|e| NexxusError::Io(format!("bundle read: {e}")))?;
        let store = Arc::clone(&self.store);
        let pin = pin.to_string();
        tokio::task::spawn_blocking(move || crate::bundle::import_bundle(&store, &vault, &pin))
            .await
            .map_err(|e| NexxusError::Io(format!("bundle task join: {e}")))?
    }

    async fn handle_node_chunks(&self) -> Result<Value, NexxusError> {
        let hashes = self.store.list_chunk_hashes()?;
        let total = hashes.len();
        let used_bytes: u64 = hashes
            .iter()
            .filter_map(|h| self.store.get_chunk(h).ok().flatten())
            .map(|d| d.len() as u64)
            .sum();
        // Реальное свободное место на диске стора (statvfs через fs2).
        let free_gb = fs2::available_space(self.store.path())
            .map(|b| b / (1u64 << 30))
            .unwrap_or(0);
        serde_json::to_value(ChunkStats {
            total_chunks: total,
            chunk_size_bytes: 16_384,
            used_bytes,
            free_gb,
        }).map_err(|e| NexxusError::Io(e.to_string()))
    }

    async fn handle_node_smp(&self) -> Result<Value, NexxusError> {
        let history = self.smp_history.lock().await.clone();
        let list: Vec<Value> = history
            .into_iter()
            .map(|m| serde_json::to_value(m).unwrap_or(Value::Null))
            .collect();
        Ok(serde_json::json!({ "messages": list }))
    }

    /// H1: отправка SMP-сообщения. params: recipient_node_id (hex),
    /// recipient_pub (ed25519 hex — конвертируется в X25519 для seal),
    /// message (plaintext, шифруется в envelope).
    async fn handle_node_smp_send(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let recipient_hex = params
            .as_ref()
            .and_then(|p| p.get("recipient_node_id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'recipient_node_id' required".into()))?;
        let recipient_bytes = hex::decode(recipient_hex)
            .map_err(|e| NexxusError::Io(format!("bad recipient_node_id hex: {e}")))?;
        let recipient: [u8; 32] = recipient_bytes
            .try_into()
            .map_err(|_| NexxusError::Io("recipient_node_id must be 32 bytes".into()))?;
        let pub_hex = params
            .as_ref()
            .and_then(|p| p.get("recipient_pub"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'recipient_pub' (ed25519 hex) required".into()))?;
        let pub_bytes = hex::decode(pub_hex)
            .map_err(|e| NexxusError::Io(format!("bad recipient_pub hex: {e}")))?;
        let pub_arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| NexxusError::Io("recipient_pub must be 32 bytes".into()))?;
        let message = params
            .as_ref()
            .and_then(|p| p.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if message.is_empty() {
            return Err(NexxusError::Io("param 'message' must be non-empty".into()));
        }
        if message.len() > 4096 {
            return Err(NexxusError::Io("message too large (max 4096 bytes)".into()));
        }
        use ed25519_dalek::VerifyingKey;
        let vk = VerifyingKey::from_bytes(&pub_arr)
            .map_err(|e| NexxusError::Io(format!("bad recipient_pub: {e}")))?;
        let recipient_x = vk.to_montgomery();
        let sender_id = self.network.our_id().0;
        let (_eph, env) = nexxus_core::wire::payloads::SmpEnvelope::seal(
            sender_id,
            recipient,
            &recipient_x,
            message.as_bytes(),
        );
        let size = message.len();
        let res = self.network.route_smp_envelope(&env).await;
        let (status, err) = match &res {
            Ok(()) => ("sent", String::new()),
            Err(e) => ("failed", e.to_string()),
        };
        self.record_smp_full("sent", &hex::encode(sender_id), recipient_hex, size, status)
            .await;
        match res {
            Ok(()) => Ok(serde_json::json!({ "ok": true, "status": status, "payload_size": size })),
            Err(_) => Ok(serde_json::json!({ "ok": false, "status": status, "error": err, "payload_size": size })),
        }
    }

    /// Specification §7: Generate standard `nexxus://contact?...` URI for this node.
    async fn handle_node_contact_link(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let name = params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("NeXXus Node");
        let node_id_hex = hex::encode(self.network.node_id().0);
        let pubkey_bytes = self.network.identity_pubkey();
        use sha2::Digest;
        let fp = hex::encode(sha2::Sha256::digest(pubkey_bytes));
        let onion = self
            .tor_status
            .lock()
            .await
            .onion_address
            .clone()
            .unwrap_or_else(|| format!("{}.onion", &node_id_hex[..16]));

        let link = nexxus_core::smp::ContactLink::new(&node_id_hex, &onion, name, &fp);
        Ok(serde_json::json!({
            "uri": link.to_uri(),
            "addr": link.addr,
            "onion": link.onion,
            "name": link.name,
            "fingerprint": link.fingerprint,
        }))
    }

    /// Specification §7: Parse and validate `nexxus://contact?...` URI.
    fn handle_node_contact_parse(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let uri = params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'uri' required".into()))?;
        let link = nexxus_core::smp::ContactLink::from_uri(uri)?;
        Ok(serde_json::json!({
            "addr": link.addr,
            "onion": link.onion,
            "name": link.name,
            "fingerprint": link.fingerprint,
            "ok": true,
        }))
    }

    async fn handle_node_epoch(&self) -> Result<Value, NexxusError> {
        let info = self.epoch_info.lock().await.clone();
        serde_json::to_value(info).map_err(|e| NexxusError::Io(e.to_string()))
    }

    async fn handle_node_tor(&self) -> Result<Value, NexxusError> {
        #[cfg_attr(not(feature = "tor"), allow(unused_mut))]
        let mut status = self.tor_status.lock().await.clone();
        // Если сессия поднята, но статус ещё без адреса — добираем из самой сессии.
        #[cfg(feature = "tor")]
        {
            let ts = self.tor_session.lock().await;
            if let Some(ts) = ts.as_ref() {
                if status.onion_address.is_none() {
                    status.onion_address = ts.our_onion().map(|s| s.to_string());
                }
                if status.api_onion.is_none() {
                    status.api_onion = ts.api_onion().map(|s| s.to_string());
                }
            }
        }
        serde_json::to_value(status).map_err(|e| NexxusError::Io(e.to_string()))
    }

    async fn handle_send_smp_envelope(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let params = params.ok_or_else(|| NexxusError::Io("missing params".into()))?;
        let recipient: String = params
            .get("recipient_node_id")
            .and_then(|v| v.as_str())
            .map(|s| s.into())
            .ok_or_else(|| NexxusError::Io("missing recipient_node_id".into()))?;
        let payload: Vec<u8> = params
            .get("payload")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|b| b as u8))
                    .collect()
            })
            .unwrap_or_default();
        let addr: Option<String> = params
            .get("addr")
            .and_then(|v| v.as_str())
            .map(|s| s.into());

        // Parse recipient node id
        let recipient_bytes = hex::decode(&recipient).map_err(|e| NexxusError::Io(e.to_string()))?;
        if recipient_bytes.len() != 32 {
            return Err(NexxusError::Io("recipient_node_id must be 32 bytes hex".into()));
        }
        let recipient_id = NodeId(recipient_bytes.try_into().map_err(|_| {
            NexxusError::Io("recipient_node_id invalid length".into())
        })?);

        // Recipient X25519 pubkey: explicit param, else our own (loopback/self-test)
        let recipient_pub = match params.get("recipient_x25519_pub").and_then(|v| v.as_str()) {
            Some(h) => {
                let bytes = hex::decode(h).map_err(|e| NexxusError::Io(e.to_string()))?;
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    NexxusError::Io("recipient_x25519_pub must be 32 bytes hex".into())
                })?;
                MontgomeryPoint(arr)
            }
            None => self.network.x25519_pub(),
        };

        // Build and seal SMP envelope
        let (ephemeral_pub, env) = SmpEnvelope::seal(
            self.network.node_id().0,
            recipient_id.0,
            &recipient_pub,
            &payload,
        );

        // Send: explicit addr if given, otherwise route via the Kademlia table
        let result = match &addr {
            Some(a) => {
                let peer_addr: SocketAddr = a
                    .parse()
                    .map_err(|e: std::net::AddrParseError| NexxusError::Io(e.to_string()))?;
                self.network.send_smp_envelope(peer_addr, &env).await
            }
            None => self.network.route_smp_envelope(&env).await,
        };

        // Record in history
        self.record_smp(
            "sent",
            &recipient,
            payload.len(),
            if result.is_ok() { "sent" } else { "failed" },
        )
        .await;

        match result {
            Ok(()) => Ok(serde_json::json!({ "status": "sent", "envelope_id": hex::encode(ephemeral_pub) })),
            Err(e) => Err(e),
        }
    }

    async fn handle_node_pause(&self) -> Result<Value, NexxusError> {
        self.network.set_paused(true);
        Ok(serde_json::json!({ "status": "paused", "paused": true }))
    }

    async fn handle_node_resume(&self) -> Result<Value, NexxusError> {
        self.network.set_paused(false);
        Ok(serde_json::json!({ "status": "resumed", "paused": false }))
    }

    async fn handle_node_connect(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let addr_str = params
            .and_then(|p| p.get("addr").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .ok_or_else(|| NexxusError::Io("missing 'addr'".into()))?;
        let addr: std::net::SocketAddr = addr_str
            .parse()
            .map_err(|_| NexxusError::Io(format!("bad addr: {addr_str}")))?;
        let peer = self.network.send_node_announce(addr).await?;
        Ok(serde_json::json!({
            "addr": addr.to_string(),
            "peer_node_id": hex::encode(peer.0),
        }))
    }

    /// Dial a peer through its Tor onion v3 address (`<56ch>.onion:port`).
    #[cfg(feature = "tor")]
    async fn handle_node_dial_onion(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let addr = params
            .and_then(|p| p.get("addr").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .ok_or_else(|| NexxusError::Io("missing 'addr'".into()))?;
        if !addr.contains(".onion") {
            return Err(NexxusError::Io(format!("not an onion address: {addr}")));
        }
        let ts = self
            .tor_session
            .lock()
            .await
            .clone()
            .ok_or_else(|| NexxusError::Io("tor session not running (NEXXUS_TOR=0?)".into()))?;
        let peer = self.network.dial_onion(&ts, &addr).await?;
        Ok(serde_json::json!({
            "onion": addr,
            "peer_node_id": hex::encode(peer.0),
        }))
    }

    #[cfg(not(feature = "tor"))]
    async fn handle_node_dial_onion(&self, _params: Option<Value>) -> Result<Value, NexxusError> {
        Err(NexxusError::Io(
            "built without tor feature — rebuild with default features".into(),
        ))
    }

    async fn handle_node_upload(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let path = params
            .and_then(|p| p.get("path").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .ok_or_else(|| NexxusError::Io("missing 'path'".into()))?;
        crate::vault::upload_file(&self.network, self.network.store(), std::path::Path::new(&path)).await
    }

    async fn handle_node_download(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let params = params.unwrap_or(Value::Null);
        let root = params
            .get("root").and_then(|v| v.as_str()).map(|s| s.to_string())
            .ok_or_else(|| NexxusError::Io("missing 'root'".into()))?;
        let out = params
            .get("out").and_then(|v| v.as_str()).map(|s| s.to_string())
            .ok_or_else(|| NexxusError::Io("missing 'out'".into()))?;
        crate::vault::download_file(&self.network, self.network.store(), &root, std::path::Path::new(&out)).await
    }

    async fn handle_node_sync_scan(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let drive_dir = if let Some(p) = params.as_ref().and_then(|p| p.get("path")).and_then(|v| v.as_str()) {
            std::path::PathBuf::from(p)
        } else {
            crate::sync::default_drive_dir()
        };
        let engine = crate::sync::SyncEngine::new(drive_dir, self.store.clone(), self.network.clone());
        let rep = engine.scan_and_sync().await?;
        serde_json::to_value(&rep).map_err(|e| NexxusError::Io(e.to_string()))
    }

    fn handle_node_sync_status(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let drive_dir = if let Some(p) = params.as_ref().and_then(|p| p.get("path")).and_then(|v| v.as_str()) {
            std::path::PathBuf::from(p)
        } else {
            crate::sync::default_drive_dir()
        };
        let engine = crate::sync::SyncEngine::new(drive_dir, self.store.clone(), self.network.clone());
        engine.status()
    }

    /// Linux Provider: pin root/hash with price in nano-TON and duration in epochs.
    fn handle_node_provider_pin(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let root = params
            .as_ref()
            .and_then(|p| p.get("root"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NexxusError::Io("param 'root' required".into()))?;
        let price = params
            .as_ref()
            .and_then(|p| p.get("price"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let duration = params
            .as_ref()
            .and_then(|p| p.get("duration"))
            .and_then(|v| v.as_u64())
            .unwrap_or(30);

        if let Ok(hb) = hex::decode(root) {
            if hb.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&hb);
                let chunk_h = nexxus_core::types::ChunkHash(arr);
                let _ = self.store.pin_chunk(&chunk_h);
            }
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let meta_val = serde_json::json!({
            "root": root,
            "price_nano_ton": price,
            "duration_epochs": duration,
            "pinned_at_unix": now,
            "status": "active"
        });
        let key = format!("provider_deal:{root}");
        self.store.put_meta(&key, serde_json::to_string(&meta_val).unwrap_or_default().as_bytes())?;

        Ok(serde_json::json!({
            "ok": true,
            "root": root,
            "price_nano_ton": price,
            "duration_epochs": duration,
            "pinned": true,
            "disclaimer": "accounting only, not payments"
        }))
    }

    fn handle_node_provider_status(&self) -> Result<Value, NexxusError> {
        let cap = self.store.max_store_bytes();
        let used = self.store.store_size().unwrap_or(0);
        let count = self.store.list_chunk_hashes().map(|v| v.len()).unwrap_or(0);
        let deals = self.store.list_meta_prefix("provider_deal:")?;
        Ok(serde_json::json!({
            "provider_mode": "active",
            "active_deals": deals.len(),
            "disk_capacity_bytes": cap,
            "used_bytes": used,
            "stored_chunks": count,
            "pricing_unit": "nano_ton_per_mb_epoch",
            "disclaimer": "accounting only, not payments"
        }))
    }

    fn handle_node_provider_list(&self) -> Result<Value, NexxusError> {
        let deal_entries = self.store.list_meta_prefix("provider_deal:")?;
        let mut deals = Vec::new();
        for (_k, val_bytes) in deal_entries {
            if let Ok(v) = serde_json::from_slice::<Value>(&val_bytes) {
                deals.push(v);
            }
        }
        Ok(serde_json::json!({
            "deals": deals,
            "count": deals.len(),
            "disclaimer": "accounting only, not payments"
        }))
    }

    async fn handle_node_por(&self) -> Result<Value, NexxusError> {
        crate::vault::run_por(self.network.store())
    }

    /// E2: одноразовый аудит пира PoR-challenge по addr (см. P2pNetwork::audit_peer_por).
    async fn handle_node_audit_peer(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let addr_str = params
            .and_then(|p| p.get("addr").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .ok_or_else(|| NexxusError::Io("missing 'addr'".into()))?;
        let addr: std::net::SocketAddr = addr_str
            .parse()
            .map_err(|_| NexxusError::Io(format!("bad addr: {addr_str}")))?;
        self.network.audit_peer_por(addr).await
    }

    async fn handle_node_test_interhost(&self, params: Option<Value>) -> Result<Value, NexxusError> {
        let addr_str = params
            .and_then(|p| p.get("addr").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .ok_or_else(|| NexxusError::Io("missing 'addr'".into()))?;
        let addr: std::net::SocketAddr = addr_str
            .parse()
            .map_err(|_| NexxusError::Io(format!("bad addr: {addr_str}")))?;
        crate::vault::test_interhost(&self.network, addr).await
    }

    /// Run the WebSocket server forever.
    pub async fn run(self: Arc<Self>, api_addr: SocketAddr) -> Result<(), NexxusError> {
        let listener = TcpListener::bind(api_addr)
            .await
            .map_err(|e| NexxusError::Io(format!("api bind failed: {e}")))?;
        println!("nexxusd local API listening on {api_addr}");

        // Inbound SMP: hand the inbox sender to the network and drain received
        // envelopes into smp_history.
        self.network.set_smp_inbox(self.smp_inbox_tx.clone()).await;
        if let Some(mut rx) = self.smp_inbox_rx.lock().await.take() {
            let api = Arc::clone(&self);
            tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    api.record_smp_inbound(
                        &hex::encode(msg.sender_node_id),
                        &hex::encode(msg.recipient_node_id),
                        msg.plaintext.len(),
                        "delivered",
                    )
                    .await;
                }
            });
        }

        while let Ok((stream, _addr)) = listener.accept().await {
            let api = Arc::clone(&self);
            // API-01: cap concurrent WS connections; excess connections are
            // accepted and closed immediately instead of spawning a task.
            let permit = match Arc::clone(&api.ws_conns).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let _permit = permit; // held until the handler finishes
                // E1: plain-HTTP GET /metrics (Prometheus text exposition) for
                // local scrapers. Detected via peek: a real WS handshake carries
                // "Upgrade: websocket" and goes down the WS path unchanged.
                let mut buf = [0u8; 2048];
                if let Ok(n) = stream.peek(&mut buf).await {
                    let head = String::from_utf8_lossy(&buf[..n]);
                    if head.starts_with("GET /metrics")
                        && !head.to_ascii_lowercase().contains("upgrade:")
                    {
                        if let Err(e) = api.handle_metrics_http(stream, &head).await {
                            eprintln!("nexxusd API: /metrics http error: {e}");
                        }
                        return;
                    }
                }
                // API-01: cap WS frame/message sizes so a local client cannot
                // exhaust memory with one giant frame; also cap the handshake.
                let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
                    max_message_size: Some(MAX_WS_MESSAGE_SIZE),
                    max_frame_size: Some(MAX_WS_FRAME_SIZE),
                    accept_unmasked_frames: false,
                    ..Default::default()
                };
                let ws_stream = match accept_async_with_config(stream, Some(config)).await {
                    Ok(ws) => ws,
                    Err(e) => {
                        eprintln!("nexxusd API: WebSocket accept failed: {e}");
                        return;
                    }
                };
                if let Err(e) = api.handle_ws(ws_stream).await {
                    eprintln!("nexxusd API: WebSocket error: {e}");
                }
            });
        }
        Ok(())
    }

    /// E1: plain-HTTP `GET /metrics` — Prometheus text exposition, token-gated
    /// via `Authorization: Bearer <token>` (constant-time compare). Served on
    /// the same localhost API port; WS handshakes never reach this path.
    async fn handle_metrics_http(
        &self,
        mut stream: tokio::net::TcpStream,
        head: &str,
    ) -> Result<(), NexxusError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Read the full header block (peek already consumed nothing).
        let mut full = head.to_string();
        let mut tmp = [0u8; 2048];
        while !full.contains("\r\n\r\n") {
            match stream.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => full.push_str(&String::from_utf8_lossy(&tmp[..n])),
            }
        }
        let token_ok = match self.api_token.lock().unwrap().as_ref() {
            None => false, // fail-closed
            Some(expected) => {
                let supplied = full
                    .lines()
                    .find_map(|l| {
                        let l = l.to_ascii_lowercase();
                        l.strip_prefix("authorization: bearer ")
                            .map(|t| t.trim().to_string())
                    })
                    .unwrap_or_default();
                !supplied.is_empty()
                    && supplied.len() == expected.len()
                    && bool::from(subtle::ConstantTimeEq::ct_eq(supplied.as_bytes(), expected.as_bytes()))
            }
        };
        let body = if token_ok {
            let mut body = self.network.metrics.prom();
            let store = self.network.store();
            let used = store.store_size().unwrap_or(0);
            let cap = store.max_store_bytes();
            let free = store.available_space().unwrap_or(0);
            let chunks = store.list_chunk_hashes().map(|v| v.len()).unwrap_or(0);
            body.push_str("# HELP nexxus_store Storage capacity gauges.\n# TYPE nexxus_store gauge\n");
            body.push_str(&format!("nexxus_store_used_bytes {used}\n"));
            body.push_str(&format!("nexxus_store_cap_bytes {cap}\n"));
            body.push_str(&format!("nexxus_store_disk_free_bytes {free}\n"));
            body.push_str(&format!("nexxus_store_chunks {chunks}\n"));
            // E0: prod gauges — peers, RSS, uptime (plan item «метрики в проде»).
            let peers_connected = self.connected_peers.lock().await.len();
            let peers_known = self.network.known_peers().await.len();
            let rss_bytes = rss_bytes().unwrap_or(0);
            let uptime_s = self.start_time.elapsed().map(|d| d.as_secs()).unwrap_or(0);
            body.push_str("# HELP nexxus_runtime Runtime gauges.\n# TYPE nexxus_runtime gauge\n");
            body.push_str(&format!("nexxus_peers_connected {peers_connected}\n"));
            body.push_str(&format!("nexxus_peers_known {peers_known}\n"));
            body.push_str(&format!("nexxus_process_rss_bytes {rss_bytes}\n"));
            body.push_str(&format!("nexxus_uptime_seconds {uptime_s}\n"));
            body
        } else {
            String::from("unauthorized\n")
        };
        let status = if token_ok { "200 OK" } else { "401 Unauthorized" };
        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(resp.as_bytes())
            .await
            .map_err(|e| NexxusError::Io(format!("metrics http write: {e}")))?;
        Ok(())
    }

    async fn handle_ws(
        &self,
        ws_stream: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) -> Result<(), NexxusError> {
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        // Соединение начинается неаутентифицированным; после успешного
        // `auth` на нём можно выполнить один настоящий запрос.
        let mut authenticated = false;
        while let Some(msg) = ws_receiver.next().await {
            let msg = msg.map_err(|e| NexxusError::Io(e.to_string()))?;
            match msg {
                Message::Text(text) => {
                    let req: JsonRpcRequest = match serde_json::from_str(&text) {
                        Ok(r) => r,
                        Err(_) => {
                            let resp = error_response(None, ERR_INVALID_REQUEST, "invalid JSON".into());
                            let _ = ws_sender
                                .send(Message::Text(serde_json::to_string(&resp).unwrap()))
                                .await;
                            continue;
                        }
                    };

                    // Гейт аутентификации: обрабатывает ping/auth/отказы сам.
                    let expected = self.api_token.lock().unwrap().clone();
                    if let Some((resp, close_after)) = auth_gate(expected.as_deref(), &req, &mut authenticated) {
                        let text = serde_json::to_string(&resp).unwrap_or_default();
                        if ws_sender.send(Message::Text(text)).await.is_err() {
                            break;
                        }
                        if close_after {
                            let _ = ws_sender.close().await;
                            break;
                        }
                        continue;
                    }

                    let resp = self.handle_request(req).await;
                    let text = serde_json::to_string(&resp).unwrap_or_default();
                    if ws_sender.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                    // Duress-PIN: ответ уже отправлен (ложный успех) —
                    // теперь необратимо затираем стор и выходим.
                    if self.duress_wipe.load(std::sync::atomic::Ordering::SeqCst) {
                        let _ = ws_sender.close().await;
                        let store_path = self.store.path().to_path_buf();
                        eprintln!(
                            "nexxusd: DURESS PIN entered — wiping store {} and panic state",
                            store_path.display()
                        );
                        let _ = crate::panic::wipe_file(&store_path);
                        let _ = crate::panic::wipe_file(&crate::panic::PanicManager::default_path(&store_path));
                        std::process::exit(0);
                    }
                    // Корректно закрываем WebSocket соединение после ответа,
                    // чтобы клиент не оставлял висячие соединения.
                    let _ = ws_sender.close().await;
                    break;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, params: Option<Value>) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            method: method.into(),
            params,
            id: Some(serde_json::json!(1)),
        }
    }

    fn resp_code(resp: &JsonRpcResponse) -> i32 {
        resp.error.as_ref().map(|e| e.code).unwrap_or(0)
    }

    #[test]
    fn gate_denies_methods_without_auth() {
        let mut auth = false;
        let r = auth_gate(Some("secret"), &req("node_status", None), &mut auth).unwrap();
        assert_eq!(resp_code(&r.0), ERR_UNAUTHORIZED);
        assert!(r.1, "соединение должно закрываться");
        assert!(!auth);
    }

    #[test]
    fn gate_allows_ping_without_auth() {
        let mut auth = false;
        let r = auth_gate(Some("secret"), &req("ping", None), &mut auth).unwrap();
        assert_eq!(resp_code(&r.0), 0);
        assert!(!r.1, "ping не закрывает соединение");
        assert!(!auth);
    }

    #[test]
    fn accounting_export_signature_verifies_and_tamper_fails() {
        // E3: подпись ed25519 над canonical JSON отчёта — verify с pubkey,
        // tamper с отчётом ломает проверку.
        let identity = nexxus_core::keys::identity::Identity::generate();
        let report = serde_json::json!({
            "kind": "nexxus_accounting_export",
            "node_id": hex::encode(identity.node_id().0),
            "disclaimer": "accounting only — not payments, not on-chain settlement",
        });
        let canonical = serde_json::to_string(&report).unwrap();
        let sig = identity.sign(canonical.as_bytes());
        assert!(nexxus_core::keys::identity::Identity::verify(
            &identity.verifying_key,
            canonical.as_bytes(),
            &sig
        ));
        let tampered = canonical.replace("accounting only", "PAYMENTS READY");
        assert!(!nexxus_core::keys::identity::Identity::verify(
            &identity.verifying_key,
            tampered.as_bytes(),
            &sig
        ));
    }

    #[test]
    fn gate_rejects_wrong_token_and_closes() {
        let mut auth = false;
        let r = auth_gate(
            Some("secret"),
            &req("auth", Some(serde_json::json!({"token": "wrong"}))),
            &mut auth,
        )
        .unwrap();
        assert_eq!(resp_code(&r.0), ERR_UNAUTHORIZED);
        assert!(r.1);
        assert!(!auth);
    }

    #[test]
    fn gate_accepts_correct_token_and_keeps_connection_open() {
        let mut auth = false;
        let r = auth_gate(
            Some("secret"),
            &req("auth", Some(serde_json::json!({"token": "secret"}))),
            &mut auth,
        )
        .unwrap();
        assert_eq!(resp_code(&r.0), 0);
        assert!(!r.1, "после auth соединение остаётся открытым для запроса");
        assert!(auth);

        // После auth гейт больше не перехватывает — диспетчеризация обычная.
        assert!(auth_gate(Some("secret"), &req("node_status", None), &mut auth).is_none());
    }

    #[test]
    fn gate_fails_closed_without_configured_token() {
        let mut auth = false;
        // Даже верный-looking auth отклоняется, если токен не задан.
        let r = auth_gate(None, &req("auth", Some(serde_json::json!({"token": "x"}))), &mut auth).unwrap();
        assert_eq!(resp_code(&r.0), ERR_UNAUTHORIZED);
        // ping по-прежнему работает — для health-check монитора.
        let r = auth_gate(None, &req("ping", None), &mut auth).unwrap();
        assert_eq!(resp_code(&r.0), 0);
    }

    #[test]
    fn contact_link_generation_and_parsing_roundtrip() {
        // Specification §7: Contact exchange standard test
        let uri = "nexxus://contact?addr=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20&onion=25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenjpzad.onion&name=TestNode&fp=1234567890abcdef";
        let parsed = nexxus_core::smp::ContactLink::from_uri(uri).unwrap();
        assert_eq!(parsed.name, "TestNode");
        assert_eq!(parsed.onion, "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenjpzad.onion");
        assert_eq!(parsed.to_uri(), uri);
    }

    #[tokio::test]
    async fn sync_api_scan_and_status_roundtrip() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("store.redb");
        let store = Arc::new(ChunkStore::open(&store_path).unwrap());
        let net = Arc::new(P2pNetwork::new(
            NodeId([0x42; 32]),
            "127.0.0.1:0".parse().unwrap(),
            store.clone(),
        ));
        let api = LocalApi::new(net.clone(), store.clone());

        let drive = dir.path().join("test_drive");
        std::fs::create_dir_all(&drive).unwrap();
        std::fs::write(drive.join("doc.txt"), b"Sovereign Drive sync content").unwrap();

        let req_scan = req(
            "node_sync_scan",
            Some(serde_json::json!({ "path": drive.display().to_string() })),
        );
        let resp_scan = api.handle_request(req_scan).await;
        assert_eq!(resp_code(&resp_scan), 0);
        let res = resp_scan.result.unwrap();
        assert_eq!(res["scanned_files"], 1);
        assert_eq!(res["newly_synced"], 1);

        let req_status = req(
            "node_sync_status",
            Some(serde_json::json!({ "path": drive.display().to_string() })),
        );
        let resp_status = api.handle_request(req_status).await;
        assert_eq!(resp_code(&resp_status), 0);
        let res2 = resp_status.result.unwrap();
        assert_eq!(res2["synced_files_count"], 1);
        assert_eq!(res2["files"][0]["relative_path"], "doc.txt");
    }

    #[tokio::test]
    async fn provider_api_pin_status_and_list_roundtrip() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("store.redb");
        let store = Arc::new(ChunkStore::open(&store_path).unwrap());
        let net = Arc::new(P2pNetwork::new(
            NodeId([0x42; 32]),
            "127.0.0.1:0".parse().unwrap(),
            store.clone(),
        ));
        let api = LocalApi::new(net.clone(), store.clone());

        let fake_root = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let req_pin = req(
            "node_provider_pin",
            Some(serde_json::json!({
                "root": fake_root,
                "price": 1000,
                "duration": 50,
            })),
        );
        let resp_pin = api.handle_request(req_pin).await;
        assert_eq!(resp_code(&resp_pin), 0);
        let pin_res = resp_pin.result.unwrap();
        assert_eq!(pin_res["ok"], true);
        assert_eq!(pin_res["price_nano_ton"], 1000);
        assert_eq!(pin_res["duration_epochs"], 50);
        assert_eq!(pin_res["disclaimer"], "accounting only, not payments");

        let req_status = req("node_provider_status", None);
        let resp_status = api.handle_request(req_status).await;
        assert_eq!(resp_code(&resp_status), 0);
        let status_res = resp_status.result.unwrap();
        assert_eq!(status_res["provider_mode"], "active");
        assert_eq!(status_res["active_deals"], 1);
        assert_eq!(status_res["disclaimer"], "accounting only, not payments");

        let req_list = req("node_provider_list", None);
        let resp_list = api.handle_request(req_list).await;
        assert_eq!(resp_code(&resp_list), 0);
        let list_res = resp_list.result.unwrap();
        assert_eq!(list_res["count"], 1);
        assert_eq!(list_res["deals"][0]["root"], fake_root);
        assert_eq!(list_res["deals"][0]["price_nano_ton"], 1000);
    }
}
