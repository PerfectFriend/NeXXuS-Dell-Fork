//! Каталог-релей: список известных адресов нод (ADR-0011).
//!
//! Нода публикует свою подписанную запись (адреса LAN/Tailscale/Tor) в
//! каталоге и забирает записи других. Каталог — отдельный подкомандный
//! режим `nexxusd directory` (обычно живёт на хосте-релее).
//!
//! Формат записи — JSON с фиксированным порядком полей; подпись Ed25519
//! поверх канонического JSON записи, так что подделать адрес нельзя.
//!
//! HTTP/1.1 реализован здесь намеренно минимально: без внешних HTTP-крейтов
//! (весь стек проекта — Rust), только то, что нужно клиенту и серверу.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ed25519_dalek::VerifyingKey;
use nexxus_core::keys::identity::Identity;
use serde::{Deserialize, Serialize};

/// Адрес ноды в каталоге.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddrRecord {
    /// "lan" | "tailscale" | "tor" | "directory"
    pub transport: String,
    /// IP или onion-адрес (без порта).
    pub addr: String,
    pub port: u16,
}

/// Запись каталога: подписанный список адресов одной ноды.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryRecord {
    /// node_id в hex.
    pub node_id: String,
    /// Ed25519 pubkey в hex.
    pub pubkey: String,
    /// cluster_tag в hex.
    pub cluster_tag: String,
    pub addrs: Vec<AddrRecord>,
    /// unix-время публикации.
    pub ts: u64,
}

/// Подписанная обёртка: запись + подпись (hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRecord {
    pub record: DirectoryRecord,
    pub sig: String,
}

/// Канонические байты для подписи (порядок полей фиксирован структурой).
pub fn record_signing_bytes(record: &DirectoryRecord) -> Result<Vec<u8>, String> {
    serde_json::to_vec(record).map_err(|e| format!("serialize record: {e}"))
}

/// Подписать запись.
pub fn sign_record(id: &Identity, record: &DirectoryRecord) -> Result<SignedRecord, String> {
    let bytes = record_signing_bytes(record)?;
    let sig = id.sign(&bytes);
    Ok(SignedRecord {
        record: record.clone(),
        sig: hex::encode(sig),
    })
}

/// Проверить подпись записи по её pubkey.
pub fn verify_record(sr: &SignedRecord) -> Result<DirectoryRecord, String> {
    let pk = hex::decode(&sr.record.pubkey).map_err(|e| format!("bad pubkey hex: {e}"))?;
    if pk.len() != 32 {
        return Err("pubkey must be 32 bytes".into());
    }
    let pk32: [u8; 32] = pk
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    let vk = VerifyingKey::from_bytes(&pk32).map_err(|e| format!("bad pubkey: {e}"))?;
    let sig = hex::decode(&sr.sig).map_err(|e| format!("bad sig hex: {e}"))?;
    if sig.len() != 64 {
        return Err("signature must be 64 bytes".into());
    }
    let mut s = [0u8; 64];
    s.copy_from_slice(&sig);
    let bytes = record_signing_bytes(&sr.record)?;
    if !Identity::verify(&vk, &bytes, &s) {
        return Err("bad record signature".into());
    }
    Ok(sr.record.clone())
}

/// Состояние каталога: node_id → запись (последняя выигрывает).
#[derive(Clone, Default)]
pub struct DirectoryState {
    inner: Arc<Mutex<HashMap<String, DirectoryRecord>>>,
    path: PathBuf,
}

impl DirectoryState {
    pub fn new(path: PathBuf) -> Self {
        let inner = HashMap::new();
        let s = Self {
            inner: Arc::new(Mutex::new(inner)),
            path,
        };
        s.load();
        s
    }

    fn load(&self) {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return;
        };
        let Ok(map) = serde_json::from_str::<HashMap<String, DirectoryRecord>>(&text) else {
            return;
        };
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = map;
    }

    fn persist(&self) {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(text) = serde_json::to_string_pretty(&*guard) else {
            return;
        };
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(&self.path, text);
    }

    /// Принять проверенную запись.
    pub fn put(&self, record: DirectoryRecord) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(record.node_id.clone(), record);
        drop(guard);
        self.persist();
    }

    /// Все записи, свежие первые.
    pub fn list(&self) -> Vec<DirectoryRecord> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<DirectoryRecord> = guard.values().cloned().collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.ts));
        v
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Запустить каталог-релей (HTTP-сервер).
pub async fn serve(bind: SocketAddr, state: DirectoryState) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("nexxusd: directory listening on {bind}");
    loop {
        let (mut sock, _peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let _ = handle_conn(&mut sock, state).await;
        });
    }
}

/// Обработать один HTTP-запрос.
async fn handle_conn(sock: &mut tokio::net::TcpStream, state: DirectoryState) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    // читаем заголовки
    let head_end = loop {
        if let Some(p) = find_subslice(&buf, b"\r\n\r\n") {
            break p + 4;
        }
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return Ok(());
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    let mut content_length = 0usize;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length.min(body.len()));

    let (status, response) = match (method, path.split('?').next().unwrap_or(path)) {
        ("POST", "/publish") => match serde_json::from_slice::<SignedRecord>(&body) {
            Ok(sr) => match verify_record(&sr) {
                Ok(rec) => {
                    state.put(rec);
                    (200, serde_json::json!({"ok": true}).to_string())
                }
                Err(e) => (400, serde_json::json!({"ok": false, "error": e}).to_string()),
            },
            Err(e) => (400, serde_json::json!({"ok": false, "error": e.to_string()}).to_string()),
        },
        ("GET", "/peers") => {
            let peers = state.list();
            (
                200,
                serde_json::json!({"peers": peers}).to_string(),
            )
        }
        ("GET", "/healthz") => (
            200,
            serde_json::json!({"ok": true, "count": state.len()}).to_string(),
        ),
        _ => (404, serde_json::json!({"ok": false, "error": "not found"}).to_string()),
    };

    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        match status {
            200 => "OK",
            400 => "Bad Request",
            _ => "Not Found",
        },
        response.len(),
        response
    );
    sock.write_all(resp.as_bytes()).await?;
    sock.flush().await?;
    Ok(())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Опубликовать свою запись в каталоге.
pub async fn publish(url: &str, sr: &SignedRecord) -> Result<(), String> {
    let body = serde_json::to_vec(sr).map_err(|e| e.to_string())?;
    let resp = http_request(url, "POST", "/publish", &body).await?;
    if !resp.contains("\"ok\":true") && !resp.contains("\"ok\": true") {
        return Err(format!("publish rejected: {}", truncate(&resp, 160)));
    }
    Ok(())
}

/// Забрать записи из каталога.
pub async fn fetch(url: &str) -> Result<Vec<DirectoryRecord>, String> {
    let resp = http_request(url, "GET", "/peers", &[]).await?;
    let v: serde_json::Value = serde_json::from_str(&resp).map_err(|e| format!("bad json: {e}"))?;
    let peers = v
        .get("peers")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for p in peers {
        if let Ok(rec) = serde_json::from_value::<DirectoryRecord>(p) {
            out.push(rec);
        }
    }
    Ok(out)
}

/// Минимальный HTTP-клиент: GET/POST, ответ читаем до конца по Content-Length
/// или до закрытия соединения.
async fn http_request(
    url: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<String, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// supported: {url}"))?;
    let (hostport, base_path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| format!("bad port in {url}"))?,
        ),
        None => (hostport.to_string(), 80u16),
    };
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|_| format!("bad host in {url}"))?;
    let mut sock = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map_err(|_| "connect timeout".to_string())?
    .map_err(|e| format!("connect: {e}"))?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut req = format!(
        "{} {}{} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        method,
        base_path,
        path,
        hostport,
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    sock.write_all(&req).await.map_err(|e| e.to_string())?;
    sock.flush().await.map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).await.map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "bad http response".to_string())?;
    if !head.starts_with("HTTP/1.1 200") {
        return Err(format!("http status: {}", head.lines().next().unwrap_or("?")));
    }
    Ok(body.to_string())
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Состояние по умолчанию: файл в каталоге данных ноды.
#[allow(dead_code)]
pub fn default_state_path(dir: &Path) -> PathBuf {
    dir.join("directory.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_sign_and_verify() {
        let id = Identity::generate();
        let rec = DirectoryRecord {
            node_id: hex::encode(id.node_id().0),
            pubkey: hex::encode(id.verifying_key.to_bytes()),
            cluster_tag: hex::encode([7u8; 16]),
            addrs: vec![AddrRecord {
                transport: "lan".into(),
                addr: "192.168.1.2".into(),
                port: 4001,
            }],
            ts: 42,
        };
        let sr = sign_record(&id, &rec).unwrap();
        assert_eq!(verify_record(&sr).unwrap(), rec);
    }

    #[test]
    fn tampered_record_is_rejected() {
        let id = Identity::generate();
        let rec = DirectoryRecord {
            node_id: hex::encode(id.node_id().0),
            pubkey: hex::encode(id.verifying_key.to_bytes()),
            cluster_tag: hex::encode([7u8; 16]),
            addrs: vec![AddrRecord {
                transport: "lan".into(),
                addr: "10.0.0.1".into(),
                port: 4001,
            }],
            ts: 1,
        };
        let mut sr = sign_record(&id, &rec).unwrap();
        sr.record.addrs[0].addr = "10.0.0.2".into();
        assert!(verify_record(&sr).is_err());
    }

    #[test]
    fn state_put_and_list() {
        let dir = std::env::temp_dir().join(format!("nexxus-dir-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let st = DirectoryState::new(dir.join("d.json"));
        let rec = DirectoryRecord {
            node_id: "aa".into(),
            pubkey: "bb".into(),
            cluster_tag: "cc".into(),
            addrs: vec![],
            ts: 5,
        };
        st.put(rec.clone());
        assert_eq!(st.len(), 1);
        assert_eq!(st.list()[0], rec);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
