//! Авто-дискавери нод (ADR-0011): LAN-beacon, LAN-sweep, Tailscale-пиры,
//! реестр кандидатов. Всё на Rust, без внешних демонов.
//!
//! Транспорты:
//!   * LAN      — UDP-broadcast beacon (подписанный) + TCP-sweep локальной подсети;
//!   * Tailscale — адреса 100.64.0.0/10 из `tailscale status --json`;
//!   * Tor      — onion-адрес приходит в beacon/каталоге (сам dial — в network.rs).
//!
//! Кластер: `cluster_tag = HMAC-SHA256(seed, "nexxus/cluster/v1")[0..16]` —
//! одинаковый BIP-39 mnemonic ⇒ одинаковый tag ⇒ «свои» ноды узнаются без настроек.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use hmac::{Hmac, Mac};
use nexxus_core::keys::identity::Identity;
use sha2::Sha256;

use crate::net::network::P2pNetwork;

type HmacSha256 = Hmac<Sha256>;

/// Магический префикс beacon-пакета.
pub const BEACON_MAGIC: &[u8; 4] = b"NXBE";
/// Версия формата beacon.
pub const BEACON_VERSION: u8 = 1;
/// Порт UDP-broadcast по умолчанию.
pub const DEFAULT_BEACON_PORT: u16 = 4002;
/// Domain separation для подписи beacon.
pub const BEACON_DOMAIN: &[u8] = b"nexxus/beacon/v1";
/// Domain separation для cluster tag.
pub const CLUSTER_DOMAIN: &[u8] = b"nexxus/cluster/v1";

/// Текущее время в секундах epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Cluster tag владельца: одинаковый seed ⇒ одинаковый tag.
pub fn cluster_tag_from_seed(seed: &[u8; 64]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(CLUSTER_DOMAIN).expect("hmac accepts any key");
    mac.update(seed);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&out[..16]);
    tag
}

/// Транспорт, по которому найден пир.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Lan,
    Tailscale,
    Tor,
    Directory,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Lan => "lan",
            Transport::Tailscale => "tailscale",
            Transport::Tor => "tor",
            Transport::Directory => "directory",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "lan" => Some(Transport::Lan),
            "tailscale" => Some(Transport::Tailscale),
            "tor" => Some(Transport::Tor),
            "directory" => Some(Transport::Directory),
            _ => None,
        }
    }
}

/// Подписанное объявление ноды в LAN (UDP-broadcast) и в каталоге.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    pub node_id: [u8; 32],
    pub pubkey: [u8; 32],
    pub cluster_tag: [u8; 16],
    pub p2p_port: u16,
    pub onion: Option<String>,
    pub ts: u64,
}

impl Beacon {
    /// Тело beacon (без подписи) — то, что подписывается.
    pub fn encode_body(&self) -> Vec<u8> {
        let onion = self.onion.clone().unwrap_or_default();
        let mut v = Vec::with_capacity(96 + onion.len());
        v.extend_from_slice(BEACON_MAGIC);
        v.push(BEACON_VERSION);
        v.push(if self.onion.is_some() { 1 } else { 0 });
        v.extend_from_slice(&self.ts.to_be_bytes());
        v.extend_from_slice(&self.node_id);
        v.extend_from_slice(&self.pubkey);
        v.extend_from_slice(&self.cluster_tag);
        v.extend_from_slice(&self.p2p_port.to_be_bytes());
        v.push(onion.len() as u8);
        v.extend_from_slice(onion.as_bytes());
        v
    }

    pub fn decode_body(b: &[u8]) -> Result<Beacon, String> {
        if b.len() < 4 + 1 + 1 + 8 + 32 + 32 + 16 + 2 + 1 {
            return Err("beacon: body too short".into());
        }
        if &b[0..4] != BEACON_MAGIC {
            return Err("beacon: bad magic".into());
        }
        if b[4] != BEACON_VERSION {
            return Err(format!("beacon: unsupported version {}", b[4]));
        }
        let has_onion = b[5] == 1;
        let ts = u64::from_be_bytes(b[6..14].try_into().map_err(|_| "beacon: ts")?);
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&b[14..46]);
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&b[46..78]);
        let mut cluster_tag = [0u8; 16];
        cluster_tag.copy_from_slice(&b[78..94]);
        let port = u16::from_be_bytes(b[94..96].try_into().map_err(|_| "beacon: port")?);
        let olen = b[96] as usize;
        if b.len() < 97 + olen {
            return Err("beacon: truncated onion".into());
        }
        let onion = if has_onion {
            let s = std::str::from_utf8(&b[97..97 + olen]).map_err(|_| "beacon: onion utf8")?;
            Some(s.to_string())
        } else {
            None
        };
        Ok(Beacon {
            node_id,
            pubkey,
            cluster_tag,
            p2p_port: port,
            onion,
            ts,
        })
    }

    /// Байты, которые подписываются (domain-separated).
    pub fn signing_bytes(body: &[u8]) -> Vec<u8> {
        let mut v = BEACON_DOMAIN.to_vec();
        v.extend_from_slice(body);
        v
    }
}

/// Подписать тело beacon.
pub fn sign_beacon(id: &Identity, body: &[u8]) -> [u8; 64] {
    id.sign(&Beacon::signing_bytes(body))
}

/// Проверить подпись и разобрать beacon.
pub fn verify_beacon(pubkey: &VerifyingKey, raw: &[u8]) -> Result<Beacon, String> {
    if raw.len() < 64 {
        return Err("beacon: too short for signature".into());
    }
    let (body, sig) = raw.split_at(raw.len() - 64);
    let mut s = [0u8; 64];
    s.copy_from_slice(sig);
    if !Identity::verify(pubkey, &Beacon::signing_bytes(body), &s) {
        return Err("beacon: bad signature".into());
    }
    Beacon::decode_body(body)
}

/// Кандидат в пиры (из любого источника).
#[derive(Debug, Clone)]
pub struct Candidate {
    pub addr: SocketAddr,
    pub transport: Transport,
    pub node_id: Option<[u8; 32]>,
    /// cluster_tag пира, если он его объявил (beacon/каталог). None — неизвестен
    /// (например, пир найден TCP-sweep'ом: чужой код наш тег не публикует).
    pub cluster_tag: Option<[u8; 16]>,
    pub source: &'static str,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Реестр кандидатов в пиры.
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<Mutex<HashMap<String, Candidate>>>,
}

impl Registry {
    pub fn upsert(
        &self,
        addr: SocketAddr,
        transport: Transport,
        node_id: Option<[u8; 32]>,
        cluster_tag: Option<[u8; 16]>,
        source: &'static str,
    ) {
        let now = now_secs();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = addr.to_string();
        match guard.get_mut(&key) {
            Some(c) => {
                c.last_seen = now;
                if node_id.is_some() {
                    c.node_id = node_id;
                }
                if cluster_tag.is_some() {
                    c.cluster_tag = cluster_tag;
                }
            }
            None => {
                guard.insert(
                    key,
                    Candidate {
                        addr,
                        transport,
                        node_id,
                        cluster_tag,
                        source,
                        first_seen: now,
                        last_seen: now,
                    },
                );
            }
        }
    }

    pub fn list(&self) -> Vec<Candidate> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<Candidate> = guard.values().cloned().collect();
        v.sort_by_key(|c| c.last_seen);
        v
    }

    /// Количество кандидатов (для API/логов).
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Локальные IPv4-подсети: из `/proc/net/route` берём интерфейс по умолчанию,
/// из `ip -j addr` — адрес и префикс. Fallback: первый не-loopback IPv4 с /24.
pub fn local_lan_cidrs() -> Vec<(Ipv4Addr, u8)> {
    let mut default_iface: Option<String> = None;
    if let Ok(routes) = std::fs::read_to_string("/proc/net/route") {
        for line in routes.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() > 2 && cols[1] == "00000000" {
                default_iface = Some(cols[0].to_string());
                break;
            }
        }
    }
    let mut out = Vec::new();
    if let Some(iface) = default_iface {
        if let Ok(json) = std::process::Command::new("ip")
            .args(["-4", "-j", "addr", "show", "dev", &iface])
            .output()
        {
            if let Ok(text) = String::from_utf8(json.stdout) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(list) = v.as_array() {
                        for e in list {
                            if let Some(a) = e.get("addr_info").and_then(|x| x.as_array()) {
                                for ai in a {
                                    if let (Some(ip), Some(plen)) = (
                                        ai.get("local").and_then(|x| x.as_str()),
                                        ai.get("prefixlen").and_then(|x| x.as_u64()),
                                    ) {
                                        if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                                            out.push((ipv4, plen as u8));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if out.is_empty() {
        // Fallback: первый не-loopback IPv4 из вывода `ip -4 addr`.
        if let Ok(json) = std::process::Command::new("ip").args(["-4", "-j", "addr"]).output() {
            if let Ok(text) = String::from_utf8(json.stdout) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(list) = v.as_array() {
                        for e in list {
                            if let Some(a) = e.get("addr_info").and_then(|x| x.as_array()) {
                                for ai in a {
                                    if let Some(ip) = ai.get("local").and_then(|x| x.as_str()) {
                                        if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                                            if !ipv4.is_loopback() {
                                                out.push((ipv4, 24));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Все адреса хоста в CIDR (кроме network/broadcast).
pub fn hosts_in_cidr(ip: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let base = u32::from(ip) & (!0u32 << (32 - prefix.min(32)));
    let size = 1u32 << (32 - prefix.min(32));
    let mut out = Vec::new();
    for i in 1..size.saturating_sub(1) {
        out.push(Ipv4Addr::from(base + i));
    }
    out
}

/// Пир из Tailscale: имя и адреса 100.64.0.0/10.
#[derive(Debug, Clone)]
pub struct TailscalePeer {
    /// Имя хоста в tailnet (для показа в дашборде).
    #[allow(dead_code)]
    pub host_name: String,
    pub ips: Vec<Ipv4Addr>,
}

/// Путь к CLI tailscale: в systemd-юнитах PATH минимальный и не содержит
/// /snap/bin, поэтому проверяем известные места явно (snap/apt/локальный).
pub fn tailscale_cli() -> Option<String> {
    const CANDIDATES: [&str; 4] = [
        "tailscale",
        "/snap/bin/tailscale",
        "/usr/bin/tailscale",
        "/usr/local/bin/tailscale",
    ];
    for c in CANDIDATES {
        if c.contains('/') {
            if std::path::Path::new(c).exists() {
                return Some(c.to_string());
            }
        } else if let Ok(out) = std::process::Command::new(c).arg("version").output() {
            if out.status.success() {
                return Some(c.to_string());
            }
        }
    }
    None
}

/// Наш собственный tailnet-адрес (`tailscale ip -4`).
pub fn tailscale_self_ip() -> Option<Ipv4Addr> {
    let cli = tailscale_cli()?;
    let out = std::process::Command::new(cli).args(["ip", "-4"]).output().ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .and_then(|l| l.parse().ok())
}

/// Пиры tailnet из `tailscale status --json`.
pub fn tailscale_peers() -> Vec<TailscalePeer> {
    let Some(cli) = tailscale_cli() else {
        return Vec::new();
    };
    let Ok(out) = std::process::Command::new(cli)
        .args(["status", "--json"])
        .output()
    else {
        return Vec::new();
    };
    let Ok(text) = String::from_utf8(out.stdout) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let mut peers = Vec::new();
    if let Some(map) = v.get("Peer").and_then(|x| x.as_object()) {
        for (_, p) in map {
            let host_name = p
                .get("HostName")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let mut ips = Vec::new();
            if let Some(list) = p.get("TailscaleIPs").and_then(|x| x.as_array()) {
                for ip in list {
                    if let Some(s) = ip.as_str() {
                        if let Ok(v4) = s.parse::<Ipv4Addr>() {
                            if is_tailscale_ip(v4) {
                                ips.push(v4);
                            }
                        }
                    }
                }
            }
            if !ips.is_empty() {
                peers.push(TailscalePeer { host_name, ips });
            }
        }
    }
    peers
}

/// CGNAT-диапазон Tailscale (100.64.0.0/10).
pub fn is_tailscale_ip(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..128).contains(&o[1])
}

/// Подключиться к адресу и выполнить signed handshake; вернуть node_id и RTT.
pub async fn handshake_probe(
    net: &P2pNetwork,
    addr: SocketAddr,
    timeout_ms: u64,
) -> Result<([u8; 32], u128), String> {
    let (_stream, hs, rtt) = connect_handshake(net, addr, timeout_ms).await?;
    Ok((hs.peer_id.0, rtt))
}

/// Подключиться + handshake, вернуть живой сокет (для Probe по тому же каналу).
pub async fn connect_handshake(
    net: &P2pNetwork,
    addr: SocketAddr,
    timeout_ms: u64,
) -> Result<(tokio::net::TcpStream, crate::net::network::Handshake, u128), String> {
    let started = std::time::Instant::now();
    let connect = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map_err(|_| "connect timeout".to_string())?
    .map_err(|e| format!("connect: {e}"))?;
    connect.set_nodelay(true).ok();
    let mut stream = connect;
    let hs = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        net.announce_handshake(&mut stream, 0xD15C),
    )
    .await
    .map_err(|_| "handshake timeout".to_string())?
    .map_err(|e| format!("handshake: {e}"))?;
    Ok((stream, hs, started.elapsed().as_millis()))
}

/// TCP-sweep локальной подсети: ищем ноды NeXXuS на P2P-порту.
pub async fn sweep_lan(
    net: Arc<P2pNetwork>,
    cidr: (Ipv4Addr, u8),
    port: u16,
    registry: Registry,
    concurrency: usize,
) -> usize {
    let hosts = hosts_in_cidr(cidr.0, cidr.1);
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut found = 0usize;
    let mut tasks = Vec::new();
    for ip in hosts {
        let sem = Arc::clone(&sem);
        let net = Arc::clone(&net);
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
            if let Ok((node_id, _rtt)) = handshake_probe(&net, addr, 700).await {
                Some((addr, node_id))
            } else {
                None
            }
        }));
    }
    for t in tasks {
        if let Ok(Some((addr, node_id))) = t.await {
            registry.upsert(addr, Transport::Lan, Some(node_id), None, "lan-sweep");
            found += 1;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_tag_is_deterministic_and_seed_bound() {
        let a = [7u8; 64];
        let b = [7u8; 64];
        let c = [8u8; 64];
        assert_eq!(cluster_tag_from_seed(&a), cluster_tag_from_seed(&b));
        assert_ne!(cluster_tag_from_seed(&a), cluster_tag_from_seed(&c));
    }

    #[test]
    fn beacon_roundtrip_and_tamper_detection() {
        let id = Identity::generate();
        let b = Beacon {
            node_id: id.node_id().0,
            pubkey: id.verifying_key.to_bytes(),
            cluster_tag: [3u8; 16],
            p2p_port: 4001,
            onion: Some("abc.onion".into()),
            ts: 42,
        };
        let body = b.encode_body();
        let sig = sign_beacon(&id, &body);
        let mut raw = body.clone();
        raw.extend_from_slice(&sig);
        let got = verify_beacon(&id.verifying_key, &raw).unwrap();
        assert_eq!(got, b);

        // подмена байта → подпись не проходит
        let mut bad = raw.clone();
        bad[20] ^= 0x01;
        assert!(verify_beacon(&id.verifying_key, &bad).is_err());
    }

    #[test]
    fn beacon_body_limits() {
        assert!(Beacon::decode_body(b"NXB").is_err());
        assert!(Beacon::decode_body(b"XXXX\x01\x00").is_err());
    }

    #[test]
    fn cidr_hosts_exclude_network_and_broadcast() {
        let hosts = hosts_in_cidr(Ipv4Addr::new(192, 168, 58, 10), 24);
        assert_eq!(hosts.len(), 254);
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 58, 0)));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 58, 255)));
        assert!(hosts.contains(&Ipv4Addr::new(192, 168, 58, 1)));
    }

    #[test]
    fn tailscale_range_detection() {
        assert!(is_tailscale_ip(Ipv4Addr::new(100, 101, 102, 103)));
        assert!(!is_tailscale_ip(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(!is_tailscale_ip(Ipv4Addr::new(192, 168, 58, 1)));
    }

    #[test]
    fn registry_upsert_keeps_first_seen_and_updates_node_id() {
        let reg = Registry::default();
        let addr: SocketAddr = "10.0.0.1:4001".parse().unwrap();
        reg.upsert(addr, Transport::Lan, None, None, "test");
        reg.upsert(addr, Transport::Lan, Some([9u8; 32]), Some([1u8; 16]), "test");
        let list = reg.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].node_id, Some([9u8; 32]));
        assert_eq!(list[0].cluster_tag, Some([1u8; 16]));
        assert_eq!(list[0].transport, Transport::Lan);
    }
}
