//! Раннер авто-дискавери (ADR-0011).
//!
//! Один цикл-таск делает всё:
//!   1) рассылает подписанный beacon в LAN (UDP-broadcast) и слушает чужие;
//!   2) периодически делает TCP-sweep локальной подсети (находит ноды, которые
//!      не публикуют наш beacon — в т.ч. ноды другой реализации);
//!   3) подтягивает адреса tailnet'а из `tailscale status --json`;
//!   4) публикует свою запись в каталог-релей и забирает чужие;
//!   5) профилирует найденных пиров (доступность, RTT, скорость, аптайм),
//!      считает рейтинг и оставляет в рабочем наборе top-K (6..12) самых быстрых.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexxus_core::keys::identity::Identity;

use crate::discovery_state::DiscoveryState;
use crate::directory::{self, AddrRecord, DirectoryRecord};
use crate::net::discovery::{
    self, Beacon, Registry, Transport,
};
use crate::net::network::P2pNetwork;
use crate::net::probe::probe_peer;

/// Что нужно раннеру от main.
pub struct DiscoveryRunner {
    pub net: Arc<P2pNetwork>,
    pub identity: Identity,
    pub cluster_tag: [u8; 16],
    pub state: Arc<DiscoveryState>,
    /// Наш onion-адрес (появляется после публикации сервиса Tor).
    pub onion_slot: Arc<Mutex<Option<String>>>,
}

impl DiscoveryRunner {
    /// Основной цикл.
    pub async fn run(self) {
        let cfg = self.state.config.clone();
        if !cfg.enabled {
            eprintln!("nexxusd: discovery disabled (node.conf: discovery=0)");
            return;
        }
        // Слушатель beacon'ов — отдельная задача, живёт до конца процесса.
        let _listener = {
            let registry = self.state.registry.clone();
            let cluster = self.cluster_tag;
            let port = cfg.beacon_port;
            tokio::spawn(async move { beacon_listener(port, cluster, registry).await })
        };

        let mut last_beacon = 0u64;
        let mut last_sweep = 0u64;
        let mut last_ts = 0u64;
        let mut last_dir = 0u64;
        let mut last_probe = 0u64;

        loop {
            let now = discovery::now_secs();
            if now.saturating_sub(last_beacon) >= cfg.beacon_interval_secs {
                last_beacon = now;
                self.broadcast_beacon().await;
            }
            if cfg.lan_sweep && now.saturating_sub(last_sweep) >= cfg.lan_sweep_interval_secs {
                last_sweep = now;
                self.sweep_lan().await;
            }
            if cfg.tailscale && now.saturating_sub(last_ts) >= 30 {
                last_ts = now;
                self.refresh_tailscale();
            }
            if let Some(url) = cfg.directory_url.clone() {
                if now.saturating_sub(last_dir) >= cfg.directory_interval_secs {
                    last_dir = now;
                    self.directory_roundtrip(&url).await;
                }
            }
            if now.saturating_sub(last_probe) >= cfg.probe_interval_secs {
                last_probe = now;
                self.probe_all().await;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    /// Рассылка нашего beacon'а в LAN.
    async fn broadcast_beacon(&self) {
        let cfg = self.state.config.clone();
        let body = Beacon {
            node_id: self.net.our_id().0,
            pubkey: self.identity.verifying_key.to_bytes(),
            cluster_tag: self.cluster_tag,
            p2p_port: cfg.p2p_port,
            onion: self.onion_slot.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            ts: discovery::now_secs(),
        };
        let mut raw = body.encode_body();
        let sig = discovery::sign_beacon(&self.identity, &body.encode_body());
        raw.extend_from_slice(&sig);

        let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("nexxusd: discovery: bind udp failed: {e}");
                return;
            }
        };
        sock.set_broadcast(true).ok();
        // Широкий адрес + broadcast-адреса наших подсетей.
        let mut targets = vec![format!("255.255.255.255:{}", cfg.beacon_port)];
        for (ip, prefix) in discovery::local_lan_cidrs() {
            let bcast = broadcast_addr(ip, prefix);
            targets.push(format!("{bcast}:{}", cfg.beacon_port));
        }
        for t in targets {
            if let Ok(addr) = t.parse::<std::net::SocketAddr>() {
                let _ = sock.send_to(&raw, addr).await;
            }
        }
    }

    /// TCP-sweep локальной подсети.
    async fn sweep_lan(&self) {
        let cfg = self.state.config.clone();
        for (ip, prefix) in discovery::local_lan_cidrs() {
            let found = discovery::sweep_lan(
                Arc::clone(&self.net),
                (ip, prefix),
                cfg.p2p_port,
                self.state.registry.clone(),
                32,
            )
            .await;
            if found > 0 {
                eprintln!("nexxusd: discovery: lan-sweep {ip}/{prefix} → {found} node(s)");
            }
        }
    }

    /// Обновить кандидатов из tailnet'а.
    fn refresh_tailscale(&self) {
        let cfg = self.state.config.clone();
        for peer in discovery::tailscale_peers() {
            for ip in peer.ips {
                let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), cfg.p2p_port);
                self.state.registry.upsert(
                    addr,
                    Transport::Tailscale,
                    None,
                    None,
                    "tailscale",
                );
            }
        }
    }

    /// Публикация своей записи + забор чужих из каталога-релея.
    async fn directory_roundtrip(&self, url: &str) {
        let cfg = self.state.config.clone();
        let mut addrs: Vec<AddrRecord> = Vec::new();
        for (ip, _prefix) in discovery::local_lan_cidrs() {
            addrs.push(AddrRecord {
                transport: "lan".into(),
                addr: ip.to_string(),
                port: cfg.p2p_port,
            });
        }
        if let Some(ip) = discovery::tailscale_self_ip() {
            addrs.push(AddrRecord {
                transport: "tailscale".into(),
                addr: ip.to_string(),
                port: cfg.p2p_port,
            });
        }
        if let Some(onion) = self.onion_slot.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            addrs.push(AddrRecord {
                transport: "tor".into(),
                addr: onion,
                port: cfg.p2p_port,
            });
        }
        let rec = DirectoryRecord {
            node_id: hex::encode(self.net.our_id().0),
            pubkey: hex::encode(self.identity.verifying_key.to_bytes()),
            cluster_tag: hex::encode(self.cluster_tag),
            addrs,
            ts: discovery::now_secs(),
        };
        match directory::sign_record(&self.identity, &rec) {
            Ok(sr) => {
                if let Err(e) = directory::publish(url, &sr).await {
                    eprintln!("nexxusd: discovery: directory publish failed: {e}");
                }
            }
            Err(e) => eprintln!("nexxusd: discovery: sign record failed: {e}"),
        }
        match directory::fetch(url).await {
            Ok(records) => {
                for r in records {
                    let cluster = hex::decode(&r.cluster_tag)
                        .ok()
                        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok());
                    let node_id = hex::decode(&r.node_id)
                        .ok()
                        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
                    for a in r.addrs {
                        let transport = Transport::from_str(&a.transport).unwrap_or(Transport::Directory);
                        let addr_text = format!("{}:{}", a.addr, a.port);
                        let Ok(sa) = addr_text.parse::<std::net::SocketAddr>() else {
                            continue;
                        };
                        self.state.registry.upsert(
                            sa,
                            transport,
                            node_id,
                            cluster,
                            "directory",
                        );
                    }
                }
            }
            Err(e) => eprintln!("nexxusd: discovery: directory fetch failed: {e}"),
        }
    }

    /// Профилирование всех кандидатов + обновление рабочего набора top-K.
    async fn probe_all(&self) {
        let candidates = self.state.registry.list();
        for c in candidates {
            let _ = probe_peer(&self.net, &c, &self.state.profiles).await;
        }
        // Топ-K пиров регистрируем в сетевой таблице и «здороваемся» с ними
        // (send_node_announce: dial + handshake + вставка в routing-таблицу) —
        // с ними нода работает дальше (эпохи, репликация, обмен).
        let top = self.state.profiles.top(self.state.config.top_peers);
        for p in top {
            let Ok(addr) = p.addr.parse::<std::net::SocketAddr>() else {
                continue;
            };
            if let Err(e) = self.net.send_node_announce(addr).await {
                crate::log_ev!("warn", "discovery.peer_announce_failed");
                let _ = e;
            }
        }
    }
}

/// Broadcast-адрес подсети для данного адреса/префикса.
pub fn broadcast_addr(ip: std::net::Ipv4Addr, prefix: u8) -> std::net::Ipv4Addr {
    let mask = !0u32 << (32 - prefix.min(32));
    let base = u32::from(ip) & mask;
    std::net::Ipv4Addr::from(base | !mask)
}

/// Слушатель чужих beacon'ов: проверяем подпись и cluster_tag.
async fn beacon_listener(port: u16, our_cluster: [u8; 16], registry: Registry) {
    let sock = match tokio::net::UdpSocket::bind(("0.0.0.0", port)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("nexxusd: discovery: beacon listen failed on udp/{port}: {e}");
            return;
        }
    };
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, src)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        let raw = &buf[..n];
        let Ok(body) = Beacon::decode_body(&raw[..raw.len().saturating_sub(64)]) else {
            continue;
        };
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&body.pubkey) else {
            continue;
        };
        if discovery::verify_beacon(&vk, raw).is_err() {
            continue;
        }
        if body.cluster_tag != our_cluster {
            // Чужой кластер: авто-приём запрещён (нужен invite).
            continue;
        }
        let ip = match src.ip() {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => continue,
        };
        let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), body.p2p_port);
        registry.upsert(
            addr,
            Transport::Lan,
            Some(body.node_id),
            Some(body.cluster_tag),
            "beacon",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_addresses() {
        assert_eq!(
            broadcast_addr(std::net::Ipv4Addr::new(192, 168, 58, 10), 24),
            std::net::Ipv4Addr::new(192, 168, 58, 255)
        );
        assert_eq!(
            broadcast_addr(std::net::Ipv4Addr::new(10, 1, 2, 3), 30),
            std::net::Ipv4Addr::new(10, 1, 2, 7)
        );
    }
}
