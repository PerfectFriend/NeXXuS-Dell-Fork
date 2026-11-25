//! Состояние авто-дискавери для API (ADR-0011).
//!
//! Держит реестр кандидатов (откуда нашли ноду) и профили пиров
//! (доступность, RTT, скорость, аптайм, score). Top-K самых быстрых
//! помечаются как «предпочтительные».

use std::sync::Arc;

use crate::net::discovery::{Candidate, Registry, Transport};
use crate::net::probe::{PeerProfile, Profiles};

/// Конфигурация дискавери (из node.conf / env).
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub enabled: bool,
    pub beacon_port: u16,
    pub beacon_interval_secs: u64,
    pub lan_sweep: bool,
    pub lan_sweep_interval_secs: u64,
    pub tailscale: bool,
    pub directory_url: Option<String>,
    pub directory_interval_secs: u64,
    pub probe_interval_secs: u64,
    /// Сколько самых быстрых пиров держим в рабочем наборе (6..12).
    pub top_peers: usize,
    /// P2P-порт ноды (для адресов, которые мы публикуем).
    pub p2p_port: u16,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            beacon_port: crate::net::discovery::DEFAULT_BEACON_PORT,
            beacon_interval_secs: 15,
            lan_sweep: true,
            lan_sweep_interval_secs: 120,
            tailscale: true,
            directory_url: None,
            directory_interval_secs: 60,
            probe_interval_secs: 60,
            top_peers: 8,
            p2p_port: 4001,
        }
    }
}

/// Состояние дискавери, разделяемое между сетью и API.
#[derive(Clone)]
pub struct DiscoveryState {
    pub registry: Registry,
    pub profiles: Profiles,
    pub config: DiscoveryConfig,
    pub cluster_tag: [u8; 16],
}

impl DiscoveryState {
    pub fn new(config: DiscoveryConfig, cluster_tag: [u8; 16]) -> Self {
        Self {
            registry: Registry::default(),
            profiles: Profiles::default(),
            config,
            cluster_tag,
        }
    }

    /// JSON-строка для API.
    pub fn to_json(&self) -> serde_json::Value {
        let candidates: Vec<serde_json::Value> = self
            .registry
            .list()
            .into_iter()
            .map(|c| candidate_json(&c, &self.cluster_tag))
            .collect();
        let profiles: Vec<serde_json::Value> = self
            .profiles
            .all()
            .into_iter()
            .map(|p| profile_json(&p))
            .collect();
        let top = self.profiles.top(self.config.top_peers);
        let top_addrs: Vec<String> = top.iter().map(|p| p.addr.clone()).collect();
        serde_json::json!({
            "enabled": self.config.enabled,
            "beacon_port": self.config.beacon_port,
            "cluster_tag": hex::encode(self.cluster_tag),
            "directory_url": self.config.directory_url,
            "top_k": self.config.top_peers,
            "candidates": candidates,
            "profiles": profiles,
            "top_peers": top_addrs,
        })
    }
}

fn candidate_json(c: &Candidate, our_cluster: &[u8; 16]) -> serde_json::Value {
    serde_json::json!({
        "addr": c.addr.to_string(),
        "transport": c.transport.as_str(),
        "source": c.source,
        "node_id": c.node_id.map(hex::encode),
        "cluster_tag": c.cluster_tag.map(hex::encode),
        "same_cluster": c.cluster_tag.map(|t| t == *our_cluster).unwrap_or(false),
        "first_seen": c.first_seen,
        "last_seen": c.last_seen,
    })
}

fn profile_json(p: &PeerProfile) -> serde_json::Value {
    serde_json::json!({
        "addr": p.addr,
        "transport": p.transport.as_str(),
        "node_id": p.node_id.map(hex::encode),
        "attempts": p.attempts,
        "successes": p.successes,
        "availability": p.availability(),
        "rtt_ms": p.rtt_ms,
        "throughput_mbps": p.throughput_mbps,
        "uptime_secs": p.uptime_secs(),
        "score": p.score(),
        "first_ok": p.first_ok,
        "last_ok": p.last_ok,
        "last_error": p.last_error,
    })
}

/// Транспорт → человекочитаемое имя (для дашборда).
#[allow(dead_code)]
pub fn transport_label(t: Transport) -> &'static str {
    match t {
        Transport::Lan => "LAN",
        Transport::Tailscale => "Tailscale",
        Transport::Tor => "Tor",
        Transport::Directory => "Каталог",
    }
}

/// Arc-обёртка для удобства в структурах.
#[allow(dead_code)]
pub type SharedDiscovery = Arc<DiscoveryState>;
