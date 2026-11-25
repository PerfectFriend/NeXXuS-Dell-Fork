//! Профилирование пиров и рейтинг (ADR-0011).
//!
//! Для каждого кандидата измеряем: доступность (handshake), RTT, скорость
//! передачи данных (opcode Probe 0x0E/0x0F), аптайм (сколько жив успешный
//! контакт) и считаем сводный score 0..1. Топ-K (по умолчанию 8, допустимо
//! 6..12) попадает в «предпочтительные» пиры.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::net::discovery::{connect_handshake, Candidate, Transport};
use crate::net::network::P2pNetwork;

/// Размер эхо-блока для замера скорости (64 КиБ).
pub const PROBE_BYTES: u32 = 64 * 1024;

/// Накопительные метрики по пиру.
#[derive(Debug, Clone)]
pub struct PeerProfile {
    pub addr: String,
    pub transport: Transport,
    pub node_id: Option<[u8; 32]>,
    pub attempts: u32,
    pub successes: u32,
    pub rtt_ms: Option<u32>,
    pub throughput_mbps: Option<f64>,
    pub first_ok: u64,
    pub last_ok: u64,
    pub last_error: Option<String>,
}

impl PeerProfile {
    /// Доля успешных попыток (0..1).
    pub fn availability(&self) -> f64 {
        if self.attempts == 0 {
            return 0.0;
        }
        self.successes as f64 / self.attempts as f64
    }

    /// Аптайм контакта в секундах (с первого успеха до последнего).
    pub fn uptime_secs(&self) -> f64 {
        if self.first_ok == 0 || self.last_ok < self.first_ok {
            return 0.0;
        }
        (self.last_ok - self.first_ok) as f64
    }

    /// Сводный score 0..1: доступность + аптайм + RTT + скорость.
    pub fn score(&self) -> f64 {
        compute_score(
            self.availability(),
            self.uptime_secs(),
            self.rtt_ms.unwrap_or(u32::MAX) as f64,
            self.throughput_mbps.unwrap_or(0.0),
        )
    }
}

/// Формула рейтинга. Веса: доступность 0.40, аптайм 0.15, RTT 0.25, скорость 0.20.
pub fn compute_score(availability: f64, uptime_secs: f64, rtt_ms: f64, mbps: f64) -> f64 {
    let avail = availability.clamp(0.0, 1.0);
    // Аптайм нормализуем к 1 часу: 0..3600 c → 0..1.
    let uptime = (uptime_secs / 3600.0).clamp(0.0, 1.0);
    // RTT: 0 мс → 1.0, 1000 мс и выше → 0.0.
    let rtt = if rtt_ms.is_finite() {
        (1.0 - rtt_ms / 1000.0).clamp(0.0, 1.0)
    } else {
        0.0
    };
    // Скорость: 0..100 Мбит/с → 0..1 (логарифмическая шкала).
    let speed = if mbps.is_finite() && mbps > 0.0 {
        ((mbps + 1.0).log10() / 101.0f64.log10()).clamp(0.0, 1.0)
    } else {
        0.0
    };
    0.40 * avail + 0.15 * uptime + 0.25 * rtt + 0.20 * speed
}

/// Хранилище профилей пиров.
#[derive(Clone, Default)]
pub struct Profiles {
    inner: Arc<Mutex<HashMap<String, PeerProfile>>>,
}

impl Profiles {
    #[allow(dead_code)]
    pub fn get(&self, addr: &str) -> Option<PeerProfile> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(addr)
            .cloned()
    }

    pub fn all(&self) -> Vec<PeerProfile> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<PeerProfile> = guard.values().cloned().collect();
        v.sort_by(|a, b| {
            b.score()
                .partial_cmp(&a.score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }

    /// Пиры, отобранные в «рабочую» top-K (6..12) по рейтингу.
    pub fn top(&self, k: usize) -> Vec<PeerProfile> {
        let k = k.clamp(6, 12);
        self.all().into_iter().take(k).collect()
    }

    fn update<F: FnOnce(&mut PeerProfile)>(&self, addr: &str, f: F) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry(addr.to_string()).or_insert_with(|| PeerProfile {
            addr: addr.to_string(),
            transport: Transport::Lan,
            node_id: None,
            attempts: 0,
            successes: 0,
            rtt_ms: None,
            throughput_mbps: None,
            first_ok: 0,
            last_ok: 0,
            last_error: None,
        });
        f(entry);
    }
}

/// Проверить пира: handshake + RTT + скорость передачи данных.
pub async fn probe_peer(net: &P2pNetwork, cand: &Candidate, profiles: &Profiles) -> bool {
    let addr_s = cand.addr.to_string();
    let transport = cand.transport;
    profiles.update(&addr_s, |p| {
        p.attempts += 1;
        p.transport = transport;
    });

    // Скорость: наш форк поддерживает Probe (0x0E); чужие ноды ответят
    // ErrorResponse — тогда скорость неизвестна, но доступность и RTT есть.
    let mut mbps = None;
    let (node_id, rtt) = match connect_handshake(net, cand.addr, 3000).await {
        Ok((mut stream, hs, rtt)) => {
            let started = Instant::now();
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                net.probe_echo(&mut stream, &hs, 0xB0BE, PROBE_BYTES),
            )
            .await
            {
                Ok(Ok(data)) => {
                    let secs = started.elapsed().as_secs_f64().max(0.001);
                    mbps = Some((data.len() as f64 * 8.0) / secs / 1_000_000.0);
                }
                _ => {
                    // Пир не поддержал Probe (чужая реализация) — это не ошибка
                    // доступности: RTT уже измерен.
                }
            }
            (hs.peer_id.0, rtt)
        }
        Err(e) => {
            profiles.update(&addr_s, |p| p.last_error = Some(e));
            return false;
        }
    };

    let now = crate::net::discovery::now_secs();
    profiles.update(&addr_s, |p| {
        p.successes += 1;
        p.rtt_ms = Some(rtt as u32);
        p.node_id = Some(node_id);
        if p.first_ok == 0 {
            p.first_ok = now;
        }
        p.last_ok = now;
        p.last_error = None;
        if let Some(m) = mbps {
            p.throughput_mbps = Some(m);
        }
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_is_bounded_and_monotonic() {
        let s0 = compute_score(0.0, 0.0, 5000.0, 0.0);
        let s1 = compute_score(1.0, 3600.0, 5.0, 50.0);
        assert!((0.0..=1.0).contains(&s0));
        assert!((0.0..=1.0).contains(&s1));
        assert!(s1 > s0);
    }

    #[test]
    fn faster_and_more_available_scores_higher() {
        let fast = compute_score(1.0, 3600.0, 10.0, 80.0);
        let slow = compute_score(1.0, 3600.0, 400.0, 2.0);
        assert!(fast > slow);
    }

    #[test]
    fn top_k_clamps_to_six_twelve() {
        let p = Profiles::default();
        for i in 0..20 {
            p.update(&format!("10.0.0.{i}"), |e| {
                e.successes = 1;
                e.attempts = 1;
                e.rtt_ms = Some(10 + i);
                e.first_ok = 1;
                e.last_ok = 1;
            });
        }
        assert_eq!(p.top(3).len(), 6);
        assert_eq!(p.top(100).len(), 12);
        let top = p.top(8);
        // Список отсортирован по убыванию score.
        for w in top.windows(2) {
            assert!(w[0].score() >= w[1].score());
        }
    }

    #[test]
    fn availability_counts_failures() {
        let p = Profiles::default();
        p.update("10.0.0.1", |e| {
            e.attempts = 4;
            e.successes = 3;
        });
        assert!((p.get("10.0.0.1").unwrap().availability() - 0.75).abs() < 1e-9);
    }
}
