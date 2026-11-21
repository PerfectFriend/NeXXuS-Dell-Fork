//! F1: per-node bandwidth caps (token bucket) for P2P traffic.
//!
//! Config: `max_up_kbps` / `max_down_kbps` in node.conf, env
//! `NEXXUS_MAX_UP_KBPS` / `NEXXUS_MAX_DOWN_KBPS`, default 0 = unlimited.
//! Burst capacity = 1 second worth of the cap.

use std::sync::Arc;
use std::sync::Mutex;

#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    state: Mutex<(f64, std::time::Instant)>,
    /// Total time spent throttled (ms) — surfaced for observability.
    pub waited_ms: std::sync::atomic::AtomicU64,
}

impl TokenBucket {
    pub fn new(kbps: u64) -> Self {
        let per_sec = (kbps.saturating_mul(1024)) as f64;
        Self {
            capacity: per_sec,
            refill_per_sec: per_sec,
            state: Mutex::new((per_sec, std::time::Instant::now())),
            waited_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Charge `bytes`; returns how long (seconds) the caller must wait.
    fn charge(&self, bytes: usize) -> f64 {
        use std::sync::atomic::Ordering;
        let mut st = self.state.lock().unwrap();
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(st.1).as_secs_f64();
        st.0 = (st.0 + elapsed * self.refill_per_sec).min(self.capacity);
        st.1 = now;
        let need = bytes as f64;
        if st.0 >= need {
            st.0 -= need;
            0.0
        } else {
            let deficit = need - st.0;
            st.0 = 0.0;
            let wait = deficit / self.refill_per_sec.max(1.0);
            self.waited_ms.fetch_add((wait * 1000.0) as u64, Ordering::Relaxed);
            wait
        }
    }

    pub async fn wait(&self, bytes: usize) {
        let d = self.charge(bytes);
        if d > 0.0 {
            tokio::time::sleep(std::time::Duration::from_secs_f64(d)).await;
        }
    }
}

/// Pair of buckets: up = bytes we write, down = bytes we read.
#[derive(Clone, Default)]
pub struct RateLimit {
    pub up: Option<Arc<TokenBucket>>,
    pub down: Option<Arc<TokenBucket>>,
}

impl RateLimit {
    #[cfg(test)]
    pub const NONE: RateLimit = RateLimit { up: None, down: None };

    pub fn new(up_kbps: u64, down_kbps: u64) -> Self {
        Self {
            up: (up_kbps > 0).then(|| Arc::new(TokenBucket::new(up_kbps))),
            down: (down_kbps > 0).then(|| Arc::new(TokenBucket::new(down_kbps))),
        }
    }

    /// Read caps from node.conf / env (0 = unlimited).
    pub fn from_config() -> Self {
        let conf = crate::node_config::load_file();
        let up = crate::node_config::cfg_or_env(&conf, "max_up_kbps", "NEXXUS_MAX_UP_KBPS", "0");
        let down = crate::node_config::cfg_or_env(&conf, "max_down_kbps", "NEXXUS_MAX_DOWN_KBPS", "0");
        let parse = |s: String| s.trim().parse::<u64>().unwrap_or(0);
        Self::new(parse(up), parse(down))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_throttles() {
        let b = TokenBucket::new(1); // 1024 B/s
        assert_eq!(b.charge(1024), 0.0, "first second is free (burst)");
        let w = b.charge(1024);
        assert!(w > 0.9 && w <= 1.0, "next 1024B must wait ~1s, got {w}");
    }

    #[tokio::test]
    async fn wait_actually_sleeps() {
        let b = TokenBucket::new(1);
        b.wait(1024).await; // burst, instant
        let t0 = std::time::Instant::now();
        b.wait(512).await;
        assert!(t0.elapsed() >= std::time::Duration::from_millis(400), "must throttle");
    }

    #[test]
    fn rate_limit_zero_is_unlimited() {
        let rl = RateLimit::new(0, 0);
        assert!(rl.up.is_none() && rl.down.is_none());
        let rl = RateLimit::new(10, 0);
        assert!(rl.up.is_some() && rl.down.is_none());
    }
}
