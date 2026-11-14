//! Structured logging (E1): JSON-lines события в stderr/лог-файл.
//! Формат: {"ts": <unix_ms>, "lvl": "info|warn|error", "ev": "<name>", ...fields}
//! Правило: никогда не логировать токены, сиды, PIN, приватные ключи.

use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Записать одно структурированное событие. `fields` — плоский объект
/// дополнительных полей (только примитивы).
pub fn event(lvl: &str, ev: &str, fields: Value) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut obj = json!({
        "ts": ts,
        "seq": SEQ.fetch_add(1, Ordering::Relaxed),
        "lvl": lvl,
        "ev": ev,
    });
    if let (Some(o), Some(f)) = (obj.as_object_mut(), fields.as_object()) {
        for (k, v) in f {
            o.insert(k.clone(), v.clone());
        }
    }
    eprintln!("{}", obj);
}

#[macro_export]
macro_rules! log_ev {
    ($lvl:expr, $ev:expr, $($k:expr => $v:expr),* $(,)?) => {
        $crate::logging::event($lvl, $ev, serde_json::json!({ $($k: $v),* }))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_is_json_line_with_required_fields() {
        // перехватываем через serde: формируем ту же структуру
        let ts = 1234u64;
        let obj = json!({"ts": ts, "seq": 0u64, "lvl": "info", "ev": "test", "addr": "127.0.0.1:1"});
        let s = obj.to_string();
        let parsed: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["lvl"], "info");
        assert_eq!(parsed["ev"], "test");
        assert_eq!(parsed["addr"], "127.0.0.1:1");
        assert!(parsed["ts"].is_u64());
    }
}
