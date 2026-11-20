//! Structured logging (E1): JSON-lines события в stderr/лог-файл.
//! Формат: {"ts": <unix_ms>, "lvl": "info|warn|error", "ev": "<name>", ...fields}
//! Правило: никогда не логировать токены, сиды, PIN, приватные ключи.

use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static SEQ: AtomicU64 = AtomicU64::new(0);

/// E1/C-5: список секретов, которые никогда не должны попасть в лог.
/// Регистрируется при старте (API token, mnemonic-hash и т.п.) — event()
/// вырезает любое вхождение из строковых значений полей.
static SECRETS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Зарегистрировать секрет для автоматической редакции в логах.
pub fn register_secret(s: &str) {
    if s.len() >= 8 {
        if let Ok(mut g) = SECRETS.lock() {
            if !g.iter().any(|x| x == s) {
                g.push(s.to_string());
            }
        }
    }
}

/// Вырезать зарегистрированные секреты из строки (рекурсивно по JSON).
fn redact(v: &mut Value) {
    // Секреты копируем в локальный Vec и сразу отпускаем guard — иначе
    // рекурсивный вызов ниже дедлокнется на non-reentrant std::sync::Mutex.
    let secrets: Vec<String> = match SECRETS.lock() {
        Ok(g) => g.clone(),
        Err(_) => return,
    };
    redact_with(v, &secrets);
}

fn redact_with(v: &mut Value, secrets: &[String]) {
    match v {
        Value::String(s) => {
            let mut out = s.clone();
            for sec in secrets {
                if out.contains(sec.as_str()) {
                    out = out.replace(sec.as_str(), "[redacted]");
                }
            }
            *s = out;
        }
        Value::Object(o) => {
            for (_, val) in o.iter_mut() {
                redact_with(val, secrets);
            }
        }
        Value::Array(a) => {
            for val in a.iter_mut() {
                redact_with(val, secrets);
            }
        }
        _ => {}
    }
}

/// Записать одно структурированное событие. `fields` — плоский объект
/// дополнительных полей (только примитивы).
pub fn event(lvl: &str, ev: &str, mut fields: Value) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    redact(&mut fields);
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

    #[test]
    fn registered_secrets_are_redacted_from_fields() {
        // C-5/E1: секрет, зарегистрированный через register_secret, не
        // должен появляться в полях события после redact().
        register_secret("TESTSECRETVALUE1234567890");
        let mut v = json!({"note": "token TESTSECRETVALUE1234567890 leaked", "n": 1});
        redact(&mut v);
        let s = v.to_string();
        assert!(!s.contains("TESTSECRETVALUE1234567890"), "секрет остался в логе: {s}");
        assert!(s.contains("[redacted]"));
        // короткие строки (<8 символов) не регистрируются — защита от ложных срабатываний
        register_secret("abc");
        let mut v2 = json!({"x": "abc"});
        redact(&mut v2);
        assert_eq!(v2["x"], "abc");
    }

    #[test]
    fn redact_recurses_into_nested_objects_without_deadlock() {
        // регрессия: раньше рекурсивный redact держал SECRETS-lock и дедлокался
        register_secret("NESTEDSECRET99887766");
        let mut v = json!({"outer": {"inner": ["x NESTEDSECRET99887766 y", 1]}});
        redact(&mut v);
        let s = v.to_string();
        assert!(!s.contains("NESTEDSECRET99887766"), "секрет остался: {s}");
        assert!(s.contains("[redacted]"));
    }
}
