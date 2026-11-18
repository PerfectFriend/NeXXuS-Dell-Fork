//! Ядро "ангела-хранителя" ноды NeXXus.
//! Управляет жизненным циклом nexxusd:
//!   - проверка запущенности (pgrep)
//!   - автозапуск nexxusd при отсутствии
//!   - ожидание готовности JSON-RPC API (порт 4010)
//!   - периодический health-check через node_status (каждые 10 сек)
//!   - автоперезапуск при потере связи (3 неудачи подряд)
//!   - отправка событий в Telegram через TelegramBot

use crate::telegram::get_bot;
use crate::process_backend::ProcessBackend;
use serde_json::{json, Value};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::sleep;

/// Путь к бинарнику nexxusd: env NEXXUSD_BIN → рядом с текущим exe →
/// /usr/local/bin и /usr/bin → PATH. Хардкод под build-хост убран.
fn nexxusd_bin() -> String {
    crate::paths::nexxusd_bin()
}

/// Путь к store.redb (переопределяется через NEXXUS_STORE).
fn nexxusd_store() -> String {
    crate::paths::nexxusd_store()
}

/// Путь к логу ноды (переопределяется через NEXXUS_LOG_FILE).
fn nexxusd_log() -> String {
    crate::paths::nexxusd_log()
}

/// Путь к лог-файлу ноды (используется командой `node_log_tail_cmd`).
pub fn nexxusd_log_path() -> String {
    nexxusd_log()
}
/// Шаблон командной строки процесса ноды.
///
/// По одному только имени `nexxusd` искать нельзя: под этим именем
/// запускается сам бинарь, а совпадение строилось по `store.redb`, который
/// есть не у всех способов запуска. Привязываемся к пути бинаря —
/// у монитора путь оканчивается на `nexxus-desktop`, поэтому совпадения
/// с ним не происходит.
/// Паттерн процесса ноды для pgrep/pkill: матчит любой путь к бинарнику
/// nexxusd (`/usr/bin/nexxusd`, `…/release/nexxusd`), но не nexxus-desktop.
pub(crate) const NEXXUSD_MATCH: &str = "(^|/)nexxusd( |$)";

/// Адрес локального WS API ноды — из конфига монитора (node.conf, поле `api`),
/// по умолчанию 127.0.0.1:4010. Раньше здесь был зашитый порт 4010, из-за чего
/// при `api=127.0.0.1:5010` в node.conf монитор не находил API и падал
/// «ошибка запуска nexxusd» после wait_for_api_ready.
pub fn api_addr() -> String {
    crate::node_config::load().api
}

/// Достаёт `result` из JSON-RPC-конверта, который возвращает api_call.
/// Без этого монитор читал поля верхнего уровня и всегда получал None:
/// PoR всегда был «ПРОВАЛЕН», а бэкап падал и повторялся каждый тик.
pub fn api_result(v: &serde_json::Value) -> &serde_json::Value {
    v.get("result").unwrap_or(v)
}

/// ws:// URL локального API ноды.
pub fn api_url() -> String {
    format!("ws://{}", api_addr())
}
const HEALTH_INTERVAL_SEC: u64 = 10;
const MAX_HEALTH_FAILURES: u32 = 3;
const HEARTBEAT_INTERVAL_SEC: u64 = 3600;

/// Состояние монитора ноды.
#[derive(Clone, Debug, serde::Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MonitorState {
    #[default]
    Stopped,
    Starting,
    Running,
    Unhealthy,
    Restarting,
}

/// Запись в файл телеметрии UI (тот же, что использует фронтенд).
/// Нужен, чтобы видеть, где именно монитор встаёт — «монитор не видит ноду».
pub fn ui_log(line: &str) {
    use std::io::Write;
    let path = crate::node_config::config_dir().join("monitor-ui.log");
    // Ограничиваем размер: файл пишется каждые 5 секунд.
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > 1024 * 1024 {
            let _ = std::fs::write(&path, "");
        }
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{ts}] [rust] {line}");
    }
}

/// Состояние узла (из API).
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct NodeStatus {
    pub node_id: String,
    /// Версия ноды из API (node_status.version) — без неё UI показывал «?».
    pub version: String,
    pub uptime_ms: u128,
    pub peers: usize,
    pub chunks: usize,
    pub smp: String,
    pub epoch: u64,
    pub tor: String,
    pub api_reachable: bool,
}

/// G5: путь к файлу состояния монитора (last_auto_backup/last_por),
/// чтобы они переживали перезапуск процесса монитора.
pub fn monitor_state_path() -> std::path::PathBuf {
    crate::paths::data_dir().join("monitor-state.json")
}

/// G5: читает (last_auto_backup, last_por) из monitor-state.json.
pub fn load_monitor_state() -> (Option<u64>, Option<u64>) {
    let Ok(content) = std::fs::read_to_string(monitor_state_path()) else {
        return (None, None);
    };
    let v: serde_json::Value = serde_json::from_str(&content).unwrap_or(serde_json::Value::Null);
    let get = |k: &str| v.get(k).and_then(|x| x.as_u64());
    (get("last_auto_backup"), get("last_por"))
}

/// G5: атомарная запись monitor-state.json сразу с mode 0o600
/// (как api_auth.rs: tmp-файл с правами → rename).
pub fn save_monitor_state(last_auto_backup: Option<u64>, last_por: Option<u64>) {
    let path = monitor_state_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let body = serde_json::json!({
        "last_auto_backup": last_auto_backup,
        "last_por": last_por,
    });
    let tmp = path.with_extension("json.tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true).mode(0o600);
        if let Ok(mut f) = opts.open(&tmp) {
            use std::io::Write;
            let _ = f.write_all(body.to_string().as_bytes());
            let _ = f.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(&tmp, body.to_string());
    }
    let _ = std::fs::rename(&tmp, &path);
}

/// G5: сохраняет обе отметки из состояния (вызывается после их обновления).
pub async fn persist_timestamps(state: &GuardianState) {
    let a = { *state.last_auto_backup.lock().await };
    let p = { *state.last_por.lock().await };
    // Писать в фоне не блокируем: маленький файл, но делаем через spawn_blocking.
    let _ = tokio::task::spawn_blocking(move || save_monitor_state(a, p)).await;
}

/// Текущее состояние гардиана.
pub struct GuardianState {
    pub state: Mutex<MonitorState>,
    pub node_status: Mutex<Option<NodeStatus>>,
    pub start_time: Mutex<Option<SystemTime>>,
    pub health_failures: Mutex<u32>,
    /// PID запущенной ноды (заполняется при старте; показывается в статусе).
    pub nexxusd_pid: Mutex<Option<u32>>,
    pub monitor_enabled: Mutex<bool>,
    /// D2: время последнего успешного автобэкапа (unix secs).
    pub last_auto_backup: Mutex<Option<u64>>,
    /// E2: время последнего планового PoR (unix secs).
    pub last_por: Mutex<Option<u64>>,
}

impl GuardianState {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MonitorState::Stopped),
            node_status: Mutex::new(None),
            start_time: Mutex::new(None),
            health_failures: Mutex::new(0),
            nexxusd_pid: Mutex::new(None),
            monitor_enabled: Mutex::new(true),
            // G5: отметки переживают перезапуск монитора
            last_auto_backup: Mutex::new(load_monitor_state().0),
            last_por: Mutex::new(load_monitor_state().1),
        }
    }
}

/// D2: пора ли делать автобэкап (hours=0 — выключено; None last — пора сразу).
pub fn auto_backup_due(now_secs: u64, last: Option<u64>, hours: u64) -> bool {
    if hours == 0 {
        return false;
    }
    match last {
        None => true,
        Some(l) => now_secs >= l.saturating_add(hours.saturating_mul(3600)),
    }
}

/// D2: ротация — список имён (newest-first), которые надо удалить, чтобы
/// осталось не больше `keep` последних.
///
/// `keep = 0` не означает «удалить всё, включая свежий бэкап»: только что
/// созданный бэкап удалять нельзя — иначе авто-бэкап лишается смысла и данные
/// остаются без последней копии. Минимум — хранить последний (keep.max(1)).
pub fn backups_to_delete(newest_first: &[String], keep: usize) -> Vec<String> {
    newest_first.iter().skip(keep.max(1)).cloned().collect()
}

/// G1: зафиксировать состояние и ТОЛЬКО ПОТОМ отправить уведомление.
///
/// Инвариант: guard `Mutex<MonitorState>` не живёт через `.await`.
/// Раньше лок брался и держался до конца `notify_*().await` (HTTP в Telegram),
/// поэтому `guardian_status` — тот же мьютекс — вставал на секунды-минуты,
/// пока Telegram недоступен: UI монитора «залипал».
async fn set_state_and_notify<F, Fut>(lock: &Mutex<MonitorState>, next: MonitorState, notify: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    {
        let mut guard = lock.lock().await;
        *guard = next;
    } // guard отпущен ДО await — лок свободен для guardian_status
    notify().await;
}

/// D2: первый примонтированный внешний носитель под /run/media (или None).
pub fn external_media_dir() -> Option<std::path::PathBuf> {
    let rd = std::fs::read_dir("/run/media").ok()?;
    for entry in rd.flatten() {
        let user_dir = entry.path();
        if let Ok(users) = std::fs::read_dir(&user_dir) {
            for u in users.flatten() {
                let mount = u.path();
                if mount.is_dir() {
                    return Some(mount);
                }
            }
        }
    }
    None
}

/// D2: один цикл автобэкапа — создать бэкап, ротация, копия на внешний носитель.
/// Возвращает (имя бэкапа, сколько удалено, путь внешней копии).
pub async fn run_auto_backup(keep: usize) -> Result<(String, usize, Option<String>), String> {
    let created = api_call("node_backup", None).await?;
    let created = api_result(&created);
    let name = created
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "node_backup: no name in response".to_string())?
        .to_string();

    // Ротация: список newest-first, удаляем хвост сверх keep.
    let mut deleted = 0usize;
    if let Ok(list) = api_call("node_backup_list", None).await {
        let list = api_result(&list);
        if let Some(arr) = list.as_array() {
            let names: Vec<String> = arr
                .iter()
                .filter_map(|b| b.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()))
                .collect();
            for old in backups_to_delete(&names, keep) {
                if api_call("node_backup_delete", Some(json!({ "name": old, "confirm": true }))).await.is_ok() {
                    deleted += 1;
                }
            }
        }
    }

    // 3-2-1: копия на внешний носитель, если примонтирован.
    let mut external = None;
    if let Some(mount) = external_media_dir() {
        let dst_dir = mount.join("nexxus-backups");
        if std::fs::create_dir_all(&dst_dir).is_ok() {
            let src = crate::node_config::config_dir().join("backups").join(&name);
            let dst = dst_dir.join(&name);
            // G3: копирование каталога — блокирующая операция, уводим из рантайма.
            let dst_str = dst.to_string_lossy().into_owned();
            let copied = tokio::task::spawn_blocking(move || {
                src.is_dir() && copy_dir_recursive(&src, &dst).is_ok()
            })
            .await
            .unwrap_or(false);
            if copied {
                external = Some(dst_str);
            }
        }
    }

    Ok((name, deleted, external))
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

/// Является ли процесс nexxusd запущенным (продакшн-бэкенд: systemd/pgrep).
pub fn is_nexxusd_running() -> bool {
    is_nexxusd_running_with(&crate::process_backend::SystemdBackend)
}

/// P0-C: проверка через произвольный бэкенд процесса.
pub fn is_nexxusd_running_with(backend: &dyn crate::process_backend::ProcessBackend) -> bool {
    backend.is_running()
}

/// Останавливает nexxusd (SIGTERM, затем добивание SIGKILL).
///
/// Если нода стоит как systemd-юнит, останавливаем её через systemctl —
/// иначе `Restart=on-failure` её воскресит, и кнопка «Остановить» снова
/// будет выглядеть нерабочей.
pub fn stop_nexxusd() -> Result<(), String> {
    stop_nexxusd_with(&crate::process_backend::SystemdBackend)
}

/// P0-C: остановка через произвольный бэкенд (в тестах — только свой child).
pub fn stop_nexxusd_with(backend: &dyn crate::process_backend::ProcessBackend) -> Result<(), String> {
    backend.stop()?;
    if backend.is_running() {
        return Err("nexxusd не завершился".into());
    }
    Ok(())
}

/// Полное отключение: стоп ноды + Telegram-отчёт. Вызывается из трея;
/// после возврата вызывающий завершает процесс монитора (выгрузка из памяти).
pub async fn guardian_shutdown_everything(state: Arc<GuardianState>) {
    *state.monitor_enabled.lock().await = false;
    *state.state.lock().await = MonitorState::Stopped;
    let bot = get_bot().await;
    if let Err(e) = stop_nexxusd() {
        let _ = bot.notify_node_start_failed(&format!("При полном отключении: {e}")).await;
    }
    let _ = bot.notify_guardian_shutdown().await;
}

/// Запускает nexxusd в фоне с параметрами из `~/.nexxus/node.conf`.
///
/// Если нода уже установлена как systemd-юнит и запущена — монитор её не
/// трогает: второй процесс занял бы тот же порт и упал бы с `address in use`.
/// Синхронная проверка: кто-то уже слушает API-адрес (настоящий WS не нужен,
/// достаточно TCP connect — но без handshake нода пишет в лог «Handshake not
/// finished», поэтому после connect сразу закрываем).
pub fn api_tcp_open(addr: &str) -> bool {
    use std::net::TcpStream;
    TcpStream::connect_timeout(
        &addr
            .parse()
            .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 4010))),
        Duration::from_millis(300),
    )
    .is_ok()
}

pub fn start_nexxusd() -> Result<(), String> {
    start_nexxusd_with(&crate::process_backend::SystemdBackend)
}

/// P0-C: запуск через произвольный бэкенд процесса (в тестах — SpawnBackend,
/// реальный хост не трогается).
pub fn start_nexxusd_with(backend: &dyn crate::process_backend::ProcessBackend) -> Result<(), String> {
    if backend.is_running() {
        return Ok(());
    }
    // Процесс не нашёлся, но API отвечает — не плодим второй экземпляр
    // на той же БД (redb lock → паника в логе).
    if api_tcp_open(&api_addr()) {
        return Ok(());
    }

    // Lock-файл БД НЕ удаляем: redb держит его через flock, после падения
    // процесса flock снимается ОС сама, а удаление файла под живым процессом
    // давало бы второму экземпляру открыть ту же БД — риск порчи store.redb.

    let cfg = crate::node_config::load();
    let log_path = std::path::PathBuf::from(nexxusd_log());
    backend.start(&cfg, &nexxusd_bin(), &nexxusd_store(), &log_path)
}

/// Ожидает готовности API (пробует подключиться к WebSocket).
pub async fn wait_for_api_ready(timeout_sec: u64) -> bool {
    let interval = Duration::from_millis(500);
    let total = Duration::from_secs(timeout_sec);
    let mut elapsed = Duration::from_secs(0);

    while elapsed < total {
        if api_is_reachable().await {
            return true;
        }
        sleep(interval).await;
        elapsed += interval;
    }
    false
}

/// Проверяет доступность API через WebSocket-handshake.
///
/// Раньше здесь был голый TCP-connect: нода принимала соединение и тут же
/// писала в лог «WebSocket accept failed: Handshake not finished», засоряя
/// лог при каждом health-check. Теперь отправляем настоящий WS-handshake
/// и ждём ответ 101 Switching Protocols.
pub async fn api_is_reachable() -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = api_addr();
    let Ok(Ok(mut stream)) = tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        TcpStream::connect(&addr),
    )
    .await
    else {
        return false;
    };

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {addr}\r\n\
         Upgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).await.is_err() {
        return false;
    }

    let mut buf = [0u8; 64];
    let Ok(n) = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await else {
        return false;
    };
    let Ok(n) = n else {
        return false;
    };
    let response = String::from_utf8_lossy(&buf[..n]);
    let ok = response.starts_with("HTTP/1.1 101");
    // WS close-фрейм, обязательно замаскированный (RFC 6455: клиент→сервер
    // все фреймы в маске). Без маски нода пишет «Received an unmasked frame».
    // Close, payload пустой: 0x88, len=0x80|0, 4 байта маски.
    let mask = [0x12, 0x34, 0x56, 0x78];
    let _ = stream.write_all(&[0x88, 0x80, mask[0], mask[1], mask[2], mask[3]]).await;
    let _ = stream.shutdown().await;
    ok
}

/// Выполняет JSON-RPC запрос к локальному API (через WebSocket).
/// Делегирует в `crate::api_client::api_call`, которая сначала делает
/// `auth` с токеном из `~/.nexxus/api.token`.
pub async fn api_call(method: &str, params: Option<Value>) -> Result<Value, String> {
    crate::api_client::api_call(method, params).await
}

/// Получает статус ноды через API.
pub async fn get_node_status() -> Result<NodeStatus, String> {
    let resp = api_call("node_status", None).await?;
    let result = resp.get("result").ok_or("Отсутствует поле result")?;

    Ok(NodeStatus {
        node_id: result.get("node_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
        version: result
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        uptime_ms: result.get("uptime_ms").and_then(|v| v.as_u64()).unwrap_or(0) as u128,
        peers: result.get("peers").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
        chunks: result.get("chunks").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
        smp: result.get("smp").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
        epoch: result.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0),
        tor: result.get("tor").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
        api_reachable: true,
    })
}

/// Путь к файлу-запросу на полное отключение.
///
/// Второй экземпляр монитора не может сам остановить первый (lock-файл
/// занят), поэтому оставляет запрос — работающий экземпляр подхватит его
/// на ближайшем тике health loop.
pub fn shutdown_request_path() -> std::path::PathBuf {
    crate::node_config::config_dir().join("monitor.shutdown")
}

/// Создан ли файл-запрос на отключение.
pub fn shutdown_requested() -> bool {
    shutdown_request_path().exists()
}

/// Фоновый цикл мониторинга здоровья.
/// Алерты — только на переходах состояния (без спама каждые 10 сек),
/// heartbeat — раз в час, отчёт об активации Tor — при смене состояния.
pub async fn health_loop(state: Arc<GuardianState>) {
    ui_log("health_loop: старт");
    let bot = get_bot().await;
    let _ = bot.notify_monitor_started().await;
    ui_log("health_loop: Telegram-старт отправлен");

    let mut heartbeat_ticks: u64 = 0;
    let mut last_tor: String = String::new();
    let mut por_disabled_logged = false;

    loop {
        sleep(Duration::from_secs(HEALTH_INTERVAL_SEC)).await;

        // Запрос на полное отключение извне (второй экземпляр с --shutdown,
        // .desktop-действие Quit). Обрабатываем всегда, даже когда мониторинг
        // выключен кнопкой «Остановить ноду».
        if shutdown_requested() {
            let _ = std::fs::remove_file(shutdown_request_path());
            guardian_shutdown_everything(state.clone()).await;
            std::process::exit(0);
        }

        if !*state.monitor_enabled.lock().await {
            continue;
        }

        // ВАЖНО: не держим state.state.lock() через await — иначе любой
        // долгий await (Telegram/бэкап/PoR) блокирует guardian_status,
        // и UI навсегда остаётся «Загрузка...».
        let prev_state = { state.state.lock().await.clone() };

        match get_node_status().await {
            Ok(status) => {
                ui_log(&format!("health_loop: тик ок, node_id={} uptime_ms={}", status.node_id, status.uptime_ms));
                *state.health_failures.lock().await = 0;
                *state.node_status.lock().await = Some(status.clone());

                // Восстановление после нездоровья/перезапуска
                if prev_state == MonitorState::Unhealthy || prev_state == MonitorState::Restarting {
                    let _ = bot.notify_node_restarted().await;
                }

                // Активация Tor: отчёт при первом появлении onion-адреса
                if status.tor != last_tor {
                    if !status.tor.is_empty() && status.tor != "unknown" && status.tor != "disabled"
                        && !last_tor.is_empty()
                    {
                        let _ = bot.notify_node_tor(&status.tor).await;
                    }
                    last_tor = status.tor.clone();
                }

                *state.state.lock().await = MonitorState::Running;

                // Heartbeat раз в час
                heartbeat_ticks += 1;
                if heartbeat_ticks * HEALTH_INTERVAL_SEC >= HEARTBEAT_INTERVAL_SEC {
                    heartbeat_ticks = 0;
                    let _ = bot.notify_heartbeat(&status.node_id, status.peers, status.uptime_ms).await;
                }

                // D2: автобэкап по расписанию (только когда нода жива и мониторинг включён)
                let cfg = crate::node_config::load();
                let now_secs = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let due = {
                    let last = *state.last_auto_backup.lock().await;
                    auto_backup_due(now_secs, last, cfg.auto_backup_hours)
                };
                if due {
                    // Timestamp ставим ДО попытки и независимо от исхода:
                    // иначе при ошибке бэкап повторялся на каждом тике (10 с).
                    *state.last_auto_backup.lock().await = Some(now_secs);
                    persist_timestamps(&state).await; // G5: на диск, не только в память
                    match run_auto_backup(cfg.auto_backup_keep).await {
                        Ok((name, deleted, external)) => {
                            let _ = bot.notify_backup(&name, deleted, external.as_deref()).await;
                        }
                        Err(e) => {
                            eprintln!("guardian: auto-backup failed: {e}");
                        }
                    }
                }

                // E2: плановый PoR по расписанию.
                // ВЫКЛЮЧЕН по умолчанию (node.conf: por_enabled=0), пока хранилище
                // не починено: на пустом сторе PoR всегда падает, а timestamp
                // обновлялся только при успехе -> оповещение сыпалось каждый тик.
                if !cfg.por_enabled {
                    if !por_disabled_logged {
                        por_disabled_logged = true;
                        ui_log("health_loop: PoR выключен (por_enabled=0) — проверка и оповещение пропущены");
                    }
                } else {
                    let por_due = {
                        let last = *state.last_por.lock().await;
                        auto_backup_due(now_secs, last, cfg.por_interval_hours)
                    };
                    if por_due {
                        // Timestamp обновляем по ЛЮБОМУ исходу (успех/провал):
                        // иначе при провале PoR повторялся на каждом тике.
                        *state.last_por.lock().await = Some(now_secs);
                        persist_timestamps(&state).await; // G5
                        match api_call("node_por", None).await {
                            Ok(v) => {
                                let v = api_result(&v);
                                let ok = v.get("ok").and_then(|o| o.as_bool()).unwrap_or(false);
                                let chunk = v.get("chunk").and_then(|c| c.as_str()).unwrap_or("").to_string();
                                let ms = v.get("elapsed_ms").and_then(|m| m.as_u64()).unwrap_or(0);
                                let total = v.get("chunks_total").and_then(|t| t.as_u64()).unwrap_or(0);
                                let _ = bot.notify_por(ok, &chunk, ms, total).await;
                            }
                            Err(e) => eprintln!("guardian: scheduled PoR failed: {e}"),
                        }
                    }
                }
            }
            Err(e) => {
                ui_log(&format!("health_loop: тик ошибка — {e}"));
                let mut failures = state.health_failures.lock().await;
                *failures += 1;
                let current_failures = *failures;
                drop(failures);

                // Алерт только на ПЕРВОЙ неудаче эпизода (transition-only)
                if prev_state != MonitorState::Unhealthy && prev_state != MonitorState::Restarting {
                    let _ = bot.notify_node_unhealthy(&e).await;
                }

                if current_failures >= MAX_HEALTH_FAILURES {
                    *state.state.lock().await = MonitorState::Restarting;
                    let _ = bot.notify_node_restarting("Потеря связи с API (3 неудачи)").await;

                    if let Err(err) = start_nexxusd() {
                        let _ = bot.notify_node_start_failed(&err).await;
                        *state.state.lock().await = MonitorState::Unhealthy;
                    } else if wait_for_api_ready(30).await {
                        match get_node_status().await {
                            Ok(status) => {
                                *state.node_status.lock().await = Some(status);
                                *state.state.lock().await = MonitorState::Running;
                                let _ = bot.notify_node_restarted().await;
                            }
                            Err(e) => {
                                let _ = bot.notify_node_start_failed(&e).await;
                                *state.state.lock().await = MonitorState::Unhealthy;
                            }
                        }
                    } else {
                        let _ = bot.notify_node_start_failed("API не отвечает после запуска").await;
                        *state.state.lock().await = MonitorState::Unhealthy;
                    }
                } else {
                    *state.state.lock().await = MonitorState::Unhealthy;
                }
            }
        }
    }
}

/// Запускает ноду (команда из UI / трея).
pub async fn guardian_start_node(state: Arc<GuardianState>) -> Result<Value, String> {
    {
        let mut state_lock = state.state.lock().await;
        *state_lock = MonitorState::Starting;
    }

    // Мониторинг включаем здесь: после «Остановить ноду» он был выключен,
    // и без этого нода поднималась «мёртвой» — без health-check и отчётов.
    *state.monitor_enabled.lock().await = true;

    let bot = get_bot().await;
    let _ = bot.notify_node_starting().await;

    // G3: синхронный start (pgrep/systemctl/TCP-проверка) — в spawn_blocking,
    // чтобы не блокировать рантайм монитора.
    let start_res = tokio::task::spawn_blocking(start_nexxusd)
        .await
        .unwrap_or_else(|e| Err(format!("join: {e}")));
    if let Err(e) = start_res {
        set_state_and_notify(&state.state, MonitorState::Unhealthy, || async {
            let _ = bot.notify_node_start_failed(&e).await;
        })
        .await;
        return Err(e);
    }

    if !wait_for_api_ready(30).await {
        set_state_and_notify(&state.state, MonitorState::Unhealthy, || async {
            let _ = bot.notify_node_start_failed("API не отвечает после запуска").await;
        })
        .await;
        return Err("API не отвечает после запуска nexxusd".into());
    }

    // G4: запоминаем PID ноды (systemd MainPID или child.id)
    {
        let pid = tokio::task::spawn_blocking(|| {
            crate::process_backend::SystemdBackend.main_pid()
        })
        .await
        .unwrap_or(None);
        *state.nexxusd_pid.lock().await = pid;
    }

    match get_node_status().await {
        Ok(status) => {
            *state.start_time.lock().await = Some(SystemTime::now());
            *state.node_status.lock().await = Some(status.clone());
            let node_id = status.node_id.clone();
            set_state_and_notify(&state.state, MonitorState::Running, || async {
                let _ = bot.notify_node_started(&node_id, &api_url()).await;
            })
            .await;
            Ok(json!({"status": "started", "node_id": status.node_id}))
        }
        Err(e) => {
            set_state_and_notify(&state.state, MonitorState::Unhealthy, || async {
                let _ = bot.notify_node_start_failed(&e).await;
            })
            .await;
            Err(e)
        }
    }
}

/// Проверяет здоровье ноды (команда из UI / трея).
pub async fn guardian_check_health(state: Arc<GuardianState>) -> Result<Value, String> {
    match get_node_status().await {
        Ok(status) => {
            *state.node_status.lock().await = Some(status.clone());
            *state.state.lock().await = MonitorState::Running;
            Ok(serde_json::to_value(&status).unwrap())
        }
        Err(e) => {
            *state.state.lock().await = MonitorState::Unhealthy;
            Ok(json!({"error": e, "status": "unhealthy"}))
        }
    }
}

/// Перезапускает ноду.
///
/// G2: при установленном systemd-юните — `systemctl --user restart`
/// (с новым PID и авторестартом); `pkill -f` — только для ветки без юнита.
/// G3: синхронные операции — в spawn_blocking.
pub async fn guardian_restart_node(state: Arc<GuardianState>) -> Result<Value, String> {
    let bot = get_bot().await;
    let _ = bot.notify_node_restarting("Ручной перезапуск").await;

    let pid_before = { *state.nexxusd_pid.lock().await };
    let restart_res = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let backend = crate::process_backend::SystemdBackend;
        if crate::node_unit::is_installed() {
            // G2: юнит перезапускает systemd — новый MainPID подхватим после.
            let out = Command::new("systemctl")
                .args(["--user", "restart", crate::node_unit::NODE_UNIT_NAME])
                .output()
                .map_err(|e| format!("systemctl restart failed: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "systemctl restart {}: {}",
                    crate::node_unit::NODE_UNIT_NAME,
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            Ok(())
        } else {
            // Без юнита: stop по PID (G4), затем start; pkill — только фолбэк.
            if let Some(p) = pid_before {
                let _ = Command::new("kill").arg(p.to_string()).status();
                std::thread::sleep(Duration::from_millis(500));
            }
            backend.stop()?;
            let cfg = crate::node_config::load();
            let log = std::path::PathBuf::from(nexxusd_log());
            backend.start(&cfg, &nexxusd_bin(), &nexxusd_store(), &log)
        }
    })
    .await
    .unwrap_or_else(|e| Err(format!("join: {e}")));
    if let Err(e) = restart_res {
        let _ = bot.notify_node_start_failed(&format!("Перезапуск: {e}")).await;
        return Err(e);
    }
    sleep(Duration::from_secs(2)).await;

    guardian_start_node(state).await
}

/// Останавливает ноду (реальный pkill) и мониторинг.
pub async fn guardian_stop_node(state: Arc<GuardianState>) -> Result<Value, String> {
    *state.monitor_enabled.lock().await = false;
    *state.state.lock().await = MonitorState::Stopped;
    let bot = get_bot().await;
    let _ = bot.notify_node_stopping().await;
    // G3+G4: stop в spawn_blocking; без юнита — сначала kill по запомненному PID.
    let pid = { *state.nexxusd_pid.lock().await };
    let result = tokio::task::spawn_blocking(move || -> Result<(), String> {
        if pid.is_some() && !crate::node_unit::is_installed() {
            if let Some(p) = pid {
                let _ = Command::new("kill").arg(p.to_string()).status();
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        stop_nexxusd()
    })
    .await
    .unwrap_or_else(|e| Err(format!("join: {e}")));
    *state.nexxusd_pid.lock().await = None;
    match &result {
        Ok(_) => {
            let _ = bot.notify_node_stopped().await;
        }
        Err(e) => {
            let _ = bot.notify_node_start_failed(&format!("Остановка ноды: {e}")).await;
        }
    }
    result?;
    Ok(json!({"status": "node_stopped"}))
}

/// Возвращает текущее состояние гардиана.
pub async fn guardian_status(state: Arc<GuardianState>) -> Result<Value, String> {
    // Live-запрос к ноде вместо ожидания health-loop: UI обязан видеть ноду
    // сразу после опроса, даже если фоновый цикл ещё не набрал первый тик.
    let live = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        get_node_status(),
    )
    .await;
    match live {
        Ok(Ok(status)) => {
            ui_log(&format!("guardian_status: live ok, node_id={} version={}", status.node_id, status.version));
            *state.node_status.lock().await = Some(status);
            let mut st = state.state.lock().await;
            if *st != MonitorState::Starting && *st != MonitorState::Restarting {
                *st = MonitorState::Running;
            }
        }
        Ok(Err(e)) => ui_log(&format!("guardian_status: live ошибка — {e}")),
        Err(_) => ui_log("guardian_status: live таймаут 3s"),
    }
    let state_val = { state.state.lock().await.clone() };
    let node_status = { state.node_status.lock().await.clone() };
    let enabled = { *state.monitor_enabled.lock().await };
    let nexxusd_pid = { *state.nexxusd_pid.lock().await };

    Ok(json!({
        "state": format!("{:?}", state_val),
        "monitor_enabled": enabled,
        "node_status": node_status,
        "nexxusd_pid": nexxusd_pid,
        "api_reachable": api_is_reachable().await,
        "tg_configured": crate::telegram::get_bot().await.is_configured(),
        "tg_status": crate::telegram::telegram_config_status(),
    }))
}

/// Переключает мониторинг ВКЛ/ВЫКЛ (сам цикл живёт постоянно —
/// это только флаг участия в мониторинге).
pub async fn guardian_toggle_monitor(state: Arc<GuardianState>) -> Result<Value, String> {
    let mut enabled = state.monitor_enabled.lock().await;
    *enabled = !*enabled;
    Ok(json!({"monitor_enabled": *enabled}))
}

/// Отправляет тестовое сообщение в Telegram.
pub async fn tg_send_test() -> Result<Value, String> {
    let bot = get_bot().await;
    eprintln!(
        "[tg] is_configured={} token_from_env={} chat_from_env={}",
        bot.is_configured(),
        std::env::var("NEXXUS_TG_BOT_TOKEN").is_ok(),
        std::env::var("NEXXUS_TG_CHAT_ID").is_ok()
    );
    let r = bot
        .send_message("🧪 <b>Тест от NeXXus Guardian</b>\n\nПодключение к Telegram работает.")
        .await;
    eprintln!("[tg] send_message result: {r:?}");
    r?;
    Ok(json!({"status": "sent"}))
}

/// Отправляет произвольный алерт в Telegram (например, duress-PIN).
pub async fn tg_send_alert(text: &str) -> Result<Value, String> {
    let bot = get_bot().await;
    if !bot.is_configured() {
        return Ok(json!({"status": "not_configured"}));
    }
    bot.send_message(text).await?;
    Ok(json!({"status": "sent"}))
}

#[cfg(test)]
mod guardian_invariant_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// G1: во время await-уведомления мьютекс состояния должен быть свободен.
    /// Раньше guard жил через `.await` → `guardian_status` (тот же мьютекс)
    /// вставал, пока Telegram недоступен.
    #[tokio::test]
    async fn state_lock_is_free_during_notification() {
        // Тот же тип мьютекса, что в GuardianState::state (tokio::sync::Mutex).
        let lock = Mutex::new(MonitorState::Stopped);
        let saw_free = Arc::new(AtomicBool::new(false));
        let seen = saw_free.clone();
        let probe: &Mutex<MonitorState> = &lock;

        set_state_and_notify(&lock, MonitorState::Running, || async move {
            // «уведомление» в Telegram висит — лок обязан быть свободен
            match probe.try_lock() {
                Ok(g) => {
                    assert!(
                        matches!(*g, MonitorState::Running),
                        "состояние должно быть зафиксировано ДО уведомления"
                    );
                    seen.store(true, Ordering::SeqCst);
                }
                Err(_) => panic!("лок состояния удерживается во время await-уведомления"),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        })
        .await;

        assert!(
            saw_free.load(Ordering::SeqCst),
            "состояние не было видно во время уведомления"
        );
    }

    /// Контроль регрессии G1: старый паттерн (guard живёт через await)
    /// действительно удерживает лок — значит тест выше ловит именно этот
    /// класс дефекта, а не «проходит всегда».
    #[tokio::test]
    async fn old_pattern_would_hold_the_lock() {
        let lock = Mutex::new(MonitorState::Stopped);
        let probe: &Mutex<MonitorState> = &lock;
        let held = {
            let mut guard = lock.lock().await;
            *guard = MonitorState::Running;
            let held = probe.try_lock().is_err();
            tokio::time::sleep(Duration::from_millis(5)).await; // await с живым guard
            held
        };
        assert!(
            held,
            "старый паттерн должен был удерживать лок — иначе тест G1 ничего не проверяет"
        );
    }

    /// G6: keep=0 не должен удалять свежий бэкап.
    #[test]
    fn backups_to_delete_keep_zero_keeps_newest() {
        let names = vec!["b_new".to_string(), "a_old".to_string()];
        let del = backups_to_delete(&names, 0);
        assert_eq!(del, vec!["a_old".to_string()], "свежий бэкап нельзя удалять");
        assert!(!del.contains(&"b_new".to_string()));
    }

    #[test]
    fn backups_to_delete_keeps_requested_count() {
        let names: Vec<String> = (0..5).map(|i| format!("b{i}")).collect();
        // newest-first: b0 — самый свежий
        assert_eq!(backups_to_delete(&names, 3), vec!["b3".to_string(), "b4".to_string()]);
        assert!(backups_to_delete(&names, 5).is_empty());
        assert!(backups_to_delete(&names, 9).is_empty());
    }
}

#[cfg(test)]
mod start_flow_tests {
    use super::*;
    use std::time::Instant;

    /// Общий мьютекс на env-мутации — тесты идут параллельно.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn real_nexxusd() -> String {
        let dir = std::env::var("CARGO_TARGET_DIR_NEXXUS")
            .or_else(|_| std::env::var("CARGO_TARGET_DIR"))
            .unwrap_or_else(|_| "target".into());
        let cand = format!("{dir}/debug/nexxusd");
        if std::path::Path::new(&cand).exists() {
            cand
        } else {
            format!("{dir}/release/nexxusd")
        }
    }

    /// Прогоняет реальный флоу кнопки «Start» на НАСТОЯЩЕМ хосте:
    /// start_nexxusd → wait_for_api_ready → node_status.
    /// P0-C: помечен #[ignore] — тесту нужен реальный бинарь nexxusd и он
    /// трогает системный юнит/процессы. Гоняется отдельным CI-шагом после
    /// `cargo build -p nexxus-node`: `cargo test -- --ignored start_flow`.
    #[ignore]
    #[tokio::test]
    async fn start_flow_completes_with_timings() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("NEXXUSD_BIN", real_nexxusd());
        let _ = stop_nexxusd();
        let t0 = Instant::now();
        start_nexxusd().expect("start_nexxusd");
        eprintln!("[t+{:.1?}] spawned", t0.elapsed());
        // Guard отпускаем ДО await: std::sync::MutexGuard нельзя держать через
        // await (clippy::await_holding_lock). Нода уже запущена — env больше
        // не нужен, а блокировку берём снова на финальный remove_var.
        drop(_g);

        let ready = wait_for_api_ready(30).await;
        eprintln!("[t+{:.1?}] wait_for_api_ready(30) = {ready}", t0.elapsed());
        assert!(ready, "API не поднялся за 30с — это и есть 'зависание на Starting'");

        let status = get_node_status().await;
        eprintln!("[t+{:.1?}] get_node_status = {:?}", t0.elapsed(), status.as_ref().map(|s| &s.node_id));
        assert!(status.is_ok(), "node_status failed: {:?}", status.err());

        let _ = stop_nexxusd();
        {
            let _g = ENV_LOCK.lock().unwrap();
            std::env::remove_var("NEXXUSD_BIN");
        }
        eprintln!("[t+{:.1?}] done", t0.elapsed());
    }

    #[test]
    fn api_tcp_open_detects_listener_and_closed_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        assert!(super::api_tcp_open(&addr));
        drop(listener);
        // порт закрыт — connect_timeout отказывает быстро
        assert!(!super::api_tcp_open(&addr));
    }

    #[test]
    fn bin_and_paths_resolve_without_hardcoded_host() {
        let _g = ENV_LOCK.lock().unwrap();
        // NEXXUSD_BIN указывает на реальный файл → берётся он
        std::env::set_var("NEXXUSD_BIN", "/bin/true");
        assert_eq!(super::nexxusd_bin(), "/bin/true");
        std::env::remove_var("NEXXUSD_BIN");
        // без env — строка непустая (любой фолбэк разумен)
        assert!(!super::nexxusd_bin().is_empty());
        // store/log уважают env и HOME
        std::env::set_var("NEXXUS_STORE", "/tmp/x.redb");
        assert_eq!(super::nexxusd_store(), "/tmp/x.redb");
        std::env::remove_var("NEXXUS_STORE");
        assert!(super::nexxusd_store().ends_with("store.redb"));
        assert!(super::nexxusd_log_path().ends_with("nexxusd.log"));
    }
}

