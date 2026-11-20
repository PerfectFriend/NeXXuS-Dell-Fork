//! P0-C: управление процессом ноды через trait, чтобы тесты не трогали
//! реальный хост (systemctl/pkill по настоящему `~/.nexxus`).
//!
//! - [`SystemdBackend`] — продакшн: юнит через `systemctl --user`, «сирота»
//!   через spawn; stop — `systemctl stop` + `pkill -f` (как раньше).
//! - [`SpawnBackend`] — тестовый: держит **только своего** `Child`,
//!   `stop()` убивает его по PID, `Drop` делает kill_on_drop. Никаких
//!   pkill/systemctl, никаких общих путей.

#![cfg_attr(not(test), allow(dead_code))]

use crate::node_config::NodeConfig;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

/// Контракт управления процессом ноды.
pub trait ProcessBackend {
    /// Запускает ноду с конфигом `cfg`: бинарь `bin`, стор `store`, лог `log`.
    fn start(&self, cfg: &NodeConfig, bin: &str, store: &str, log: &Path) -> Result<(), String>;
    /// Останавливает ноду и ждёт завершения.
    fn stop(&self) -> Result<(), String>;
    /// Запущен ли процесс сейчас.
    fn is_running(&self) -> bool;
    /// MainPID (G4): у юнита — из systemd, у spawn — id child.
    fn main_pid(&self) -> Option<u32>;
}

/// C-5: лог-файл демона открывается с правами 0600 (только владелец),
/// т.к. туда может попасть чувствительное. На не-unix — обычное открытие.
fn open_log_private(log: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(log)
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
    }
}

/// Строит команду запуска: env из конфига + лог в файл.
pub(crate) fn build_spawn_cmd(cfg: &NodeConfig, bin: &str, store: &str, log: &Path) -> Result<Command, String> {
    if let Some(parent) = log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let log_out = open_log_private(log)
        .map_err(|e| format!("Не удалось открыть лог {}: {e}", log.display()))?;
    let log_err = log_out
        .try_clone()
        .map_err(|e| format!("Не удалось клонировать лог: {e}"))?;

    let mut cmd = Command::new(bin);
    cmd.arg(store)
        .env("NEXXUS_LOG", log)
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err));
    for (key, value) in crate::node_config::to_env(cfg) {
        cmd.env(key, value);
    }
    Ok(cmd)
}

/// Продакшн-бэкенд: systemd-юнит или «сиротский» процесс.
pub struct SystemdBackend;

impl ProcessBackend for SystemdBackend {
    fn start(&self, cfg: &NodeConfig, bin: &str, store: &str, log: &Path) -> Result<(), String> {
        // Нода под управлением systemd — поднимаем ТОЛЬКО через systemctl.
        if crate::node_unit::is_installed() {
            if crate::node_unit::unit_state() == "active" {
                return Ok(());
            }
            let out = Command::new("systemctl")
                .args(["--user", "start", crate::node_unit::NODE_UNIT_NAME])
                .output()
                .map_err(|e| format!("systemctl start failed: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "systemctl start {}: {}",
                    crate::node_unit::NODE_UNIT_NAME,
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            return Ok(());
        }
        // Без юнита — detached spawn (child не держим: процесс живёт сам).
        let mut cmd = build_spawn_cmd(cfg, bin, store, log)?;
        let _child = cmd
            .spawn()
            .map_err(|e| format!("Не удалось запустить nexxusd: {e}"))?;
        Ok(())
    }

    fn stop(&self) -> Result<(), String> {
        if crate::node_unit::is_installed() {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", crate::node_unit::NODE_UNIT_NAME])
                .status();
            std::thread::sleep(Duration::from_millis(800));
        }
        let _ = Command::new("pkill")
            .args(["-f", crate::guardian::NEXXUSD_MATCH])
            .status();
        std::thread::sleep(Duration::from_millis(1500));
        if self.is_running() {
            let _ = Command::new("pkill")
                .args(["-9", "-f", crate::guardian::NEXXUSD_MATCH])
                .status();
            std::thread::sleep(Duration::from_millis(500));
        }
        if self.is_running() {
            return Err("nexxusd не завершился после SIGKILL".into());
        }
        Ok(())
    }

    fn is_running(&self) -> bool {
        let output = Command::new("pgrep")
            .args(["-f", crate::guardian::NEXXUSD_MATCH])
            .stdout(Stdio::piped())
            .output();
        matches!(output, Ok(out) if !out.stdout.is_empty())
    }

    fn main_pid(&self) -> Option<u32> {
        if crate::node_unit::is_installed() {
            if let Ok(out) = Command::new("systemctl")
                .args(["--user", "show", "-p", "MainPID", "--value", crate::node_unit::NODE_UNIT_NAME])
                .output()
            {
                if let Ok(s) = String::from_utf8(out.stdout) {
                    if let Ok(pid) = s.trim().parse::<u32>() {
                        if pid > 0 {
                            return Some(pid);
                        }
                    }
                }
            }
        }
        // Fallback: самый старый подходящий процесс.
        Command::new("pgrep")
            .args(["-o", "-f", crate::guardian::NEXXUSD_MATCH])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|s| s.trim().parse::<u32>().ok())
    }
}

/// Тестовый бэкенд: только свой child, kill_on_drop.
pub struct SpawnBackend {
    child: Mutex<Option<Child>>,
}

impl SpawnBackend {
    pub fn new() -> Self {
        Self { child: Mutex::new(None) }
    }

    /// Убивает только своего child и ждёт его.
    fn kill_own(&self) {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut c) = guard.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}

impl Default for SpawnBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SpawnBackend {
    fn drop(&mut self) {
        // kill_on_drop: даже если тест забыл stop() — чужие процессы не тронуты.
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut c) = guard.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}

impl ProcessBackend for SpawnBackend {
    fn start(&self, cfg: &NodeConfig, bin: &str, store: &str, log: &Path) -> Result<(), String> {
        if self.is_running() {
            return Ok(());
        }
        let mut cmd = build_spawn_cmd(cfg, bin, store, log)?;
        let child = cmd
            .spawn()
            .map_err(|e| format!("Не удалось запустить {bin}: {e}"))?;
        *self.child.lock().map_err(|_| "mutex poisoned")? = Some(child);
        Ok(())
    }

    fn stop(&self) -> Result<(), String> {
        self.kill_own();
        Ok(())
    }

    fn is_running(&self) -> bool {
        let Ok(mut guard) = self.child.lock() else { return false };
        match guard.as_mut() {
            None => false,
            Some(c) => matches!(c.try_wait(), Ok(None)),
        }
    }

    fn main_pid(&self) -> Option<u32> {
        self.child.lock().ok()?.as_ref().map(|c| c.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TMP_N: AtomicUsize = AtomicUsize::new(0);

    /// Временный каталог без внешних крейтов.
    fn tempdir(tag: &str) -> PathBuf {
        let n = TMP_N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "nexxus-p0c-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Заглушка вместо nexxusd: спит, пока не убьют.
    fn stub_bin(dir: &Path) -> String {
        let p = dir.join("nexxusd-stub");
        std::fs::write(&p, "#!/bin/sh\nexec sleep 300\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        p.to_string_lossy().into_owned()
    }

    /// P0-C: SpawnBackend стартует/останавливает только СВОЕГО child.
    #[test]
    fn spawn_backend_start_stop_own_child_only() {
        let dir = tempdir("spawn");
        let bin = stub_bin(&dir);
        let store = dir.join("store.redb").to_string_lossy().into_owned();
        let log = dir.join("node.log");
        let cfg = NodeConfig::default();

        let backend = SpawnBackend::new();
        assert!(!backend.is_running());
        assert!(backend.main_pid().is_none());

        backend.start(&cfg, &bin, &store, &log).expect("start");
        assert!(backend.is_running(), "child должен быть жив");
        let pid = backend.main_pid().expect("pid своего child");
        assert!(pid > 0);

        backend.stop().expect("stop");
        assert!(!backend.is_running(), "после stop child мёртв");
        assert!(backend.main_pid().is_none());

        // Повторный start после stop — снова жив.
        backend.start(&cfg, &bin, &store, &log).expect("restart");
        assert!(backend.is_running());
        // Drop без stop — kill_on_drop, процесс не выживает.
        let pid2 = backend.main_pid().unwrap();
        drop(backend);
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !std::path::Path::new(&format!("/proc/{pid2}")).exists(),
            "kill_on_drop не сработал: процесс {pid2} выжил"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P0-C п.2+п.4: изолированный flow через SpawnBackend — tempdir,
    /// свободный порт, env в tempdir, предохранитель на занятом порту.
    /// Реальный хост (systemctl/pkill/~/.nexxus) не трогается вообще.
    #[tokio::test]
    async fn isolated_start_flow_via_spawn_backend() {
        let _g = crate::node_config::TEST_ENV_LOCK.lock().unwrap();
        let dir = tempdir("flow");
        let cfg_dir = dir.join("cfg");
        std::fs::create_dir_all(&cfg_dir).unwrap();

        // свободные порты
        let l1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let api_port = l1.local_addr().unwrap().port();
        let l2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p2p_port = l2.local_addr().unwrap().port();
        drop(l1);
        drop(l2);

        // П.4: предохранитель — дефолтный адрес API не должен быть занят,
        // иначе тест падает сразу и ничего не трогает.
        assert!(
            !crate::guardian::api_tcp_open("127.0.0.1:4010"),
            "порт 4010 занят реальной нодой — изолированный тест не запускаем"
        );

        // env → tempdir (сохраняем старые значения)
        let save = |k: &str| std::env::var(k).ok();
        let old_bin = save("NEXXUSD_BIN");
        let old_store = save("NEXXUS_STORE");
        let old_cfgdir = save("NEXXUS_CONFIG_DIR");
        let bin = stub_bin(&dir);
        std::env::set_var("NEXXUSD_BIN", &bin);
        std::env::set_var("NEXXUS_STORE", dir.join("store.redb").to_string_lossy().as_ref());
        std::env::set_var("NEXXUS_CONFIG_DIR", cfg_dir.to_string_lossy().as_ref());
        std::fs::write(
            cfg_dir.join("node.conf"),
            format!("listen=127.0.0.1:{p2p_port}\napi=127.0.0.1:{api_port}\nauditors=\nthreshold=0\nepoch_secs=300\ntor=0\nauto_backup_hours=24\nauto_backup_keep=5\npor_interval_hours=24\npor_enabled=0\nspec_version=v3\nlog_path={}\n", dir.join("node.log").display()),
        )
        .unwrap();

        let backend = SpawnBackend::new();
        crate::guardian::start_nexxusd_with(&backend).expect("start через SpawnBackend");
        assert!(backend.is_running(), "свой child запущен");
        assert!(backend.main_pid().is_some(), "main_pid заполнен (G4)");

        // guard внутри start: порт API занят → второй экземпляр НЕ плодим
        let occ = std::net::TcpListener::bind(("127.0.0.1", api_port)).unwrap();
        let backend2 = SpawnBackend::new();
        crate::guardian::start_nexxusd_with(&backend2).expect("start при занятом порту — тихий Ok");
        assert!(!backend2.is_running(), "при занятом API-порту новый процесс не spawn-ится");
        drop(occ);

        crate::guardian::stop_nexxusd_with(&backend).expect("stop через SpawnBackend");
        assert!(!backend.is_running(), "свой child убит");

        // восстановление env
        for (k, v) in [("NEXXUSD_BIN", old_bin), ("NEXXUS_STORE", old_store), ("NEXXUS_CONFIG_DIR", old_cfgdir)] {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P0-C: предохранитель — если на адресе API кто-то слушает, тест должен
    /// упасть сразу (ничего не трогая). Здесь проверяем сам детектор.
    #[test]
    fn guard_detects_occupied_api_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        assert!(
            crate::guardian::api_tcp_open(&addr),
            "занятый порт должен детектироваться"
        );
        drop(listener);
        // порт освободился — детектор молчит
        assert!(!crate::guardian::api_tcp_open(&addr));
    }
}
