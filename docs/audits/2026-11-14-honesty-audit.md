# Аудит NeXXus-Node: что реально работает vs что нет (2026-11-14, post-`df4a2b8`)

Метод: самостоятельная сборка и прогон всех тестов, статический кросс-чек
UI→main.js→tauri-команды→методы ноды, проверка собранных артефактов,
живые WS-пробы против демона. Без доверия к чужим отчётам.

## 1. Работает реально (с доказательствами)

| Что | Доказательство |
|---|---|
| Workspace-тесты ноды | `cargo test --workspace` → 189 passed / 0 failed (прогнано в аудите) |
| Десктоп-тесты (guardian start/stop/restart реальным spawn) | `cargo test` в src-tauri → 22/22 (прогнано в аудите) |
| JS-тесты фронтенда | `npm run test` в nexxus-desktop → 5/5 |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` → 0 warnings |
| E2E против живого nexxusd | `scripts/e2e_smoke.py` → 46/46 (auth, все методы, bundles, names, bootstrap, подпись econ) |
| Цепочка монитор→нода | WS на порт из `~/.nexxus/node.conf` (5010): auth ok, `node_status` → node_id (проба в аудите) |
| UI→нода wiring (статика) | 50 кнопок: все 50 имеют обработчики; 29 api()-методов все есть в dispatch ноды; 31 tauri-команда все зарегистрированы в `generate_handler!` |
| Guardian spawn | `start_nexxusd()` реально спавнит `nexxusd` с env из конфига (guardian.rs:309-360) |
| CSP Tauri | в tauri.conf.json и в собранном бинарнике: `connect-src ... tauri://localhost http://tauri.localhost ipc: ws://...` — invoke() проходит |
| Bootstrap-список (E6) | ed25519 verify + expiry; tamper/expired → error (unit + e2e) |
| Versioning имён (E2) | name_set/get/history/list; история на наносекундах; e2e 44/44→46/46 |

## 2. Найдено и ИСПРАВЛЕНО в этом аудите (broken)

1. **Собранный фронтенд отставал от src** — `src-tauri/gen/assets` не содержал
   `btn-name-set`/`node_name_set` (E2 UI). Инсталлированный бинарник
   `~/.local/bin/nexxus-desktop` (12:32) был собран до фикса CSP-era UI.
   → `npm run build` (gen обновлён 18:06, `btn-name-set` на месте), пересборка
   release (18:08), установка в `~/.local/bin/`. Теперь бинарник содержит свежий UI.
2. **systemd-юнит монитора указывал на старый кэш-путь**
   `ExecStart=/home/thomas/build/cache/cargo-target-nexxus/release/nexxus-desktop`
   → заменён на `/home/thomas/.local/bin/nexxus-desktop`.

## 3. Найдено, требует решения владельца (не баг кода)

- **`~/.nexxus/node.conf` на этом хосте: `api=127.0.0.1:5010`, `listen=0.0.0.0:4001`.**
  Нода по умолчанию слушает API на 4010; если нода запущена НЕ через guardian
  (который передаёт `NEXXUS_API_ADDR` из конфига), а напрямую/скриптом —
  она поднимется на 4010, а монитор будет стучаться в 5010 → «кнопки мёртвые».
  Это ровно та симптоматика, что была в логах раньше. Рекомендация: либо
  guardian всегда единственный способ запуска, либо привести конфиг к 4010.
  Сейчас guardian→нода консистентны (проверено живой пробой на 5010).
- P2P на `0.0.0.0:4001` в конфиге хоста — осознанный выбор (RES-02 закрыт для
  дефолта 127.0.0.1), но на этом хосте наружу торчит. Записано, не баг.

## 4. Мёртвое/фейковое — НЕ обнаружено

- Stub-grep по Rust/JS: нет TODO/FIXME/placeholder в боевом коде (3 хита —
  легитимные комментарии про placeholder-подпись в wire-векторах, где верификация
  — задача вызывающего; это задокументировано).
- Нет «кнопок без обработчика»: все 50 id из index.html имеют addEventListener.
- Нет api()-вызовов без метода в ноде; нет invoke() без команды в generate_handler.
- Нет «успех без записи»: статусы пишутся из реальных ответов ноды.

## 5. Не проверено (нужен дисплей/хост)

- Реальный рендер окна Tauri на этом хосте (нет DISPLAY/Xvfb) — проверялось
  через тесты guardian (22/22, включая реальный start/stop/restart процесса)
  и статический кросс-чек, но не «глазами».
- Tor onion publish вживую — есть opt-in тест (CI job `tor-integration`),
  здесь не запускался (нужна сеть Tor).
- Windows-сборка — только CI cross-compile артефакт, без запуска на Windows.

## 6. Unbuilt (план, не дефект)

FUSE-монтирование, light-client/mobile viewer, плагины политик хранения,
formal verification, settlement-код (ADR-0009 — только дизайн), marketplace.
