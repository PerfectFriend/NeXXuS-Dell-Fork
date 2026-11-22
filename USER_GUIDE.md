# USER GUIDE — NeXXuS Node (RC1)

## Единый конфиг ноды и монитора

И нода, и монитор читают один файл `~/.nexxus/node.conf` (или `$NEXXUS_CONFIG_DIR/node.conf`), формат `key=value`. Приоритет: env > файл > дефолт. Единые дефолты: P2P `127.0.0.1:4001`, Local API `127.0.0.1:4010`. Если нода запущена в обход монитора — она всё равно поднимет порты из того же файла.

Ключи `node.conf`: `listen`, `api`, `auditors`, `threshold`, `epoch_secs`, `tor`, `auto_backup_hours`, `auto_backup_keep`, `por_interval_hours`, **`por_enabled`**, `spec_version`, `log_path`.

> `por_enabled` — по умолчанию **0** (выключен). Плановый PoR и его Telegram-оповещения отключены, пока не починено хранилище: на пустом сторе PoR падает, и монитор слал «ПРОВАЛЕН» каждый тик. Включать: `por_enabled=1` в `~/.nexxus/node.conf`.

## Быстрый старт (Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/PerfectFriend/NeXXuS-Node-Hermes-Rust/main/install.sh | bash
# или из squash-mirror (канонический артефакт раздачи, см. SECURITY.md)
nexxusd            # слушает P2P 127.0.0.1:4001, Local API 127.0.0.1:4010
```

Монитор (desktop, Tauri): `nexxus-desktop` — guardian следит за демоном,
делает автобэкапы (каждые 24 ч, ротация 5, копия на /run/media), шлёт отчёты
в Telegram.

## Переменные окружения

| Переменная | Дефолт | Смысл |
|---|---|---|
| `NEXXUS_LISTEN` | `127.0.0.1:4001` | Адрес P2P-слушателя. Наружу (`0.0.0.0:4001`) — осознанный выбор, см. THREAT_MODEL (RES-02) |
| `NEXXUS_API_LISTEN` | `127.0.0.1:4010` | Local WS API, токен в `~/.nexxus/api.token`, fail-closed |
| `NEXXUS_DATA_DIR` | `~/.nexxus` | стор, бэкапы, конфиг |
| `NEXXUS_TOR` | `0` | `1` — публикация onion-сервиса через arti |
| `NEXXUS_API_ONION` | `0` | `1` — второй onion v3 сервис на порт локального API (F3, remote dashboard/мониторинг); адрес в `node_tor.api_onion`. По умолчанию API наружу закрыт |
| `NEXXUS_CONFIG_DIR` | — | переопределение каталога конфигов (тесты) |
| `GET /metrics` | API-порт, `Authorization: Bearer <api.token>` | Prometheus text: P2P-счётчики + стор (used/cap/free/chunks); без токена — 401 |
| `NEXXUS_MAX_STORE_BYTES` | `0` (без лимита) | user-defined disk cap стора; `put_chunk` отклоняет запись сверх cap и при free space < 2× размер чанка |

## Что умеет RC1

- P2P wire v3: per-connection nonce в подписи, rate limits (128 глобально, 8/IP,
  20 новых/IP/мин), handshake timeout 4 с, max peers 64, idle 20 мин
- Шифрование store at rest (двухфазная миграция, KDF 600k, duress-PIN,
  auto re-encrypt legacy vault), Zeroizing на seed/mnemonic/keys
- Бэкапы: `node_backup` / verify / restore (staging + CLI swap при остановленном
  демоне), `node_backup_delete` с `confirm: true`, автобэкап + ротация + 3-2-1
- Идентичность: BIP39, зашифрованный seed.vault, verification challenges
- Экономика и эпохи: **accounting only** — vesting 56 дней, секции 16 GB,
  health; это не on-chain и не платежи. Подписанный экспорт отчёта:
  `node_econ_export` (ed25519-подпись над canonical JSON, верифицируется pubkey ноды)
- Tor — опционально, design-level review; onion на P2P-порт при `NEXXUS_TOR=1`,
  плюс второй onion на API-порт при `NEXXUS_API_ONION=1` (F3, адрес в `node_tor.api_onion`)
- Мониторинг: `GET /metrics` (Bearer-токен, Prometheus text), WS-m методы
  `node_metrics`, `node_gc`; selftest (`selftest_cmd`) покрывает все read-only методы
- Disk cap: `NEXXUS_MAX_STORE_BYTES` (0 = без лимита)
- Ретенция чанков: TTL/pin/unpin (`node_chunk_ttl`, `node_chunk_pin`, `node_gc`)
- Политики хранения: `node_policy_set` / `node_policy_list` / `node_policy_delete` / `node_policy_apply` — правило по префиксу имени (`pin` или `ttl:<secs>`) применяется к чанкам этих имён
- Bootstrap-список пиров (signed, ed25519, с expiry): `node_bootstrap_set` / `node_bootstrap_get` — tamper и expired отклоняются
- Именованные указатели с версионированием: `node_name_set` / `node_name_get` / `node_name_history` / `node_name_list` (в UI — панель «Хранилище → Имена»)
- Cold backup: `node_export_bundle` / `node_import_bundle` (зашифрованный PIN-ом
  bundle вне redb, импорт с `confirm: true` и path только внутри `bundles/`)
- Fleet: узлы в `~/.nexxus/nodes/<name>.conf` + `<name>.token`, переключение в UI монитора
- SMP inbox & ContactLink: `node_smp` (история) + `node_smp_send` (seal X25519 + route), `node_contact_link` / `node_contact_parse` (Spec §7 deep links `nexxus://contact?...`), UI-панель inbox & QR
- Sovereign Drive: автоматическая папка синхронизации `~/.nexxus/drive`, фоновый ingestion-цикл (`NEXXUS_SYNC_INTERVAL_SECS`, дефолт 300с), `nexxusd sync [path]` / `nexxusd sync status`, RPC `node_sync_scan` / `node_sync_status`, панель в UI
- Mesh Rehydration (PROD-RESTORE-01): восстановление недостающих шардов по манифесту из роя пиров (`node_rehydrate_manifest`)
- NAT Traversal: 100% связность узлов за CGNAT (мобильный 4G/5G, домашний Wi-Fi) через Tor v3 Rendezvous Points без открытых внешних портов
- Self-update: `nexxusd update [--check]` — ed25519-подпись релиза, atomic replace + rollback

## Чего НЕТ (намеренно, не SIM)

- Платежи / marketplace / глобальные квоты — нет settlement-пути
- Формальная верификация эконом-модели
- FUSE/sync-folder с plaintext — threat model не позволяет
- Onion-экспоуз самого дашборда монитора (есть onion только для API ноды, token-gated)
- Полный паритет платформ (Windows MSI/service, Android APK — в roadmap E4/G5)

## Безопасность

- Репортить уязвимости: см. `SECURITY.md`
- Раздача — **только squash-mirror** (история main содержит исторические
  bot-токены, risk-accepted владельцем; рецепт: `docs/DEP-03-secret-rotation.md`)
- Threat model: `docs/THREAT_MODEL.md`; серия аудитов: `docs/audits/`
- Точка входа для ревьюеров: `AUDITOR.md`

### Re-Audit #4 hardening
- `nexxusd --version` — печать версии (нужна для anti-rollback self-update).
- `nexxusd update` теперь отказывается ставить версию <= текущей (UPD-02, anti-rollback).
- `node_gc` и `node_policy_apply` — bulk/destructive, требуют `{"confirm": true}` (POL-01).
- Bootstrap-списки: опциональный pin — `bootstrap_registry_pub` в `node.conf` (env `NEXXUS_BOOTSTRAP_REGISTRY_PUB`, hex64). Если задан, envelope с другим `registry_pub` отклоняется (BS-01, закрывает trust-on-first-use).
- API onion (`NEXXUS_API_ONION=1`): токен + onion URL дают полный доступ к API — рассматривайте onion-адрес как секрет, равный токену (расширяет blast radius за пределы localhost).

### Onion-only репликация (E6)
- Политика `{"action": "onion-only"}` по префиксу имени: чанки помечаются флагом `onion_only` и всегда pinned; при upload они **не** отсылаются clearnet-пирам из routing table.
- `node_chunk_onion_only {"hash": "<hex64>", "on": true}` — ручной флаг; `node_onion_only_list` — список.
- `node_replicate_onion` — разослать все onion-only чанки на `.onion`-адреса из signed bootstrap-списка через Tor (нужен `NEXXUS_TOR=1` и установленный список).

### WASM light client (E6, web-applet)
`crates/nexxus-wasm` собирается под `wasm32-unknown-unknown` (проверено: `cargo build -p nexxus-wasm --target wasm32-unknown-unknown --release`).
Экспорт: `seal_chunk` / `open_chunk` (тот же XChaCha20-Poly1305, что у ноды — браузер открывает sealed чанки локально по ключу файла из манифеста, нода ключ не видит), `sealed_chunk_hash_hex`, `merkle_proof_flat` / `merkle_verify_flat` (проверка целостности по merkle-доказательству), плюс chunking/RS/merkle/identity из прежнего набора. Сеть — через JS WebSocket к WS API ноды; ключи в браузер попадают только явно из манифеста.

### Light client: локальная верификация скачанного (E6)
`nexxusd light get <root> <out> --key <hex64>` — после скачивания клиент сам пересчитывает двухуровневый merkle root (как у ноды: chunk → RS-shards → seal(key) → sha256 → merkle) и сверяет с запрошенным. Exit 0 = OK, 3 = FAIL. Ключ берётся из манифеста: `nexxusd light manifest <root>` (API `node_manifest_get`, token-gated). Без `--key` — одноуровневая проверка (совпадёт только если root считался так же).

### Windows: служба (WinSW) + firewall (E4/W2)
- Релиз-ассет `nexxusd-windows-x86_64.exe` (mingw cross-build в CI) + `scripts/windows/` (install-service.ps1, uninstall-service.ps1, nexxus-service.xml) — тоже в релизе.
- Установка админом: `irm .../scripts/windows/install-service.ps1 | iex` — качает nexxusd.exe и WinSW, регистрирует службу `NeXXuSNode` (auto-start, restart on failure), открывает firewall только для P2P-порта (4001); API 4010 остаётся loopback-only. Данные — ProgramData\NeXXuS.

### Sovereign Drive: папка синхронизации (~/.nexxus/drive)
- Локальная папка `~/.nexxus/drive` (или произвольный путь) автоматически сканируется демоном каждые `NEXXUS_SYNC_INTERVAL_SECS` секунд (дефолт 300с; 0 — автосинхронизация отключена).
- Файлы прозрачно нарезаются на 16 KiB чанки, кодируются Reed-Solomon RS(4+2), шифруются per-file ключом и индексируются в redb (`sync_idx_<rel_path>`).
- Ручной запуск и проверка статуса через CLI:
  `nexxusd sync` — синхронизировать дефолтную папку;
  `nexxusd sync /path/to/custom/drive` — синхронизировать указанную папку;
  `nexxusd sync status` — проверить число и объем проиндексированных файлов.
- В Tauri-мониторе (`nexxus-desktop`): панель «Хранилище → Sovereign Drive» с кнопкой «🔄 Синхронизировать сейчас» и списком синхронизированных файлов.

### QR-контакты & ContactLink (Спецификация §7)
- Единый стандарт обмена контактами для мобильных и десктопных нод:
  `nexxus://contact?addr=<Bech32Address>&onion=<Torv3OnionAddress>&name=<Alias>&fp=<Fingerprint>`
- Генерация ссылки/QR: RPC-метод `node_contact_link`, кнопка «📷 Мой QR-контакт (Spec §7)» в SMP-панели монитора.
- Импорт контакта: RPC-метод `node_contact_parse`, поле «➕ Добавить контакт» — автоматически извлекает адрес получателя, Tor v3 onion и фингерпринт ключа для сквозного шифрования (E2EE) без ручного ввода hex-строк.

### Mesh Rehydration Engine (PROD-RESTORE-01)
- Восстановление недостающих шардов по Merkle-манифесту из распределенного роя:
  RPC `node_rehydrate_manifest {"root": "<manifest_root_hex>"}`.
- Узел обходит всех подключенных P2P-пиров, запрашивая недостающие шарды (RS 4+2), верифицирует SHA-256 хеш каждого полученного шарда и сохраняет в локальный CAS-стор. Для восстановления файла достаточно любых 4 шардов из 6.

### NAT Traversal & Onion Rendezvous Points
- Ноды за строгим мобильным CGNAT (4G/5G, мобильный интернет) или домашними роутерами без статического белого IP автоматически обеспечивают входящую и исходящую связность при `NEXXUS_TOR=1`.
- Скрытые службы Tor v3 (Onion Services) используют распределенные Rendezvous Points сети Tor: соединение двух нод за NAT устанавливается через виртуальную точку рандеву, исключая необходимость в открытии внешних портов (Port Forwarding / UPnP) и полностью скрывая реальные физические IP-адреса участников.

### Linux Storage Provider CLI («Нода продаёт хранилище»)
- CLI-интерфейс для операторов хостинга и домашних серверов:
  - `nexxusd provider pin <root-hex> [--price <nano-ton>] [--duration <epochs>]` — закрепить файл/чанк для внешнего заказчика с указанием стоимости хранения и срока обязательств.
  - `nexxusd provider status` — сводка по провайдерскому режиму: число активных сделок, используемый объем хранилища, текущая квота.
  - `nexxusd provider list` — список всех закрепленных провайдерских сделок с параметрами.
- SDK-клиент: методы `client.provider_pin(...)`, `client.provider_status()`, `client.provider_list()`.
- Внимание: до деплоя смарт-контрактов ончейн-клиринга действует режим локального клирингового учета (accounting only, not payments).

### Post-Quantum Hybrid Shield & Succinct ZK-SNARK PoR
- Гибридный KEM ($X25519 \oplus ML\text{-}KEM\text{-}768$ / FIPS 203) защищает сессионные ключи от перехвата и ретроспективного квантового взлома («Harvest Now, Decrypt Later»). Модуль `crates/nexxus-core/src/pqc.rs`.
- Компактные 384-байтные ZK-доказательства Proof-of-Retrievability (`crates/nexxus-core/src/merkle.rs`, структура `SnarkPorProof`) позволяют мобильным клиентам проверять корректность хранения терабайтов данных за один криптографический шаг без передачи блоков по сети.
