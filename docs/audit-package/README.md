# External Audit Package — NeXXus Node v2.0.0-prototype (2026-11-14)

Для внешнего аудитора (Grok). Цель: честная карта проекта — что реализовано,
как это проверить самостоятельно, что сознательно НЕ сделано.

## 1. Что это

NeXXus Node — P2P-узел децентрализованного хранилища (Rust workspace):
- `crates/nexxus-node` — демон `nexxusd` (P2P 4001, локальный WS API 4010, token-auth)
- `crates/nexxus-core` — wire-протокол v3, crypto, PoR
- `nexxus-desktop` — Tauri-монитор/гардиан (управляет процессом ноды, UI)
- `nexxus-mobile` — Android-клиент

## 2. Как проверить самостоятельно (5 команд)

```bash
git clone <repo> && cd NeXXus-Node
cargo test --workspace                 # 190+ тестов, все зелёные на момент аудита
cargo clippy --workspace --all-targets -- -D warnings   # 0 warnings
cargo build --release -p nexxus-node   # собирает nexxusd
NEXXUS_DATA_DIR=$(mktemp -d) NEXXUS_LISTEN=127.0.0.1:14001 NEXXUS_API_ADDR=127.0.0.1:14010 NEXXUS_TOR=0 \
  ./target/release/nexxusd &            # поднять демон
python3 scripts/e2e_smoke.py            # 46/46 живых WS-проверок (auth, chunks, backup, SMP, names, bootstrap, econ-подпись)
```

Desktop: `cd nexxus-desktop/src-tauri && cargo test` (22/22, включая реальный spawn/stop ноды).

## 3. Единый конфиг (важно для понимания портов)

Нода и монитор читают **один файл** `<NEXXUS_CONFIG_DIR|~/.nexxus>/node.conf`
(ключ=значение; приоритет env > файл > дефолт). Дефолты единые:
P2P `127.0.0.1:4001`, API `127.0.0.1:4010`. См. `crates/nexxus-node/src/node_config.rs`.

## 4. Документы аудита (читать в этом порядке)

1. `SECURITY.md`, `docs/THREAT_MODEL.md` — модель угроз, RES-01..05, политика eviction
2. `docs/audits/2026-11-14-honesty-audit.md` — наш собственный честный аудит (что работает, что исправлено, что не проверено)
3. `docs/adr/` — архитектурные решения (включая ADR-0009 settlement — **только дизайн**, платежей нет)
4. `docs/plans/2026-11-12-evolution-post-rc1.md` — roadmap post-RC1 со статусами
5. `PROTOCOL_WIRE_SPEC.md`, `NEXXUS_SPECIFICATION_V2.md` — спецификации
6. `USER_GUIDE.md` — эксплуатация, env-таблица

## 5. Безопасность: что заявлено

- API: token auth, fail-closed, constant-time compare, 401 без токена; `/metrics` тоже под токеном
- Store at rest: шифрование (A2), файл 0600
- Backup/bundle: PIN + шифрование, delete только с confirm
- Self-update (G4): ed25519-подпись, rollback
- Bootstrap-список (E6): ed25519-подпись registry, expiry, tamper→error
- Structured logging: JSON-lines, zero-secret policy
- Squash-mirror артефакт раздачи: 0 реальных хитов секретов при строгом скане (проверено 2026-11-14: worktree + вся git-история, 0 хитов)

## 6. Сознательно НЕ сделано (не считать багами)

- Экономика: **accounting only** — нет платежей, нет on-chain (явный disclaimer в README и `node_econ_export`)
- Settlement: только ADR-0009 (дизайн off-chain IOU), кода нет
- FUSE-монтирование, light-client, marketplace, плагины политик — в плане, не реализованы
- Windows service/MSI — есть cross-compile артефакт в CI, установщика нет
- Живой Tor-onion publish проверен только opt-in CI job

## 7. Известные открытые вопросы для аудитора

- P2P по умолчанию на 127.0.0.1 (RES-02), но хостовой конфиг может открыть 0.0.0.0 — см. THREAT_MODEL
- Eviction пиров при full table (score < 40) — задокументировано RES-05
- Desktop UI на этом хосте проверен тестами + статикой, но не «глазами» (нет дисплея)
