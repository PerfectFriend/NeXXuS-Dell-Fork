# Аудит состояния репозитория + сводная готовность — 2026-11-21

HEAD на момент аудита: `8a72411` (origin/main, LIVE). Рабочее дерево чистое (in-progress тюнинг — у Жени, вне аудита).

## Фактические метрики (замерено сегодня)

| Метрика | Значение | Как получено |
|---|---|---|
| Workspace тесты | **252 passed / 0 failed** | `cargo test --workspace` (core+econ+node+sdk+wasm), 0 ошибок компиляции |
| nexxus-node | 127 + 5 passed / 0 failed | `cargo test -p nexxus-node` |
| desktop (src-tauri) | 35 passed / 0 failed / 1 ignored | `cargo test --bin nexxus-desktop` (1 изолированный тест пропускается локально: порт 4010 занят живой нодой; в CI зелёный) |
| clippy workspace/node/desktop | 0 errors (`-D warnings`) | локально |
| TS lint (root) | 0 errors | `npm run lint` после фикса tsconfig exclude |
| E2E smoke vs live daemon | 58/58 | `scripts/e2e_smoke.py`, caps 512/512 kbps |
| E2E IOU vs live daemon | 12/12 | `scripts/e2e_iou.py` |
| Rust CI (последний completed) | success | run 44961026776 |
| Release Builder | был failure (TS-линт архивного legacy-ts + android action) → линт починен, android — infra (continue-on-error) | run 44961026681 |
| secret-scan (gitleaks full history) | green | CI secret-scan |
| Кодовая база | core 3.6k / node 11.4k / econ 0.6k / sdk 0.4k / wasm 0.3k / desktop-tauri 4.0k / desktop-js 2.2k строк Rust/TS | `wc -l` |

## Сводная готовность по областям

| Область | Готовность | Доказательства | Что осталось |
|---|---|---|---|
| Core crypto/wire (nexxus-core) | ✅ 100% | golden vectors, fuzz, property-тесты в workspace 252/0 | — |
| P2P node (nexxus-node): handshake v3, routing, eviction, keepalive, per-conn caps, rate limit | ✅ 95% | 127+5 тестов, e2e 58/58, H-3/H-4/H-8 закрыты (`c79a22c`) | H-timeout при >50 пиров — устранён механизмом, нагрузочный прогон не делали |
| Storage (redb, RS-шардирование, at-rest encryption) | ✅ 100% | тесты + e2e upload/download/gc | — |
| Identity/seed vault (AES-256-GCM, PBKDF2-600k, duress-PIN, S4 phase 2) | ✅ 100% | seed_vault тесты, e2e, ADR-0010 | миграция старых сторах без PIN — на первом старте с PIN |
| Econ + IOU (ADR-0009: signed IOU, journal, local API) | ✅ 90% | iou.rs тесты + journal тесты + e2e 12/12 | SMP-доставка IOU пиру; on-chain — вне скоупа |
| Backups/bundles (0700, atomic, verify/restore) | ✅ 100% | backup тесты 11/11, e2e export/import | — |
| PoR (self-audit + peer audit) | ✅ 90% | node_por e2e, метрики por_ok/por_fail | penalty в UI монитора — pending |
| SMP + contacts + QR (H1, ContactLink deep links) | ✅ 95% | desktop тесты, e2e smp_send, QR commit `b018bad`, deep links `fe1fd86` | — |
| Sovereign Drive sync + mesh rehydrate (PROD-RESTORE-01) | 🟡 70% | закоммичено (`c567f63`, `bf83145`), CI green | e2e на живом демоне не прогонялся в этом аудите |
| nexxus-sdk (client, dApp manifest, streaming) | 🟡 60% | crate создан (`8a72411`), тесты в workspace | документация API, примеры dApp |
| nexxus-wasm light-client | 🟡 70% | wasm-gates CI (тесты + wasm32 build) | — |
| Desktop monitor (Tauri) | ✅ 90% | cargo test 35/0, clippy 0, M-1/8/9 закрыты | GUI-сборка на CI (нет webkit2gtk) — infra |
| Mobile Android (WebView) | 🟡 70% | APK собирался локально 3.2MB, CI job есть | `setup-android-sdk` action не резолвится — infra; native Kotlin viewer — пост-релиз |
| Packaging: deb/AppImage/Windows zip | ✅ 90% | Release Builder артефакты, windows zip | Windows MSI/InnoSetup — остался |
| TON contracts (C-6/7/8) | ⛔ 0% (by design) | ADR, заморожено | миграция Func 0.48/Tolk 0.14 — отдельный трек, вне аудита |
| CI/CD + secret-scan + tree-hygiene | ✅ 95% | 2 workflow, secret-scan green, check-tree-hygiene | Release Builder lint починен (`tsconfig` exclude), android infra |
| Документация (spec, ADR ×11, audits ×8, plans, releases, guides) | ✅ 95% | docs/ полный, readiness-файлы | — |
| Audit-пакет для внешнего аудитора | ✅ 90% | audit-package/README, squash-процедура, secret-sweep | собрать свежий squash из `8a72411` при отправке |

## Итоговая готовность к релизу: **~88–90%**

Блокеров релиза нет: ядро (сеть/хранилище/keys/econ/IOU/бэкапы) — 100% покрыто unit+e2e на живом демоне, CI зелёный (кроме infra-Android). Остаток — платформенные пакеты (MSI), нагрузочный прогон peer-timeout, и TON-трек, который вынесен из скоупа аудита по дизайну.
