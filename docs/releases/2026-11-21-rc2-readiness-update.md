# RC2 readiness update — 2026-11-21

HEAD: `c79a22c` (origin/main, LIVE)

## Gates (run 2026-11-21)

| Gate | Result |
|---|---|
| `cargo test -p nexxus-node` | 128 passed / 0 failed / 1 ignored |
| `cargo clippy -p nexxus-node --all-targets -- -D warnings` | 0 errors |
| nexxus-desktop `cargo test --bin nexxus-desktop` | 35 passed / 0 failed / 1 ignored (1 изолированный тест пропускается локально: порт 4010 занят живой нодой; в CI зелёный) |
| desktop clippy `--bins --all-targets -- -D warnings` | 0 errors |
| e2e smoke vs live daemon (bandwidth caps 512/512) | 58/58 |
| `scripts/e2e_iou.py` vs live daemon | 12/12 |
| Rust CI + Release Builder on `af410d4`+ | success; secret-scan (gitleaks, full history) green |

## Closed this cycle (pre-audit sweep 2026-11-21)

- **H-4/H-8** (`c79a22c`): keepalive — signed Ping каждые 60s на established P2P-соединениях (мёртвый пир обнаруживается по ошибке записи, метрика `keepalives_sent`); per-connection inbound token bucket `NEXXUS_CONN_MAX_DOWN_KBPS` (дефолт 4096 kbps) поверх глобального cap — один пир не может душить остальных; убран дубль `register_peer`; poison-tolerant `peer_scores`; тест `wait_down2_waits_the_longer_bucket`. H-3 (replacement cache) закрыт ранее 2026-11-20.
- **ADR-0009 (IOU)** полностью: `nexxus-econ/src/iou.rs` (signed `nexxus-iou/v1`, canonical JSON, ed25519, expiry 30d, min 0.001 NEXX), `iou_journal.rs` (append-only `iou.log` 0600 + fsync, load при старте, anti-replay по (debtor, nonce)), local API `iou_issue/iou_list/iou_balance/iou_redeem`, E2E 12/12 на живом демоне (`b811617`, `46e259e`, `d585abc`, `834762e`).
- **H1**: QR-обмен контактами в SMP-панели (`b018bad`).
- **M-1/M-8/M-9** (desktop): код закрыт — `get_bot()` без реентрантного дедлока (ранний drop guard, komment в telegram.rs), `monitor_version_cmd` + `NodeStatus.version`, старт ноды через `systemctl --user` при установленном юните (guardian.rs). Desktop-тесты зелёные.
- **H-20–H-22 (legacy-TS демон/инсталляторы)**: жёсткая фиксация — legacy web-UI (корневые `src/`, `vite.config.ts`, `tsconfig.json`, `index.html`, root `package.json`), `scripts/linux-daemon.ts`, `install*.ps1/bat`, `nexxus-start/stop.bat` помечены как **frozen/deprecated** в `docs/audits/2026-11-15-auditor-briefing.md` (M-11/M-12); канон — Rust/SLIP-0010 + Tauri `nexxus-desktop`. Физически переносить в `docs/archive/` не стали: корневой vite-app не входит в release-сборку (CI `desktop-gates` работает в `nexxus-desktop/`), перенос не даёт выигрыша и рискует ломом локальных скриптов. Удаление — отдельное решение владельца после аудита.
- **BKP-02** (backups dir 0700 + тест), **VLT-03** (duress-PIN неотличим от успеха), **Windows zip-артефакт** в Release Builder — закрыты ранее.

## Known non-blockers / out of audit scope

- **C-6/C-7/C-8** TON-контракты: заморожены до миграции Func 0.48 / Tolk 0.14; on-chain деплоя нет.
- STUN/hole-punching: отложено. PoR-penalty в UI: pending. S4 phase-2 на старых сторах без PIN: произойдёт на первом старте с PIN (ADR-0010).
- Android CI (`setup-android-sdk` не резолвится в реестре) и desktop-GUI CI (нет webkit2gtk на раннере) — infra, вне скоупа; APK и Windows zip собираются.

## Release readiness

**~90%** — core node (P2P + keepalive + per-conn caps, storage, vault/seed, econ + IOU, backups, bundles, PoR) покрыт unit + двумя e2e-наборами на живом демоне. Остаток — платформенные пакеты (Windows MSI) и TON-трек (вне скоупа аудита).

## Пакет внешнему аудитору (Коляну)

Следовать `docs/audit-package/README.md` §0 + скилл `external-audit-handoff`:
1. Squash-артефакт из текущего HEAD (1 коммит, `export-ignore` для owner-only материалов), secret-sweep артефакта (magic bytes, не только текст), 0 хитов.
2. Brief по `docs/audits/` + этот файл как «что изменилось с прошлого базового коммита»: `git log --oneline 41a7335..HEAD`.
3. Полная история `main` **не** отдаётся (в истории были секреты S1 — squash-only).
4. В work order включить: TON out-of-scope, H-20–22 freeze decision, S4 phase-2 на старых сторах.
