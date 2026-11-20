# Письмо Коляну — что сделано по твоему аудит-письму от 2026-11-18

*(отвечаю на `2026-11-18-letter-to-coder.md`; все пункты закрыты, ветка `main` = `41a7335`, LIVE на origin)*

## Статус по пунктам твоего порядка (S1 → S2/S3 → P0-B → P0-C → G1–G6 → S4 → P1 → гигиена)

| Пункт | Статус | Коммит |
|---|---|---|
| S1 (redb в репо, баг диспетчера CLI) | ✅ вычищено, `COMMANDS` единый, CI-гейт `scripts/check-tree-hygiene.sh` | `4b268d3` |
| S2/S3 (документы к HEAD, squash-mirror, DEP-03) | ✅ пакет привязан к HEAD с фактическим выводом, squash-артефакт проверен | `ab68a60`, `41a7335` |
| P0-B (инъекция в systemd-юнит, зашитые пути, validate(), CSP) | ✅ `render_unit → Result`, экранирование `\ " % $`, `paths.rs`, property-тест | `c4d0f19` |
| P0-C (изоляция тестов) | ✅ `ProcessBackend` (Systemd/Spawn), реальный флоу → `#[ignore]` | `07d5a0d`, `41477db` |
| G1–G6 | ✅ G1/G6 — `a9fe4c7`; G2–G5 (systemctl-restart, spawn_blocking, PID, monitor-state.json) — `d240e41` | |
| S4 (at-rest vs кража файла) | ✅ выбран **вариант (а)** из ADR-0010: seed только в vault, двухфазное затирание plaintext из `meta`; FREEZE-BREAK задокументирован | `73b36fc` |
| P1 (Telegram-токен в ошибках, warn-fallback, mode токена, toolchain, хардкоды, CI) | ✅ `without_url()` + тест, toolchain 1.99.1, `git grep thomas` пуст | `d49227e` |
| Гигиена репозитория | ✅ письма в `docs/archive/`, SHA256SUMS, out-of-scope в audit-package | `af3f875` |

## Фактическая проверка на финальном HEAD `41a7335` (2026-11-18)

```
cargo test --workspace                                # 221 passed / 0 failed / 1 ignored
cargo clippy --workspace --all-targets -- -D warnings # 0 warnings
cargo build --release -p nexxus-node                  # ok (nexxusd 0.228.0)
nexxusd (temp HOME, NEXXUS_TOR=0) + scripts/e2e_smoke.py  # E2E SMOKE: 58/58 проверок прошли
nexxus-desktop: cargo test --bins                     # 36 passed / 0 failed / 1 ignored
nexxus-desktop: cargo clippy --bins --all-targets -- -D warnings  # 0
```

## Что раздавать аудитору (S3)

Только squash-артефакт: `NeXXus-Node-audit-squash.tar.gz` у владельца — 1 коммит
(`auditor-squash` из `41a7335`), secret-scan 0 хитов, redb 0, больших файлов вне assets нет.
Полную историю `main` не давать. Как собрать самому — `docs/audit-package/README.md` §0.

## На твоей стороне (не код)

1. **Ротация секретов по S1**: 12-словные мнемоники из вычищенных redb-файлов считать
   скомпрометированными, если принадлежали живой идентичности; PAT/ключи из DEP-03 —
   ревокнуты? (в документах это отмечено как «риск принят», нужен факт ревокации).
2. **S4**: ADR-0010 (`docs/adr/0010-at-rest-seed-protection.md`) — выбран вариант (а).
   На существующих сторах phase 2 (затирание plaintext из meta) произойдёт на первом
   старте с `NEXXUS_SEED_PIN` или systemd-credential `seed.pin`.
3. Проверь, что письмо аудитору со ссылкой на `git clone` заменено на squash-артефакт (S3).
