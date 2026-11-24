# Циклы аудита

Формат записи на каждый цикл:

```
## Цикл N — <дата>
- База: commit <sha>, тег audit-cycle-N
- Отчёты: AUDIT/reports/<...>.md (модели: ...)
- План: AUDIT/PLAN-<дата>.md
- Baseline до: clippy <clean/N warnings>, tests <pass/fail: X/Y>, hygiene OK/FAIL
- Сделано: <коммиты>
- Baseline после: clippy ..., tests ...
- Остаток на следующий цикл: ...
```

## Цикл 1 — 2026-11-24 (старт, baseline)
- База: commit cc6b0cd, тег audit-cycle-0 (процесс) / ветка main форка NeXXuS-Dell-Fork
- Baseline: hygiene OK (`scripts/check-tree-hygiene.sh`); clippy `--workspace --all-targets -D warnings` — чист
  после фикса cc6b0cd (был 1 dead-code: `publish_onion` → удалён, тест переведён на `publish_onion_with_api`);
  `cargo test --workspace` — **241 passed / 0 failed**; smoke на живом хосте после redeploy: node_status OK,
  p2p_client (handshake+store+fetch) OK.
- Сигналы для аудиторов (baseline-заметки, не дефекты сами по себе):
  - unwrap/expect/panic в не-тестовом коде: network.rs ~144, storage.rs ~129, identity_store.rs ~70,
    backup.rs ~41, panic.rs ~39, seed_vault.rs ~31 (часть — внутри #[cfg(test)], надо разобрать по месту);
    core: keys/vault.rs 19, chunk.rs 13, payloads.rs 11.
  - TODO/FIXME в crates/: нет.
  - Известное ограничение среды: новые HS-дескрипторы Tor отклоняются (HTTP 400) — не код, noted.
- Отчёты внешних моделей: ожидаются в `AUDIT/reports/` (шаблон — REPORT_TEMPLATE.md)
- План: будет после получения отчётов → `AUDIT/PLAN-2026-11-24.md`
- Хост: /usr/local/bin/nexxusd пересобран из cc6b0cd, сервисы active.
