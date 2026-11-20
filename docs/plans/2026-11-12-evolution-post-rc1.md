# 🗺️ NeXXuS — План эволюции после RC1

**База:** NeXXuS-Node-Hermes-Rust (RC1, post-hardening, audit series closed)  
**Дата:** 12 ноября 2026  
**Цель документа:** практичный roadmap расширения функционала без потери того, что уже доказано аудитом (честность границ, fail-closed, wire-совместимость, zeroize, rate-limits).

---

## 0. Принципы эволюции (не нарушать)

1. **Сначала инвариант, потом фича.** Любая новая поверхность (платежи, квоты, marketplace) — отдельная версия протокола или явный feature-flag, а не тихая ломка wire v3.
2. **Threat model обновляется вместе с кодом.** Новый trust boundary → запись в `THREAT_MODEL.md` до мержа.
3. **CI-гейт не ослаблять:** test + clippy `-D warnings` + `cargo audit` + wire fuzz/vectors.
4. **Раздача — squash-mirror** (пока DEP-03 risk-accepted).
5. **SIM и «как будто»** помечать явно; не выдавать зажившее за живое.

---

## 1. Где мы сейчас (RC1)

| Слой | Состояние |
|------|-----------|
| Crypto / vault / at-rest | Готово (600k PBKDF2, duress, Zeroizing, two-phase migrate) |
| Wire v3 + P2P | Готово (nonce per-conn, rate limits, peer cap, idle) |
| Local API | Готово (token fail-closed, WS limits, confirm на delete/restore) |
| Backups | Готово (flock, validate name, auto-backup + rotation + 3-2-1) |
| Desktop guardian | Готово (tray, schedule, Telegram report) |
| Econ | Модель + API-панель; **не** on-chain и не формально верифицирована |
| Tor (arti) | Опционально; design-level review |
| Windows / Android | Частично (скрипты/Termux); не паритет с Linux daemon |
| Платежи / marketplace / глобальные квоты | Нет (и правильно — не имитировать) |

---

## 2. Фазы эволюции

### Фаза E0 — «Release hygiene» (1–2 недели)
*Цель: RC1 можно спокойно отдавать людям.*

- [x] Тег `v0.1.0-rc1` на origin + GitHub Release **только со squash-артефакта** (`NeXXus-Node-v0.1.0-rc1-squash.tar.gz`, 1 коммит, sha256 76f5577e…, secret-scan 0, redb 0) — 2026-11-20, HEAD 37ed222
- [x] `SECURITY.md` (включая self-update ноты Re-Audit #4) + USER_GUIDE с границами «что умеет / чего нет»
- [x] Метрики в проде: node_metrics (peers, handshake timeouts, prom) + **uptime_secs и rss_kb** добавлены 2026-11-20 (HEAD 37ed222); /metrics token-gated
- [x] Bind-адрес: `NEXXUS_LISTEN` (дефолт `127.0.0.1:4001`), задокументирован в USER_GUIDE
- [x] README ссылается на docs/THREAT_MODEL.md и docs/audits/ (re-audit #1–#4)

**Критерий готовности:** внешний человек поднимает ноду по one-liner и понимает границы доверия.

---

### Фаза E1 — «Надёжность сети» (3–6 недель) — ✅ ЗАКРЫТА 2026-11-20
*Цель: меньше eclipse / DoS-чувствительности, лучше observability.*

| Функция | Зачем | Заметки |
|---------|--------|---------|
| Reputation / soft-score пиров | ✅ DONE: score (success/fail + EWMA RTT), eviction lowest-score при full table ниже порога 40, метрика peers_evicted, THREAT_MODEL обновлён | + half-life decay 24ч (2026-11-20, `PeerScore::decay`), eviction мёртвых по score `fail≥5 && fail≥2·success` — не рвёт живые соединения |
| Метрики Prometheus / JSON | ✅ DONE: `/metrics` plain-HTTP, token-gated; JSON + prom text в `node_metrics` | localhost по умолчанию |
| Structured logging | ✅ DONE: JSON-lines через log_ev!; **2026-11-20**: redaction зарегистрированных секретов (`register_secret`, API-токен при старте), дедлок рекурсии исправлен, регрессионный тест | без секретов в логах — закреплено тестом |
| Connection quality hints | ✅ DONE: node_ping_peer + EWMA rtt_ms в PeerScore, UI-кнопка Ping | ✅ 2026-11-20: loss-индикатор `req_timeouts` + `recv_req_frame` (таймаут 10с) для ping/fetch/por |
| Routing: replacement cache | ✅ DONE 2026-11-20 (M-16/H-3): полный k-bucket → replacement cache (cap 64), `evict_dead`/`evict_addr` дозаполняют бакет; тест `full_bucket_goes_to_replacement_and_evict_backfills` | раньше пир молча отбрасывался |
| M-18: паника на не-ASCII в логе | ✅ DONE 2026-11-20: срез по `chars().take(16)` вместо байтов | |
| Опциональный STUN / hole-punching | Lab без Tor | Не ломать onion-профиль — отложено, не RC-блокер |

**Безопасность:** score не вектор «накрутил и вытеснил честных» — пороги + decay, задокументировано.

---

### Фаза E2 — «Хранилище как продукт» (4–8 недель)
*Цель: то, чего не хватает обычному пользователю суверенного диска.*

| Функция | Описание |
|---------|----------|
| **Реальные квоты диска** | Не только «64 MiB foreign» / abstract sections — проверка free space + user-defined cap |
- **Политики ретенции** | TTL чанков (`node_chunk_ttl`), pin/unpin (`node_chunk_pin`/`node_chunk_unpin`), GC просроченных (`node_gc`), lazy-expiry в `get_chunk`; pin защищает и от TTL, и от GC |
| **Доказательства хранения (PoR) в расписании** | ✅ DONE 2026-11-20: self-audit цикл в `main.rs` (`NEXXUS_POR_AUDIT_SECS`, дефолт 6ч, 0=off): sample до 64 чанков, SHA-256(data)==hash, метрики por_ok/por_fail + `log_ev!("por.audit")`; клиентский аудит пиров `audit_peer_por` + RPC `node_audit_peer`, scheduled-цикл аудирует до 8 пиров (`por.peers_audit`); wire PoR challenge/response — тест `audit_peer_por_ok_over_wire` | penalty в UI — следующая итерация |
| **Импорт/экспорт архивов** | Зашифрованный bundle (chunk set + manifest) для cold backup вне redb |
| **Версионирование файлов (optional)** | Не git; простой history указателей в журнале владельца |
| **drive/ как FUSE или sync-folder** | Только если threat model ясен: plaintext folder = plaintext |

Приоритет: квоты + scheduled PoR + export bundle. FUSE — позже.

---

### Фаза E3 — «Экономика без самообмана» (6–12 недель)
*Цель: перевести econ с панели на проверяемые правила, не строя сразу «биржу».*

1. **Локальный accounting**  
   - Учёт отданных/принятых ГБ, uptime, успешных PoR  
   - Экспорт отчёта (подписанный JSON) — ещё без токена

2. **Анти-луп и вестинг**  
   - ✅ DONE: proptest property-набор `crates/nexxus-econ/tests/props.rs` — anti-loop (1.30 > 1.25 строго), saturating money math (u64::MAX → i64::MAX без wrap), conservation split_into_sections, vesting monotone+conservation+burn, degradation ladder пороги; 6/6 proptest зелёные, clippy 0

3. **Канал расчётов (отдельная веха)**  
   - Не вшивать в wire v3  
   - ✅ DONE (doc): ADR-0009 — off-chain signed IOU (ed25519, nonce, expiry), транспорт вне wire v3; threat model секция 5; код — отдельным ADR после review
   - Платежи = новый документ PROTOCOL + threat model (двойная трата, griefing, spam)

4. **Marketplace UI** — только после (1)+(3); иначе снова SIM.

**Правило:** пока нет реального settlement-пути, в README писать «accounting only, not payments».

---

### Фаза E4 — «Платформы» (параллельно E1–E3)
Опираться на `docs/ROADMAP_WINDOWS_ANDROID.md`, но с приоритетом **одного ядра**.

| Приоритет | Платформа | Что сделать |
|-----------|-----------|-------------|
| P0 | **Linux** | Уже основной; systemd unit, deb из CI (есть задел) |
| P1 | **Windows** | Нативный `nexxusd.exe` (не Node SEA как цель), служба, firewall rule, tray (Tauri уже есть) |
| P2 | **Android** | Termux — поддержка; нативный foreground service + scoped storage — отдельный milestone |
| P3 | **WASM / web applet** | Только read-only monitor / light client; ключи не в браузере без явного UX |

Единое правило: `nexxus-core` не ветвить под OS; OS-специфика только в `nexxus-node` / desktop / mobile shell.

---

### Фаза E5 — «Приватность и транспорт» (по мере готовности E1)

- Tor: onion-ключ/bootstrap есть; ✅ DONE integration test (#[ignore], CI job tor-integration, реальный publish onion v3)
- Опциональный second transport (QUIC?) — только если не ломает v3 framing abstraction
- Traffic analysis resistance: padding/timing — research track, не RC2 blocker

---

### Фаза E6 — «Экосистема» (после стабильного E2–E3)

- Публичный registry bootstrap-пиров ✅ DONE: signed list (ed25519, expiry, canonical JSON) — bootstrap.rs, node_bootstrap_set/get, tamper/expired → error, e2e 46/46
- Light client ✅ DONE (CLI): `nexxusd light status|chunks|peers|get <root-hex> <out>|pin <hash> [--api host:port] [--token-file path]` — без запуска демона, roundtrip проверен живьём; WASM web-applet ✅ DONE: nexxus-wasm расширен light-client поверхом (seal/open чанков локально, merkle proof verify, hash) — сборка под wasm32-unknown-unknown проверена, тесты 4/4; Kotlin mobile viewer — остался в плане
- Плагины политик хранения ✅ DONE (v1): node_policy_set/list/delete/apply — правила по префиксу имени (pin | ttl:<secs>), реально применяются к чанкам; e2e 51/51. Расширение «только onion-пиры» ✅ DONE: action `onion-only` (флаг + pin, upload не шлёт clearnet-пирам), `node_chunk_onion_only` / `node_onion_only_list` / `node_replicate_onion` (репликация на .onion из bootstrap через Tor); e2e 58/58
- Formal verification (точечно) ✅ DONE: proptest-доказательства в `crates/nexxus-core/tests/formal_props.rs` — v3 signature binds nonce/payload/req/opcode (replay в другую сессию → false), vault KDF per-salt + roundtrip + wrong-PIN + tamper; econ anti-loop/saturating — `nexxus-econ/tests/props.rs`; wire fuzz — `wire_fuzz.rs`

---

## 3. Чего **не** делать в ближайших фазах

| Антипаттерн | Почему |
|-------------|--------|
| Глобальный ban-list «как в CDN» | Противоречит суверенной модели; максимум локальный penalty |
| Платежи «в одну ночь» внутри wire v3 | Ломает audit-границы и совместимость |
| Фейковый onion / фейковый marketplace | Уже отвергнуто культурой проекта — сохранить |
| Хранение мнемоники в облаке «для удобства» | Seed compromise = total |
| Ослабление CI «чтобы быстрее мержить» | Цена уже известна |

---

## 4. Предлагаемый порядок работ (квартальный взгляд)

```text
Q0 (сейчас)     E0 Release hygiene + tag RC1
Q1              E1 Network reliability + E4 Windows P1
Q1–Q2           E2 Storage product (quotas, PoR schedule, export)
Q2              E3 Accounting → design settlement (doc first)
Q2–Q3           E4 Android P2 + Tor hardening (E5)
Q3+             E6 Ecosystem, formal bits, marketplace only with real settlement
```

Сроки условные; важнее порядок зависимостей: **квоты и PoR до marketplace; accounting до payments; threat model до opcode.**

---

## 5. Критерии «фаза закрыта»

Для каждой фазы минимум:

1. Код + тесты в CI  
2. Запись в `THREAT_MODEL.md` / ADR при новых границах  
3. USER_GUIDE: что пользователь реально получает  
4. Нет новых Medium+ без плана закрытия  
5. Wire: либо backward compatible, либо явный `v4` / capability bit

---

## 6. Быстрые победы (можно взять сразу после E0)

1. [x] **User-defined disk cap** (`NEXXUS_MAX_STORE_BYTES`) + free-space guard в `put_chunk` + метрики в `node_metrics`  
2. [x] **Prometheus metrics** — plain-HTTP `GET /metrics` на API-порту (localhost), `Authorization: Bearer <api.token>`, constant-time compare, fail-closed 401; WS-путь не затронут (smoke OK)  
3. [x] **Signed accounting export** — `node_econ_export`: canonical JSON отчёта (метрики, стор, econ, disclaimer «accounting only») + ed25519-подпись ноды; WS smoke OK  
4. **Windows service + firewall** из текущего Tauri/CI задела  
5. [x] **Peer score MVP** — скоринг в ноде (success/fail → 0..100) + score/success/fail в панели «Сеть и пиры» монитора

Эти пять пунктов сильно поднимают ощущение «готового продукта» при минимальном риске для протокола.

---

## 7. Связь с аудитом

Всё, что закрыто в audit series (NET-01/02/03, VLT, STR, BKP, API, DEP-01), считается **базовой линией**.  
Новые фазы не имеют права откатывать эти инварианты.  
При появлении settlement / marketplace — отдельный security pass (как минимум wire + economic griefing).

---

*Документ можно класть в `docs/plans/` как `2026-11-12-evolution-post-rc1.md` и уточнять по мере закрытия E0–E1.*

— Grok, 12 November 2026

## Re-Audit #4 (Grok, 14.11.2026, HEAD 1e3427d) — closed items
- [x] UPD-02 anti-rollback: `check_not_downgrade` — кандидат прогоняется через `--version`, установка拒绝дена если <= текущей; `nexxusd --version` добавлен; тесты + e2e
- [x] POL-01: `node_gc` / `node_policy_apply` требуют `{"confirm": true}`; e2e 53/53 (включая negative-проверки)
- [x] BS-01: pin `bootstrap_registry_pub` (node.conf/env) — mismatch отклоняется до store_set
- [x] UPD-01/UPD-03: задокументированы в SECURITY.md (curl-зависимость, канал раздачи)
- [x] UPD-01 closed: in-process ureq+rustls download (https-only, loopback-http для тестов, cap 512MiB); curl убран из update.rs; живой прогон через локальный сервер подтверждён

## Re-Audit #4 follow-up (14.11.2026, after 62a4c7d/742807e)
- [x] UPD-01 closed: in-process ureq+rustls download (742807e)
- [x] E3 property tests: nexxus-econ/tests/props.rs (proptest)
- [x] E0 hygiene: README→THREAT_MODEL/audits, SECURITY.md/USER_GUIDE закрыты
- [x] E6 onion-only политики + репликация через Tor (policy action, upload- enforcement, node_replicate_onion); e2e 58/58
- [x] E6 WASM light-client surface: seal_chunk/open_chunk/sealed_chunk_hash_hex/merkle_proof_flat/merkle_verify_flat в nexxus-wasm; wasm32 release build OK (916KB), host tests 4/4
- [x] Formal bits: formal_props.rs (nonce binding + vault KDF properties, 2/2 proptest зелёные), воркспейс 206 passed / 0 failed
- [x] E6 light client self-verify: `light get --key` локально сверяет двухуровневый merkle root (exit 3 при mismatch), `light manifest` + API `node_manifest_get`; живой прогон: OK + bytes identical + bad-key FAIL exit 3
- [x] E4/W2 artifacts: scripts/windows/{nexxus-service.xml,install-service.ps1,uninstall-service.ps1} (pwsh parser OK), CI release asset nexxusd-windows-x86_64.exe + windows scripts; firewall = P2P port only, API loopback
