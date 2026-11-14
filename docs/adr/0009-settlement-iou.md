# ADR-0009: Settlement-канал — дизайн off-chain signed IOU (документ first, без платежей в wire v3)

**Статус:** Предложен (design doc), 2026-11-14. Ничего из этого не реализовано в коде — это план, не фича.
**Правило из roadmap:** accounting уже есть (подписанный экспорт `node_econ_export`); **пока нет реального settlement-пути, в README пишется «accounting only, not payments»** — и это остаётся так.

## 1. Зачем

Сейчас узел ведёт только локальный accounting (отданные/принятые ГБ, uptime, PoR). Чтобы когда-то появились расчёты между узлами, нужен settlement-путь. Встраивать платежи в wire v3 нельзя (ломает audit-границы и совместимость — см. roadmap «чего не делать»).

## 2. Решение: off-chain signed IOU, отдельная opcode-family `0x2x` — позже

| Вариант | Оценка |
|---|---|
| On-chain платежи в wire v3 | ❌ ломает wire v3, threat model, audit-границы |
| **Off-chain signed IOU → later settlement** | ✅ выбран: нода A и B обмениваются подписанными расписками (ed25519 узла), долг гасится оффчейн или позже отдельным механизмом |
| Новый opcode family `0x2x` в том же wire | ⚠️ только как транспорт для IOU-сообщений, **не** для платежей; требует нового ADR + threat model pass |

## 3. Формат IOU (проект)

```json
{
  "kind": "nexxus-iou/v1",
  "debtor": "<node_id A, hex>",
  "creditor": "<node_id B, hex>",
  "amount_micro": "123456789",        // строка, микро-NEXX (см. ADR-0004)
  "epoch": 42,
  "nonce": "<32B hex, анти-replay>",
  "issued_unix": 1794659095,
  "expiry_unix": 1797251095,          // IOU протухает (30 дней)
  "sig": "<ed25519 debtor over canonical JSON без поля sig>"
}
```

- Каноническая сериализация: JSON с сортировкой ключей, compact separators — та же, что в `node_econ_export`.
- Подпись — ed25519 ключа идентичности узла (уже есть в `identity_store`).
- Анти-replay: nonce хранится у кредитора; повторный IOU с тем же nonce отклоняется.

## 4. Поток

1. B обслужил запрос A (fetch/PoR) → B выпускает IOU на адрес A (или A запрашивает расписку за уже оказанное).
2. IOU передаётся **вне wire v3** (SMP-сообщение или локальный API), später — возможно opcode `0x2x`.
3. A хранит IOU, сверяет подпись и дедлайн; по наступлении settlement (внешний, решается отдельно) предъявляет.
4. Aggregация: несколько IOU между парой можно схлопнуть в один на большую сумму (reduces spam).

## 5. Threat model (новые границы — required до любого кода)

| Угроза | Митигция |
|---|---|
| Double-spend IOU (одна расписка предъявлена дважды) | nonce + дедуп у кредитора; journal на диске |
| Replay старого IOU | `expiry_unix` + проверка эпохи |
| Фальшивая подпись | verify ed25519 по node_id; тест tamper |
| Griefing: спам IOU малыми суммами | min amount, rate-limit, агрегация, cap на число IOU от одного пира |
| Потеря IOU при крэше | journal (append-only) + fsync, как в backup |
| Приватность сумм | суммы видят только стороны; в метриках — только агрегаты |

## 6. Что НЕ делаем сейчас

- ❌ Никаких изменений в wire v3 opcodes.
- ❌ Никаких on-chain платежей.
- ❌ Marketplace UI — только после реального settlement (иначе SIM).
- ✅ Только этот документ + учёт в README/USER_GUIDE как «accounting only».

## 7. План реализации (когда понадобится)

1. ADR-0009 → Принят после review; threat model обновить до кода.
2. `nexxus-econ`: модуль `iou.rs` (тип, канонизация, sign/verify, expiry) + property-тесты (tamper, replay, overflow сумм).
3. Хранение: append-only journal `~/.nexxus/iou.log` (fsync), чтение при старте.
4. Транспорт: сначала локальный API/SMP, opcode `0x2x` — отдельным ADR.
5. Settlement: внешний документ (вне репо ноды), не код.
