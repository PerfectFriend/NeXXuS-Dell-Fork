# TON-контракты NeXXus (FunC v2) — СТАТУС: ПЕРЕПИСАНЫ (Phase 4), АУДИТ C-6/C-7/C-8 ЗАКРЫТ

> **Архитектурный статус: Все 3 контракта переписаны с нуля с устранением уязвимостей аудита.**
> Контракты готовы к тестовой компиляции в Blueprint/Sandbox и развертыванию в testnet.

## Состояние смарт-контрактов (Ревизия Phase 4, ноябрь 2026)

| Файл | Назначение | Устранённый дефект аудита |
|---|---|---|
| `NexxusTreasuryVesting.fc` | Казначейство, 56-дневный линейный вестинг и аннулирование (Slashing) | **C-6: Закрыт.** Добавлена строгая проверка `sender == beneficiary`, реестр `batches_dict` с защитой от повторного снятия (anti-replay), формат TEP-74 Jetton Transfer. |
| `NexxusEpochController.fc` | Контроллер триггера эпохи и кворума Совета Аудиторов | **C-7: Закрыт.** Фиктивная проверка BLS заменена на нативную проверку **Ed25519 M-of-N Multi-Sig** (`check_data_signature`), согласованную с ADR-0008 и wire-форматом Rust-ноды. |
| `NexxusAuditorCouncilBond.fc` | Управление залогами (1,000 TON) и мандатами аудиторов | **C-8: Закрыт.** Внедрён per-address учёт в `auditor_bonds_dict`, двухфазный вывод залога с 14-дневным unbonding-периодом и перевод средств при Slashing напрямую в казну. |

---

## Детальный реестр исправлений

### 1. `NexxusEpochController.fc` (Fix C-7)
- **Удалена фиктивная проверка:** `signature_hash > 0` полностью устранена.
- **Интеграция Ed25519 M-of-N:** Контракт проверяет подписи аудиторов через `check_data_signature` TVM над каноническим хэшем эпохи `SHA-256(epoch_number || merkle_root || total_bytes)`.
- **Защита от дублей:** Введён `seen_signers` словарь — подпись одного и того же аудитора не засчитывается дважды.
- **Динамический кворум:** Поддержка операции `OP_UPDATE_AUDITOR_SET` (0x7e1a0002) администратором для ротации ключей и изменения порога $M \ge \text{threshold}$.

### 2. `NexxusTreasuryVesting.fc` (Fix C-6)
- **Защита от кражи казны:** `OP_RELEASE_VESTING_BATCH` проверяет `equal_slices(sender, beneficiary)`. Любой посторонний вызов отклоняется кодом ошибки `ERROR_UNAUTHORIZED (201)`.
- **Учёт батчей:** `OP_REGISTER_VESTING_BATCH` фиксирует `batch_id` в `batches_dict`. Повторное создание батча с тем же ID запрещено (`ERROR_BATCH_ALREADY_EXISTS (205)`).
- **Anti-Replay:** При выплате батч безвозвратно удаляется из словаря `batches_dict~udict_delete?(64, batch_id)`.
- **TEP-74 Jetton Transfer:** Формирование исходящего сообщения по официальному стандарту TON Jetton: `op::transfer (0x0f8a7ea5)`, `coins`, `destination`, `response_destination`, `forward_ton_amount`.

### 3. `NexxusAuditorCouncilBond.fc` (Fix C-8)
- **Per-Address залог:** Залоги аудиторов хранятся в `auditor_bonds_dict`, ключом выступает `slice_hash(sender)`.
- **Двухфазный вывод (`OP_WITHDRAW_BOND`):**
  - Шаг 1: Аудитор подаёт заявку на анбондинг (`unbond_requested_at = now()`), место аудитора деактивируется.
  - Шаг 2: По истечении 14 дней (`UNBONDING_PERIOD_SECONDS = 1209600`) залог возвращается на адрес владельца.
- **Боевой Slashing (`OP_SLASH_AUDITOR_COLLUSION`):** При обнаружении сговора сумма залога удерживается именно у нарушителя, его запись удаляется, а средства перечисляются на адрес контракта казны (`treasury_address`).
