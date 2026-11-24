# ADR-0011: Multi-transport peer connections — LAN / Tailscale / Tor, авто-discovery

**Статус:** Принят (дизайн), 2026-11-24. Форк NeXXuS-Dell-Fork; базовый репозиторий
NeXXuS-Node-Hermes-Rust не трогаем — совместимость с чужими нодами идёт через этот
спек (wire v3 + этот ADR), а не через общий код.

## Контекст
Ноды живут в разных сетях: один LAN, разные LAN за NAT, tailnet, «чужие» клиенты.
Пользователь не должен знать про IP/onion/порты: «установил пакет — ноды сами нашли
друг друга и соединились». Три класса соединений:

1. **LAN** — ноды в одной локалке: прямое TCP, минимальная задержка.
2. **Tailscale** — ноды одного владельца (один BIP39-mnemonic хранилища) в одном
   tailnet: адреса `100.64.0.0/10`, прямой TCP через tailnet.
3. **Tor** — разные подсети и разные владельцы: onion v3 (Arti), pairing по invite.

## Решение

### 1. Identity и «владелец» (BIP39)
- Ключ ноды — **SLIP-10 derived key** от seed хранилища (в core уже есть
  `keys::slip10::DerivedKey::from_seed`), путь `m/44'/77777'/<account>'/<host_index>'`.
  Один mnemonic = один владелец; у каждого хоста в кластере свой deterministic node key.
- `cluster_tag = HMAC-SHA256(seed, "nexxus/cluster/v1")[0..16]` — keyed-хеш, не раскрывает
  seed, но позволяет отличить «своих» от «чужих». Передаётся в beacon/announce.
- **Политика авто-приёма:** на LAN/Tailscale авто-коннект только к peer с **тем же
  cluster_tag**. Чужой cluster — только по invite (п.4). На Tor — всегда только invite.

### 2. Адреса и multiaddr
- `NodeAnnounce` (wire v3, opcode 0x03) расширяется списком адресов
  (`addrs: Vec<Addr>`), обратно совместимо: старые поля `ip`/`port` = первый LAN-адрес.
  `Addr { kind: lan|tailscale|tor, addr: string, port: u16, onion: Option<String> }`.
- `KadPeer` в Kademlia несёт тот же список — DHT (уже есть: KadFindNode/KadNodesFound)
  становится registry адресов: зашёл через любой транспорт — узнал все остальные.

### 3. Discovery (zero-config)
- **LAN beacon:** UDP broadcast на порту 4002 (пока нода жива, каждые 10 с):
  подписанный пакет `{node_id, pubkey, cluster_tag, addrs[], ts}`. Получил — если
  cluster_tag свой и pubkey ещё не в таблице — dial по LAN.
- **Tailscale:** при старте `tailscale ip -4` (или чтение интерфейсов 100.64/10);
  tailscale-адрес добавляется в `addrs` и рассылается через beacon/Kademlia.
  Если tailscale не установлен — тихо пропускаем, транспорт выключен.
- **Tor:** onion v3 публикуется всегда при `tor=1` (уже реализовано, ADR-0006);
  onion-адрес — в `addrs`.

### 4. Cross-client pairing: invite link
Формат: `nexxus://<onion>:4001?pk=<hex ed25519 pubkey>&ct=<cluster_tag?>`
- pubkey **пining**: dial только если pubkey в announce совпал — MITM невозможен
  (все кадры подписаны Ed25519, см. wire v3).
- cluster_tag в invite опционален: если указан и не совпал с нашим — отклоняем
  (защита от «чужой» invite в «свою» сеть).
- Invite вводится один раз (дашборд/API `node_invite`), дальше нода сама держит
  соединение и подхватывает новые адреса пира через Kademlia.

### 5. Path selection и failover
- Для каждого peer храним все известные addrs. Dialer пробует в порядке
  **LAN → Tailscale → Tor**, измеряет RTT (Ping/Pong, уже есть), выбирает лучший.
- Каждые 30 с — re-check: если активный путь умер (нет Pong за timeout), failover
  на следующий; событие пишется в метрики/API (`node_peers` показывает transport,
  rtt, last_failover) и в дашборд — пользователю видно, по какому каналу нода.
- Все транспорты end-to-end подписаны Ed25519; Tor добавляет только транспортную
  анонимность, crypto не ослабляется.

### 6. Прозрачность для пользователя
- Ничего настраивать не надо: пакет → сервис стартует → beacon + tailscale + onion
  + Kademlia сами поднимают связи. Дашборд (control-plane :3998) показывает пиров
  с лейбами `LAN/Tailscale/Tor`, RTT и cluster; «пригласить чужую ноду» — одна
  ссылка `nexxus://…`.
- Все решения (dial, failover, accept/reject peer) пишутся в audit-лог ноды.

## Service-модель (лёгкий LLM рядом с нодой)
- Отдельный ADR-0012. Кратко: маленькая локальная модель (llama.cpp, loopback +
  api-key) как **NL → JSON tool-call** поверх whitelist нашего WS API; валидация
  ответа по JSON-schema; деструктивные операции — с подтверждением; секреты в
  промпт не попадают. База: Qwen3-0.6B (Apache-2.0, 100+ языков incl. RU, native
  tools; GGUF `bartowski/Qwen_Qwen3-0.6B-GGUF:Q4_K_M` 0.48 ГБ) или Granite-4.0-350M
  для совсем слабых хостов (castle: 3.7 ГБ RAM). Обучается LoRA на синтетике
  «команда → вызов API ноды» (схема методов из local_api.rs), инференс — llama-server.

## Последствия
- +Новый UDP-порт 4002 (beacon) и расширение payload'ов announce/KadPeer.
- +Зависимость от SLIP-10 path и HMAC для cluster_tag (оба примитива уже в core).
- +Invite-link парсинг в API/дашборде.
- Wire v3 заголовок не меняется — только payload'ы, обратная совместимость сохраняется.
