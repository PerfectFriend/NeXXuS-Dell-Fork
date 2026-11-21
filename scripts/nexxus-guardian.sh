#!/usr/bin/env bash
# ==============================================================================
# nexxus-guardian.sh — headless guardian ("хранитель") ноды NeXXUs.
#
# Зачем он нужен, если у юнита ноды стоит Restart=always:
#   Restart=always спасает только при ВЫХОДЕ процесса. Зависший демон
#   (зависший ввод-вывод, deadlock, поток в syscall) продолжает жить —
#   systemd считает его работающим и ничего не делает. Хранитель ловит
#   именно этот случай: проверяет живость по API и перезапускает ноду.
#
# Порядок загрузки: guardian стартует ПЕРВЫМ (Before=nexxus-node.service),
# поднимает ноду и дальше следит за ней. Если нода упала или перестала
# отвечать — хранитель её перезапускает.
#
# КАНАЛ УПРАВЛЕНИЯ ОТ ТРЕЯ (без polkit и без прав sudo у пользователя):
#   Трей (обычный пользователь) пишет JSON-команду в
#       $NEXXUS_CONTROL_DIR/command.json
#   Хранитель (root) забирает её, выполняет и кладёт результат в
#       $NEXXUS_CONTROL_DIR/result.json
#   Так привилегированные операции (systemctl) делает только хранитель,
#   а пользователю не выдаётся парольный доступ к systemd.
#
# Все пути и тайминги задаются переменными окружения (дефолты — под
# стандартный Linux-разворот), чтобы скрипт переносился на другой хост
# без правок.
#
# Управление вручную:
#   systemctl restart nexxus-guardian
#   systemctl status  nexxus-guardian
#   touch /var/lib/nexxus/.guardian-pause   # пауза: не перезапускать ноду
#   rm /var/lib/nexxus/.guardian-pause       # снять паузу
# ==============================================================================
set -uo pipefail

# ── Конфигурация (env с фолбэками) ─────────────────────────────────────────
NEXXUS_UNIT="${NEXXUS_UNIT:-nexxus-node.service}"
NEXXUS_BIN="${NEXXUS_BIN:-/usr/local/bin/nexxusd}"
NEXXUS_DATA_DIR="${NEXXUS_DATA_DIR:-/var/lib/nexxus}"
NEXXUS_PORT="${NEXXUS_PORT:-3999}"
NEXXUS_HOST="${NEXXUS_HOST:-127.0.0.1}"
# Health-check всегда идёт по loopback: NEXXUS_HOST в /etc/nexxus/nexxus.conf
# — это адрес ПРОСЛУШИВАНИЯ ноды (0.0.0.0), а не адрес, по которому
# ходят health-check'и. Поэтому используем отдельную переменную.
NEXXUS_HEALTH_URL="${NEXXUS_HEALTH_URL:-http://127.0.0.1:${NEXXUS_PORT}/api/status}"
NEXXUS_CHECK_INTERVAL="${NEXXUS_CHECK_INTERVAL:-15}"      # секунд между проверками
NEXXUS_HEALTH_TIMEOUT="${NEXXUS_HEALTH_TIMEOUT:-10}"      # таймаут одного запроса
NEXXUS_MAX_FAILURES="${NEXXUS_MAX_FAILURES:-3}"            # столько подряд → перезапуск
NEXXUS_RESTART_COOLDOWN="${NEXXUS_RESTART_COOLDOWN:-60}"  # сек между рестартами
NEXXUS_RECOVER_TIMEOUT="${NEXXUS_RECOVER_TIMEOUT:-90}"    # сколько ждём возврата здоровья
NEXXUS_PAUSE_FILE="${NEXXUS_PAUSE_FILE:-${NEXXUS_DATA_DIR}/.guardian-pause}"
NEXXUS_STATE_FILE="${NEXXUS_STATE_FILE:-${NEXXUS_DATA_DIR}/meta/guardian-state.json}"
NEXXUS_LOG_FILE="${NEXXUS_LOG_FILE:-${NEXXUS_DATA_DIR}/logs/guardian.log}"
NEXXUS_CONTROL_DIR="${NEXXUS_CONTROL_DIR:-${NEXXUS_DATA_DIR}/control}"
NEXXUS_GROUP="${NEXXUS_GROUP:-nexxus}"
# Опциональные уведомления в Telegram (в репозитории секретов нет):
NEXXUS_TG_BOT_TOKEN="${NEXXUS_TG_BOT_TOKEN:-}"
NEXXUS_TG_CHAT_ID="${NEXXUS_TG_CHAT_ID:-}"

LOG_LEVEL="${NEXXUS_LOG_LEVEL:-info}"

mkdir -p "$(dirname "$NEXXUS_STATE_FILE")" "$(dirname "$NEXXUS_LOG_FILE")" "$NEXXUS_CONTROL_DIR" 2>/dev/null || true
# Каталог управления должен быть доступен группе nexxus: трей пишет туда
# команду от обычного пользователя. Права — 2770, запись только группе.
if getent group "$NEXXUS_GROUP" >/dev/null 2>&1; then
  chgrp "$NEXXUS_GROUP" "$NEXXUS_CONTROL_DIR" 2>/dev/null || true
  chmod 2770 "$NEXXUS_CONTROL_DIR" 2>/dev/null || true
fi

ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() {
  local level="$1"; shift
  local line="[$(ts)] [$level] $*"
  printf '%s\n' "$line"
  # В journal пишет systemd; дублируем в файл, чтобы не терять историю
  # при ротации журнала и иметь её рядом с логом ноды.
  printf '%s\n' "$line" >> "$NEXXUS_LOG_FILE" 2>/dev/null || true
  # Не даём логу расти бесконечно.
  if [ -f "$NEXXUS_LOG_FILE" ]; then
    local sz
    sz=$(stat -c%s "$NEXXUS_LOG_FILE" 2>/dev/null || echo 0)
    [ "$sz" -gt 1048576 ] && tail -n 500 "$NEXXUS_LOG_FILE" > "$NEXXUS_LOG_FILE.tmp" \
      && mv "$NEXXUS_LOG_FILE.tmp" "$NEXXUS_LOG_FILE"
  fi
}

notify() {
  # Уведомление в Telegram — только если токен и chat_id заданы в env.
  [ -n "$NEXXUS_TG_BOT_TOKEN" ] && [ -n "$NEXXUS_TG_CHAT_ID" ] || return 0
  command -v curl >/dev/null 2>&1 || return 0
  local text="$1"
  curl -fsS --max-time 10 -X POST \
    "https://api.telegram.org/bot${NEXXUS_TG_BOT_TOKEN}/sendMessage" \
    -d chat_id="$NEXXUS_TG_CHAT_ID" \
    --data-urlencode "text=${text}" >/dev/null 2>&1 || \
    log WARN "не удалось отправить уведомление в Telegram"
}

# ── Проверка здоровья ──────────────────────────────────────────────────────
# Возвращает 0, если нода жива и отдаёт валидный статус.
health_check() {
  local out
  if command -v curl >/dev/null 2>&1; then
    out=$(curl -fsS --max-time "$NEXXUS_HEALTH_TIMEOUT" "$NEXXUS_HEALTH_URL" 2>&1) || return 1
  elif command -v node >/dev/null 2>&1; then
    out=$(node -e '
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), Number(process.argv[2] || 10) * 1000);
      fetch(process.argv[1], { signal: c.signal })
        .then(r => r.text())
        .then(t => { clearTimeout(t); process.stdout.write(t); })
        .catch(e => { clearTimeout(t); process.exit(1); });
    ' "$NEXXUS_HEALTH_URL" "$NEXXUS_HEALTH_TIMEOUT" 2>&1) || return 1
  else
    log ERROR "нет ни curl, ни node — нечем проверять здоровье"
    return 2
  fi
  # Ответ должен быть JSON со строкой nodeId — иначе это не наша нода.
  printf '%s' "$out" | grep -q '"nodeId"'
}

# ── Состояние (последний рестарт) ──────────────────────────────────────────
read_state() {
  [ -f "$NEXXUS_STATE_FILE" ] && cat "$NEXXUS_STATE_FILE" 2>/dev/null || echo '{}'
}
write_state() {
  printf '%s' "$1" > "$NEXXUS_STATE_FILE.tmp" 2>/dev/null &&
    chmod 600 "$NEXXUS_STATE_FILE.tmp" 2>/dev/null &&
    mv "$NEXXUS_STATE_FILE.tmp" "$NEXXUS_STATE_FILE" 2>/dev/null
}

last_restart_epoch() {
  read_state | grep -o '"lastRestartEpoch":[0-9]*' | cut -d: -f2
}

record_restart() {
  local now; now=$(date +%s)
  write_state "{\"lastRestartEpoch\":${now},\"lastAction\":\"$1\"}"
}

# ── Действия над systemd-юнитом ────────────────────────────────────────────
unit_exists() { systemctl cat "$NEXXUS_UNIT" >/dev/null 2>&1; }
unit_active() { systemctl is-active --quiet "$NEXXUS_UNIT" 2>/dev/null; }

# Поднять ноду, если она не работает.
ensure_started() {
  if unit_active; then return 0; fi
  if unit_exists; then
    log INFO "нода не активна — запускаю $NEXXUS_UNIT"
    systemctl start "$NEXXUS_UNIT" >/dev/null 2>&1
  else
    # Фолбэк: юнита нет — запускаем бинарь напрямую.
    log WARN "юнит $NEXXUS_UNIT не найден — запускаю $NEXXUS_BIN напрямую"
    nohup "$NEXXUS_BIN" serve --port="$NEXXUS_PORT" --data-dir="$NEXXUS_DATA_DIR" \
      >> "$NEXXUS_LOG_FILE" 2>&1 &
    disown 2>/dev/null || true
  fi
}

# Перезапуск. Для ЗАВИСШЕГО процесса используем SIGKILL по main-процессу:
# systemctl restart шлёт сначала SIGTERM, который зависший процесс не
# обработает, и systemd будет ждать TimeoutStopSec (90 с по умолчанию).
# SIGKILL по main PID systemd воспринимает как падение и поднимает ноду
# сразу (Restart=always).
restart_node() {
  local reason="$1"
  log WARN "перезапускаю ноду: ${reason}"
  notify "⚠️ NeXXus guardian: перезапуск ноды (${reason})"

  if unit_exists; then
    if unit_active; then
      systemctl kill --kill-whom=main --signal=SIGKILL "$NEXXUS_UNIT" >/dev/null 2>&1
      sleep 3
      # Если после SIGKILL systemd не поднял ноду — просим явно.
      if ! unit_active; then
        systemctl start "$NEXXUS_UNIT" >/dev/null 2>&1
      fi
    else
      systemctl restart "$NEXXUS_UNIT" >/dev/null 2>&1
    fi
  else
    pkill -f "^${NEXXUS_BIN}" >/dev/null 2>&1 || true
    sleep 2
    ensure_started
  fi
  record_restart "$reason"
}

# Ждём, пока нода вернёт здоровье.
wait_healthy() {
  local timeout="$1" waited=0
  while [ "$waited" -lt "$timeout" ]; do
    if health_check; then return 0; fi
    sleep 3
    waited=$((waited + 3))
  done
  return 1
}

# ── Канал управления от трея ───────────────────────────────────────────────
# Трей пишет command.json: {"id":"<uuid>","action":"restart|stop|start|status"}
# Хранитель выполняет команду от root и пишет result.json с тем же id.
json_field() {
  # $1 — файл, $2 — имя поля. Значение — строка в кавычках.
  [ -f "$1" ] || return 1
  grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null |
    head -1 | sed "s/.*:[[:space:]]*\"//; s/\"$//"
}

write_result() {
  local id="$1" action="$2" ok="$3" message="$4"
  printf '{"id":"%s","action":"%s","ok":%s,"message":"%s"}\n' \
    "$id" "$action" "$ok" "$message" > "$NEXXUS_CONTROL_DIR/result.json.tmp" 2>/dev/null &&
    chmod 660 "$NEXXUS_CONTROL_DIR/result.json.tmp" 2>/dev/null &&
    mv "$NEXXUS_CONTROL_DIR/result.json.tmp" "$NEXXUS_CONTROL_DIR/result.json" 2>/dev/null
}

handle_control_command() {
  local cmd_file="$NEXXUS_CONTROL_DIR/command.json"
  [ -f "$cmd_file" ] || return 0

  local action id
  action=$(json_field "$cmd_file" action)
  id=$(json_field "$cmd_file" id)
  [ -n "$action" ] || { log WARN "команда без поля action — игнорирую"; rm -f "$cmd_file"; return 0; }

  log INFO "команда от трея: ${action}${id:+ (id=${id})}"

  local ok=true message=""
  case "$action" in
    restart)
      restart_node "запрошено из трея"
      if wait_healthy "$NEXXUS_RECOVER_TIMEOUT"; then
        message="нода перезапущена и отвечает"
      else
        ok=false; message="нода не восстановилась за ${NEXXUS_RECOVER_TIMEOUT}s"
      fi
      ;;
    stop)
      # Пауза: иначе хранитель вернёт ноду через минуту.
      printf 'stopped via tray at %s\n' "$(ts)" > "$NEXXUS_PAUSE_FILE" 2>/dev/null
      systemctl stop "$NEXXUS_UNIT" >/dev/null 2>&1
      message="нода остановлена (пауза хранителя активна)"
      ;;
    start)
      rm -f "$NEXXUS_PAUSE_FILE" 2>/dev/null
      ensure_started
      if wait_healthy "$NEXXUS_RECOVER_TIMEOUT"; then
        message="нода запущена и отвечает"
      else
        ok=false; message="нода запущена, но API не отвечает"
      fi
      ;;
    status)
      if health_check; then message="нода работает"
      else ok=false; message="нода не отвечает"; fi
      ;;
    *)
      ok=false; message="неизвестная команда: ${action}"
      ;;
  esac

  write_result "${id:-}" "$action" "$ok" "$message"
  rm -f "$cmd_file" 2>/dev/null
  log INFO "команда ${action} выполнена: ${message}"
}

# ── Основной цикл ─────────────────────────────────────────────────────────
main() {
  log INFO "хранитель запущен: юнит=${NEXXUS_UNIT} health=${NEXXUS_HEALTH_URL}"
  log INFO "интервал=${NEXXUS_CHECK_INTERVAL}s порог=${NEXXUS_MAX_FAILURES} cooldown=${NEXXUS_RESTART_COOLDOWN}s"
  log INFO "канал управления: ${NEXXUS_CONTROL_DIR}/command.json"
  notify "🛡️ NeXXus guardian запущен"

  local failures=0
  local paused_notified=0

  while true; do
    sleep "$NEXXUS_CHECK_INTERVAL"

    # Команды от трея обрабатываем всегда, даже на паузе: «Запустить ноду»
    # из трея должен снять паузу и поднять ноду.
    handle_control_command

    # Пауза: администратор осознанно остановил ноду — не вмешиваемся.
    if [ -f "$NEXXUS_PAUSE_FILE" ]; then
      if [ "$paused_notified" -eq 0 ]; then
        log INFO "пауза активна (${NEXXUS_PAUSE_FILE}) — ноду не трогаю"
        paused_notified=1
      fi
      failures=0
      continue
    fi
    [ "$paused_notified" -eq 1 ] && { log INFO "пауза снята — продолжаю наблюдение"; paused_notified=0; }

    if health_check; then
      if [ "$failures" -gt 0 ]; then
        log INFO "нода снова отвечает (предыдущих сбоев: ${failures})"
        notify "✅ NeXXus guardian: нода восстановилась"
      fi
      failures=0
      continue
    fi

    failures=$((failures + 1))
    log WARN "проверка здоровья не прошла (${failures}/${NEXXUS_MAX_FAILURES})"

    # Юнит упал сам — systemd с Restart=always его поднимет, но если он
    # в статусе failed, нужно помочь.
    if ! unit_active && unit_exists; then
      log WARN "юнит ${NEXXUS_UNIT} не активен — поднимаю"
      ensure_started
    fi

    [ "$failures" -lt "$NEXXUS_MAX_FAILURES" ] && continue

    # Порог достигнут — действуем, но не чаще, чем раз в cooldown.
    local last; last=$(last_restart_epoch)
    local now; now=$(date +%s)
    if [ -n "$last" ] && [ $((now - last)) -lt "$NEXXUS_RESTART_COOLDOWN" ]; then
      log WARN "пропускаю перезапуск: прошло $((now - last))с < cooldown ${NEXXUS_RESTART_COOLDOWN}с"
      failures=0
      continue
    fi

    restart_node "API не отвечает ${failures} раз подряд"
    failures=0

    if wait_healthy "$NEXXUS_RECOVER_TIMEOUT"; then
      log INFO "нода поднялась и отвечает"
      notify "✅ NeXXus guardian: нода перезапущена и отвечает"
    else
      log ERROR "нода не восстановилась за ${NEXXUS_RECOVER_TIMEOUT}s — следующая попытка на следующем цикле"
      notify "❌ NeXXus guardian: нода не восстановилась"
    fi
  done
}

main "$@"
