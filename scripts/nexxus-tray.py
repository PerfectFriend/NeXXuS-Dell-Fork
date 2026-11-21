#!/usr/bin/env python3
"""
nexxus-tray.py — иконка в системном трее для хранителя ноды NeXXUs.

Трей показывает состояние ноды (зелёный — работает, красный — не отвечает,
жёлтый — перезапускается) и даёт меню базовых команд управления и тестирования:

  Состояние    — паспорт ноды (NodeID, onion, аптайм, пиры, чанки)
  Паспорт      — крипто-идентичность и onion-адрес
  Пиры         — список подключённых узлов
  Логи         — хвост лога ноды
  ─────────────
  Перезапустить — рестарт ноды через systemd
  Остановить    — остановить ноду (хранитель её не вернёт: пауза)
  Запустить     — запустить ноду
  Проверка PoR  — Proof-of-Retrievability (аудит хранилища)
  Бенчмарк      — тест скорости диска и Merkle-дерева
  Тест-файл     — загрузить тестовый файл через RS(4+2) и проверить
  ─────────────
  Обновить      — принудительное обновление состояния
  Выход         — закрыть трей (хранитель продолжает работать)

Все настройки — через переменные окружения (NEXXUS_*), чтобы скрипт
переносился на другой хост без правок кода.
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

# PyQt5 — системный пакет python3-pyqt5.
from PyQt5.QtCore import QPoint, QTimer, Qt
from PyQt5.QtGui import QIcon, QPainter, QColor, QPixmap
from PyQt5.QtWidgets import QAction, QApplication, QMenu, QMessageBox, QSystemTrayIcon

# ── Конфигурация (env с фолбэками) ─────────────────────────────────────────
NEXXUS_HOST = os.environ.get("NEXXUS_HOST", "127.0.0.1")
NEXXUS_PORT = os.environ.get("NEXXUS_PORT", "3999")
NEXXUS_DATA_DIR = os.environ.get("NEXXUS_DATA_DIR", "/var/lib/nexxus")
NEXXUS_BIN = os.environ.get("NEXXUS_BIN", "/usr/local/bin/nexxusd")
NEXXUS_UNIT = os.environ.get("NEXXUS_UNIT", "nexxus-node.service")
NEXXUS_PAUSE_FILE = os.environ.get(
    "NEXXUS_PAUSE_FILE", os.path.join(NEXXUS_DATA_DIR, ".guardian-pause")
)
# Канал управления привилегированным хранителем: сюда трей пишет команду,
# хранитель (root) её выполняет. Не требует пароля и polkit-правил.
NEXXUS_CONTROL_DIR = os.environ.get(
    "NEXXUS_CONTROL_DIR", os.path.join(NEXXUS_DATA_DIR, "control")
)
BASE_URL = f"http://{NEXXUS_HOST}:{NEXXUS_PORT}"
REFRESH_MS = int(os.environ.get("NEXXUS_TRAY_REFRESH_MS", "5000"))
LOG_LINES = int(os.environ.get("NEXXUS_TRAY_LOG_LINES", "40"))


def api_get(path, timeout=8):
    """GET к локальному API ноды. Возвращает (данные, ошибка)."""
    try:
        with urllib.request.urlopen(f"{BASE_URL}{path}", timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
        return json.loads(body), None
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}"
    except Exception as exc:  # таймаут, connection refused, битый JSON
        return None, str(exc)


def api_post(path, payload=None, timeout=30):
    try:
        data = json.dumps(payload or {}).encode("utf-8")
        req = urllib.request.Request(
            f"{BASE_URL}{path}", data=data, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace")), None
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}"
    except Exception as exc:
        return None, str(exc)


def systemctl(*args):
    """Заглушка совместимости: прямое управление systemd из трея больше не
    используется. Привилегированные операции выполняет хранитель через
    канал управления (см. guardian_command)."""
    return False, "прямое управление systemd отключено — используйте guardian_command"


def guardian_command(action, timeout=180):
    """Отправить команду привилегированному хранителю и дождаться ответа.

    Трей работает от обычного пользователя и НЕ имеет прав на systemctl.
    Вместо polkit-правила (дающего passwordless-доступ к systemd) используется
    файловый канал: трей пишет command.json в каталог, доступный группе
    nexxus, а хранитель (root) её выполняет и пишет result.json.

    Возвращает (ok, сообщение).
    """
    cmd_id = uuid.uuid4().hex
    cmd_path = os.path.join(NEXXUS_CONTROL_DIR, "command.json")
    res_path = os.path.join(NEXXUS_CONTROL_DIR, "result.json")
    payload = {"id": cmd_id, "action": action}
    try:
        os.makedirs(NEXXUS_CONTROL_DIR, exist_ok=True)
        # Пишем через временный файл и rename — хранитель не прочитает
        # наполовину записанный JSON.
        tmp = f"{cmd_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, cmd_path)
    except Exception as exc:
        return False, f"не удалось отправить команду хранителю: {exc}"

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(res_path, "r", encoding="utf-8") as fh:
                result = json.load(fh)
            if result.get("id") == cmd_id:
                return bool(result.get("ok")), str(result.get("message", ""))
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        except Exception:
            pass
        time.sleep(0.5)
    return False, "хранитель не ответил вовремя"


def run_cli(*args, timeout=180):
    """Запуск CLI-команды nexxusd (test-por, benchmark, upload...)."""
    try:
        proc = subprocess.run(
            [NEXXUS_BIN, *args], capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode == 0, (proc.stdout + proc.stderr).strip()
    except Exception as exc:
        return False, str(exc)


def tail_log(path, lines=LOG_LINES):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return "".join(fh.readlines()[-lines:])
    except Exception as exc:
        return f"не удалось прочитать лог: {exc}"


def format_uptime(seconds):
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return "?"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}д {hours}ч {minutes}м"
    if hours:
        return f"{hours}ч {minutes}м"
    return f"{minutes}м {secs}с"


class TrayIcon(QSystemTrayIcon):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.state = "unknown"
        self.status = {}
        self.last_error = None

        self.setIcon(self.make_icon("unknown"))
        self.setToolTip("NeXXUs — проверка…")

        self._build_menu()
        self.activated.connect(self.on_activated)
        self.refresh()
        # Периодическое обновление состояния — иконка сама показывает,
        # жива нода или нет, без кликов пользователя.
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(REFRESH_MS)

    # ── Иконка ──────────────────────────────────────────────────────────────
    def make_icon(self, state):
        """Рисуем иконку сами: не зависит от наличия PNG-ресурса в репозитории.
        Цвет кодирует состояние, точка — свечение."""
        pix = QPixmap(64, 64)
        pix.fill(Qt.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.Antialiasing)
        colors = {
            "ok": QColor("#38b764"),
            "down": QColor("#d34841"),
            "restarting": QColor("#e8a33d"),
            "unknown": QColor("#8a8a8a"),
        }
        color = colors.get(state, colors["unknown"])

        # Стилизованный «узел» — ромб с подсвеченным центром.
        p.setBrush(color)
        p.setPen(QColor("#1a1a1a"))
        p.drawPolygon(
            [QPoint(32, 6), QPoint(58, 32), QPoint(32, 58), QPoint(6, 32)]
        )
        p.setBrush(QColor("#f5f5f5"))
        p.setPen(Qt.NoPen)
        p.drawEllipse(24, 24, 16, 16)
        p.end()
        return QIcon(pix)

    # ── Меню ────────────────────────────────────────────────────────────────
    def _build_menu(self):
        menu = QMenu()

        self.status_action = QAction("Состояние: проверка…", menu)
        self.status_action.setEnabled(False)
        menu.addAction(self.status_action)

        self.passport_action = QAction("Паспорт ноды", menu)
        self.passport_action.triggered.connect(self.show_passport)
        menu.addAction(self.passport_action)

        self.peers_action = QAction("Пиры", menu)
        self.peers_action.triggered.connect(self.show_peers)
        menu.addAction(self.peers_action)

        self.logs_action = QAction("Логи ноды", menu)
        self.logs_action.triggered.connect(self.show_logs)
        menu.addAction(self.logs_action)

        menu.addSeparator()

        self.restart_action = QAction("Перезапустить ноду", menu)
        self.restart_action.triggered.connect(self.restart_node)
        menu.addAction(self.restart_action)

        self.stop_action = QAction("Остановить ноду", menu)
        self.stop_action.triggered.connect(self.stop_node)
        menu.addAction(self.stop_action)

        self.start_action = QAction("Запустить ноду", menu)
        self.start_action.triggered.connect(self.start_node)
        menu.addAction(self.start_action)

        menu.addSeparator()

        self.por_action = QAction("Проверка PoR (аудит хранилища)", menu)
        self.por_action.triggered.connect(self.run_por)
        menu.addAction(self.por_action)

        self.bench_action = QAction("Бенчмарк диска и Merkle", menu)
        self.bench_action.triggered.connect(self.run_benchmark)
        menu.addAction(self.bench_action)

        self.filetest_action = QAction("Тест-файл: загрузка и восстановление", menu)
        self.filetest_action.triggered.connect(self.run_file_test)
        menu.addAction(self.filetest_action)

        menu.addSeparator()

        refresh_action = QAction("Обновить", menu)
        refresh_action.triggered.connect(self.refresh)
        menu.addAction(refresh_action)

        quit_action = QAction("Выход (хранитель продолжит работать)", menu)
        quit_action.triggered.connect(self.quit_tray)
        menu.addAction(quit_action)

        self.setContextMenu(menu)
        self.menu = menu

    def on_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.refresh()

    # ── Состояние ───────────────────────────────────────────────────────────
    def refresh(self):
        data, err = api_get("/api/status")
        if data is None:
            self.last_error = err
            self.status = {}
            # Если хранитель на паузе — нода выключена намеренно.
            if os.path.exists(NEXXUS_PAUSE_FILE):
                self.state = "unknown"
                self.setIcon(self.make_icon("unknown"))
                self.setToolTip("NeXXUs — на паузе (хранитель не вмешивается)")
            else:
                self.state = "down"
                self.setIcon(self.make_icon("down"))
                self.setToolTip(f"NeXXUs — не отвечает ({err})")
            self.update_status_line()
            return

        self.last_error = None
        self.status = data
        self.state = "ok"
        self.setIcon(self.make_icon("ok"))
        uptime = format_uptime(data.get("uptimeSeconds"))
        peers = len(data.get("peers", []) or []) if isinstance(data.get("peers"), list) else 0
        self.setToolTip(
            f"NeXXUs — работает\n"
            f"NodeID: {data.get('nodeId', '?')}\n"
            f"Аптайм: {uptime} · Пиры: {peers}\n"
            f"Чанки: {data.get('storedChunksCount', 0)} · "
            f"Пул: {data.get('allocatedGb', 0)} ГБ"
        )
        self.update_status_line()

    def update_status_line(self):
        if self.state == "ok":
            data = self.status
            uptime = format_uptime(data.get("uptimeSeconds"))
            peers = len(data.get("peers", []) or []) if isinstance(data.get("peers"), list) else 0
            text = (
                f"Состояние: работает · аптайм {uptime} · "
                f"пиры {peers} · чанки {data.get('storedChunksCount', 0)}"
            )
        elif os.path.exists(NEXXUS_PAUSE_FILE):
            text = "Состояние: на паузе (остановлена вручную)"
        else:
            text = f"Состояние: НЕ ОТВЕЧАЕТ ({self.last_error})"
        self.status_action.setText(text)

    # ── Команды ─────────────────────────────────────────────────────────────
    def notify(self, title, text, error=False):
        # QSystemTrayIcon — это НЕ QWidget, передавать его родителем в
        # QMessageBox нельзя (TypeError: unexpected type 'TrayIcon').
        # Поэтому диалог создаём без родителя.
        box = QMessageBox()
        box.setWindowTitle(title)
        box.setIcon(QMessageBox.Critical if error else QMessageBox.Information)
        box.setText(text)
        box.setTextFormat(Qt.PlainText)
        box.exec_()

    def show_passport(self):
        data, err = api_get("/api/id")
        if data is None:
            self.notify("Паспорт ноды", f"Нода не отвечает: {err}", error=True)
            return
        text = (
            f"NodeID:       {data.get('nodeId', '?')}\n"
            f"Onion v3:     {data.get('onionAddress', '?')}\n"
            f"Master Pub:   {data.get('masterPublicKey', '?')}\n"
            f"Хост:         {data.get('hostname', '?')}\n"
            f"Система:      {data.get('os', '?')}\n"
            f"Порт:         {data.get('port', '?')}\n"
            f"Пул:          {data.get('allocatedGb', '?')} ГБ"
        )
        self.notify("Паспорт ноды", text)

    def show_peers(self):
        data, err = api_get("/api/peers")
        if data is None:
            self.notify("Пиры", f"Нода не отвечает: {err}", error=True)
            return
        if not data:
            self.notify("Пиры", "Подключённых пиров нет.\n\nДобавьте пира:\nnexxusd peer add <ip:port>")
            return
        lines = []
        for peer in data:
            lines.append(
                f"• {peer.get('nodeId', '?')}\n"
                f"  onion: {peer.get('onionAddress', '?')}\n"
                f"  endpoint: {peer.get('p2pEndpoint', '?')}  "
                f"uptime: {format_uptime(peer.get('uptimeSeconds'))}"
            )
        self.notify("Пиры", "\n".join(lines))

    def show_logs(self):
        log_path = os.path.join(NEXXUS_DATA_DIR, "logs", "nexxusd.log")
        self.notify("Логи ноды (хвост)", tail_log(log_path))

    def restart_node(self):
        ok, out = guardian_command("restart", timeout=180)
        if ok:
            self.notify("Перезапуск ноды", f"Нода перезапущена.\n{out}")
        else:
            self.notify(
                "Перезапуск ноды",
                f"Не удалось перезапустить:\n{out}",
                error=True,
            )
        QTimer.singleShot(3000, self.refresh)

    def stop_node(self):
        # Остановку выполняет хранитель: он же ставит паузу, иначе вернёт
        # ноду через минуту. Трей только просит.
        ok, out = guardian_command("stop", timeout=60)
        if ok:
            self.notify(
                "Остановка ноды",
                f"Нода остановлена. Хранитель её не поднимет, пока пауза активна.\n"
                f"{out}\n"
                "Чтобы вернуть: «Запустить ноду».",
            )
        else:
            self.notify("Остановка ноды", f"Не удалось остановить:\n{out}", error=True)
        QTimer.singleShot(2000, self.refresh)

    def start_node(self):
        # Запуск и снятие паузы — тоже через хранителя.
        ok, out = guardian_command("start", timeout=180)
        if ok:
            self.notify("Запуск ноды", f"Нода запущена, пауза снята.\n{out}")
        else:
            self.notify("Запуск ноды", f"Не удалось запустить:\n{out}", error=True)
        QTimer.singleShot(4000, self.refresh)

    def run_por(self):
        self.notify("Проверка PoR", "Выполняется аудит хранилища…")
        data, err = api_post("/api/por/challenge")
        if data is None:
            self.notify("Проверка PoR", f"Аудит не выполнен: {err}", error=True)
            return
        verify = data.get("verify", {}) or {}
        challenge = data.get("challenge", {}) or {}
        response = data.get("response", {}) or {}
        ok = verify.get("verified", False)
        text = (
            f"Результат: {'✅ ПРОЙДЕН' if ok else '❌ ПРОВАЛЕН'}\n"
            f"Чанк:      {challenge.get('chunkIndex', '?')}\n"
            f"Ответ за:  {response.get('respondedInMs', '?')} мс\n"
            f"Дедлайн:   {challenge.get('deadlineMs', 3000)} мс"
        )
        self.notify("Проверка PoR", text, error=not ok)

    def run_benchmark(self):
        data, err = api_get("/api/benchmark", timeout=120)
        if data is None:
            self.notify("Бенчмарк", f"Не удалось выполнить: {err}", error=True)
            return
        text = "\n".join(f"{k}: {v}" for k, v in data.items())
        self.notify("Бенчмарк диска и Merkle", text)

    def run_file_test(self):
        """Полный цикл: загрузка файла через RS(4+2) и восстановление.
        Проверяет не только код, но и что данные не потерялись."""
        # Рабочие файлы — во временном каталоге пользователя: каталог данных
        # ноды принадлежит root'у, и трей не может писать туда напрямую.
        # Сами чанки и манифест пишет CLI от root в каталог данных ноды.
        import tempfile

        tmpdir = tempfile.mkdtemp(prefix="nexxus-selftest-")
        test_file = os.path.join(tmpdir, "selftest.bin")
        out_file = os.path.join(tmpdir, "selftest.out.bin")
        payload = os.urandom(64 * 1024)
        try:
            with open(test_file, "wb") as fh:
                fh.write(payload)
        except Exception as exc:
            self.notify("Тест-файл", f"Не удалось создать тестовый файл: {exc}", error=True)
            return

        ok, out = run_cli("upload", test_file, f"--dir={NEXXUS_DATA_DIR}", timeout=300)
        if not ok:
            self.notify("Тест-файл", f"Ошибка загрузки:\n{out}", error=True)
            return
        file_hash = ""
        for line in out.splitlines():
            if "SHA-256" in line:
                file_hash = line.split("SHA-256:")[-1].strip().split()[0]
                break
        if not file_hash:
            self.notify("Тест-файл", f"Не удалось получить хэш из вывода:\n{out}", error=True)
            return

        ok, out = run_cli("download", file_hash, out_file, f"--dir={NEXXUS_DATA_DIR}", timeout=300)
        if not ok:
            self.notify("Тест-файл", f"Ошибка скачивания:\n{out}", error=True)
            return

        try:
            with open(out_file, "rb") as fh:
                restored = fh.read()
        except Exception as exc:
            self.notify("Тест-файл", f"Не удалось прочитать восстановленный файл: {exc}", error=True)
            return

        if restored == payload:
            text = (
                f"✅ Файл восстановлен байт-в-байт\n"
                f"Размер:    {len(payload)} байт\n"
                f"SHA-256:   {file_hash}\n"
                f"Шардов:    RS(4+2), кворум 4 из 6"
            )
        else:
            text = (
                f"❌ Восстановленный файл не совпадает с исходным\n"
                f"Ожидалось: {len(payload)} байт\n"
                f"Получено:  {len(restored)} байт"
            )
        self.notify("Тест-файл: загрузка и восстановление", text, error=restored != payload)

    def quit_tray(self):
        self.timer.stop()
        self.hide()
        self.app.quit()


def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    # Иконка в трее: без этого Qt не покажет значок в GNOME/KDE.
    app.setDesktopFileName("nexxus-tray")

    if not QSystemTrayIcon.isSystemTrayAvailable():
        print("Нет системного трея — иконка не может быть показана", file=sys.stderr)
        return 1

    tray = TrayIcon(app)
    tray.show()
    # Не даём процессу умереть при закрытии меню.
    app.setQuitOnLastWindowClosed(False)
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
