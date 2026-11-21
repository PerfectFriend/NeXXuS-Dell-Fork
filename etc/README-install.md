# ==============================================================================
# NeXXuS — установка ноды, хранителя и трея на Linux-хосте.
#
# Три компонента:
#   nexxus-node.service     — сама нода (Go/TS-бандл nexxusd), порт 3999
#   nexxus-guardian.service  — хранитель: стартует ПЕРВЫМ, следит за API,
#                              перезапускает ноду при зависании или отказе
#   nexxus-tray.service      — иконка в системном трее (user-юнит, KDE/GNOME)
#
# Порядок загрузки задаётся в nexxus-guardian.service:
#   Before=nexxus-node.service + Wants=nexxus-node.service
#   Хранитель поднимается первым и тянет ноду за собой.
#
# Установка (из клона репозитория):
#   1. Собрать бандл демона:
#        npm install --omit=dev
#        npx esbuild scripts/linux-daemon.ts --bundle --platform=node \
#          --format=cjs --outfile=dist/nexxusd.cjs
#   2. Разложить файлы:
#        /opt/nexxus/scripts/nexxus-guardian.sh   (chmod 755)
#        /opt/nexxus/scripts/nexxus-tray.py       (chmod 755)
#        /opt/nexxus/dist/nexxusd.cjs → /usr/local/bin/nexxusd
#        etc/nexxus.conf        → /etc/nexxus/nexxus.conf
#        etc/nexxus-node.service    → /etc/systemd/system/
#        etc/nexxus-guardian.service → /etc/systemd/system/
#        etc/nexxus-tray.service     → ~/.config/systemd/user/
#   3. Создать каталоги и идентичность:
#        mkdir -p /var/lib/nexxus/{chunks,meta,logs,control} /etc/nexxus
#        nexxusd init --dir=/var/lib/nexxus
#   4. systemctl daemon-reload
#        systemctl enable --now nexxus-guardian   # поднимет и ноду
#        systemctl --user enable --now nexxus-tray
#
# ТРЕБОВАНИЯ И НЕОБХОДИМЫЕ ПРАВА:
#   * node в /usr/local/bin — демон запускается от root, а node из
#     ~/.hermes/tools/... в PATH root'а не попадает (был exit 127).
#   * Группа nexxus + POSIX ACL (u:<user>:rwx, default тоже):
#     трей работает от пользователя и должен писать в каталог данных.
#     Членства в группе НЕ хватает, если сессия стартовала до создания
#     группы, а SupplementaryGroups= в user-юните не работает вовсе
#     (user-менеджер не может менять группы → status=216/GROUP).
#   * Права на каталог данных: root:nexxus, chmod 2775 (setgid), файлы 664.
#   * Идентичность: /var/lib/nexxus/node_identity.json — 0600, НЕ в git.
#     Мнемоника BIP-39 внутри файла — хранить отдельно, не в репозитории.
#
# ПУЛ ХРАНИЛИЩА: NEXXUS_STORAGE_GB — кратно 16 ГБ (разделы по 16 ГБ).
# Ставить больше, чем реально свободно на диске, бессмысленно.
#
# КАНАЛ УПРАВЛЕНИЯ ОТ ТРЕЯ (без polkit и без sudo для пользователя):
#   Трей пишет  /var/lib/nexxus/control/command.json
#                {"id":"<uuid>","action":"restart|stop|start|status"}
#   Хранитель (root) выполняет и пишет
#                /var/lib/nexxus/control/result.json
#                {"id":"<uuid>","action":"...","ok":true,"message":"..."}
#   Каталог control: root:nexxus, chmod 2770.
#   Так пользователю не выдаётся парольный доступ к systemd.
#
# ПРОВЕРКА:
#   curl -s http://127.0.0.1:3999/api/status
#   nexxusd test-por --dir=/var/lib/nexxus
#   tail -f /var/lib/nexxus/logs/guardian.log
#   systemctl status nexxus-guardian nexxus-node
# ==============================================================================
