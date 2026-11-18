#!/usr/bin/env bash
# CI-гейт: в дереве репозитории не должно быть redb-хранилищ и крупных
# не-ассетных файлов (аудит S1).
#
# S1: в репозиторий попали 4 файла `redb` по 1,5 МБ (`--help`, `light`,
# `update`, `nexxus-desktop/doctor`). Внутри — таблица `meta` с полем
# `identity_mnemonic`: 12-словная мнемоника в открытом виде.
# Файлы появились из-за бага диспетчера CLI (неизвестный первый аргумент
# трактовался как путь к хранилищу, и демон стартовал на файле с таким именем).
#
# Гейт ловит (по ОТСЛЕЖИВАЕМЫМ файлам — ровно то, что попадёт в репозиторий):
#   1) любой файл с magic `redb`;
#   2) любой не-ассетный файл крупнее 1 МБ;
#   3) файлы, которые раньше создавались как побочный эффект CLI
#      (`--help`, `light`, `update`, `doctor`).
set -euo pipefail

cd "$(dirname "$0")/.."

FAIL=0
MAGIC="72656462"  # hex "redb"

echo "== S1: проверка дерева на redb-хранилища и крупные файлы =="

while IFS= read -r -d '' f; do
  [ -f "$f" ] || continue

  # 1) magic 'redb'
  if [ "$(head -c 4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "$MAGIC" ]; then
    echo "FAIL: redb-хранилище в дереве: $f"
    FAIL=1
  fi

  # 2) крупные не-ассетные файлы
  case "$f" in
    assets/*|src/assets/*|public/*|*/assets/*|*/public/*) ;;
    *)
      sz=$(stat -c%s "$f")
      if [ "$sz" -gt 1048576 ]; then
        echo "FAIL: файл >1 МБ вне assets/public: $f ($sz байт)"
        FAIL=1
      fi
      ;;
  esac

  # 3) файлы-побочки старого диспетчера
  case "$f" in
    --help|light|update|doctor|nexxus-desktop/doctor)
      echo "FAIL: файл-побочка CLI в дереве: $f"
      FAIL=1
      ;;
  esac
done < <(git ls-files -z)

if [ "$FAIL" -ne 0 ]; then
  echo "S1-гейт: ПРОВАЛ"
  exit 1
fi
echo "S1-гейт: OK"
