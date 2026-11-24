#!/usr/bin/env bash
# NeXXuS-Dell-Fork — headless server package (deb).
#
# Собирает самодостаточный пакет всего стека хоста:
#   /usr/local/bin/{nexxusd,smp-server,smp-client,xftp-h2,node}
#   /opt/nexxus/{scripts,dashboard,package.json,node_modules/ws}
#   /etc/systemd/system/*.service (+ drop-in nexxus-rust-node.service.d)
#   /etc/tor/nexxus-torrc, /etc/nexxus-rust/node.conf (conffile)
# Секрет api.token в пакет НЕ входит — генерируется в postinst.
#
# Usage:
#   scripts/build-deb-dell.sh [version-suffix] [nexxusd] [rustsimplex-release-dir] [node-bin]
# Пример:
#   scripts/build-deb-dell.sh dell1 target/release/nexxusd ~/rustsimplex/target/release /usr/local/bin/node
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUFFIX="${1:-dell1}"
NEXXUSD="${2:-$ROOT/target/release/nexxusd}"
RS_DIR="${3:-$HOME/rustsimplex/target/release}"
NODE_BIN="${4:-/usr/local/bin/node}"

VERSION="$(grep -m1 '^version' "$ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')-${SUFFIX}"
PKG="nexxus-dell"
ARCH="amd64"
STAGE="$ROOT/dist/pkg-staging-dell/${PKG}_${VERSION}_${ARCH}"
DEB="$ROOT/dist/${PKG}_${VERSION}_${ARCH}.deb"

for f in "$NEXXUSD" "$RS_DIR/smp-server" "$RS_DIR/smp-client" "$RS_DIR/xftp-h2" "$NODE_BIN"; do
    [ -f "$f" ] || { echo "нет файла: $f" >&2; exit 1; }
done

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" \
    "$STAGE/usr/local/bin" \
    "$STAGE/opt/nexxus/scripts" \
    "$STAGE/opt/nexxus/node_modules" \
    "$STAGE/etc/systemd/system/nexxus-rust-node.service.d" \
    "$STAGE/etc/tor" \
    "$STAGE/etc/nexxus-rust"

# --- бинарники ---
install -m 0755 "$NEXXUSD"                    "$STAGE/usr/local/bin/nexxusd"
install -m 0755 "$RS_DIR/smp-server"          "$STAGE/usr/local/bin/smp-server"
install -m 0755 "$RS_DIR/smp-client"          "$STAGE/usr/local/bin/smp-client"
install -m 0755 "$RS_DIR/xftp-h2"             "$STAGE/usr/local/bin/xftp-h2"
install -m 0755 "$NODE_BIN"                   "$STAGE/usr/local/bin/node"

# --- control-plane скрипты + дашборд (всё, что читает nexxus-control.service) ---
install -m 0644 "$ROOT/scripts/nx-api.cjs"                "$STAGE/opt/nexxus/scripts/nx-api.cjs"
install -m 0644 "$ROOT/scripts/nexxus-control-server.cjs" "$STAGE/opt/nexxus/scripts/nexxus-control-server.cjs"
install -m 0755 "$ROOT/scripts/nexxus-guardian.sh"        "$STAGE/opt/nexxus/scripts/nexxus-guardian.sh"
install -m 0644 "$ROOT/scripts/nexxus-tray.py"            "$STAGE/opt/nexxus/scripts/nexxus-tray.py"
cp -r "$ROOT/dashboard" "$STAGE/opt/nexxus/dashboard"
[ -f "$ROOT/package.json" ] && install -m 0644 "$ROOT/package.json" "$STAGE/opt/nexxus/package.json"
# control-server требует модуль 'ws' (остальные зависимости — stdlib node)
if [ -d "$ROOT/node_modules/ws" ]; then
    cp -r "$ROOT/node_modules/ws" "$STAGE/opt/nexxus/node_modules/ws"
else
    echo "warning: node_modules/ws не найден в репо — control-server потребует ws" >&2
fi

# --- systemd-юниты (лежат в репо, etc/) ---
for u in nexxus-rust-node nexxus-smp nexxus-control nexxus-guardian nexxus-tray nexxus-tor; do
    install -m 0644 "$ROOT/etc/$u.service" "$STAGE/etc/systemd/system/$u.service"
done
install -m 0644 "$ROOT/etc/nexxus-rust-node.service.d/10-tor-cache.conf" \
                "$STAGE/etc/systemd/system/nexxus-rust-node.service.d/10-tor-cache.conf"
install -m 0644 "$ROOT/etc/nexxus-rust-node.service.d/20-api-onion.conf" \
                "$STAGE/etc/systemd/system/nexxus-rust-node.service.d/20-api-onion.conf"

# --- конфиги (conffiles; api.token генерируется в postinst) ---
install -m 0644 "$ROOT/etc/tor/nexxus-torrc"     "$STAGE/etc/tor/nexxus-torrc"
install -m 0644 "$ROOT/etc/nexxus-rust/node.conf" "$STAGE/etc/nexxus-rust/node.conf"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: ${PKG}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: NeXXuS Dell Fork <ops@nexxus.local>
Depends: tor
Description: NeXXuS Dell Fork — headless node stack (all-Rust)
 Rust node daemon (nexxusd, P2P wire v3 + Ed25519, Tor/Arti onion,
 WS JSON-RPC API), RustSimplex SMP relay (smp-server/smp-client/xftp-h2),
 always-on control-plane (dashboard on 127.0.0.1:3998), guardian watchdog,
 tray applet, system Tor publishing the P2P onion. API token is generated
 at install time (/etc/nexxus-rust/api.token, 0640 root:nexxus).
EOF

cat > "$STAGE/DEBIAN/conffiles" <<EOF
/etc/tor/nexxus-torrc
/etc/nexxus-rust/node.conf
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
groupadd -f nexxus
mkdir -p /var/lib/nexxus-rust /var/lib/nexxus-smp /var/lib/nexxus-tor
chown root:nexxus /var/lib/nexxus-rust /var/lib/nexxus-smp
chmod 0750 /etc/nexxus-rust 2>/dev/null || true
# API-токен: создаём, если его ещё нет (секрет не входит в пакет)
if [ ! -s /etc/nexxus-rust/api.token ]; then
    od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > /etc/nexxus-rust/api.token
    echo >> /etc/nexxus-rust/api.token
fi
chown root:nexxus /etc/nexxus-rust/api.token
chmod 0640 /etc/nexxus-rust/api.token
systemctl daemon-reload
systemctl enable nexxus-tor.service nexxus-smp.service nexxus-rust-node.service \
    nexxus-control.service nexxus-guardian.service nexxus-tray.service 2>/dev/null || true
# Трей стартует только в графической сессии (WantedBy=graphical-session.target)
for s in nexxus-tor nexxus-smp nexxus-rust-node nexxus-control nexxus-guardian; do
    systemctl start "$s.service" 2>/dev/null || true
done
exit 0
EOF

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    for s in nexxus-guardian nexxus-control nexxus-rust-node nexxus-smp nexxus-tor nexxus-tray; do
        systemctl stop "$s.service" 2>/dev/null || true
    done
fi
exit 0
EOF

cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = purge ]; then
    systemctl disable nexxus-tor.service nexxus-smp.service nexxus-rust-node.service \
        nexxus-control.service nexxus-guardian.service nexxus-tray.service 2>/dev/null || true
    rm -rf /var/lib/nexxus-rust /var/lib/nexxus-smp /var/lib/nexxus-tor
    # api.token удаляем только при purge
    rm -f /etc/nexxus-rust/api.token
fi
systemctl daemon-reload 2>/dev/null || true
exit 0
EOF

chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"

mkdir -p "$ROOT/dist"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB"
echo "OK: $DEB ($(du -h "$DEB" | cut -f1))"
