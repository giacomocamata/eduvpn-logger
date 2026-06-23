#!/usr/bin/env bash
# One-command installer for eduvpn-logger. Idempotent: safe to re-run.
set -euo pipefail

SBIN=/usr/local/sbin
UNITS=/etc/systemd/system
SRC="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo ./install.sh" >&2
    exit 1
fi

echo "==> Installing dependencies"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq || true
    apt-get install -y wireguard-tools python3-maxminddb geoipupdate || \
        echo "WARN: some packages failed to install (continuing)" >&2
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y wireguard-tools python3-maxminddb geoipupdate || \
        echo "WARN: some packages failed to install (continuing)" >&2
else
    echo "WARN: no apt/dnf found — install wireguard-tools, python3-maxminddb, geoipupdate manually" >&2
fi

echo "==> Installing scripts to $SBIN"
install -m 0755 "$SRC/eduvpn-logger.py" "$SBIN/eduvpn-logger.py"
install -m 0755 "$SRC/proxyguard-watcher.py" "$SBIN/proxyguard-watcher.py"

echo "==> Installing systemd units to $UNITS"
install -m 0644 "$SRC/systemd/eduvpn-logger.service" "$UNITS/eduvpn-logger.service"
install -m 0644 "$SRC/systemd/proxyguard-watcher.service" "$UNITS/proxyguard-watcher.service"

echo "==> Creating /var/log/eduvpn"
mkdir -p /var/log/eduvpn

echo "==> Installing rsyslog snippet"
install -m 0644 "$SRC/examples/rsyslog-10-eduvpn.conf" /etc/rsyslog.d/10-eduvpn.conf
systemctl restart rsyslog 2>/dev/null || echo "WARN: could not restart rsyslog" >&2

echo "==> Enabling correlator service"
systemctl daemon-reload
systemctl enable --now eduvpn-logger.service

cat <<'EOF'

==> Done. The correlator is running: journalctl -fu eduvpn-logger.service

NEXT STEPS (cannot be safely automated):

1. GeoIP (optional) — put your MaxMind account ID + license key in /etc/GeoIP.conf
   with "EditionIDs GeoLite2-City", then:
     sudo geoipupdate -v

2. Apache / ProxyGuard — add examples/apache-proxyguard.conf to your VirtualHost
   (edit the FQDN), then:
     sudo apache2ctl configtest && sudo systemctl reload apache2
   Point the watcher at your VirtualHost ErrorLog by editing ExecStart in
   /etc/systemd/system/proxyguard-watcher.service, then:
     sudo systemctl enable --now proxyguard-watcher.service

WireGuard connect/roam/disconnect events are detected internally.
EOF
