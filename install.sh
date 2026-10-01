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
# wireguard-tools is required; the GeoIP packages are optional and installed one
# at a time (geoipupdate is in Debian *contrib*, python3-maxminddb may need EPEL):
# one missing optional package must not abort the required one.
if command -v apt-get >/dev/null 2>&1; then
    PKG="apt-get install -y"
    apt-get update -qq || true
elif command -v dnf >/dev/null 2>&1; then
    PKG="dnf install -y"
else
    PKG=""
fi
if [ -n "$PKG" ]; then
    $PKG wireguard-tools
    for p in python3-maxminddb geoipupdate; do
        $PKG "$p" || echo "WARN: optional package $p not installed (GeoIP only)" >&2
    done
fi
command -v wg >/dev/null 2>&1 || { echo "ERROR: 'wg' not found — install wireguard-tools" >&2; exit 1; }

echo "==> Installing scripts to $SBIN"
install -m 0755 "$SRC/eduvpn-logger.py" "$SBIN/eduvpn-logger.py"
install -m 0755 "$SRC/proxyguard-watcher.py" "$SBIN/proxyguard-watcher.py"

echo "==> Installing systemd units to $UNITS"
# Units are overwritten on re-run: customise them with `systemctl edit <unit>`
# (drop-ins survive), not by editing these files.
install -m 0644 "$SRC/systemd/eduvpn-logger.service" "$UNITS/eduvpn-logger.service"
install -m 0644 "$SRC/systemd/proxyguard-watcher.service" "$UNITS/proxyguard-watcher.service"

echo "==> Creating /var/log/eduvpn (0750: the logs hold personal data)"
install -d -m 0750 -o root -g adm /var/log/eduvpn

echo "==> Installing logrotate policy"
install -m 0644 "$SRC/examples/logrotate-eduvpn" /etc/logrotate.d/eduvpn-logger

if [ -d /etc/rsyslog.d ]; then
    echo "==> Installing rsyslog snippet"
    install -m 0644 "$SRC/examples/rsyslog-10-eduvpn.conf" /etc/rsyslog.d/10-eduvpn.conf
    systemctl restart rsyslog 2>/dev/null || echo "WARN: could not restart rsyslog" >&2
else
    echo "==> rsyslog not installed: events still reach the journal (journalctl -t eduvpn-logger)"
fi

echo "==> Enabling correlator service"
systemctl daemon-reload
systemctl enable --now eduvpn-logger.service

cat <<'EOF'

==> Done. The correlator is running: journalctl -fu eduvpn-logger.service

NEXT STEPS (cannot be safely automated):

1. GeoIP (optional) — put your MaxMind account ID + license key in /etc/GeoIP.conf
   with "EditionIDs GeoLite2-City", then:
     sudo geoipupdate -v

2. Portal — /etc/vpn-user-portal/config.php must have
   'Log' => ['syslogConnectionEvents' => true, ...] (see README "Portal logging").

3. Apache / ProxyGuard — add examples/apache-proxyguard.conf to your VirtualHost
   (edit the FQDN), then:
     sudo apache2ctl configtest && sudo systemctl reload apache2
   If your VirtualHost ErrorLog is not /var/log/apache2/error.log, override
   ExecStart with `sudo systemctl edit proxyguard-watcher.service`, then:
     sudo systemctl enable --now proxyguard-watcher.service

WireGuard connect/roam/disconnect events are detected internally.
EOF
