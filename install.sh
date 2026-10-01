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
# wireguard-tools and python3 are required; the GeoIP packages are optional and installed one
# at a time (geoipupdate is in Debian *contrib*, python3-maxminddb may need EPEL):
# one missing optional package must not abort the required one. Already installed
# packages are left alone: installing the logger must not upgrade a live server's
# python3 or wireguard-tools as a side effect (dnf install never upgrades).
if command -v apt-get >/dev/null 2>&1; then
    PKG="apt-get install -y --no-upgrade"
    apt-get update -qq || true
elif command -v dnf >/dev/null 2>&1; then
    PKG="dnf install -y"
else
    PKG=""
fi
if [ -n "$PKG" ]; then
    $PKG wireguard-tools python3
    for p in python3-maxminddb geoipupdate; do
        $PKG "$p" || echo "WARN: optional package $p not installed (GeoIP only)" >&2
    done
fi
for c in wg python3; do
    command -v "$c" >/dev/null 2>&1 || { echo "ERROR: '$c' not found — install wireguard-tools and python3" >&2; exit 1; }
done

echo "==> Installing scripts to $SBIN"
install -m 0755 "$SRC/eduvpn-logger.py" "$SBIN/eduvpn-logger.py"
install -m 0755 "$SRC/proxyguard-watcher.py" "$SBIN/proxyguard-watcher.py"

# An existing unit means this is an upgrade (see the end of the script).
UPGRADE=0
[ -f "$UNITS/eduvpn-logger.service" ] && UPGRADE=1

echo "==> Installing systemd units to $UNITS"
# Units are overwritten on re-run: customise them with `systemctl edit <unit>`
# (drop-ins survive), not by editing these files. The first release said to edit
# them in place, so carry such settings over into a drop-in first: losing the
# watcher's ErrorLog path would silently cost every TCP session its source IP.
# 00-migrated.conf sorts before override.conf: existing drop-ins still win.
keep_local_settings() {
    local unit="$UNITS/$1" lines cmd
    lines=$(grep -s '^Environment=' "$unit" | grep -vxF -f "$SRC/systemd/$1" || true)
    cmd=$(grep -s '^ExecStart=' "$unit" | tail -n 1 || true)
    if [ "$1" = proxyguard-watcher.service ] && [ -n "$cmd" ] && [[ $cmd != *" /var/log/apache2/error.log "* ]]; then
        # `-n 0` (missing in old units): a restart must not replay old lines as
        # fresh START events.
        lines+=$'\nExecStart=\n'"${cmd/tail -F /tail -n 0 -F }"
    fi
    [ -n "$lines" ] || return 0
    install -d "$unit.d"
    printf '[Service]\n%s\n' "$lines" >>"$unit.d/00-migrated.conf"
    echo "WARN: settings edited into $unit kept in $unit.d/00-migrated.conf" >&2
}
keep_local_settings eduvpn-logger.service
keep_local_settings proxyguard-watcher.service
install -m 0644 "$SRC/systemd/eduvpn-logger.service" "$UNITS/eduvpn-logger.service"
install -m 0644 "$SRC/systemd/proxyguard-watcher.service" "$UNITS/proxyguard-watcher.service"

echo "==> Creating /var/log/eduvpn (2750 root:adm: the logs hold personal data)"
# setgid: files created in it (by the daemon, rsyslog) belong to group adm too.
install -d -m 2750 -o root -g adm /var/log/eduvpn

if [ -d /etc/logrotate.d ]; then
    echo "==> Installing logrotate policy"
    install -m 0644 "$SRC/examples/logrotate-eduvpn" /etc/logrotate.d/eduvpn-logger
else
    echo "WARN: logrotate not installed: /var/log/eduvpn will not be rotated (install it, re-run)" >&2
fi

if [ -d /etc/rsyslog.d ] && grep -qs '^[$]PrivDropToUser' /etc/rsyslog.conf; then
    # Ubuntu: rsyslog runs as user syslog and cannot write into the root:adm
    # 2750 log directory; the snippet would only make the events vanish from
    # /var/log/syslog (its "& stop"). They stay in the journal and eduvpn.log.
    echo "WARN: rsyslog drops privileges here: snippet not installed (events: journalctl -t eduvpn-logger)" >&2
    if [ -f /etc/rsyslog.d/10-eduvpn.conf ]; then
        rm -f /etc/rsyslog.d/10-eduvpn.conf
        systemctl restart rsyslog 2>/dev/null || echo "WARN: could not restart rsyslog" >&2
    fi
elif [ -d /etc/rsyslog.d ]; then
    echo "==> Installing rsyslog snippet"
    # Restart the system logger only when the snippet actually changed.
    if ! cmp -s "$SRC/examples/rsyslog-10-eduvpn.conf" /etc/rsyslog.d/10-eduvpn.conf; then
        install -m 0644 "$SRC/examples/rsyslog-10-eduvpn.conf" /etc/rsyslog.d/10-eduvpn.conf
        systemctl restart rsyslog 2>/dev/null || echo "WARN: could not restart rsyslog" >&2
    fi
else
    echo "==> rsyslog not installed: events still reach the journal (journalctl -t eduvpn-logger)"
fi

systemctl daemon-reload
if [ "$UPGRADE" -eq 1 ]; then
    # Upgrade: restart what is running (the old code must not keep running), but
    # never re-enable a service the administrator stopped or disabled.
    echo "==> Restarting the running services"
    systemctl try-restart eduvpn-logger.service proxyguard-watcher.service
else
    echo "==> Enabling and starting eduvpn-logger"
    systemctl enable --now eduvpn-logger.service
fi
if ! systemctl is-active --quiet eduvpn-logger.service; then
    echo "WARN: eduvpn-logger is not running: sudo systemctl enable --now eduvpn-logger.service" >&2
fi

cat <<'EOF'

==> Done. Status and warnings: journalctl -u eduvpn-logger.service

Remaining steps (see README, "Installation"):

1. REQUIRED, if not done yet: portal connection logging, i.e. in
   /etc/vpn-user-portal/config.php
     'Log' => ['syslogConnectionEvents' => true, ...]

2. Only with ProxyGuard (WireGuard over TCP/443): add
   examples/apache-proxyguard.conf to the VirtualHost, reload Apache, then
     sudo systemctl enable --now proxyguard-watcher.service

3. Optional, GeoIP: MaxMind account ID + license key in /etc/GeoIP.conf
   ("EditionIDs GeoLite2-City"), then: sudo geoipupdate -v

Customise with `sudo systemctl edit eduvpn-logger.service` (drop-ins survive
re-installs). Output: /var/log/eduvpn/eduvpn.log
EOF
