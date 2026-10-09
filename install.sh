#!/usr/bin/env bash
# One-command installer for eduvpn-logger on an eduVPN 3 server (Debian, Ubuntu,
# Enterprise Linux, Fedora). Idempotent: safe to re-run, also to upgrade.
#
#   sudo ./install.sh
#   sudo GEOIP_ACCOUNT_ID=123456 GEOIP_LICENSE_KEY=xxxxxxxx ./install.sh   # with GeoIP
#
# Besides the logger it turns on, when missing, what it needs on the eduVPN side:
# the portal's connection log (config.php, backup kept) and, with ProxyGuard,
# Apache's trace of tunnel starts (a conf file of its own; Apache reloaded).
set -euo pipefail

SBIN=/usr/local/sbin
UNITS=/etc/systemd/system
SRC="$(cd "$(dirname "$0")" && pwd)"
PORTAL_CONF=/etc/vpn-user-portal/config.php
NOTES=()  # what is left to the administrator, printed at the end

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo ./install.sh" >&2
    exit 1
fi
warn() { echo "WARN: $*" >&2; }
same() { [ -f "$2" ] && [ "$(cat "$1")" = "$(cat "$2")" ]; }  # no cmp: diffutils may be missing

echo "==> Installing dependencies"
# wireguard-tools, python3 and logrotate (the log holds personal data: its
# retention must be enforced) are required. The GeoIP packages are optional and
# installed one at a time (geoipupdate is in Debian *contrib*, python3-maxminddb
# may need EPEL): one missing optional package must not abort the others. Only
# missing packages are installed: installing the logger must not upgrade a live
# server's python3 or wireguard-tools as a side effect (`dnf install` would).
if command -v apt-get >/dev/null 2>&1; then
    PKG="apt-get install -y --no-upgrade"
    apt-get update -qq || true
    missing() { ! dpkg-query -W -f '${Status}' "$1" 2>/dev/null | grep -q "ok installed"; }
elif command -v dnf >/dev/null 2>&1; then
    PKG="dnf install -y"
    missing() { ! rpm -q --whatprovides "$1" >/dev/null 2>&1; }
else
    PKG=""
fi
if [ -n "$PKG" ]; then
    for p in wireguard-tools python3 logrotate; do
        if missing "$p"; then $PKG "$p"; fi
    done
    for p in python3-maxminddb geoipupdate; do
        if missing "$p"; then $PKG "$p" || warn "optional package $p not installed (GeoIP only)"; fi
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
    warn "settings edited into $unit kept in $unit.d/00-migrated.conf"
}
keep_local_settings eduvpn-logger.service
keep_local_settings proxyguard-watcher.service
install -m 0644 "$SRC/systemd/eduvpn-logger.service" "$UNITS/eduvpn-logger.service"
install -m 0644 "$SRC/systemd/proxyguard-watcher.service" "$UNITS/proxyguard-watcher.service"

# The VirtualHost that proxies /proxyguard/ (eduVPN's own), if any.
PG_VHOST=$(grep -lsE '^[^#]*ProxyPass[^#]*/proxyguard/' /etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf 2>/dev/null | head -n 1 || true)

# The watcher must follow that VirtualHost's ErrorLog. eduVPN gives it its own
# (<host>_ssl_error.log on Debian/Ubuntu, logs/<host>_ssl_error_log on EL/Fedora):
# the unit's default, /var/log/apache2/error.log, would miss every tunnel start.
# Detected on every run into 00-errorlog.conf; 00-migrated.conf and
# `systemctl edit` still win.
apache_errorlog() {  # plain bash: minimal EL/Fedora systems may have no awk
    local root=/etc/apache2 log="" line e="" pg=0
    [ -d /etc/apache2 ] || root=/etc/httpd
    if [ -n "$PG_VHOST" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            if [[ $line =~ ^[[:space:]]*[\<]VirtualHost ]]; then e="" pg=0; fi
            if [[ $line =~ ^[[:space:]]*ErrorLog[[:space:]]+([^[:space:]]+) ]]; then e=${BASH_REMATCH[1]}; fi
            if [[ $line =~ ^[^#]*ProxyPass[^#]*/proxyguard/ ]]; then pg=1; fi
            if [[ $line =~ ^[[:space:]]*[\<]/VirtualHost ]] && [ "$pg" = 1 ] && [ -n "$e" ]; then log=$e; break; fi
        done <"$PG_VHOST"
    fi
    log=${log//\"/}
    log=${log//'${APACHE_LOG_DIR}'//var/log/apache2}
    case $log in
        "") [ -d /var/log/apache2 ] || { [ -d /var/log/httpd ] && log=/var/log/httpd/error_log; } ;;
        \|* | syslog*) log="" ;;  # piped or sent to syslog: nothing to follow
        /*) ;;
        *) log="$root/$log" ;;    # relative to ServerRoot
    esac
    [ -z "$log" ] || readlink -f "$log" || echo "$log"
}
WATCH_LOG=$(apache_errorlog || true)
if [ -n "$WATCH_LOG" ] && [ "$WATCH_LOG" != /var/log/apache2/error.log ]; then
    install -d "$UNITS/proxyguard-watcher.service.d"
    printf '[Service]\nExecStart=\nExecStart=/bin/sh -c '\''exec tail -n 0 -F "%s" | python3 -u %s/proxyguard-watcher.py'\''\n' \
        "$WATCH_LOG" "$SBIN" >"$UNITS/proxyguard-watcher.service.d/00-errorlog.conf"
else
    rm -f "$UNITS/proxyguard-watcher.service.d/00-errorlog.conf"
fi
WATCH_LOG=${WATCH_LOG:-/var/log/apache2/error.log}

echo "==> Creating /var/log/eduvpn (2750 root:adm: the logs hold personal data)"
# setgid: files created in it (by the daemon, rsyslog) belong to group adm too.
install -d -m 2750 -o root -g adm /var/log/eduvpn

if [ -d /etc/logrotate.d ]; then
    echo "==> Installing logrotate policy"
    install -m 0644 "$SRC/examples/logrotate-eduvpn" /etc/logrotate.d/eduvpn-logger
else
    warn "logrotate not installed: /var/log/eduvpn will not be rotated (install it, re-run)"
fi

if [ -d /etc/rsyslog.d ] && grep -iqsE '^[[:space:]]*([$]PrivDropToUser|global\(.*privDropToUser)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf; then
    # Ubuntu: rsyslog runs as user syslog and cannot write into the root:adm
    # 2750 log directory; the snippet would only make the events vanish from
    # /var/log/syslog (its "& stop"). They stay in the journal and eduvpn.log.
    echo "==> rsyslog drops privileges here: no rsyslog file (events: journalctl -t eduvpn-logger)"
    if [ -f /etc/rsyslog.d/10-eduvpn.conf ]; then
        rm -f /etc/rsyslog.d/10-eduvpn.conf
        systemctl restart rsyslog 2>/dev/null || warn "could not restart rsyslog"
    fi
elif [ -d /etc/rsyslog.d ]; then
    echo "==> Installing rsyslog snippet"
    # Restart the system logger only when the snippet actually changed.
    if ! same "$SRC/examples/rsyslog-10-eduvpn.conf" /etc/rsyslog.d/10-eduvpn.conf; then
        install -m 0644 "$SRC/examples/rsyslog-10-eduvpn.conf" /etc/rsyslog.d/10-eduvpn.conf
        systemctl restart rsyslog 2>/dev/null || warn "could not restart rsyslog"
    fi
else
    echo "==> rsyslog not installed: events still reach the journal (journalctl -t eduvpn-logger)"
fi

# --- eduVPN side ---------------------------------------------------------------

# Portal connection log, read from the effective configuration: "on|off <format>",
# format = kv (templates the logger parses fully), default (the portal's own,
# understood, no byte counters) or custom (not understood).
portal_log_state() {
    php -r '
        $c = require $argv[1];
        $l = (is_array($c) && isset($c["Log"]) && is_array($c["Log"])) ? $c["Log"] : [];
        $ct = (string) ($l["connectLogTemplate"] ?? "");
        $dt = (string) ($l["disconnectLogTemplate"] ?? "");
        $f = ($ct === "" && $dt === "") ? "default"
            : ((strpos($ct, "CONNECT ") === 0 && strpos($dt, "DISCONNECT ") === 0
                && strpos($ct, "{{CONNECTION_ID}}") !== false && strpos($dt, "{{CONNECTION_ID}}") !== false) ? "kv" : "custom");
        echo empty($l["syslogConnectionEvents"]) ? "off" : "on", " ", $f, "\n";
    ' "$1" 2>/dev/null || true
}
# Turn the connection log on in a copy of config.php (with the recommended
# templates, unless the administrator set some), check it with PHP, keep a backup,
# then replace the file in place (owner, mode and SELinux label kept). The portal
# reads it on its next request.
enable_portal_log() {
    local new="$PORTAL_CONF.eduvpn-logger.new"
    python3 - "$PORTAL_CONF" "$new" <<'PY' || { rm -f "$new"; return 1; }
import re
import sys

src, dst = sys.argv[1], sys.argv[2]
s = open(src, encoding="utf-8").read()
t = ("'connectLogTemplate' => 'CONNECT USER={{USER_ID}} PROFILE={{PROFILE_ID}} PROTO={{VPN_PROTO}} CONN={{CONNECTION_ID}} IP4={{IP_FOUR}} IP6={{IP_SIX}}',",
     "'disconnectLogTemplate' => 'DISCONNECT USER={{USER_ID}} PROFILE={{PROFILE_ID}} PROTO={{VPN_PROTO}} CONN={{CONNECTION_ID}} BYTES_IN={{BYTES_IN}} BYTES_OUT={{BYTES_OUT}}',")
templates = () if re.search(r"^[ \t]*'(dis)?connectLogTemplate'\s*=>", s, re.M) else t
flag = re.compile(r"^([ \t]*'syslogConnectionEvents'\s*=>\s*)(false|0)\b", re.M)
log = re.search(r"^([ \t]*)'Log'\s*=>\s*\[[ \t]*\r?$", s, re.M)
if log:
    ind = log.group(1) + "    "
    add = ([] if flag.search(s) else ["'syslogConnectionEvents' => true,"]) + list(templates)
    s = flag.sub(r"\1true", s, count=1)
    at = s.index("\n", log.start()) + 1
    s = s[:at] + "".join(f"{ind}{a}\n" for a in add) + s[at:]
else:
    ret = re.search(r"^[ \t]*return\s*\[[ \t]*\r?$", s, re.M)
    if not ret:
        sys.exit("no 'return [' line")
    at = s.index("\n", ret.start()) + 1
    body = ["'syslogConnectionEvents' => true,"] + list(templates)
    s = s[:at] + "    'Log' => [\n" + "".join(f"        {a}\n" for a in body) + "    ],\n" + s[at:]
open(dst, "w", encoding="utf-8").write(s)
PY
    if ! php -l "$new" >/dev/null 2>&1 || [ "$(portal_log_state "$new" | cut -d' ' -f1)" != on ]; then
        rm -f "$new"
        return 1
    fi
    cp -p "$PORTAL_CONF" "$PORTAL_CONF.eduvpn-logger.bak"
    cat "$new" >"$PORTAL_CONF"
    rm -f "$new"
}
if [ ! -f "$PORTAL_CONF" ]; then
    warn "no $PORTAL_CONF: is this the eduVPN portal? (portal and WireGuard must be on this host)"
    NOTES+=("Install the logger on the host running vpn-user-portal and WireGuard (README: Requirements).")
elif ! command -v php >/dev/null 2>&1; then
    warn "php not found: cannot check the portal's connection log"
    NOTES+=("Check that the portal logs connections (README: Manual setup).")
else
    STATE=$(portal_log_state "$PORTAL_CONF")
    case $STATE in
        "on kv") echo "==> Portal connection log: on" ;;
        "on default") echo "==> Portal connection log: on (default format: disconnects carry no byte counters, see README)" ;;
        "on custom")
            warn "the portal's connect/disconnect templates are custom: they must start with CONNECT/DISCONNECT and keep CONN={{CONNECTION_ID}}"
            NOTES+=("Check the portal's log templates (README: Manual setup).") ;;
        off*)
            if enable_portal_log; then
                echo "==> Portal connection log turned on in $PORTAL_CONF (backup: $PORTAL_CONF.eduvpn-logger.bak)"
            else
                warn "could not turn on the portal's connection log in $PORTAL_CONF (left unchanged)"
                NOTES+=("Turn on the portal's connection log by hand (README: Manual setup).")
            fi ;;
        *)
            warn "cannot read $PORTAL_CONF with php"
            NOTES+=("Check that the portal logs connections (README: Manual setup).") ;;
    esac
fi

# ProxyGuard: Apache logs a tunnel start (client address) only with the proxy
# module at trace1 for /proxyguard/. A conf file of its own, not an edit of the
# eduVPN VirtualHost; skipped if the administrator already traces it.
if [ -n "$PG_VHOST" ]; then
    if [ -d /etc/apache2/conf-available ]; then
        PG_CONF=/etc/apache2/conf-available/eduvpn-logger-proxyguard.conf APACHECTL=apache2ctl APACHE_UNIT=apache2
    else
        PG_CONF=/etc/httpd/conf.d/eduvpn-logger-proxyguard.conf APACHECTL=apachectl APACHE_UNIT=httpd
    fi
    PG_NEW=$(mktemp)
    cat >"$PG_NEW" <<'APACHE'
# Installed by eduvpn-logger's install.sh. When a ProxyGuard tunnel opens, Apache
# logs one line with the client's address (AH10212) to the VirtualHost's ErrorLog;
# proxyguard-watcher turns it into a tunnel-start event.
<IfModule proxy_module>
    <LocationMatch "^/proxyguard/">
        LogLevel warn proxy:trace1
    </LocationMatch>
</IfModule>
APACHE
    if grep -RlsE '^[^#]*proxy:trace[1-8]' /etc/apache2/sites-enabled /etc/apache2/conf-enabled /etc/httpd/conf.d 2>/dev/null \
        | grep -qv eduvpn-logger-proxyguard; then
        echo "==> ProxyGuard: Apache already traces tunnel starts"
    elif ! same "$PG_NEW" "$PG_CONF"; then
        install -m 0644 "$PG_NEW" "$PG_CONF"
        [ "$APACHE_UNIT" = apache2 ] && a2enconf -q eduvpn-logger-proxyguard >/dev/null
        if $APACHECTL configtest >/dev/null 2>&1; then
            systemctl try-reload-or-restart "$APACHE_UNIT.service"
            echo "==> ProxyGuard: Apache traces tunnel starts ($PG_CONF; $APACHE_UNIT reloaded)"
        else
            [ "$APACHE_UNIT" = apache2 ] && a2disconf -q eduvpn-logger-proxyguard
            rm -f "$PG_CONF"
            warn "Apache rejected $PG_CONF (configtest failed): removed"
            NOTES+=("Make Apache trace /proxyguard/ by hand (README: Manual setup).")
        fi
    fi
    rm -f "$PG_NEW"
    echo "==> proxyguard-watcher follows $WATCH_LOG"
fi

# GeoIP (optional): MaxMind credentials from the environment, the only thing the
# installer cannot work out by itself.
if [ -n "${GEOIP_ACCOUNT_ID:-}" ] && [ -n "${GEOIP_LICENSE_KEY:-}" ]; then
    if command -v geoipupdate >/dev/null 2>&1; then
        # Debian's package ships placeholders (AccountID 0): not an account.
        if grep -qsE '^AccountID[[:space:]]+[1-9]' /etc/GeoIP.conf; then
            echo "==> GeoIP: keeping the account already in /etc/GeoIP.conf (edit it to change account)"
            grep -qsE '^EditionIDs.*GeoLite2-City' /etc/GeoIP.conf || warn "add GeoLite2-City to EditionIDs in /etc/GeoIP.conf"
        else
            echo "==> GeoIP: /etc/GeoIP.conf (MaxMind account, GeoLite2-City)"
            # A new file: umask does not apply to an existing (0644) one, and the
            # license key is a secret.
            [ ! -f /etc/GeoIP.conf ] || mv /etc/GeoIP.conf /etc/GeoIP.conf.eduvpn-logger.bak
            (umask 077; printf 'AccountID %s\nLicenseKey %s\nEditionIDs GeoLite2-City\n' "$GEOIP_ACCOUNT_ID" "$GEOIP_LICENSE_KEY" >/etc/GeoIP.conf)
        fi
        geoipupdate || warn "geoipupdate failed: check the MaxMind account ID and license key"
    else
        warn "geoipupdate not available on this system: GeoIP not configured"
        NOTES+=("Install geoipupdate (README: GeoIP), then re-run install.sh with the GEOIP_ variables.")
    fi
fi
# The GeoLite license requires each new database to be in use within 30 days.
# Debian and Ubuntu's geoipupdate brings a weekly timer; elsewhere (Fedora,
# MaxMind's own package) add one once an account is set up.
GEO_TIMER=0
GEO_BIN=$(command -v geoipupdate || true)
if [ -n "$GEO_BIN" ] && grep -qsE '^AccountID[[:space:]]+[1-9]' /etc/GeoIP.conf \
    && ! systemctl cat geoipupdate.timer >/dev/null 2>&1 \
    && ! grep -qs geoipupdate /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.weekly/* /var/spool/cron/root /var/spool/cron/crontabs/root; then
    echo "==> GeoIP: weekly update (eduvpn-logger-geoipupdate.timer)"
    # The binary just used, by absolute path (systemd's own search path may differ).
    sed "s|^ExecStart=.*|ExecStart=$GEO_BIN|" "$SRC/systemd/eduvpn-logger-geoipupdate.service" >"$UNITS/eduvpn-logger-geoipupdate.service"
    install -m 0644 "$SRC/systemd/eduvpn-logger-geoipupdate.timer" "$UNITS/eduvpn-logger-geoipupdate.timer"
    GEO_TIMER=1
fi

systemctl daemon-reload
if [ "$GEO_TIMER" -eq 1 ] && ! systemctl enable --now eduvpn-logger-geoipupdate.timer; then
    warn "could not start eduvpn-logger-geoipupdate.timer"
    NOTES+=("Schedule geoipupdate weekly: MaxMind's license requires current data (README: GeoIP).")
fi
if [ "$UPGRADE" -eq 1 ]; then
    # Upgrade: restart what is running (the old code must not keep running), but
    # never re-enable a service the administrator stopped or disabled.
    echo "==> Restarting the running services"
    systemctl try-restart eduvpn-logger.service proxyguard-watcher.service
    if [ -n "$PG_VHOST" ] && ! systemctl is-enabled --quiet proxyguard-watcher.service; then
        NOTES+=("ProxyGuard is in use but proxyguard-watcher is disabled: sudo systemctl enable --now proxyguard-watcher.service")
    fi
else
    echo "==> Enabling and starting the services"
    systemctl enable --now eduvpn-logger.service
    if [ -n "$PG_VHOST" ]; then
        systemctl enable --now proxyguard-watcher.service
    fi
fi

# --- Check ---------------------------------------------------------------------
sleep 2
row() { printf '  %-14s %s\n' "$1" "$2"; }
echo
echo "==> Check"
row eduvpn-logger "$(systemctl is-active eduvpn-logger.service || true)"
if [ -f "$PORTAL_CONF" ] && command -v php >/dev/null 2>&1; then
    case $(portal_log_state "$PORTAL_CONF") in
        "on kv") row "portal log" "on" ;;
        "on default") row "portal log" "on (portal's default format: no byte counters)" ;;
        "on custom") row "portal log" "on (custom templates: check them)" ;;
        off*) row "portal log" "OFF" ;;
        *) row "portal log" "unreadable" ;;
    esac
fi
row "portal DB" "$(python3 - <<'PY' 2>/dev/null || echo "not readable"
import sqlite3
c = sqlite3.connect("file:/var/lib/vpn-user-portal/db.sqlite?mode=ro", uri=True)
n = c.execute("SELECT COUNT(*) FROM wg_peers").fetchone()[0]
print(f"ok ({n} WireGuard configurations)")
PY
)"
WG_IFS=$(wg show interfaces 2>/dev/null | tr -s ' ' ',' || true)
row WireGuard "${WG_IFS:-no interface up (yet)}"
if [ -n "$PG_VHOST" ]; then
    row ProxyGuard "watcher $(systemctl is-active proxyguard-watcher.service || true), following $WATCH_LOG"
else
    row ProxyGuard "not in use (no VirtualHost proxies /proxyguard/)"
fi
GEO=$(ls /usr/local/share/GeoIP/GeoLite2-City.mmdb /usr/share/GeoIP/GeoLite2-City.mmdb /var/lib/GeoIP/GeoLite2-City.mmdb 2>/dev/null | head -n 1 || true)
if [ -z "$GEO" ]; then
    row GeoIP "off (optional: GEOIP_ACCOUNT_ID=... GEOIP_LICENSE_KEY=... ./install.sh)"
elif ! python3 -c 'import maxminddb' 2>/dev/null; then
    row GeoIP "off: python3-maxminddb missing ($GEO)"
    NOTES+=("Install python3-maxminddb (Enterprise Linux: from EPEL), then: sudo systemctl restart eduvpn-logger.service")
else
    row GeoIP "on ($GEO)"
fi
systemctl is-active --quiet eduvpn-logger.service || NOTES+=("eduvpn-logger is not running: journalctl -u eduvpn-logger.service")

echo
if [ "${#NOTES[@]}" -eq 0 ]; then
    echo "==> Ready. Output: /var/log/eduvpn/eduvpn.log (also journalctl -t eduvpn-logger)"
else
    echo "==> Installed. Left to do:"
    printf '  - %s\n' "${NOTES[@]}"
fi
echo "Settings: sudo systemctl edit eduvpn-logger.service (drop-ins survive re-installs)."
