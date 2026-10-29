#!/usr/bin/env bash
# One-command installer for eduvpn-logger on an eduVPN 3 server (Debian, Ubuntu,
# Enterprise Linux, Fedora). Idempotent: safe to re-run, also to upgrade.
#
#   sudo ./install.sh
#   sudo GEOIP_ACCOUNT_ID=123456 ./install.sh    # with GeoIP (the license key is asked for)
#   sudo ./install.sh --uninstall
#
# Besides the logger it turns on, when missing, what it needs on the eduVPN side:
# the portal's connection log (config.php, backup kept) and, with ProxyGuard,
# Apache's trace of tunnel starts (a conf file of its own; Apache reloaded) and
# proxyguard-server's log of its tunnels (a drop-in; its restart is asked for).
set -euo pipefail

SBIN=/usr/local/sbin
UNITS=/etc/systemd/system
SRC="$(cd "$(dirname "$0")" && pwd)"
PORTAL_CONF=/etc/vpn-user-portal/config.php
NOTES=()  # what is left to the administrator, printed at the end

case ${1:-} in
    "" | --uninstall) ;;
    *) echo "Usage: sudo ./install.sh [--uninstall]" >&2; exit 2 ;;
esac
if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo ./install.sh" >&2
    exit 1
fi
if [ -d /etc/apache2/conf-available ]; then
    PG_CONF=/etc/apache2/conf-available/eduvpn-logger-proxyguard.conf APACHECTL=apache2ctl APACHE_UNIT=apache2
else
    PG_CONF=/etc/httpd/conf.d/eduvpn-logger-proxyguard.conf APACHECTL=apachectl APACHE_UNIT=httpd
fi
PGS=proxyguard-server.service
PGS_DROPIN=$UNITS/$PGS.d/eduvpn-logger.conf
warn() { echo "WARN: $*" >&2; }
same() { [ -f "$2" ] && [ "$(cat "$1")" = "$(cat "$2")" ]; }  # no cmp: diffutils may be missing
# A file administrators may adapt (log retention, forwarding to a SIEM): installed
# when missing or still as an earlier release shipped it (sha256 listed), kept
# otherwise. Succeeds only when it was (re)installed.
install_conf() {  # src dst [sha256 of earlier shipped versions...]
    local src=$1 dst=$2 sum
    shift 2
    same "$src" "$dst" && return 1
    if [ -f "$dst" ]; then
        sum=$(sha256sum "$dst" | cut -d' ' -f1)
        case " $* " in
            *" $sum "*) ;;
            *) warn "kept $dst: changed locally (the new version is $src)"; return 1 ;;
        esac
    fi
    install -m 0644 "$src" "$dst"
}

if [ "${1:-}" = --uninstall ]; then
    echo "==> Removing eduvpn-logger"
    # One at a time: a unit that is not there (the GeoIP timer often) must not
    # keep the others running.
    for u in eduvpn-logger.service proxyguard-watcher.service eduvpn-logger-geoipupdate.timer; do
        systemctl disable --now "$u" >/dev/null 2>&1 || true
    done
    rm -rf "$SBIN/eduvpn-logger.py" "$SBIN/proxyguard-watcher.py" "$UNITS"/eduvpn-logger.service* \
        "$UNITS"/proxyguard-watcher.service* "$UNITS"/eduvpn-logger-geoipupdate.* \
        /etc/logrotate.d/eduvpn-logger /var/lib/eduvpn-logger
    if same "$SRC/examples/rsyslog-10-eduvpn.conf" /etc/rsyslog.d/10-eduvpn.conf; then
        rm -f /etc/rsyslog.d/10-eduvpn.conf
        systemctl restart rsyslog 2>/dev/null || warn "could not restart rsyslog"
    elif [ -f /etc/rsyslog.d/10-eduvpn.conf ]; then
        warn "kept /etc/rsyslog.d/10-eduvpn.conf: changed locally"
    fi
    if [ -f "$PG_CONF" ]; then
        if [ "$APACHE_UNIT" = apache2 ]; then a2disconf -q eduvpn-logger-proxyguard >/dev/null 2>&1 || true; fi
        rm -f "$PG_CONF"
        if $APACHECTL configtest >/dev/null 2>&1; then systemctl try-reload-or-restart "$APACHE_UNIT.service" || true; fi
    fi
    PGS_LEFT=0
    if [ -f "$PGS_DROPIN" ]; then
        rm -f "$PGS_DROPIN"
        rmdir --ignore-fail-on-non-empty "$UNITS/$PGS.d"
        PGS_LEFT=1
    fi
    systemctl daemon-reload
    echo "==> Removed. Left in place: the logs in /var/log/eduvpn (personal data: delete them as your"
    echo "    retention policy says), the portal's connection log (config.php as it was before install.sh:"
    echo "    $PORTAL_CONF.eduvpn-logger.bak, if it turned the log on), /etc/GeoIP.conf, the packages."
    if [ "$PGS_LEFT" = 1 ]; then
        echo "    proxyguard-server logs its tunnels until it next restarts (restarting it drops the open"
        echo "    ProxyGuard tunnels: sudo systemctl restart proxyguard-server)."
    fi
    exit 0
fi

echo "==> Installing dependencies"
# wireguard-tools, python3 and logrotate (the log holds personal data: its
# retention must be enforced) are required. The GeoIP packages are optional and
# installed one at a time (geoipupdate is in Debian *contrib*, python3-maxminddb
# may need EPEL): one missing optional package must not abort the others. Only
# missing packages are installed: installing the logger must not upgrade a live
# server's python3 or wireguard-tools as a side effect (`dnf install` would).
if command -v apt-get >/dev/null 2>&1; then
    # Never a prompt (there may be no terminal): a configuration file already
    # there, such as a hand-written /etc/GeoIP.conf, is kept.
    export DEBIAN_FRONTEND=noninteractive
    PKG="apt-get install -y --no-upgrade -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
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
    # geoipupdate only with a MaxMind account to use it with (see GeoIP below).
    for p in python3-maxminddb ${GEOIP_ACCOUNT_ID:+geoipupdate}; do
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

# The VirtualHost that proxies ProxyGuard (eduVPN's own), if any: /proxyguard/
# as eduVPN documents it, or any path upgraded to ProxyGuard's protocol (proxyUrl).
PG_RE='^[^#]*ProxyPass[^#]*(/proxyguard/|upgrade=UoTLV)'
PG_VHOST=$(grep -lsE "$PG_RE" /etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf 2>/dev/null | head -n 1 || true)

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
            if [[ $line =~ $PG_RE ]]; then pg=1; fi
            if [[ $line =~ ^[[:space:]]*[\<]/VirtualHost ]] && [ "$pg" = 1 ] && [ -n "$e" ]; then log=$e; break; fi
        done <"$PG_VHOST"
    fi
    log=${log//\"/}
    log=${log//'${APACHE_LOG_DIR}'//var/log/apache2}
    case $log in
        "") [ -d /var/log/apache2 ] || { [ -d /var/log/httpd ] && log=/var/log/httpd/error_log; } ;;
        \|* | syslog*) echo "$log"; return ;;  # piped or sent to syslog: nothing to follow
        /*) ;;
        *) log="$root/$log" ;;    # relative to ServerRoot
    esac
    [ -z "$log" ] || readlink -f "$log" || echo "$log"
}
WATCH_LOG=$(apache_errorlog || true)
case $WATCH_LOG in
    \|* | syslog*)
        warn "the ProxyGuard VirtualHost logs its errors to \"$WATCH_LOG\": proxyguard-watcher needs a file"
        NOTES+=("Have proxyguard-watcher read the ProxyGuard VirtualHost's errors from a file (README: Manual setup).")
        WATCH_LOG="" ;;
esac
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
    # Its retention (rotate 180) is meant to be adapted: an upgrade keeps it.
    install_conf "$SRC/examples/logrotate-eduvpn" /etc/logrotate.d/eduvpn-logger \
        7a0efd7268fcc75da2c832b2915360b68db6a2373cabc5eadc401a6d850d81f3 || true
else
    warn "logrotate not installed: /var/log/eduvpn will not be rotated (install it, re-run)"
fi

if [ -d /etc/rsyslog.d ] && grep -iqsE '^[[:space:]]*([$]PrivDropToUser|global\(.*privDropToUser)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf; then
    # Ubuntu: rsyslog runs as user syslog and cannot write into the root:adm
    # 2750 log directory; the snippet would only make the events vanish from
    # /var/log/syslog (its "& stop"). They stay in the journal and eduvpn.log.
    echo "==> rsyslog drops privileges here: no rsyslog file (events: journalctl -t eduvpn-logger)"
    if same "$SRC/examples/rsyslog-10-eduvpn.conf" /etc/rsyslog.d/10-eduvpn.conf; then  # ours, as shipped
        rm -f /etc/rsyslog.d/10-eduvpn.conf
        systemctl restart rsyslog 2>/dev/null || warn "could not restart rsyslog"
    fi
elif [ -d /etc/rsyslog.d ]; then
    echo "==> Installing rsyslog snippet"
    # Restart the system logger only when the snippet actually changed; one adapted
    # locally (e.g. forwarding to a SIEM) is kept.
    if install_conf "$SRC/examples/rsyslog-10-eduvpn.conf" /etc/rsyslog.d/10-eduvpn.conf; then
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
                && strpos($ct, " CONN={{CONNECTION_ID}}") !== false && strpos($dt, " CONN={{CONNECTION_ID}}") !== false) ? "kv" : "custom");
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
import os
import re
import sys

os.umask(0o077)  # the copy is root's only: config.php may hold passwords (database, LDAP)
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
# module at trace1 for ProxyGuard's requests. A conf file of its own, not an edit
# of the eduVPN VirtualHost; the trace is skipped if the administrator already has
# one. Exact sources: proxyguard-server 2.1+ logs, for each tunnel, Apache's
# connection and the source port WireGuard sees (-logip, with a drop-in of its own),
# and Apache's error log format adds the port of that connection to the start.
# Older ProxyGuard logs nothing per tunnel: its tunnels are matched by time.
PG_EXACT=""  # why sources are matched by time (Check); empty: by port
PGS_NEW=""   # the drop-in's [Service] lines, when one is needed
PGS_VER=""
if [ -n "$PG_VHOST" ]; then
    PGS_BIN=$(command -v proxyguard-server || true)
    if [ -z "$PGS_BIN" ]; then
        PG_EXACT="proxyguard-server is not on this host"
    else
        PGS_VER=$(timeout 10 "$PGS_BIN" -version 2>&1 | sed -n 's/^Version: //p' || true)
        if [[ $(timeout 10 "$PGS_BIN" -help 2>&1 || true) != *-logip* ]]; then
            PG_EXACT="proxyguard-server ${PGS_VER:-?} does not log its tunnels (2.1 or later does)"
            NOTES+=("Upgrade proxyguard-server to 2.1 or later from the eduVPN repository (apt install --only-upgrade proxyguard-server, or dnf upgrade proxyguard-server), then re-run install.sh: until then ProxyGuard sources are matched by time (README: Limitations).")
        else
            PGS_UNIT=$(systemctl show -p FragmentPath --value "$PGS" 2>/dev/null || true)
            PGS_EXEC=$(grep -sE '^ExecStart=' "$PGS_UNIT" | tail -n 1 || true)
            # EnvironmentFile= wins over Environment=: an OTHER_ARGS set there stays.
            PGS_ENVF=$(systemctl show -p EnvironmentFiles --value "$PGS" 2>/dev/null | sed 's/ (ignore_errors=[a-z]*)//g' || true)
            # shellcheck disable=SC2086  # a list of files; /dev/null: never stdin
            PGS_OTHER=$(grep -shE '^[[:space:]]*OTHER_ARGS=' /dev/null $PGS_ENVF | tail -n 1 || true)
            if [ -z "$PGS_EXEC" ]; then
                PG_EXACT="no ExecStart= in proxyguard-server's unit ($PGS_UNIT)"
            elif [[ $(systemctl show -p ExecStart --value "$PGS" 2>/dev/null || true) == *' -logip '* ]]; then
                :  # the administrator's own ExecStart (README: Manual setup) has it
            elif [[ $PGS_EXEC != *OTHER_ARGS* ]]; then
                # ProxyGuard 2.1.0's unit passes no other arguments: overriding its
                # ExecStart would break the service if a package update changed it.
                PG_EXACT="proxyguard-server ${PGS_VER:-?}'s unit takes no other options (2.1.1 does): re-run install.sh after upgrading"
            elif [ -z "$PGS_OTHER" ]; then
                PGS_NEW="Environment=OTHER_ARGS=-logip"
            elif [[ $PGS_OTHER != *-logip* ]]; then
                PG_EXACT="OTHER_ARGS is set without -logip in $PGS_ENVF"
                NOTES+=("Add -logip to OTHER_ARGS in $PGS_ENVF, then restart proxyguard-server (open ProxyGuard tunnels drop and reconnect): until then ProxyGuard sources are matched by time.")
            fi  # else: the administrator set OTHER_ARGS=-logip
        fi
    fi

    PG_NEW=$(mktemp)
    echo "# Installed by eduvpn-logger's install.sh, removed by install.sh --uninstall." >"$PG_NEW"
    # A trace of the administrator's own counts only in the VirtualHost that proxies
    # ProxyGuard: one elsewhere (another site) may not cover its requests, and ours,
    # limited to ProxyGuard's requests, is harmless next to one that does.
    if grep -qsE '^[^#]*proxy:trace[1-8]' "$PG_VHOST"; then
        echo "==> ProxyGuard: Apache already traces tunnel starts"
    else
        cat >>"$PG_NEW" <<'APACHE'
# When a ProxyGuard tunnel opens, Apache logs one line with the client's address
# (AH10212) to the VirtualHost's ErrorLog; proxyguard-watcher turns it into a
# tunnel-start event. Only ProxyGuard's own requests (whatever their path) and
# only mod_proxy's level are raised.
<IfModule proxy_module>
    <If "%{HTTP:Upgrade} =~ /^UoTLV/i">
        LogLevel proxy:trace1
    </If>
</IfModule>
APACHE
    fi
    # An ErrorLogFormat of the administrator's own (server-wide, or a VirtualHost's,
    # in any .conf of the configuration but the disabled *-available ones; Debian's
    # *-enabled links followed) stays as it is: the port has to be added by hand.
    ELF_OWN=$(grep -RlsE --include='*.conf' --exclude-dir='*-available' '^[[:space:]]*ErrorLogFormat[[:space:]]' \
        /etc/apache2 /etc/httpd 2>/dev/null | grep -v eduvpn-logger-proxyguard | head -n 1 || true)
    if [ -z "$PG_EXACT" ] && [ -n "$ELF_OWN" ] && ! grep -qs proxy-source-port "$ELF_OWN"; then
        PG_EXACT="the ErrorLogFormat in $ELF_OWN has no [pgport]"
        NOTES+=("Add [pgport\\ %8{proxy-source-port}n] right after [client\\ %a] to the ErrorLogFormat in $ELF_OWN, for exact ProxyGuard sources (README: Manual setup).")
    elif [ -z "$PG_EXACT" ] && [ -z "$ELF_OWN" ]; then
        # Since 2.4.60 Apache logs the kernel's thread id by default (Linux): same here.
        TID='%T'
        AV=$($APACHECTL -v 2>/dev/null | sed -n 's#.*Apache/\([0-9.]*\).*#\1#p' || true)
        [ "$(printf '%s\n' 2.4.60 "$AV" | sort -V | head -n 1)" != 2.4.60 ] || TID='%{g}T'
        printf '%s\n' "# Apache's default error log format plus, on trace lines only (%8: the tunnel" \
            "# start), the local port of Apache's connection to proxyguard-server, which" \
            "# proxyguard-server -logip ties to the source port WireGuard sees." \
            'ErrorLogFormat "[%{u}t] [%-m:%l] [pid\ %P% :tid\ '"$TID"'% ] %7F: %E: [client\ %a] [pgport\ %8{proxy-source-port}n] %M% ,\ referer:\ %{Referer}i"' \
            >>"$PG_NEW"
    fi
    if [ "$(wc -l <"$PG_NEW")" -le 1 ]; then
        # Nothing to add (a trace of the administrator's own, sources by time).
        if [ -f "$PG_CONF" ]; then
            if [ "$APACHE_UNIT" = apache2 ]; then a2disconf -q eduvpn-logger-proxyguard >/dev/null 2>&1 || true; fi
            rm -f "$PG_CONF"
            if $APACHECTL configtest >/dev/null 2>&1; then systemctl try-reload-or-restart "$APACHE_UNIT.service" || true; fi
        fi
    elif ! same "$PG_NEW" "$PG_CONF"; then
        PG_OLD=$(mktemp)
        [ ! -f "$PG_CONF" ] || cat "$PG_CONF" >"$PG_OLD"
        install -m 0644 "$PG_NEW" "$PG_CONF"
        [ "$APACHE_UNIT" = apache2 ] && a2enconf -q eduvpn-logger-proxyguard >/dev/null
        if $APACHECTL configtest >/dev/null 2>&1; then
            systemctl try-reload-or-restart "$APACHE_UNIT.service"
            echo "==> ProxyGuard: Apache logs tunnel starts ($PG_CONF; $APACHE_UNIT reloaded)"
        elif [ -s "$PG_OLD" ]; then
            cat "$PG_OLD" >"$PG_CONF"  # an upgrade: the version Apache accepted stays
            warn "Apache rejected the new $PG_CONF (configtest failed): the previous one is kept"
            PG_EXACT="Apache rejected the new $PG_CONF"
        else
            [ "$APACHE_UNIT" = apache2 ] && a2disconf -q eduvpn-logger-proxyguard
            rm -f "$PG_CONF"
            warn "Apache rejected $PG_CONF (configtest failed): removed"
            NOTES+=("Make Apache trace ProxyGuard's requests by hand (README: Manual setup).")
            PG_EXACT="Apache rejected $PG_CONF"
        fi
        rm -f "$PG_OLD"
    fi
    rm -f "$PG_NEW"

    # The drop-in only while proxyguard-server can use it: an unknown -logip would
    # keep it from starting (every ProxyGuard client cut off).
    if [ -z "$PG_EXACT" ] && [ -n "$PGS_NEW" ]; then
        PGS_TMP=$(mktemp)
        printf '%s\n' "# Installed by eduvpn-logger's install.sh, removed by install.sh --uninstall:" \
            "# proxyguard-server logs each tunnel it opens (-logip), for exact ProxyGuard sources." \
            "[Service]" "$PGS_NEW" >"$PGS_TMP"
        if ! same "$PGS_TMP" "$PGS_DROPIN"; then
            install -d "$UNITS/$PGS.d"
            install -m 0644 "$PGS_TMP" "$PGS_DROPIN"
            echo "==> ProxyGuard: proxyguard-server logs its tunnels ($PGS_DROPIN)"
        fi
        rm -f "$PGS_TMP"
    elif [ -f "$PGS_DROPIN" ]; then
        rm -f "$PGS_DROPIN"
        rmdir --ignore-fail-on-non-empty "$UNITS/$PGS.d"
        PGS_DROPPED=1  # one that failed to start with it starts again (after daemon-reload)
    fi
    echo "==> proxyguard-watcher follows $WATCH_LOG"
fi

# GeoIP (optional): the MaxMind account, the only thing the installer cannot work
# out by itself. The license key is asked for when only the account is given, so
# it stays out of the shell history.
# geoipupdate is not packaged on Enterprise Linux, and is in Debian's contrib
# section, often not enabled: MaxMind's own package then, from its latest release
# and checked against the release's checksums.
maxmind_geoipupdate() {
    local arch ext=rpm pkg rc
    case $(uname -m) in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) return 1 ;; esac
    [ -n "$PKG" ] || return 1
    command -v apt-get >/dev/null 2>&1 && ext=deb
    pkg=$(python3 - "$arch" "$ext" <<'PY'
import hashlib, json, os, sys, tempfile, urllib.request

arch, ext = sys.argv[1:]
try:
    get = lambda url: urllib.request.urlopen(url, timeout=60).read()
    rel = json.loads(get("https://api.github.com/repos/maxmind/geoipupdate/releases/latest"))
    urls = {a["name"]: a["browser_download_url"] for a in rel["assets"]}
    ver = rel["tag_name"].lstrip("v")
    name = f"geoipupdate_{ver}_linux_{arch}.{ext}"
    data = get(urls[name])
    lines = get(urls[f"geoipupdate_{ver}_checksums.txt"]).decode().splitlines()
    sums = {p[1]: p[0] for p in (line.split() for line in lines) if len(p) == 2}
    if sums.get(name) != hashlib.sha256(data).hexdigest():
        raise ValueError(f"{name}: checksum mismatch")
except Exception as e:
    sys.exit(f"cannot get geoipupdate from github.com/maxmind/geoipupdate: {e}")
path = os.path.join(tempfile.mkdtemp(), name)
with open(path, "wb") as f:
    f.write(data)
print(path)
PY
    ) || return 1
    echo "==> GeoIP: installing MaxMind's ${pkg##*/} (github.com/maxmind/geoipupdate)"
    $PKG "$pkg" && rc=0 || rc=1
    rm -rf "${pkg%/*}"
    return "$rc"
}
if [ -n "${GEOIP_ACCOUNT_ID:-}" ] && [ -z "${GEOIP_LICENSE_KEY:-}" ]; then
    if [ -t 0 ]; then
        read -rsp "MaxMind license key for account $GEOIP_ACCOUNT_ID: " GEOIP_LICENSE_KEY
        echo
    else
        warn "GEOIP_ACCOUNT_ID without GEOIP_LICENSE_KEY, and no terminal to ask for it: GeoIP not configured"
        NOTES+=("Re-run install.sh with GEOIP_ACCOUNT_ID from a terminal, or with GEOIP_LICENSE_KEY too (README: GeoIP).")
    fi
fi
GEO_FETCH=0
if [ -n "${GEOIP_ACCOUNT_ID:-}" ] && [ -n "${GEOIP_LICENSE_KEY:-}" ]; then
    command -v geoipupdate >/dev/null 2>&1 || maxmind_geoipupdate || true
    if command -v geoipupdate >/dev/null 2>&1; then
        # Debian's package ships placeholders (AccountID 0): not an account.
        if grep -qsE '^AccountID[[:space:]]+[1-9]' /etc/GeoIP.conf; then
            # An account set up before (by install.sh or by hand): the one given now
            # replaces it (a renewed license key, say); other settings and editions
            # in the file stay, GeoLite2-City is added if missing.
            echo "==> GeoIP: /etc/GeoIP.conf updated (MaxMind account, GeoLite2-City)"
            chmod 600 /etc/GeoIP.conf  # before the new key is in it
            # The key in the environment, not on the command line: any local user
            # can read a process's arguments (ps), only root its environment.
            GEOIP_LICENSE_KEY="$GEOIP_LICENSE_KEY" python3 - "$GEOIP_ACCOUNT_ID" <<'PY'
import os
import re
import sys

p = "/etc/GeoIP.conf"
s = open(p, encoding="utf-8").read()
for key, value in (("AccountID", sys.argv[1]), ("LicenseKey", os.environ["GEOIP_LICENSE_KEY"])):
    s, n = re.subn(rf"(?m)^{key}\s.*$", lambda m: f"{key} {value}", s)
    s += "" if n else f"{key} {value}\n"
if not re.search(r"(?m)^EditionIDs\s.*\bGeoLite2-City\b", s):
    s, n = re.subn(r"(?m)^EditionIDs\s.*$", lambda m: m.group(0) + " GeoLite2-City", s)
    s += "" if n else "EditionIDs GeoLite2-City\n"
with open(p, "w", encoding="utf-8") as f:  # same file: owner kept
    f.write(s)
PY
        else
            echo "==> GeoIP: /etc/GeoIP.conf (MaxMind account, GeoLite2-City)"
            # A new file: umask does not apply to an existing (0644) one, and the
            # license key is a secret.
            [ ! -f /etc/GeoIP.conf ] || mv /etc/GeoIP.conf /etc/GeoIP.conf.eduvpn-logger.bak
            (umask 077; printf 'AccountID %s\nLicenseKey %s\nEditionIDs GeoLite2-City\n' "$GEOIP_ACCOUNT_ID" "$GEOIP_LICENSE_KEY" >/etc/GeoIP.conf)
        fi
        GEO_FETCH=1
    else
        warn "geoipupdate not available on this system: GeoIP not configured"
        NOTES+=("Install geoipupdate (README: GeoIP), then re-run install.sh with GEOIP_ACCOUNT_ID.")
    fi
fi
# Download now (also for an account set up by hand that has no database yet), not
# at the next weekly run.
GEO_DIRS="/usr/local/share/GeoIP /usr/share/GeoIP /var/lib/GeoIP"
geo_db() { for d in $GEO_DIRS; do [ ! -f "$d/GeoLite2-City.mmdb" ] || { echo "$d/GeoLite2-City.mmdb"; return; }; done; }
if command -v geoipupdate >/dev/null 2>&1 && grep -qsE '^AccountID[[:space:]]+[1-9]' /etc/GeoIP.conf \
    && { [ "$GEO_FETCH" = 1 ] || [ -z "$(geo_db)" ]; }; then
    echo "==> GeoIP: downloading GeoLite2-City (geoipupdate)"
    geoipupdate || warn "geoipupdate failed: check the MaxMind account ID and license key in /etc/GeoIP.conf"
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
if [ "${PGS_DROPPED:-0}" = 1 ] && systemctl is-failed --quiet "$PGS"; then
    systemctl restart "$PGS" || warn "could not restart proxyguard-server"
fi
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

# proxyguard-server takes -logip when it restarts, which drops the open ProxyGuard
# tunnels (the apps reconnect at once): asked for, never done unasked.
pgs_logip() {
    local pid
    pid=$(systemctl show -p MainPID --value "$PGS" 2>/dev/null || true)
    [ "${pid:-0}" != 0 ] && [[ " $(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null) " == *" -logip "* ]]
}
if [ -n "$PG_VHOST" ] && [ -z "$PG_EXACT" ] && systemctl is-active --quiet "$PGS" && ! pgs_logip; then
    ANSWER=n
    if [ -t 0 ]; then
        read -rp "Restart proxyguard-server now, so that it logs its tunnels? Open ProxyGuard (TCP) tunnels drop and the apps reconnect. [y/N] " ANSWER || ANSWER=n
    fi
    if [[ $ANSWER == [yY]* ]]; then
        systemctl restart "$PGS" || true
        sleep 2
        if ! systemctl is-active --quiet "$PGS"; then
            rm -f "$PGS_DROPIN"
            rmdir --ignore-fail-on-non-empty "$UNITS/$PGS.d"
            systemctl daemon-reload
            systemctl restart "$PGS" || true
            warn "proxyguard-server did not start with -logip: $PGS_DROPIN removed, started as before"
            PG_EXACT="proxyguard-server did not start with -logip"
        fi
    fi
    if [ -z "$PG_EXACT" ] && ! pgs_logip; then
        PG_EXACT="proxyguard-server not restarted yet"
        NOTES+=("Restart proxyguard-server when convenient, so that it logs its tunnels (open ProxyGuard tunnels drop and the apps reconnect): sudo systemctl restart proxyguard-server. Until then ProxyGuard sources are matched by time.")
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
# The portal DB is read only when it is SQLite: eduVPN can also use PostgreSQL or
# MariaDB. Only the driver is shown: the DSN may hold a password.
DB_KIND=""
if [ -f "$PORTAL_CONF" ] && command -v php >/dev/null 2>&1; then
    DB_KIND=$(php -r '$c = require $argv[1]; echo strtok((is_array($c) && isset($c["Db"]["dbDsn"])) ? (string) $c["Db"]["dbDsn"] : "", ":");' \
        "$PORTAL_CONF" 2>/dev/null || true)
fi
UNIT_ENV=$(systemctl show -p Environment --value eduvpn-logger.service 2>/dev/null || true)
DB_PATH=$(tr ' ' '\n' <<<"$UNIT_ENV" | sed -n 's/^EDUVPN_PORTAL_DB=//p' | tail -n 1 || true)
case $DB_KIND in
    "" | sqlite)
        row "portal DB" "$(python3 - "${DB_PATH:-/var/lib/vpn-user-portal/db.sqlite}" <<'PY' 2>/dev/null || echo "not readable"
import sqlite3, sys, urllib.parse
c = sqlite3.connect(f"file:{urllib.parse.quote(sys.argv[1])}?mode=ro", uri=True)
n = c.execute("SELECT COUNT(*) FROM wg_peers").fetchone()[0]
print(f"ok ({n} WireGuard configurations)")
PY
)" ;;
    *) row "portal DB" "$DB_KIND: not read (users come from the portal's events only, see README: Limitations)" ;;
esac
WG_IFS=$(wg show interfaces 2>/dev/null | tr -s ' ' ',' || true)
case $WG_IFS in
    "") WG_IFS="no interface up (yet)" ;;
    *,*) [[ $UNIT_ENV == *EDUVPN_WG_INTERFACES=* ]] \
        || WG_IFS="$WG_IFS (all eduVPN's? If not: EDUVPN_WG_INTERFACES, README: Configuration)" ;;
esac
row WireGuard "$WG_IFS"
if [ -n "$PG_VHOST" ]; then
    row ProxyGuard "watcher $(systemctl is-active proxyguard-watcher.service || true), following $WATCH_LOG"
    [ -f "$WATCH_LOG" ] || NOTES+=("proxyguard-watcher follows $WATCH_LOG, which does not exist: point it at the ProxyGuard VirtualHost's ErrorLog (README: Manual setup).")
    if [ -z "$PG_EXACT" ]; then
        row "PG sources" "exact, by port (proxyguard-server ${PGS_VER:-?} -logip)"
    else
        row "PG sources" "by time: $PG_EXACT"
    fi
else
    row ProxyGuard "not in use (no VirtualHost proxies it)"
fi
# The database the daemon uses: the one EDUVPN_GEOIP_DB names, else the first found.
GEO_SET=$(tr ' ' '\n' <<<"$UNIT_ENV" | sed -n 's/^EDUVPN_GEOIP_DB=//p' | tail -n 1 || true)
GEO=${GEO_SET:-$(geo_db)}
if [ -n "$GEO_SET" ] && [ ! -f "$GEO_SET" ]; then
    row GeoIP "off: EDUVPN_GEOIP_DB=$GEO_SET not found"
    NOTES+=("GeoIP: EDUVPN_GEOIP_DB names $GEO_SET, which does not exist (README: Configuration).")
elif [ -z "$GEO" ] && grep -qsE '^AccountID[[:space:]]+[1-9]' /etc/GeoIP.conf; then
    row GeoIP "off: no database downloaded yet"
    NOTES+=("GeoIP: GeoLite2-City could not be downloaded: check the account and license key in /etc/GeoIP.conf and the server's access to MaxMind, then re-run install.sh (README: GeoIP).")
elif [ -z "$GEO" ]; then
    row GeoIP "off (optional: sudo GEOIP_ACCOUNT_ID=<MaxMind account> ./install.sh)"
elif ! python3 -c 'import maxminddb' 2>/dev/null; then
    row GeoIP "off: python3-maxminddb missing ($GEO)"
    NOTES+=("Install python3-maxminddb (Enterprise Linux: from EPEL): the logger starts using it within an hour.")
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
