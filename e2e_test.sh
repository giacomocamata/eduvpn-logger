#!/usr/bin/env bash
# End-to-end test on a REAL Linux host with systemd: installs eduvpn-logger with
# install.sh and runs it as a hardened systemd service against
#   * real WireGuard tunnels (clients in network namespaces, one roaming),
#   * a ProxyGuard-like path: client -> UDP relay -> 127.0.0.1:51820, with the
#     START taken from Apache's error.log through proxyguard-watcher,
#   * real journald portal events (www-data), plus spoofed ones from a login user,
#   * a fake portal DB (wg_peers), restarts (journal cursor replay, bad cursor),
#     logrotate, and handshake-silence disconnects.
#
# DISPOSABLE machines only (VM, WSL, CI runner): it installs packages, systemd
# units, a test user and a portal DB. It refuses to run where an eduVPN portal
# DB already exists.
#
#   sudo EDUVPN_E2E_DISPOSABLE=1 bash e2e_test.sh
#
# Takes ~5 minutes (the silence-disconnect check must wait WireGuard's 180 s).
set -euo pipefail

die() { echo "e2e: $*" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || die "run as root"
[ "${EDUVPN_E2E_DISPOSABLE:-}" = 1 ] || die "set EDUVPN_E2E_DISPOSABLE=1 (disposable machines only)"
[ -e /var/lib/vpn-user-portal/db.sqlite ] && die "a portal DB exists: this looks like a real eduVPN server"
[ -d /run/systemd/system ] || die "systemd is not running"

SRC="$(cd "$(dirname "$0")" && pwd)"
LOG=/var/log/eduvpn/eduvpn.log
START_LOG=/var/log/apache2/proxyguard_start.log
APACHE_ERR=/var/log/apache2/error.log
DROPIN=/etc/systemd/system/eduvpn-logger.service.d/e2e.conf
WGS=e2ewg0
T0=$(date +%s)
WORK=$(mktemp -d)
chmod 700 "$WORK"

PASS=0
FAIL=0
ok() { echo "PASS  $*"; PASS=$((PASS + 1)); }
ko() { echo "FAIL  $*"; FAIL=$((FAIL + 1)); }
check() { local d=$1; shift; if "$@"; then ok "$d"; else ko "$d"; fi; }
wait_for() { local end=$((SECONDS + $1)); shift; until "$@"; do [ $SECONDS -ge $end ] && return 1; sleep 1; done; }
# Last line of event $1 for public key $2 (keys contain + / =: fixed-string match).
line() { grep -F " event=$1 " "$LOG" 2>/dev/null | grep -F " conn=$2 " | tail -n 1; }
has() { line "$1" "$2" | grep -qF -- "$3"; }
lacks() { ! line "$1" "$2" | grep -qF -- "$3"; }
count() { grep -F " event=$1 " "$LOG" 2>/dev/null | grep -cF " conn=$2 " || true; }
exists() { [ -n "$(line "$1" "$2")" ]; }
portal() { runuser -u www-data -- logger -t vpn-user-portal -- "$*"; }
daemon_log() { journalctl -u eduvpn-logger.service --since "@$T0" --no-pager -o cat; }
daemon_says() { daemon_log | grep -qF -- "$1"; }
mode_of() { stat -c '%a %U:%G' "$1"; }
install_quiet() { bash "$SRC/install.sh" >"$WORK/install$1.log" 2>&1 || { cat "$WORK/install$1.log"; return 1; }; }
apache_start_line() {
    echo "[$(date '+%a %b %d %H:%M:%S.%6N %Y')] [proxy:trace1] [pid 4242:tid 4243] proxy_util.c(5645): [client $1] AH10212: proxy: UoTLV/1: tunnel running (timeout 300.000000)" >>"$APACHE_ERR"
}

lo_rules() {
    ip rule "$1" pref 0 to 127.0.0.1 ipproto udp dport 51820 lookup local 2>/dev/null
    ip rule "$1" pref 0 to 127.0.0.1 ipproto udp sport 51820 lookup local 2>/dev/null
}

cleanup() {
    set +e
    lo_rules del
    pkill -f "socat UDP4-LISTEN:51821" 2>/dev/null
    ip netns del e2e-c1 2>/dev/null
    ip netns del e2e-c2 2>/dev/null
    ip link del "$WGS" 2>/dev/null
    rm -rf /var/lib/vpn-user-portal "$WORK" "$(dirname "$DROPIN")"
    userdel e2espoof 2>/dev/null
    systemctl disable --now eduvpn-logger.service proxyguard-watcher.service >/dev/null 2>&1
    systemctl daemon-reload
}
trap cleanup EXIT

echo "==> Packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq wireguard-tools apache2 socat sqlite3 iproute2 logrotate iputils-ping >/dev/null
id e2espoof >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin e2espoof   # regular (non-system) UID

echo "==> install.sh (twice: must be idempotent)"
check "install.sh first run" install_quiet 1
check "install.sh second run" install_quiet 2
check "eduvpn-logger enabled" systemctl is-enabled --quiet eduvpn-logger.service
check "/var/log/eduvpn is 0750 root:adm" test "$(mode_of /var/log/eduvpn)" = "750 root:adm"
check "systemd-analyze verify (both units)" systemd-analyze verify /etc/systemd/system/eduvpn-logger.service /etc/systemd/system/proxyguard-watcher.service

echo "==> Fixtures: keys, server interface, portal DB, test drop-in"
umask 077
for n in s 1 2 3 4 5 6; do wg genkey >"$WORK/k$n"; wg pubkey <"$WORK/k$n" >"$WORK/p$n"; done
umask 022
SP=$(cat "$WORK/ps"); P1=$(cat "$WORK/p1"); P2=$(cat "$WORK/p2"); P3=$(cat "$WORK/p3")
P4=$(cat "$WORK/p4"); P5=$(cat "$WORK/p5"); P6=$(cat "$WORK/p6")

ip link del "$WGS" 2>/dev/null || true
ip link add "$WGS" type wireguard
wg set "$WGS" private-key "$WORK/ks" listen-port 51820 \
    peer "$P1" allowed-ips 10.99.0.2/32 peer "$P2" allowed-ips 10.99.0.3/32
ip addr add 10.99.0.1/24 dev "$WGS"
ip link set "$WGS" up

mkdir -p /var/lib/vpn-user-portal
# WAL mode is the hard case for a read-only reader (it must create the -shm file):
# proves the unit's capability set is enough.
sqlite3 /var/lib/vpn-user-portal/db.sqlite <<SQL
PRAGMA journal_mode=WAL;
CREATE TABLE wg_peers (user_id TEXT, profile_id TEXT, node_number INTEGER, display_name TEXT,
  public_key TEXT, ip_four TEXT, ip_six TEXT, created_at TEXT, expires_at TEXT, auth_key TEXT);
INSERT INTO wg_peers VALUES ('alice','staff',0,'org.eduvpn.app.android','$P1','10.99.0.2','fd99::2','2026-01-01T00:00:00+00:00','2027-01-01T00:00:00+00:00',NULL);
INSERT INTO wg_peers VALUES ('bob','students',0,'org.eduvpn.app.linux','$P2','10.99.0.3','fd99::3','2026-01-01T00:00:00+00:00','2027-01-01T00:00:00+00:00',NULL);
SQL
chown -R www-data:www-data /var/lib/vpn-user-portal
chmod 0600 /var/lib/vpn-user-portal/db.sqlite

mkdir -p "$(dirname "$DROPIN")"
cat >"$DROPIN" <<'EOF'
[Service]
Environment=EDUVPN_WG_POLL_SEC=1
Environment=EDUVPN_CONNECT_GRACE_SEC=5
# below WireGuard's 180 s on purpose: must be raised (with a warning)
Environment=EDUVPN_DISCONNECT_AFTER_SEC=60
EOF
systemctl daemon-reload
systemctl restart eduvpn-logger.service
systemctl enable --now proxyguard-watcher.service >/dev/null 2>&1
sleep 2
check "eduvpn-logger active under hardening" systemctl is-active --quiet eduvpn-logger.service
check "proxyguard-watcher active" systemctl is-active --quiet proxyguard-watcher.service
check "DISCONNECT_AFTER_SEC<180 raised with a warning" wait_for 10 daemon_says "below WireGuard's 180 s"

netns_client() { # name veth-host veth-ns host-ip ns-ip key tunnel-ip endpoint
    ip netns del "$1" 2>/dev/null || true
    ip netns add "$1"
    ip link add "$2" type veth peer name "$3"
    ip link set "$3" netns "$1"
    ip addr add "$4/24" dev "$2"
    ip link set "$2" up
    ip -n "$1" link set lo up
    ip -n "$1" addr add "$5/24" dev "$3"
    ip -n "$1" link set "$3" up
    ip -n "$1" link add wgc type wireguard
    ip netns exec "$1" wg set wgc private-key "$6" peer "$SP" endpoint "$8" allowed-ips 10.99.0.1/32
    ip -n "$1" addr add "$7/32" dev wgc
    ip -n "$1" link set wgc up
    ip -n "$1" route add 10.99.0.1/32 dev wgc
}

echo "==> 1. eduVPN app over UDP: portal CONNECT first, then the handshake"
portal "CONNECT USER=alice PROFILE=staff PROTO=wireguard CONN=$P1 IP4=10.99.0.2 IP6=fd99::2"
netns_client e2e-c1 e2e-v1 e2e-v1c 172.31.250.1 172.31.250.2 "$WORK/k1" 10.99.0.2 172.31.250.1:51820
ip netns exec e2e-c1 ping -c 2 -W 2 10.99.0.1 >/dev/null || true
check "connect line for alice" wait_for 20 exists connect "$P1"
check "  user/profile from the portal" has connect "$P1" "user=alice profile=staff"
check "  device from the DB display_name" has connect "$P1" "device=android"
check "  real UDP source" has connect "$P1" 'src_ip="172.31.250.2"'
check "  transport=udp" has connect "$P1" "transport=udp"
check "  tunnel IP from the portal" has connect "$P1" 'tunnel_ip4="10.99.0.2"'
check "  not inferred (portal-backed)" lacks connect "$P1" "inferred=1"
check "  same event forwarded to syslog through the sandbox" bash -c "journalctl -t eduvpn-logger --since @$T0 --no-pager -o cat | grep -F ' conn=$P1 ' | grep -qF 'event=connect'"

echo "==> 2. Spoofed portal events from non-system UIDs are rejected"
runuser -u e2espoof -- logger -t vpn-user-portal -- "CONNECT USER=mallory PROFILE=admins PROTO=wireguard CONN=$P3 IP4=10.99.0.66 IP6=fd99::66"
runuser -u nobody -- logger -t vpn-user-portal -- "CONNECT USER=mallory2 PROFILE=admins PROTO=wireguard CONN=$P3 IP4=10.99.0.67 IP6=fd99::67"
check "rejection logged for the login user's UID" wait_for 15 daemon_says "untrusted _UID=$(id -u e2espoof)"
check "rejection logged for nobody" wait_for 5 daemon_says "untrusted _UID=$(id -u nobody)"
sleep 2
check "  no line for the spoofed users" bash -c "! grep -qE 'user=mallory' '$LOG'"

echo "==> 3. proxyguard-watcher: forged START via a request path is ignored"
echo "[$(date '+%a %b %d %H:%M:%S.%6N %Y')] [core:info] [pid 1:tid 2] [client 192.0.2.66:1234] AH00128: File does not exist: /var/www/html/[client 198.51.100.66:1] AH10212: proxy: UoTLV/1: tunnel running" >>"$APACHE_ERR"
sleep 3
check "forged START not promoted" bash -c "! grep -qE '198\.51\.100\.66|192\.0\.2\.66' '$START_LOG' 2>/dev/null"

echo "==> 4. TCP/ProxyGuard path: START from Apache, tunnel via 127.0.0.1, user from DB"
apache_start_line "203.0.113.50:44444"
check "real START promoted by the watcher" wait_for 10 grep -qF "src_ip=203.0.113.50 src_port=44444" "$START_LOG"
# The relay plays proxyguard-server: WireGuard sees the client as 127.0.0.1:<port>.
# WSL2 "mirrored" networking routes UDP to 127.0.0.1 to the Windows host; pin
# this port's loopback traffic to the local table (a no-op on plain Linux).
lo_rules add || true
netns_client e2e-c2 e2e-v2 e2e-v2c 172.31.251.1 172.31.251.2 "$WORK/k2" 10.99.0.3 172.31.251.1:51821
socat UDP4-LISTEN:51821,bind=172.31.251.1,reuseaddr,fork UDP4:127.0.0.1:51820 >/dev/null 2>&1 &
sleep 1
ip netns exec e2e-c2 ping -c 2 -W 2 10.99.0.1 >/dev/null || true
check "server sees bob on 127.0.0.1 (ProxyGuard-like)" bash -c "wg show $WGS endpoints | grep -F '$P2' | grep -qF '127.0.0.1:'"
check "connect line for bob" wait_for 30 exists connect "$P2"
check "  user/profile from the portal DB" has connect "$P2" "user=bob profile=students"
check "  device from the DB" has connect "$P2" "device=linux"
check "  real public IP from the START" has connect "$P2" 'src_ip="203.0.113.50" src_port=44444'
check "  transport=tcp" has connect "$P2" "transport=tcp"
check "  tcp_candidates=1" has connect "$P2" "tcp_candidates=1"
check "  inferred=1 (no portal event)" has connect "$P2" "inferred=1"

echo "==> 5. Roam: alice changes source IP"
ip -n e2e-c1 addr del 172.31.250.2/24 dev e2e-v1c
ip -n e2e-c1 addr add 172.31.250.3/24 dev e2e-v1c
ip netns exec e2e-c1 ping -c 3 -W 2 10.99.0.1 >/dev/null || true
check "roam line for alice" wait_for 15 exists roam "$P1"
check "  old and new source" has roam "$P1" 'src_ip_old="172.31.250.2" src_port_old='
check "  new source IP" has roam "$P1" 'src_ip="172.31.250.3"'

echo "==> 6. Portal DISCONNECT (then the peer is removed, as eduVPN does)"
portal "DISCONNECT USER=alice PROFILE=staff PROTO=wireguard CONN=$P1 BYTES_IN=111 BYTES_OUT=222"
wg set "$WGS" peer "$P1" remove
check "disconnect line for alice" wait_for 10 exists disconnect "$P1"
check "  bytes from the portal" has disconnect "$P1" "bytes_in=111 bytes_out=222"
check "  last (roamed) source" has disconnect "$P1" 'src_ip="172.31.250.3"'
check "  not inferred" lacks disconnect "$P1" "inferred=1"
sleep 8
check "  no spurious connect after the disconnect" test "$(count connect "$P1")" -eq 1

echo "==> 7. Restart: portal events logged while the daemon is down are replayed"
check "journal cursor persisted" test -s /var/lib/eduvpn-logger/journal.cursor
systemctl stop eduvpn-logger.service
portal "CONNECT USER=carol PROFILE=staff PROTO=wireguard CONN=$P4 IP4=10.99.0.4 IP6=fd99::4"
portal "DISCONNECT USER=carol PROFILE=staff PROTO=wireguard CONN=$P4 BYTES_IN=5 BYTES_OUT=6"
sleep 1
T_START=$(date +%s)
systemctl start eduvpn-logger.service
check "replayed disconnect for carol" wait_for 15 exists disconnect "$P4"
check "  replayed connect for carol" exists connect "$P4"
check "  connect written before its disconnect" bash -c "grep -nF ' conn=$P4 ' '$LOG' | head -n1 | grep -qF 'event=connect'"
check "  original (pre-restart) timestamp kept" bash -c "[ \$(date -d \"\$(grep -F ' conn=$P4 ' '$LOG' | grep -F 'event=connect' | cut -d' ' -f1)\" +%s) -lt $T_START ]"
check "  entries before the cursor not replayed twice" test "$(count disconnect "$P1")" -eq 1
check "active TCP peer re-announced after restart" wait_for 20 bash -c "[ \$(grep -F ' event=connect ' '$LOG' | grep -cF ' conn=$P2 ') -ge 2 ]"
check "  re-announcement is inferred" has connect "$P2" "inferred=1"

echo "==> 8. Unusable saved cursor: falls back to 'now' and keeps working"
systemctl stop eduvpn-logger.service
echo "s=deadbeef;i=1;b=00;m=1;t=1;x=1" >/var/lib/eduvpn-logger/journal.cursor
systemctl start eduvpn-logger.service
check "bad cursor detected" wait_for 15 daemon_says "with saved cursor; restarting from now"
sleep 2
portal "CONNECT USER=dave PROFILE=staff PROTO=wireguard CONN=$P5 IP4=10.99.0.5 IP6=fd99::5"
portal "DISCONNECT USER=dave PROFILE=staff PROTO=wireguard CONN=$P5 BYTES_IN=1 BYTES_OUT=1"
check "events processed after the fallback" wait_for 15 exists disconnect "$P5"

echo "==> 9. logrotate"
check "logrotate config has no duplicates/errors" bash -c "! logrotate -d /etc/logrotate.conf 2>&1 | grep -iE 'duplicate|^error:'"
rm -f /var/log/eduvpn/eduvpn.log-"$(date +%Y%m%d)"*
logrotate -f /etc/logrotate.d/eduvpn-logger
check "fresh log created 0640 root:adm" test "$(mode_of "$LOG")" = "640 root:adm"
portal "CONNECT USER=eve PROFILE=staff PROTO=wireguard CONN=$P6 IP4=10.99.0.6 IP6=fd99::6"
portal "DISCONNECT USER=eve PROFILE=staff PROTO=wireguard CONN=$P6 BYTES_IN=1 BYTES_OUT=1"
check "daemon writes to the rotated-in file" wait_for 15 exists disconnect "$P6"

echo "==> 10. Handshake silence: bob's tunnel goes away (waits WireGuard's 180 s)"
ip -n e2e-c2 link del wgc
pkill -f "socat UDP4-LISTEN:51821" || true
check "inferred disconnect for bob" wait_for 230 exists disconnect "$P2"
check "  marked inferred=1" has disconnect "$P2" "inferred=1"
check "  keeps bob's TCP identity" has disconnect "$P2" "user=bob"

echo "==> 11. Re-install keeps the operator's drop-in; no crashes"
check "install.sh third run" install_quiet 3
check "drop-in preserved" test -f "$DROPIN"
check "service still active" systemctl is-active --quiet eduvpn-logger.service
check "no Python tracebacks in the daemon's journal" bash -c "! journalctl -u eduvpn-logger.service -u proxyguard-watcher.service --since @$T0 --no-pager -o cat | grep -q Traceback"
# Only the warnings this test provokes on purpose are allowed: anything else
# (e.g. a sandbox-denied write, a failing `wg`) is a failure.
unexpected() { daemon_log | grep '^\[eduvpn-logger\]' | grep -vE 'config: |untrusted _UID=|with saved cursor; restarting from now'; }
U=$(unexpected || true)
if [ -z "$U" ]; then ok "no unexpected daemon errors"; else ko "unexpected daemon errors: $(echo "$U" | head -n 3)"; fi
echo "--- systemd-analyze security (informational)"
for u in eduvpn-logger proxyguard-watcher; do systemd-analyze security --no-pager "$u.service" 2>/dev/null | tail -n 1 || true; done

echo
echo "e2e: $PASS passed, $FAIL failed ($(($(date +%s) - T0)) s)"
if [ "$FAIL" -ne 0 ]; then
    echo "--- daemon journal"; daemon_log | tail -n 40
    echo "--- $LOG"; tail -n 30 "$LOG"
    exit 1
fi
