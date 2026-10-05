#!/usr/bin/env python3
"""eduvpn-logger — unified, correlated logging for eduVPN v3 (WireGuard).

Merges three independent log sources into one structured line per session event
(CONNECT / ROAM / DISCONNECT):

  * vpn-user-portal (journald)  -> user, profile, WG public key, assigned VPN IPs, bytes
  * WireGuard (`wg show`, polled) -> WG public key <-> public source IP:port; connect/roam/disconnect
  * Apache ProxyGuard (file)    -> public source IP:port for TCP-fallback sessions

The WireGuard public key is the correlation key across all three. Connect/roam/
disconnect events are derived internally by polling `wg show` (no external daemon).
Optional GeoIP enrichment (MaxMind GeoLite2 City) and forwarding to syslog for SIEM.

Configuration is read from environment variables (see CONFIG block below); all
have sensible defaults, so the daemon also runs with no configuration at all.
"""
import json
import math
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import ipaddress
import sqlite3
from collections import deque
import dataclasses
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple
try:
    import syslog as _syslog
except Exception:
    _syslog = None


def _env_float(name: str, default: float) -> float:
    # A malformed value in a drop-in must not crash-loop the daemon (every event
    # would be lost): warn and keep the default.
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        v = float(raw)
        if math.isfinite(v):
            return v
    except ValueError:
        pass
    print(f"[eduvpn-logger] config: {name}={raw!r} is not a number; using {default:g}",
          file=sys.stderr, flush=True)
    return default


# --------------------------------------------------------------------------- #
# CONFIG — everything site-specific lives here, overridable via environment.   #
# --------------------------------------------------------------------------- #
OUT_PATH = os.environ.get("EDUVPN_LOG", "/var/log/eduvpn/eduvpn.log")
DB_PATH = os.environ.get("EDUVPN_PORTAL_DB", "/var/lib/vpn-user-portal/db.sqlite")
PROXYGUARD_START_LOG = os.environ.get(
    "EDUVPN_PROXYGUARD_START_LOG", "/var/log/apache2/proxyguard_start.log"
)
# If set, use this GeoLite2 .mmdb directly; otherwise the usual locations are tried.
GEOIP_DB = os.environ.get("EDUVPN_GEOIP_DB", "")
# Preferred language(s) for GeoIP names, comma-separated, first match wins.
GEOIP_LANG = os.environ.get("EDUVPN_GEOIP_LANG", "en")
SYSLOG_IDENT = os.environ.get("EDUVPN_SYSLOG_IDENT", "eduvpn-logger")
SYSLOG_FACILITY = os.environ.get("EDUVPN_SYSLOG_FACILITY", "local0")
# Floor: 0 would spawn `wg` in a busy loop, a negative value would kill the poller.
WG_POLL_SEC = max(0.5, _env_float("EDUVPN_WG_POLL_SEC", 2.0))
# WireGuard interfaces to follow, comma-separated; empty = all. Set it when the
# host also runs WireGuard tunnels that are not eduVPN's (they would log user=-).
WG_INTERFACES = {s.strip() for s in os.environ.get("EDUVPN_WG_INTERFACES", "").split(",") if s.strip()}
# Persistent state (the journald cursor). Give test instances their own directory.
STATE_DIR = os.environ.get("EDUVPN_STATE_DIR", "/var/lib/eduvpn-logger")
CURSOR_PATH = os.path.join(STATE_DIR, "journal.cursor")

GEOIP_DEFAULT_PATHS = (
    "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
)


def _log_err(context: str, exc: BaseException) -> None:
    # Surface unexpected failures to stderr (captured by journald) instead of
    # swallowing them silently. The daemon keeps running.
    try:
        print(f"[eduvpn-logger] {context}: {exc!r}", file=sys.stderr, flush=True)
    except Exception:
        pass


def _syslog_facility_const() -> int:
    if _syslog is None:
        return 0
    name = "LOG_" + SYSLOG_FACILITY.strip().upper()
    return getattr(_syslog, name, _syslog.LOG_LOCAL0)


def _parse_journal_realtime_ts(entry: dict) -> Optional[float]:
    v = entry.get("__REALTIME_TIMESTAMP")
    if not isinstance(v, str):
        return None
    try:
        return int(v) / 1_000_000.0
    except Exception:
        return None


def _iso_now_local() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="microseconds")

def _iso_from_ts(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat(timespec="microseconds")
    except Exception:
        return _iso_now_local()

def _is_global_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except Exception:
        return False


def _is_loopback(ip: Optional[str]) -> bool:
    # ProxyGuard hands WireGuard its packets from a loopback address (127.0.0.1,
    # or ::1 if proxyguard-server is set up that way): the client IP is hidden.
    try:
        return ipaddress.ip_address(ip or "").is_loopback
    except ValueError:
        return False


def _san(value: str) -> str:
    # Neutralize whitespace / control chars / kv delimiters in free-text fields
    # (user, profile) so a crafted value from the IdP/portal can't break the
    # structured line or forge extra key=value pairs in the SIEM.
    if not value or value == "-":
        return value
    return re.sub(r'[\s"=\x00-\x1f\x7f]+', "_", value)


def _split_kv(message: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in message.split():
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


# A WireGuard public key: 32 bytes, standard base64 -> 43 chars + "=".
_WG_PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
# vpn-user-portal's *default* templates (no connectLogTemplate configured):
#   CONNECT user (profile:conn) [orig_ip => ip4,ip6]   (older: [ip4,ip6])
#   DISCONNECT user (profile:conn)
_PORTAL_DEFAULT_RE = re.compile(
    r"^(CONNECT|DISCONNECT) (\S+) \(([^:()\s]+):([^)\s]+)\)(?: \[(?:[^\]]*=> )?([^,\]\s]*),([^\]\s]*)\])?"
)


def _parse_portal_event(message: str) -> Optional[Tuple[str, Dict[str, str]]]:
    # Returns ("CONNECT"|"DISCONNECT", kv) with the template keys (USER, PROFILE, CONN,
    # IP4, IP6, BYTES_IN, BYTES_OUT), or None if the line is not a WireGuard session
    # event. Accepts the recommended key=value template and the portal's default
    # format. CONN must be a WireGuard public key: it is the correlation key, so
    # OpenVPN sessions (X.509 CN) and malformed lines are dropped here.
    if message.startswith("CONNECT "):
        kind = "CONNECT"
    elif message.startswith("DISCONNECT "):
        kind = "DISCONNECT"
    else:
        return None
    kv = _split_kv(message[len(kind) + 1 :])
    if "CONN" not in kv:
        m = _PORTAL_DEFAULT_RE.match(message)
        if m is None:
            return None
        kv = {"USER": m.group(2), "PROFILE": m.group(3), "CONN": m.group(4)}
        if m.group(5):
            kv["IP4"] = m.group(5)
        if m.group(6):
            kv["IP6"] = m.group(6)
    if kv.get("PROTO", "wireguard") != "wireguard":
        return None
    if not _WG_PUBKEY_RE.match(kv.get("CONN", "")):
        return None
    return kind, kv


def _device_from_client_marker(*markers: str) -> str:
    for m in markers:
        if not m or m == "-":
            continue
        s = str(m).strip().lower()
        m2 = re.search(r"\borg\.eduvpn\.app\.(android|ios|windows|macos|linux)\b", s)
        if m2 is not None:
            return str(m2.group(1))
    return "-"


def _parse_wg_dump_output(
    text: str,
) -> Tuple[Dict[str, Tuple[int, int]], Dict[str, int], Dict[str, str]]:
    # `wg show all dump`: one tab-separated line per peer:
    #   <iface> <pubkey> <psk> <endpoint> <allowed-ips> <handshake> <rx> <tx> <keepalive>
    # The per-interface header line has fewer fields and is skipped by the length check.
    snap: Dict[str, Tuple[int, int]] = {}
    handshake: Dict[str, int] = {}
    endpoint: Dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 9 or (WG_INTERFACES and parts[0] not in WG_INTERFACES):
            continue
        pubkey = parts[1].strip()
        ep = parts[3].strip()
        hs_raw = parts[5].strip()
        rx_raw = parts[6].strip()
        tx_raw = parts[7].strip()
        try:
            rx = int(rx_raw)
            tx = int(tx_raw)
            hs = int(hs_raw) if hs_raw else 0
        except Exception:
            continue
        if pubkey:
            snap[pubkey] = (rx, tx)
            handshake[pubkey] = hs
            endpoint[pubkey] = ep
    return snap, handshake, endpoint


def _parse_wg_transfer_output(text: str) -> Dict[str, Tuple[int, int]]:
    # `wg show all transfer`: one tab-separated line per peer:
    #   <iface> <pubkey> <rx> <tx>
    snap: Dict[str, Tuple[int, int]] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 4 or (WG_INTERFACES and parts[0] not in WG_INTERFACES):
            continue
        pubkey = parts[1].strip()
        try:
            rx = int(parts[2].strip())
            tx = int(parts[3].strip())
        except Exception:
            continue
        if pubkey:
            snap[pubkey] = (rx, tx)
    return snap


WG_CONNECTED_PREFIX = " connected from "
WG_DISCONNECTED_PREFIX = " disconnected from "
WG_ROAMED_PREFIX = " roamed to "

# Emit a disconnect after this many seconds of handshake silence. Overridable via env,
# but never below 180 s: WireGuard drops a session's keys 180 s after its handshake
# (REJECT_AFTER_TIME) and a tunnel carrying traffic re-handshakes before that (every
# ~120-165 s), so a shorter threshold would "disconnect" live sessions.
_DISCONNECT_AFTER_ENV = _env_float("EDUVPN_DISCONNECT_AFTER_SEC", 180.0)
SYNTH_DISCONNECT_AFTER_SEC = max(180.0, _DISCONNECT_AFTER_ENV)
# A peer is "active" while its last WireGuard handshake is within this window.
# Capped at the disconnect threshold: a peer already past that threshold must never
# count as active again, or lowering EDUVPN_DISCONNECT_AFTER_SEC below 180 would
# make idle-but-alive peers flap (synth disconnect -> still "active" -> re-connect).
ACTIVE_HANDSHAKE_MAX_AGE_SEC = min(180.0, SYNTH_DISCONNECT_AFTER_SEC)
# Defer a synthesized connect this long so the portal event / DB row can attribute it
# to a user before we emit; we emit early as soon as it resolves. Overridable via env.
CONNECT_GRACE_SEC = _env_float("EDUVPN_CONNECT_GRACE_SEC", 10.0)
# Minimum gap between two roam events for the same peer. A roam where only the
# source port changed (same IP — typical NAT rebind) is suppressed entirely;
# this caps the rest so a flapping mobile NAT can't spam the SIEM. Env-overridable.
ROAM_MIN_INTERVAL_SEC = _env_float("EDUVPN_ROAM_MIN_INTERVAL_SEC", 30.0)

@dataclass(frozen=True)
class TcpStartEvent:
    ts: float
    src_ip: str
    src_port: str


@dataclass(frozen=True)
class ConnectEvent:
    ts: float
    user: str
    profile: str
    device: str
    conn: str
    ip4: str
    ip6: str
    # True when the session was announced by a portal CONNECT; otherwise the connect
    # is synthesized from WireGuard (+ DB attribution) and marked inferred=1.
    from_portal: bool = False


@dataclass(frozen=True)
class DbConnInfo:
    user: str
    profile: str
    ip4: str
    ip6: str
    display_name: str
    client_id: str


class PortalDb:
    def __init__(self, db_path: str = DB_PATH) -> None:
        self._db_path = db_path
        self._conn: Optional["sqlite3.Connection"] = None
        self._query: Optional[str] = None
        self._col_user: Optional[str] = None
        self._col_profile: Optional[str] = None
        self._col_ip4: Optional[str] = None
        self._col_ip6: Optional[str] = None
        self._col_display_name: Optional[str] = None
        self._col_client_id: Optional[str] = None
        self._retry_at = 0.0
        self._warned = False
        self._lookup_warned = False
        self._detect()

    def _detect(self) -> None:
        # Schema detection runs on a temporary connection. Lookups then use a fresh
        # short-lived connection each time, so rows the portal commits after startup
        # are always visible (a long-lived reader can miss them). Until it succeeds
        # it is retried at most once a minute from lookup(): the DB may not exist
        # yet at boot, or its schema may change with a portal upgrade.
        self._retry_at = time.time() + 60.0
        try:
            if not os.path.exists(self._db_path):
                return
            self._conn = sqlite3.connect(f"file:{self._db_path}?mode=ro", uri=True, timeout=1.0)
            self._conn.row_factory = sqlite3.Row
            self._detect_schema()
        except Exception:
            self._query = None
        finally:
            if self._query is None and not self._warned:
                self._warned = True
                _log_err("portal db", RuntimeError(
                    f"no usable session table in {self._db_path}; connects without a portal "
                    "event get user=- until it appears (retried every minute)"))
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None

    def _detect_schema(self) -> None:
        assert self._conn is not None

        tables = []
        try:
            rows = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            tables = [str(r[0]) for r in rows if r and r[0]]
        except Exception:
            return

        best = None
        best_score = -1
        best_cols: Dict[str, str] = {}
        best_order = None

        # Correlation is ALWAYS by WireGuard public key, so prefer pubkey-named
        # columns over a generic "connection_id" — otherwise a portal DB with an
        # unrelated connection_id+user+profile table could bind the WHERE to the
        # wrong column and silently make every lookup miss (user=-).
        conn_candidates = [
            "public_key",
            "wg_public_key",
            "wireguard_public_key",
            "wireguard_pubkey",
            "connection_id",
            "conn",
        ]
        user_candidates = ["user_id", "user"]
        profile_candidates = ["profile_id", "profile"]
        ip4_candidates = ["ip_four", "ip4", "ip_f", "ip_v4"]
        ip6_candidates = ["ip_six", "ip6", "ip_v6"]
        display_name_candidates = ["display_name", "device_name", "name"]
        client_id_candidates = ["oauth_client_id", "client_id", "vpn_client_id", "api_client_id"]
        order_candidates = ["created_at", "issued_at", "updated_at", "id"]

        for t in tables:
            try:
                col_rows = self._conn.execute(f'PRAGMA table_info("{t}")').fetchall()
            except Exception:
                continue
            cols = [str(r[1]).lower() for r in col_rows if r and r[1]]
            col_set = set(cols)

            def pick(cands: list[str]) -> Optional[str]:
                for c in cands:
                    if c in col_set:
                        return c
                return None

            c_conn = pick(conn_candidates)
            c_user = pick(user_candidates)
            c_profile = pick(profile_candidates)
            c_ip4 = pick(ip4_candidates)
            c_ip6 = pick(ip6_candidates)
            c_display_name = pick(display_name_candidates)
            c_client_id = pick(client_id_candidates)
            if c_conn is None or c_user is None or c_profile is None:
                continue

            score = 0
            score += 3 if c_conn else 0
            score += 2 if c_user else 0
            score += 2 if c_profile else 0
            score += 1 if c_ip4 else 0
            score += 1 if c_ip6 else 0
            score += 1 if c_display_name else 0
            score += 1 if c_client_id else 0

            if score > best_score:
                best_score = score
                best = t
                best_cols = {
                    "conn": c_conn,
                    "user": c_user,
                    "profile": c_profile,
                    "ip4": c_ip4 or "",
                    "ip6": c_ip6 or "",
                    "display_name": c_display_name or "",
                    "client_id": c_client_id or "",
                }
                best_order = pick(order_candidates)

        if best is None:
            return

        self._col_user = best_cols["user"] or None
        self._col_profile = best_cols["profile"] or None
        self._col_ip4 = best_cols["ip4"] or None
        self._col_ip6 = best_cols["ip6"] or None
        self._col_display_name = best_cols["display_name"] or None
        self._col_client_id = best_cols["client_id"] or None

        select_cols = [
            self._col_user,
            self._col_profile,
            self._col_ip4,
            self._col_ip6,
            self._col_display_name,
            self._col_client_id,
        ]
        select_cols_quoted = [f'"{c}"' for c in select_cols if c]
        where_conn = best_cols["conn"]

        q = f'SELECT {", ".join(select_cols_quoted)} FROM "{best}" WHERE "{where_conn}" = ?'
        if best_order:
            q += f' ORDER BY "{best_order}" DESC'
        q += " LIMIT 1"
        self._query = q

    def lookup(self, conn_id: str) -> Optional[DbConnInfo]:
        # Called from the correlator while self._lock is held, so keep it light:
        # a fresh mode=ro connection with a 1s timeout (no write lock, WAL-safe).
        if not conn_id or conn_id == "-":
            return None
        if self._query is None and time.time() >= self._retry_at:
            self._detect()
        if self._query is None:
            return None
        try:
            conn = sqlite3.connect(f"file:{self._db_path}?mode=ro", uri=True, timeout=1.0)
            conn.row_factory = sqlite3.Row
            try:
                row = conn.execute(self._query, (conn_id,)).fetchone()
            finally:
                conn.close()
        except Exception as e:
            if isinstance(e, sqlite3.OperationalError) and str(e).startswith("no such"):
                # Table/column gone (portal upgrade): detect the schema again.
                self._query = None
            elif str(e) != "database is locked" and not self._lookup_warned:
                # A lock is transient (user=- for one event); anything else, e.g.
                # "unable to open database file", would silently turn every
                # connect into user=-: say it, once per outage.
                self._lookup_warned = True
                _log_err("portal db lookup", e)
            return None
        self._lookup_warned = False
        if row is None:
            return None

        user = "-"
        profile = "-"
        ip4 = "-"
        ip6 = "-"
        display_name = "-"
        client_id = "-"
        try:
            if self._col_user and row[self._col_user] is not None:
                user = str(row[self._col_user])
            if self._col_profile and row[self._col_profile] is not None:
                profile = str(row[self._col_profile])
            if self._col_ip4 and row[self._col_ip4] is not None:
                ip4 = str(row[self._col_ip4])
            if self._col_ip6 and row[self._col_ip6] is not None:
                ip6 = str(row[self._col_ip6])
            if self._col_display_name and row[self._col_display_name] is not None:
                display_name = str(row[self._col_display_name])
            if self._col_client_id and row[self._col_client_id] is not None:
                client_id = str(row[self._col_client_id])
        except Exception:
            return None
        return DbConnInfo(
            user=user,
            profile=profile,
            ip4=ip4,
            ip6=ip6,
            display_name=display_name,
            client_id=client_id,
        )


class Correlator:
    def __init__(self) -> None:
        self._lock = threading.RLock()

        # Bounded: /proxyguard/ is reachable unauthenticated, so starts can be spammed.
        self._tcp_start_queue: deque[TcpStartEvent] = deque(maxlen=4096)
        self._pubkey_src: Dict[str, Tuple[float, str, str, str]] = {}
        self._pending_connect: Dict[str, Tuple[float, ConnectEvent]] = {}
        self._conn_info: Dict[str, ConnectEvent] = {}
        self._emitted_connect_ts: Dict[str, float] = {}
        self._emitted_disconnect_ts: Dict[str, float] = {}
        self._wg_bytes_baseline: Dict[str, Tuple[int, int]] = {}
        self._wg_bytes_baseline_pending: set[str] = set()
        self._wg_bytes_last: Dict[str, Tuple[int, int]] = {}
        self._wg_endpoint_last: Dict[str, str] = {}
        self._peer_last_handshake: Dict[str, int] = {}
        # pubkey -> last raw endpoint seen via `wg show`; drives the internal
        # connect/roam/disconnect synthesis.
        self._virtual_peers: Dict[str, str] = {}
        # pubkey -> (deadline by which a first-sighting connect must be emitted,
        # handshake time it was first seen at); while present, the connect is still
        # deferred waiting for user attribution.
        self._virtual_due: Dict[str, Tuple[float, float]] = {}
        # pubkey -> ts of the last roam line emitted (throttles roam noise).
        self._roam_last: Dict[str, float] = {}
        # pubkey -> number of ProxyGuard starts its TCP source was chosen among.
        self._tcp_candidates: Dict[str, int] = {}
        # pubkey -> last time a peer whose session ended by handshake silence was
        # still seen in wg: a portal DISCONNECT arriving later only echoes that end.
        self._silence_closed: Dict[str, float] = {}
        self._warned_portal_format = False
        self._wg_warned = False
        self._recent_lines: deque[str] = deque()
        self._recent_lines_set: set[str] = set()

        self._out_path = OUT_PATH
        out_dir = os.path.dirname(self._out_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        self._geo = GeoIp()
        self._db = PortalDb()
        if _syslog is not None:
            try:
                _syslog.openlog(ident=SYSLOG_IDENT, logoption=_syslog.LOG_PID, facility=_syslog_facility_const())
            except Exception:
                pass

    def _wg_peer_endpoint(self, ts: float, pubkey: str, consume: bool = False) -> Tuple[str, str, str]:
        # Best-effort recovery of endpoint for a peer, from the snapshot the poller
        # refreshes every WG_POLL_SEC. Reads in-memory state only — never spawns a
        # subprocess while the lock is held (see _wg_dump / update_wg_counters).
        # consume=True means "attribute a *new* TCP tunnel" (connect): it time-matches a
        # ProxyGuard start and claims it so it can't be reused for another peer. Without
        # it (disconnect) no matching is done: the start of a long-lived tunnel is long
        # gone, so a time match would only ever find another client's tunnel.
        if not pubkey or pubkey == "-":
            return "-", "-", "unknown"
        endpoint = self._wg_endpoint_last.get(pubkey, "")
        if not endpoint or endpoint == "(none)":
            return "-", "-", "unknown"
        ip, port = _split_endpoint(endpoint)
        if not ip:
            return "-", "-", "unknown"
        if _is_loopback(ip):
            if not consume:
                return "-", "-", "tcp"
            tcp = self._match_tcp_start(ts, pubkey)
            if tcp is not None:
                return tcp.src_ip, tcp.src_port, "tcp"
            return "-", "-", "tcp"
        return ip, port or "-", "udp"

    def _write_line(self, line: str) -> None:
        with self._lock:
            if line in self._recent_lines_set:
                return
            self._recent_lines.append(line)
            self._recent_lines_set.add(line)
            while len(self._recent_lines) > 2000:
                old = self._recent_lines.popleft()
                self._recent_lines_set.discard(old)
            try:
                with open(self._out_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                    f.flush()
            except OSError as e:
                # Disk full / permissions: still deliver the event to syslog below.
                _log_err("write log file", e)
            if _syslog is not None:
                try:
                    if " " in line:
                        _ts, msg = line.split(" ", 1)
                        _syslog.syslog(_syslog.LOG_INFO, msg)
                    else:
                        _syslog.syslog(_syslog.LOG_INFO, line)
                except Exception:
                    pass

    def _emit_connect(
        self,
        ev: ConnectEvent,
        src_ip: str,
        src_port: str,
        transport: str,
    ) -> None:
        # Counters from the poller's snapshot (no subprocess under the lock).
        last = self._wg_bytes_last.get(ev.conn)
        if last is not None:
            self._wg_bytes_baseline[ev.conn] = last
        else:
            self._wg_bytes_baseline_pending.add(ev.conn)
        country, city = self._geo.lookup(src_ip)
        msg = f"event=connect user={_san(ev.user)} profile={_san(ev.profile)}"
        if ev.device and ev.device != "-":
            msg += f" device={ev.device}"
        msg += (
            f" conn={ev.conn} tunnel_ip4=\"{ev.ip4}\" tunnel_ip6=\"{ev.ip6}\" "
            f"src_ip=\"{src_ip}\" src_port={src_port} transport={transport}"
        )
        msg += self._tcp_candidates_kv(ev.conn, transport)
        if not ev.from_portal:
            msg += " inferred=1"
        if country is not None:
            msg += f" country=\"{country}\""
        if city is not None:
            msg += f" city=\"{city}\""
        line = f"{_iso_from_ts(ev.ts)} {msg}"
        self._write_line(line)

    def _emit_disconnect(
        self,
        ts: float,
        user: str,
        profile: str,
        conn: str,
        bytes_in: str,
        bytes_out: str,
        src_ip: str,
        src_port: str,
        transport: str,
        inferred: bool = False,
    ) -> None:
        country, city = self._geo.lookup(src_ip)
        msg = f"event=disconnect user={_san(user)} profile={_san(profile)}"
        info = self._conn_info.get(conn)
        if info is not None and info.device and info.device != "-":
            msg += f" device={info.device}"
        msg += (
            f" conn={conn} bytes_in={bytes_in} bytes_out={bytes_out} "
            f"src_ip=\"{src_ip}\" src_port={src_port} transport={transport}"
        )
        if inferred:
            msg += " inferred=1"
        if country is not None:
            msg += f" country=\"{country}\""
        if city is not None:
            msg += f" city=\"{city}\""
        line = f"{_iso_from_ts(ts)} {msg}"
        self._write_line(line)

    def _emit_roam(
        self,
        ts: float,
        user: str,
        profile: str,
        conn: str,
        ip4: str,
        ip6: str,
        src_ip_old: str,
        src_port_old: str,
        src_ip: str,
        src_port: str,
        transport: str,
    ) -> None:
        country, city = self._geo.lookup(src_ip)
        msg = f"event=roam user={_san(user)} profile={_san(profile)}"
        info = self._conn_info.get(conn)
        if info is not None and info.device and info.device != "-":
            msg += f" device={info.device}"
        msg += (
            f" conn={conn} tunnel_ip4=\"{ip4}\" tunnel_ip6=\"{ip6}\" "
            f"src_ip_old=\"{src_ip_old}\" src_port_old={src_port_old} src_ip=\"{src_ip}\" src_port={src_port} transport={transport}"
        )
        msg += self._tcp_candidates_kv(conn, transport)
        if country is not None:
            msg += f" country=\"{country}\""
        if city is not None:
            msg += f" city=\"{city}\""
        line = f"{_iso_from_ts(ts)} {msg}"
        self._write_line(line)

    def _tcp_candidates_kv(self, pubkey: str, transport: str) -> str:
        # How many ProxyGuard starts the time match chose from: 1 = unambiguous,
        # >1 = the closest one was picked (see README "Limitations").
        n = self._tcp_candidates.get(pubkey)
        return f" tcp_candidates={n}" if transport == "tcp" and n else ""

    @staticmethod
    def _wg_dump() -> Tuple[Dict[str, Tuple[int, int]], Optional[Dict[str, int]], Dict[str, str], bool]:
        # Spawn `wg show` and parse it. Runs WITHOUT the lock held (called from
        # update_wg_counters before locking), so a slow/hung wg never blocks the
        # event pipeline. The returned `ok` flag is True when wg actually ran
        # (return code 0) — even with zero peers — so the caller can tell a genuine
        # empty fleet (act on it: synthesize disconnects) from a failed poll
        # (skip: don't disconnect everyone because one `wg` call timed out).
        # `handshake` is None when only the byte-counter fallback worked: then there
        # is no liveness data and no events must be synthesized from it.
        wg = shutil.which("wg") or "wg"
        snap: Dict[str, Tuple[int, int]] = {}
        handshake: Optional[Dict[str, int]] = {}
        endpoint: Dict[str, str] = {}
        ok = False

        try:
            p = subprocess.run(
                [wg, "show", "all", "dump"],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
        except Exception:
            p = None
        if p is not None and p.returncode == 0:
            ok = True
            if p.stdout:
                snap, handshake, endpoint = _parse_wg_dump_output(p.stdout)

        if not ok:
            # Degraded fallback: byte counters only (no handshake/endpoint, so no
            # event synthesis this cycle — just keeps the transfer deltas moving).
            handshake = None
            try:
                p = subprocess.run(
                    [wg, "show", "all", "transfer"],
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                )
            except Exception:
                p = None
            if p is not None and p.returncode == 0:
                ok = True
                if p.stdout:
                    snap = _parse_wg_transfer_output(p.stdout)

        return snap, handshake, endpoint, ok

    def update_wg_counters(self) -> None:
        # Called periodically by a background thread. The wg subprocess runs here
        # WITHOUT the lock; only the in-memory update + reconciliation are locked.
        snap, handshake, endpoint, ok = self._wg_dump()
        if handshake is None:
            # Once per outage, not every poll: without `wg show ... dump` (wg missing,
            # no CAP_NET_ADMIN, timeout) nothing is derived from WireGuard.
            if not self._wg_warned:
                self._wg_warned = True
                _log_err("wg poller", RuntimeError(
                    "`wg show all dump` failed: no connect/roam/disconnect from WireGuard until it works"))
        else:
            self._wg_warned = False
        if not ok:
            # wg show failed this cycle: don't act on absent data (it would synth a
            # disconnect for every live peer), but time-based pruning is always safe.
            self._prune(time.time())
            return
        with self._lock:
            self._wg_bytes_last.update(snap)
            self._wg_endpoint_last.update(endpoint)
            if self._wg_bytes_baseline_pending:
                for pubkey in list(self._wg_bytes_baseline_pending):
                    last = self._wg_bytes_last.get(pubkey)
                    if last is None:
                        continue
                    self._wg_bytes_baseline[pubkey] = last
                    self._wg_bytes_baseline_pending.discard(pubkey)

            now = time.time()
            if handshake is not None:
                # Also with an empty fleet: peers that left wg must still get their
                # synthesized disconnect.
                self._synthesize_wg_events(now, handshake, endpoint)
            # Reconcile the poller-populated maps to the live peer set so they don't
            # grow unbounded over the daemon's lifetime (peers removed from wg by
            # teardown / appGoneInterval drop out of `snap`). Keep peers still present
            # in wg, plus those awaiting a synthesized disconnect, so their byte delta
            # survives until the disconnect line is written.
            keep = set(snap) | set(self._virtual_peers)
            for d in (
                self._wg_bytes_last,
                self._wg_endpoint_last,
                self._peer_last_handshake,
                self._wg_bytes_baseline,
                self._roam_last,
                self._tcp_candidates,
            ):
                for k in [k for k in d if k not in keep]:
                    d.pop(k, None)
            self._wg_bytes_baseline_pending &= keep
            # The portal may close a silenced session hours later (eduVPN keeps the
            # peer in wg until then): keep its marker while the peer is there, then
            # 5 min for the DISCONNECT to arrive.
            for k, seen in list(self._silence_closed.items()):
                if k in snap:
                    self._silence_closed[k] = now
                elif now - seen > 300.0:
                    del self._silence_closed[k]
            # Drain pending connects / expire stale state — the poll cycle is what
            # keeps these moving.
            self._prune_locked(now)

    def _synthesize_wg_events(self, now: float, hs: Dict[str, int], ep: Dict[str, str]) -> None:
        # Derive connect/roam/disconnect by diffing the raw peer endpoints between
        # polls, then feed them through _handle_wg_event_locked. WireGuard reports an
        # endpoint and a last-handshake per peer, so polling `wg show` carries the
        # association at the poll resolution without any external daemon.
        for pubkey, last_hs in hs.items():
            self._peer_last_handshake[pubkey] = last_hs
            endpoint = ep.get(pubkey, "")
            active = bool(last_hs) and (now - float(last_hs)) <= ACTIVE_HANDSHAKE_MAX_AGE_SEC
            if not active or not endpoint or endpoint == "(none)":
                continue
            prev = self._virtual_peers.get(pubkey)
            if prev is None:
                # First sighting: defer the connect so the portal event / DB row can
                # attribute it to a user before we emit (avoids user=- connect lines).
                self._virtual_peers[pubkey] = endpoint
                self._virtual_due[pubkey] = (now + CONNECT_GRACE_SEC, float(last_hs))
                continue
            if pubkey in self._virtual_due:
                # Connect deferred and not yet emitted; track the latest endpoint and
                # emit as soon as it can be attributed, or when the grace expires.
                self._virtual_peers[pubkey] = endpoint
                attributed = (
                    self._emitted_connect_ts.get(pubkey, 0.0) > 0.0
                    or pubkey in self._pending_connect
                    or self._db.lookup(pubkey) is not None
                )
                deadline, first_hs = self._virtual_due[pubkey]
                if attributed or now >= deadline:
                    self._virtual_due.pop(pubkey, None)
                    # Stamp the connect with the handshake that started the session,
                    # not the (deferred) poll time: accurate, and it keeps the
                    # ProxyGuard start match tight.
                    self._handle_wg_event_locked(first_hs, f"{pubkey} connected from {endpoint}")
                continue
            if prev != endpoint:
                self._virtual_peers[pubkey] = endpoint
                # Suppress port-only changes (same IP — typical NAT rebind) and
                # rate-limit the rest, so a flapping mobile NAT can't spam the SIEM.
                prev_ip, _prev_port = _split_endpoint(prev)
                new_ip, new_port = _split_endpoint(endpoint)
                # Port-only change on a real (non-loopback) IP = NAT rebind -> suppress.
                # For TCP/ProxyGuard the raw IP is always loopback, so the real client
                # IP is hidden: treat any endpoint change as a roam candidate.
                real_roam = _is_loopback(new_ip) or (prev_ip != new_ip)
                # A connect still held (TCP, waiting for its start) is written later
                # with the current source: no roam line before it.
                held = pubkey in self._pending_connect and pubkey not in self._emitted_connect_ts
                if real_roam and not held and (now - self._roam_last.get(pubkey, 0.0)) >= ROAM_MIN_INTERVAL_SEC:
                    self._roam_last[pubkey] = now
                    self._handle_wg_event_locked(now, f"{pubkey} roamed to {endpoint}")
                elif _is_loopback(new_ip):
                    # No roam line, but a new ProxyGuard tunnel still claims its start
                    # (or it could be matched to another client) and the disconnect
                    # line must carry the current source (unknown without a start).
                    tcp = self._match_tcp_start(now, pubkey)
                    if tcp is not None:
                        self._pubkey_src[pubkey] = (now, tcp.src_ip, tcp.src_port, "tcp")
                    else:
                        self._pubkey_src[pubkey] = (now, "-", "-", "tcp")
                elif new_ip:
                    self._pubkey_src[pubkey] = (now, new_ip, new_port or "-", "udp")

        # A peer whose handshake has gone silent past the threshold is treated as
        # disconnected. For app sessions the portal DISCONNECT normally fires first
        # and clears the peer before we get here.
        for pubkey in list(self._virtual_peers.keys()):
            last_hs = self._peer_last_handshake.get(pubkey, 0)
            silent_for = (now - float(last_hs)) if last_hs else 1e9
            if silent_for < SYNTH_DISCONNECT_AFTER_SEC:
                continue
            endpoint = self._virtual_peers.pop(pubkey, "")
            if self._virtual_due.pop(pubkey, None) is not None:
                # Connect was never emitted (peer vanished during the grace window):
                # nothing to disconnect.
                continue
            self._handle_wg_event_locked(now, f"{pubkey} disconnected from {endpoint}")

    def _wg_peer_bytes_delta(self, pubkey: str) -> Tuple[str, str]:
        last = self._wg_bytes_last.get(pubkey)
        if last is None:
            return "-", "-"
        now_rx, now_tx = last
        base = self._wg_bytes_baseline.get(pubkey)
        if base is None:
            return str(now_rx), str(now_tx)
        base_rx, base_tx = base
        # A counter below its baseline means the peer was re-created (e.g. a
        # vpn-daemon restart) and counts from 0 again: report what came after.
        d_rx = now_rx - base_rx if now_rx >= base_rx else now_rx
        d_tx = now_tx - base_tx if now_tx >= base_tx else now_tx
        return str(d_rx), str(d_tx)

    def _prune(self, now_ts: float) -> None:
        with self._lock:
            self._prune_locked(now_ts)

    def _prune_locked(self, now_ts: float) -> None:
        cutoff_tcp = now_ts - 120.0
        while self._tcp_start_queue and self._tcp_start_queue[0].ts < cutoff_tcp:
            self._tcp_start_queue.popleft()

        cutoff_src = now_ts - 3600.0
        for pubkey, (ts, _ip, _port, _transport) in list(self._pubkey_src.items()):
            # Live sessions keep their source for the disconnect line, however long.
            if ts < cutoff_src and pubkey not in self._virtual_peers:
                self._pubkey_src.pop(pubkey, None)

        for pubkey, (ts, ev) in list(self._pending_connect.items()):
            if pubkey in self._virtual_due:
                continue  # first handshake just seen: the next poll writes it, with its source
            # Handshake seen, waiting for its ProxyGuard start: 20 s. Announced by
            # the portal but no handshake yet: 120 s (clients retry for 90 s, the
            # app may fall back to TCP), then it is written without a source.
            if ts < now_ts - (20.0 if pubkey in self._virtual_peers else 120.0):
                if pubkey in self._emitted_connect_ts:
                    # Session already announced; don't emit a second connect.
                    self._pending_connect.pop(pubkey, None)
                    continue
                src_ip, src_port, transport = self._pending_source(pubkey, ts)
                self._emit_connect(ev, src_ip, src_port, transport)
                self._emitted_connect_ts[pubkey] = now_ts
                self._pending_connect.pop(pubkey, None)

        cutoff_emitted = now_ts - 7200.0
        for pubkey, ts in list(self._emitted_connect_ts.items()):
            # Keep the "announced" marker for the whole session (cleared on disconnect),
            # so a long-lived session never re-emits a connect; only orphans expire.
            if ts < cutoff_emitted and pubkey not in self._virtual_peers:
                self._emitted_connect_ts.pop(pubkey, None)
        for pubkey, ts in list(self._emitted_disconnect_ts.items()):
            if ts < cutoff_emitted:
                self._emitted_disconnect_ts.pop(pubkey, None)
        for pubkey, info in list(self._conn_info.items()):
            # A portal CONNECT whose peer never showed up in wg and that never got
            # a DISCONNECT would otherwise be kept for the daemon's whole lifetime.
            if info.ts < cutoff_emitted and pubkey not in self._virtual_peers and pubkey not in self._pending_connect:
                self._conn_info.pop(pubkey, None)

    def _pending_source(self, pubkey: str, held_ts: float) -> Tuple[str, str, str]:
        # Source for a held connect being written: the one already known, else a
        # ProxyGuard start matched at the time the connect was held (handshake or
        # portal event), not now — a start seconds later is another client's.
        # Recorded, so the disconnect line carries it too.
        cur = self._pubkey_src.get(pubkey)
        if cur is not None and cur[1] != "-":
            return cur[1], cur[2], cur[3]
        src_ip, src_port, transport = self._wg_peer_endpoint(held_ts, pubkey, consume=True)
        if transport != "unknown":
            self._pubkey_src[pubkey] = (held_ts, src_ip, src_port, transport)
        return src_ip, src_port, transport

    def _match_tcp_start(self, now_ts: float, pubkey: str) -> Optional[TcpStartEvent]:
        # Closest start in time. A start may be stamped slightly *after* the WG
        # handshake (watcher latency, integer handshake seconds), hence the small
        # negative tolerance.
        # ponytail: time proximity is a heuristic; concurrent TCP starts within a few
        # seconds can be swapped (see README "Limitations").
        # Only used to attribute a NEW tunnel (connect/roam): the match is consumed.
        best: Optional[TcpStartEvent] = None
        best_dt = 10_000.0
        candidates = 0
        for ev in reversed(self._tcp_start_queue):
            dt = now_ts - ev.ts
            if dt < -3.0:
                continue
            if dt > 120.0:
                break
            candidates += 1
            if abs(dt) < best_dt:
                best = ev
                best_dt = abs(dt)
        if best is not None:
            # One ProxyGuard tunnel maps to exactly one peer: claim it so a second
            # peer can't be matched to the same src ip:port.
            try:
                self._tcp_start_queue.remove(best)
            except ValueError:
                pass
            self._tcp_candidates[pubkey] = candidates
        return best

    def on_tcp_start(self, ts: float, src_ip: str, src_port: str) -> None:
        with self._lock:
            self._tcp_start_queue.append(TcpStartEvent(ts=ts, src_ip=src_ip, src_port=src_port))
            self._prune_locked(ts)

    def _handle_wg_event_locked(self, ts: float, message: str) -> None:
        # Parses a "connected from / roamed to / disconnected from" WireGuard event
        # (synthesized by _synthesize_wg_events) and emits the correlated line.
        if WG_CONNECTED_PREFIX in message:
            pubkey, endpoint = message.split(WG_CONNECTED_PREFIX, 1)
            pubkey = pubkey.strip()
            endpoint = endpoint.strip()
            ip, port = _split_endpoint(endpoint)
            if pubkey and ip is None:
                self._prune_locked(ts)
                return
            if _is_loopback(ip):
                cur = self._pubkey_src.get(pubkey)
                tcp = None
                if cur is not None and cur[3] == "tcp" and cur[1] != "-":
                    pass  # already attributed (portal path): another start would be someone else's
                else:
                    tcp = self._match_tcp_start(ts, pubkey)
                if tcp is not None:
                    self._pubkey_src[pubkey] = (ts, tcp.src_ip, tcp.src_port, "tcp")
                elif cur is None or cur[1] == "-":
                    self._pubkey_src[pubkey] = (ts, "-", "-", "tcp")
                    if pubkey not in self._emitted_connect_ts:
                        # No start yet: hold the connect (the portal's, if it already
                        # announced the session) and let the prune retry the match.
                        pending = self._pending_connect.get(pubkey)
                        info = pending[1] if pending is not None else self._conn_info.get(pubkey)
                        if info is None:
                            db = self._db.lookup(pubkey)
                            if db is None:
                                info = ConnectEvent(ts=ts, user="-", profile="-", device="-", conn=pubkey, ip4="-", ip6="-")
                            else:
                                info = ConnectEvent(ts=ts, user=db.user, profile=db.profile, device=_device_from_client_marker(db.client_id, db.display_name), conn=pubkey, ip4=db.ip4, ip6=db.ip6)
                        self._conn_info[pubkey] = info
                        self._pending_connect[pubkey] = (ts, info)
                        self._prune_locked(ts)
                        return
            else:
                self._pubkey_src[pubkey] = (ts, ip or "-", port or "-", "udp")

            pending = self._pending_connect.pop(pubkey, None)
            if pending is not None:
                _pending_ts, ev = pending
                _ts2, src_ip, src_port, transport = self._pubkey_src.get(pubkey, (ts, "-", "-", "unknown"))
                if pubkey not in self._emitted_connect_ts:
                    self._emit_connect(ev, src_ip, src_port, transport)
                    self._emitted_connect_ts[pubkey] = ts
            else:
                if pubkey not in self._emitted_connect_ts:
                    info = self._conn_info.get(pubkey)
                    if info is None:
                        db = self._db.lookup(pubkey)
                        if db is None:
                            info = ConnectEvent(ts=ts, user="-", profile="-", device="-", conn=pubkey, ip4="-", ip6="-")
                        else:
                            info = ConnectEvent(ts=ts, user=db.user, profile=db.profile, device=_device_from_client_marker(db.client_id, db.display_name), conn=pubkey, ip4=db.ip4, ip6=db.ip6)
                    else:
                        info = dataclasses.replace(info, ts=ts, conn=pubkey)
                    self._conn_info[pubkey] = info
                    _ts2, src_ip, src_port, transport = self._pubkey_src.get(pubkey, (ts, "-", "-", "unknown"))
                    self._emit_connect(info, src_ip, src_port, transport)
                    self._emitted_connect_ts[pubkey] = ts
            self._prune_locked(ts)
            return

        if WG_ROAMED_PREFIX in message:
            pubkey, endpoint = message.split(WG_ROAMED_PREFIX, 1)
            pubkey = pubkey.strip()
            endpoint = endpoint.strip()
            ip, port = _split_endpoint(endpoint)
            if pubkey and ip is None:
                self._prune_locked(ts)
                return

            old = self._pubkey_src.get(pubkey)
            if old is None:
                src_ip_old, src_port_old, transport = "-", "-", "unknown"
            else:
                _old_ts, src_ip_old, src_port_old, transport = old

            if _is_loopback(ip):
                transport = "tcp"
                tcp = self._match_tcp_start(ts, pubkey)
                if tcp is not None:
                    ip = tcp.src_ip
                    port = tcp.src_port
                else:
                    # A new tunnel without its start: source unknown. The previous one
                    # (another tunnel, or the UDP path before a fallback) is not it.
                    ip = "-"
                    port = "-"
                    self._tcp_candidates.pop(pubkey, None)
            else:
                transport = "udp"

            self._pubkey_src[pubkey] = (ts, ip or "-", port or "-", transport)

            info = self._conn_info.get(pubkey)
            if info is None:
                db = self._db.lookup(pubkey)
                if db is None:
                    ip4 = "-"
                    ip6 = "-"
                    user = "-"
                    profile = "-"
                else:
                    info = ConnectEvent(ts=ts, user=db.user, profile=db.profile, device=_device_from_client_marker(db.client_id, db.display_name), conn=pubkey, ip4=db.ip4, ip6=db.ip6)
                    self._conn_info[pubkey] = info
                    ip4 = info.ip4
                    ip6 = info.ip6
                    user = info.user
                    profile = info.profile
            else:
                ip4 = info.ip4
                ip6 = info.ip6
                user = info.user
                profile = info.profile

            self._emit_roam(
                ts=ts,
                user=user,
                profile=profile,
                conn=pubkey,
                ip4=ip4,
                ip6=ip6,
                src_ip_old=src_ip_old,
                src_port_old=src_port_old,
                src_ip=ip or "-",
                src_port=port or "-",
                transport=transport,
            )
            self._prune_locked(ts)
            return

        if WG_DISCONNECTED_PREFIX in message:
            pubkey, endpoint = message.split(WG_DISCONNECTED_PREFIX, 1)
            pubkey = pubkey.strip()
            endpoint = endpoint.strip()
            if pubkey:
                # Already disconnected by the portal moments ago: don't log it twice.
                # Unless a new session (same key) was announced since then — that one
                # must get its own disconnect.
                if (ts - self._emitted_disconnect_ts.get(pubkey, 0.0)) < 300.0 and pubkey not in self._emitted_connect_ts:
                    self._pubkey_src.pop(pubkey, None)
                    self._pending_connect.pop(pubkey, None)
                    self._conn_info.pop(pubkey, None)
                    self._emitted_connect_ts.pop(pubkey, None)
                    self._peer_last_handshake.pop(pubkey, None)
                    self._wg_bytes_baseline.pop(pubkey, None)
                    self._wg_bytes_baseline_pending.discard(pubkey)
                    self._virtual_peers.pop(pubkey, None)
                    self._tcp_candidates.pop(pubkey, None)
                    self._virtual_due.pop(pubkey, None)
                    self._prune_locked(ts)
                    return

                src = self._pubkey_src.get(pubkey)
                if src is None:
                    ip, port = _split_endpoint(endpoint)
                    if ip and not _is_loopback(ip):
                        src_ip, src_port, transport = ip, port or "-", "udp"
                    elif ip:
                        # Never time-match a start here (see _wg_peer_endpoint).
                        src_ip, src_port, transport = "-", "-", "tcp"
                    else:
                        src_ip, src_port, transport = "-", "-", "unknown"
                else:
                    _ts2, src_ip, src_port, transport = src

                info = self._conn_info.get(pubkey)
                if info is None:
                    db = self._db.lookup(pubkey)
                    if db is None:
                        user = "-"
                        profile = "-"
                    else:
                        user = db.user
                        profile = db.profile
                else:
                    user = info.user
                    profile = info.profile

                bytes_in, bytes_out = self._wg_peer_bytes_delta(pubkey)
                # Synthesized from handshake silence, not reported by the portal.
                self._emit_disconnect(ts, user, profile, pubkey, bytes_in, bytes_out, src_ip, src_port, transport, inferred=True)
                self._emitted_disconnect_ts[pubkey] = ts
                self._silence_closed[pubkey] = ts
                self._peer_last_handshake.pop(pubkey, None)

                self._pubkey_src.pop(pubkey, None)
                self._pending_connect.pop(pubkey, None)
                self._conn_info.pop(pubkey, None)
                self._emitted_connect_ts.pop(pubkey, None)
                self._wg_bytes_baseline.pop(pubkey, None)
                self._virtual_peers.pop(pubkey, None)
                self._tcp_candidates.pop(pubkey, None)
                self._virtual_due.pop(pubkey, None)
            self._prune_locked(ts)
            return

    def on_portal(self, ts: float, message: str) -> None:
        with self._lock:
            self._on_portal_locked(ts, message)

    def _on_portal_locked(self, ts: float, message: str) -> None:
        parsed = _parse_portal_event(message)
        if parsed is None:
            if message.startswith(("CONNECT ", "DISCONNECT ")) and not self._warned_portal_format:
                # One warning, not one per event: most likely an OpenVPN session or a
                # custom connectLogTemplate without CONN= (see README).
                self._warned_portal_format = True
                _log_err("portal", ValueError(f"ignoring unparsable/non-WireGuard event: {message[:120]!r}"))
            return
        kind, kv = parsed
        if kind == "CONNECT":
            user = kv.get("USER", "-")
            profile = kv.get("PROFILE", "-")
            conn = kv.get("CONN", "-")
            ip4 = kv.get("IP4", "-")
            ip6 = kv.get("IP6", "-")

            device = "-"
            db = self._db.lookup(conn)
            if db is not None:
                device = _device_from_client_marker(db.client_id, db.display_name)
            ev = ConnectEvent(ts=ts, user=user, profile=profile, device=device, conn=conn, ip4=ip4, ip6=ip6, from_portal=True)
            self._conn_info[conn] = ev

            src = self._pubkey_src.get(conn)
            if src is None or (ts - src[0]) > 60.0:
                src_ip, src_port, transport = self._wg_peer_endpoint(ts, conn, consume=True)
                # A TCP peer without its ProxyGuard start yet is held like an
                # unseen one: the prune retries the match before writing it.
                if src_ip != "-":
                    self._pubkey_src[conn] = (ts, src_ip, src_port, transport)
                    if conn not in self._emitted_connect_ts:
                        self._emit_connect(ev, src_ip, src_port, transport)
                        self._emitted_connect_ts[conn] = ts
                    self._prune_locked(ts)
                    return
                self._pending_connect[conn] = (ts, ev)
                self._prune_locked(ts)
                return

            _ts2, src_ip, src_port, transport = src
            if transport == "tcp" and (src_ip == "-" or _is_loopback(src_ip)):
                self._pending_connect[conn] = (ts, ev)
                self._prune_locked(ts)
                return
            if conn not in self._emitted_connect_ts:
                self._emit_connect(ev, src_ip, src_port, transport)
                self._emitted_connect_ts[conn] = ts
            self._prune_locked(ts)
            return

        if kind == "DISCONNECT":
            user = kv.get("USER", "-")
            profile = kv.get("PROFILE", "-")
            conn = kv.get("CONN", "-")
            bytes_in = kv.get("BYTES_IN", "-")
            bytes_out = kv.get("BYTES_OUT", "-")
            # The session already ended by handshake silence and none started since:
            # the portal is closing it late (app reconnecting, expiry). Its end is
            # in the log already, don't write it twice.
            echo = (self._silence_closed.pop(conn, None) is not None
                    and conn not in self._emitted_connect_ts and conn not in self._pending_connect)
            if conn not in self._conn_info:
                device = "-"
                db = self._db.lookup(conn)
                if db is not None:
                    device = _device_from_client_marker(db.client_id, db.display_name)
                if device != "-":
                    self._conn_info[conn] = ConnectEvent(
                        ts=ts,
                        user=user,
                        profile=profile,
                        device=device,
                        conn=conn,
                        ip4="-",
                        ip6="-",
                    )
            pending = self._pending_connect.pop(conn, None)
            if pending is not None and conn not in self._emitted_connect_ts:
                # The portal announced it but it never resolved (e.g. no handshake):
                # write the connect now so it precedes its disconnect.
                c_ip, c_port, c_transport = self._pending_source(conn, pending[0])
                self._emit_connect(pending[1], c_ip, c_port, c_transport)
            src = self._pubkey_src.get(conn)
            if src is None:
                src_ip, src_port, transport = self._wg_peer_endpoint(ts, conn)
            else:
                _ts2, src_ip, src_port, transport = src
            if not echo:
                self._emit_disconnect(ts, user, profile, conn, bytes_in, bytes_out, src_ip, src_port, transport)
                self._emitted_disconnect_ts[conn] = ts
            # End of session: drop ALL per-session state, including the connect
            # marker — otherwise a reconnect with the same key would be swallowed.
            self._emitted_connect_ts.pop(conn, None)
            self._peer_last_handshake.pop(conn, None)
            self._conn_info.pop(conn, None)
            self._pubkey_src.pop(conn, None)
            self._wg_bytes_baseline.pop(conn, None)
            self._wg_bytes_baseline_pending.discard(conn)
            self._virtual_peers.pop(conn, None)
            self._tcp_candidates.pop(conn, None)
            self._virtual_due.pop(conn, None)
            # The portal removed the peer before logging: its last endpoint/counters
            # belong to the ended session. A CONNECT reusing the key (allowed by the
            # API) must not inherit them, nor time-match another client's TCP start.
            # If the peer is still in wg, the next poll reloads them.
            self._wg_endpoint_last.pop(conn, None)
            self._wg_bytes_last.pop(conn, None)
            self._prune_locked(ts)
            return


def _sys_uid_max(path: str = "/etc/login.defs") -> int:
    # Highest UID of a *system* account (SYS_UID_MAX, Debian/Fedora default 999).
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "SYS_UID_MAX" and parts[1].isdigit():
                    return int(parts[1])
    except OSError:
        pass
    return 999


def _trusted_portal_entry(entry: dict, uid_max: int) -> bool:
    # SYSLOG_IDENTIFIER (journalctl -t) can be set by any local user with
    # `logger -t vpn-user-portal ...`, so on its own it would let anyone forge
    # CONNECT/DISCONNECT records. _UID is a trusted field stamped by journald (the
    # sender cannot set it). The portal runs as a system account (www-data under
    # php-fpm on Debian, apache on Fedora/EL, root for maintenance jobs), so entries
    # from regular login accounts (UID > SYS_UID_MAX) are rejected.
    uid = entry.get("_UID")
    return isinstance(uid, str) and uid.isdigit() and int(uid) <= uid_max


def _load_cursor() -> Optional[str]:
    try:
        with open(CURSOR_PATH, encoding="utf-8") as f:
            c = f.read().strip()
        return c or None
    except OSError:
        return None


def _save_cursor(cursor: str) -> None:
    # Atomic replace: a crash mid-write must never leave a truncated cursor.
    os.makedirs(os.path.dirname(CURSOR_PATH) or ".", exist_ok=True)
    tmp = CURSOR_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(cursor)
    os.replace(tmp, CURSOR_PATH)


def _portal_journal_cmd(cursor: Optional[str]) -> list[str]:
    # Resume right after the last processed entry, so portal events logged while
    # the daemon was down are not lost; with no cursor, start from "now".
    cmd = ["journalctl", "-f", "-o", "json", "-t", "vpn-user-portal", "--no-pager"]
    return cmd + ([f"--after-cursor={cursor}"] if cursor else ["-n", "0"])


def _reader_journal(q: "queue.Queue[Tuple[str, float, Optional[str], Optional[str]]]") -> None:
    # Puts ("portal", ts, message-or-None, cursor). The main loop persists the
    # cursor only AFTER the entry is processed (at-least-once delivery); here we
    # track the last *enqueued* one, so a journalctl restart neither skips nor
    # re-reads entries.
    uid_max = _sys_uid_max()
    cursor = _load_cursor()
    rejected_uids: set[str] = set()
    failing = False  # warn once per outage, not once a second
    while True:
        p = None
        got_entry = False
        try:
            p = subprocess.Popen(_portal_journal_cmd(cursor), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 text=True, errors="replace")
            assert p.stdout is not None
            for line in p.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception:
                    continue
                got_entry = True
                failing = False
                c = entry.get("__CURSOR")
                if isinstance(c, str) and c:
                    cursor = c
                ts = _parse_journal_realtime_ts(entry)
                if ts is None:
                    ts = time.time()
                msg = entry.get("MESSAGE")
                if not isinstance(msg, str) or not msg:
                    msg = None
                elif not _trusted_portal_entry(entry, uid_max):
                    uid = str(entry.get("_UID"))
                    if uid not in rejected_uids:
                        rejected_uids.add(uid)
                        _log_err("portal", PermissionError(
                            f"ignoring vpn-user-portal entries from untrusted _UID={uid} (possible spoofing)"))
                    msg = None
                q.put(("portal", ts, msg, cursor))
            rc = p.wait()
            if rc != 0 and not got_entry and cursor:
                # An unusable cursor (journal vacuumed away, machine-id change)
                # makes journalctl fail at once: fall back to "now".
                _log_err("journal reader", RuntimeError(f"journalctl rc={rc} with saved cursor; restarting from now"))
                cursor = None
                try:
                    os.remove(CURSOR_PATH)
                except OSError:
                    pass
            elif rc != 0 and not got_entry and not failing:
                failing = True
                _log_err("journal reader", RuntimeError(
                    f"journalctl rc={rc}: no portal events until it works (retrying every second)"))
        except Exception as e:
            if not failing:
                failing = True
                _log_err("journal reader (portal)", e)
        finally:
            if p is not None:
                try:
                    p.terminate()
                except Exception:
                    pass
        time.sleep(1.0)


def _reader_proxyguard_start(q: "queue.Queue[Tuple[str, float, Optional[str], Optional[str]]]") -> None:
    cmd = ["tail", "-n", "0", "-F", PROXYGUARD_START_LOG]
    while True:
        p = None
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
            assert p.stdout is not None
            for raw in p.stdout:
                line = raw.strip()
                if not line:
                    continue
                parsed = _parse_proxyguard_start_line(line)
                if parsed is None:
                    continue
                ts, src_ip, src_port = parsed
                q.put(("proxyguard_start", ts, f"{src_ip} {src_port}", None))
        except Exception as e:
            _log_err("proxyguard reader", e)
        finally:
            if p is not None:
                try:
                    p.terminate()
                except Exception:
                    pass
        time.sleep(1.0)


def _wg_poller(corr: Correlator) -> None:
    while True:
        try:
            corr.update_wg_counters()
        except Exception as e:
            _log_err("wg poller", e)
        time.sleep(WG_POLL_SEC)


class GeoIp:
    def __init__(self) -> None:
        self._reader = None
        self._path = ""
        self._mtime = 0.0
        self._next_check = 0.0
        self._langs = [s.strip() for s in GEOIP_LANG.split(",") if s.strip()] or ["en"]
        try:
            import maxminddb  # type: ignore
        except Exception:
            if GEOIP_DB:
                # The operator explicitly asked for GeoIP: don't fail silently.
                _log_err("geoip", RuntimeError("EDUVPN_GEOIP_DB is set but the maxminddb module is not installed"))
            return
        self._open_database = maxminddb.open_database

        paths = (GEOIP_DB,) if GEOIP_DB else GEOIP_DEFAULT_PATHS
        for p in paths:
            if p and os.path.exists(p) and self._open(p):
                return
        if GEOIP_DB and self._reader is None:
            _log_err("geoip", FileNotFoundError(GEOIP_DB))

    def _open(self, path: str) -> bool:
        try:
            mtime = os.stat(path).st_mtime
            self._reader = self._open_database(path)
            self._path, self._mtime = path, mtime
            return True
        except Exception as e:
            _log_err("geoip", RuntimeError(f"cannot open GeoIP database {path}: {e!r}"))
            return False

    def _maybe_reload(self) -> None:
        # geoipupdate replaces the file (weekly, typically) while the open reader
        # keeps serving the old data: reopen it when it changes, checked hourly.
        now = time.time()
        if not self._path or now < self._next_check:
            return
        self._next_check = now + 3600.0
        try:
            changed = os.stat(self._path).st_mtime != self._mtime
        except OSError:
            return  # mid-replacement or removed: keep the reader we have
        old = self._reader
        if changed and self._open(self._path) and old is not None:
            try:
                old.close()
            except Exception:
                pass

    def _name(self, node: object) -> Optional[str]:
        if not isinstance(node, dict):
            return None
        names = node.get("names")
        if not isinstance(names, dict):
            return None
        for lang in self._langs:
            v = names.get(lang)
            if isinstance(v, str) and v:
                return v.replace('"', "'")
        return None

    def lookup(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        self._maybe_reload()
        if self._reader is None or not _is_global_ip(ip):
            return None, None
        try:
            rec = self._reader.get(ip)
        except Exception:
            return None, None
        if not isinstance(rec, dict):
            return None, None
        return self._name(rec.get("country")), self._name(rec.get("city"))


def _parse_proxyguard_start_line(line: str) -> Optional[Tuple[float, str, str]]:
    parts = line.split()
    if not parts:
        return None
    ts_raw = parts[0]
    kv = _split_kv(" ".join(parts[1:]))
    if kv.get("event") != "start":
        return None
    src_ip = kv.get("src_ip")
    if not src_ip:
        return None
    src_port = kv.get("src_port", "-")
    try:
        ts = datetime.fromisoformat(ts_raw).timestamp()
    except Exception:
        ts = time.time()
    return ts, src_ip, src_port


def _split_endpoint(endpoint: str) -> Tuple[Optional[str], Optional[str]]:
    endpoint = endpoint.strip()
    if not endpoint:
        return None, None
    if endpoint.startswith("[") and "]" in endpoint:
        try:
            host, rest = endpoint[1:].split("]", 1)
        except Exception:
            host = ""
            rest = ""
        if rest.startswith(":") and rest[1:].isdigit():
            return host, rest[1:]
        if host:
            return host, None
    if ":" not in endpoint:
        return endpoint, None
    ip, port = endpoint.rsplit(":", 1)
    if not port.isdigit():
        return endpoint, None
    if ip.startswith("[") and ip.endswith("]"):
        ip = ip[1:-1]
    return ip, port


def main() -> None:
    q: "queue.Queue[Tuple[str, float, Optional[str], Optional[str]]]" = queue.Queue()
    corr = Correlator()
    if _DISCONNECT_AFTER_ENV < SYNTH_DISCONNECT_AFTER_SEC:
        _log_err("config", ValueError(
            f"EDUVPN_DISCONNECT_AFTER_SEC={_DISCONNECT_AFTER_ENV:g} is below WireGuard's 180 s key "
            f"lifetime and would cut live sessions; using {SYNTH_DISCONNECT_AFTER_SEC:g}"))

    # WireGuard connect/roam/disconnect events are synthesized internally by the
    # wg poller (_synthesize_wg_events) — no external WireGuard logger required.
    t_portal = threading.Thread(target=_reader_journal, args=(q,), daemon=True)
    t_pg = threading.Thread(target=_reader_proxyguard_start, args=(q,), daemon=True)
    t_poll = threading.Thread(target=_wg_poller, args=(corr,), daemon=True)

    t_portal.start()
    t_pg.start()
    t_poll.start()

    cursor_err_logged = False
    while True:
        source, ts, msg, cursor = q.get()
        try:
            if source == "portal":
                if msg is not None:
                    corr.on_portal(ts, msg)
            elif source == "proxyguard_start" and msg is not None:
                src_ip, src_port = msg.split(" ", 1)
                corr.on_tcp_start(ts, src_ip, src_port)
        except Exception as e:
            _log_err(f"event handling ({source})", e)
        finally:
            # Saved even if handling failed, so one bad entry can't be replayed on
            # every restart.
            if cursor:
                try:
                    _save_cursor(cursor)
                except OSError as e:
                    if not cursor_err_logged:
                        cursor_err_logged = True
                        _log_err("save journal cursor", e)


if __name__ == "__main__":
    main()
