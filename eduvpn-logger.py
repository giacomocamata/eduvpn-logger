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
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import ipaddress
import sqlite3
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple
try:
    import syslog as _syslog
except Exception:
    _syslog = None


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
WG_POLL_SEC = float(os.environ.get("EDUVPN_WG_POLL_SEC", "2.0"))

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


def _san(value: str) -> str:
    # Neutralize whitespace / control chars / kv delimiters in free-text fields
    # (user, profile) so a crafted value from the IdP/portal can't break the
    # structured line or forge extra key=value pairs in the SIEM.
    if not value or value == "-":
        return value
    return re.sub(r'[\s"=]+', "_", value)


def _split_kv(message: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in message.split():
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


def _device_from_client_marker(*markers: str) -> str:
    for m in markers:
        if not m or m == "-":
            continue
        s = str(m).strip().lower()
        m2 = re.search(r"\borg\.eduvpn\.app\.(android|ios|windows|macos|linux)\b", s)
        if m2 is not None:
            return str(m2.group(1))
    return "-"


WG_CONNECTED_PREFIX = " connected from "
WG_DISCONNECTED_PREFIX = " disconnected from "
WG_ROAMED_PREFIX = " roamed to "

# A peer is "active" while its last WireGuard handshake is within this window.
ACTIVE_HANDSHAKE_MAX_AGE_SEC = 180.0
# Emit a disconnect after this many seconds of handshake silence. Overridable via env.
SYNTH_DISCONNECT_AFTER_SEC = float(os.environ.get("EDUVPN_DISCONNECT_AFTER_SEC", "180.0"))
# Defer a synthesized connect this long so the portal event / DB row can attribute it
# to a user before we emit; we emit early as soon as it resolves. Overridable via env.
CONNECT_GRACE_SEC = float(os.environ.get("EDUVPN_CONNECT_GRACE_SEC", "10.0"))
# Minimum gap between two roam events for the same peer. A roam where only the
# source port changed (same IP — typical NAT rebind) is suppressed entirely;
# this caps the rest so a flapping mobile NAT can't spam the SIEM. Env-overridable.
ROAM_MIN_INTERVAL_SEC = float(os.environ.get("EDUVPN_ROAM_MIN_INTERVAL_SEC", "30.0"))

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

        try:
            if not os.path.exists(db_path):
                return
            # Schema detection runs once on a temporary connection. Lookups then use
            # a fresh short-lived connection each time, so rows the portal commits
            # after startup are always visible (a long-lived reader can miss them).
            self._conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1.0)
            self._conn.row_factory = sqlite3.Row
            self._detect_schema()
        except Exception:
            self._query = None
        finally:
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
        if self._query is None:
            return None
        if not conn_id or conn_id == "-":
            return None
        try:
            conn = sqlite3.connect(f"file:{self._db_path}?mode=ro", uri=True, timeout=1.0)
            conn.row_factory = sqlite3.Row
            try:
                row = conn.execute(self._query, (conn_id,)).fetchone()
            finally:
                conn.close()
        except Exception:
            return None
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
        self._hostname = socket.gethostname()
        self._pid = os.getpid()

        self._tcp_start_queue: deque[TcpStartEvent] = deque()
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
        # pubkey -> deadline by which a first-sighting connect must be emitted; while
        # present, the connect is still deferred waiting for user attribution.
        self._virtual_due: Dict[str, float] = {}
        # pubkey -> ts of the last roam line emitted (throttles roam noise).
        self._roam_last: Dict[str, float] = {}
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
        # consume=True claims the matched ProxyGuard start (use only when attributing
        # a *new* TCP tunnel, e.g. a connect) so it can't be reused for another peer.
        if not pubkey or pubkey == "-":
            return "-", "-", "unknown"
        endpoint = self._wg_endpoint_last.get(pubkey, "")
        if not endpoint or endpoint == "(none)":
            return "-", "-", "unknown"
        ip, port = _split_endpoint(endpoint)
        if not ip:
            return "-", "-", "unknown"
        if ip == "127.0.0.1":
            tcp = self._match_tcp_start(ts, consume=consume)
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
            with open(self._out_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
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
        inferred: bool = False,
    ) -> None:
        bytes_in, bytes_out = self._wg_peer_bytes_int(ev.conn)
        if bytes_in is not None and bytes_out is not None:
            self._wg_bytes_baseline[ev.conn] = (bytes_in, bytes_out)
        else:
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
        if inferred:
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
        if country is not None:
            msg += f" country=\"{country}\""
        if city is not None:
            msg += f" city=\"{city}\""
        line = f"{_iso_from_ts(ts)} {msg}"
        self._write_line(line)

    def _wg_peer_bytes_int(self, pubkey: str) -> Tuple[Optional[int], Optional[int]]:
        # Read rx/tx from the poller's snapshot (refreshed every WG_POLL_SEC). No
        # subprocess: this is called while the lock is held, where a blocking
        # `wg show` could stall live event processing.
        if not pubkey or pubkey == "-":
            return None, None
        last = self._wg_bytes_last.get(pubkey)
        if last is None:
            return None, None
        return last[0], last[1]

    @staticmethod
    def _wg_dump() -> Tuple[Dict[str, Tuple[int, int]], Dict[str, int], Dict[str, str], bool]:
        # Spawn `wg show` and parse it. Runs WITHOUT the lock held (called from
        # update_wg_counters before locking), so a slow/hung wg never blocks the
        # event pipeline. The returned `ok` flag is True when wg actually ran
        # (return code 0) — even with zero peers — so the caller can tell a genuine
        # empty fleet (act on it: synthesize disconnects) from a failed poll
        # (skip: don't disconnect everyone because one `wg` call timed out).
        wg = shutil.which("wg") or "wg"
        snap: Dict[str, Tuple[int, int]] = {}
        handshake: Dict[str, int] = {}
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
        if p is not None and p.returncode == 0 and p.stdout:
            for line in p.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) < 9:
                    continue
                if parts[0] == "interface" and parts[1] == "public-key":
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

        if not snap:
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
            if p is not None and p.returncode == 0 and p.stdout:
                current_peer = None
                for raw in p.stdout.splitlines():
                    line = raw.strip()
                    if not line:
                        continue
                    if line.startswith("peer:"):
                        current_peer = line.split(":", 1)[1].strip()
                        continue
                    if current_peer is None:
                        continue
                    if not line.startswith("transfer:"):
                        continue
                    m = re.search(r"transfer:\s*(\d+)\s*received,\s*(\d+)\s*sent", line)
                    if m is None:
                        continue
                    try:
                        rx = int(m.group(1))
                        tx = int(m.group(2))
                    except Exception:
                        continue
                    snap[current_peer] = (rx, tx)

        return snap, handshake, endpoint, ok

    def update_wg_counters(self) -> None:
        # Called periodically by a background thread. The wg subprocess runs here
        # WITHOUT the lock; only the in-memory update + reconciliation are locked.
        snap, handshake, endpoint, ok = self._wg_dump()
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
            if handshake:
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
            ):
                for k in [k for k in d if k not in keep]:
                    d.pop(k, None)
            self._wg_bytes_baseline_pending &= keep
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
                self._virtual_due[pubkey] = now + CONNECT_GRACE_SEC
                continue
            if pubkey in self._virtual_due:
                # Connect deferred and not yet emitted; track the latest endpoint and
                # emit as soon as it can be attributed, or when the grace expires.
                self._virtual_peers[pubkey] = endpoint
                attributed = (
                    self._emitted_connect_ts.get(pubkey, 0.0) > 0.0
                    or self._db.lookup(pubkey) is not None
                )
                if attributed or now >= self._virtual_due[pubkey]:
                    self._virtual_due.pop(pubkey, None)
                    self._handle_wg_event_locked(now, f"{pubkey} connected from {endpoint}")
                continue
            if prev != endpoint:
                self._virtual_peers[pubkey] = endpoint
                # Suppress port-only changes (same IP — typical NAT rebind) and
                # rate-limit the rest, so a flapping mobile NAT can't spam the SIEM.
                prev_ip, _prev_port = _split_endpoint(prev)
                new_ip, _new_port = _split_endpoint(endpoint)
                # Port-only change on a real (non-loopback) IP = NAT rebind -> suppress.
                # For TCP/ProxyGuard the raw IP is always 127.0.0.1, so the real client
                # IP is hidden: treat any endpoint change as a roam candidate.
                real_roam = (new_ip == "127.0.0.1") or (prev_ip != new_ip)
                if real_roam and (now - self._roam_last.get(pubkey, 0.0)) >= ROAM_MIN_INTERVAL_SEC:
                    self._roam_last[pubkey] = now
                    self._handle_wg_event_locked(now, f"{pubkey} roamed to {endpoint}")

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
        now_rx, now_tx = self._wg_peer_bytes_int(pubkey)
        if now_rx is None or now_tx is None:
            last = self._wg_bytes_last.get(pubkey)
            if last is None:
                return "-", "-"
            now_rx, now_tx = last
        base = self._wg_bytes_baseline.get(pubkey)
        if base is None:
            return str(now_rx), str(now_tx)
        base_rx, base_tx = base
        d_rx = now_rx - base_rx
        d_tx = now_tx - base_tx
        if d_rx < 0:
            d_rx = 0
        if d_tx < 0:
            d_tx = 0
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
            if ts < cutoff_src:
                self._pubkey_src.pop(pubkey, None)

        cutoff_pending = now_ts - 20.0
        for pubkey, (ts, ev) in list(self._pending_connect.items()):
            if ts < cutoff_pending:
                if pubkey in self._emitted_connect_ts:
                    # Session already announced; don't emit a second connect.
                    self._pending_connect.pop(pubkey, None)
                    continue
                src_ip, src_port, transport = self._wg_peer_endpoint(now_ts, pubkey, consume=True)
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

    def _match_tcp_start(self, now_ts: float, consume: bool = False) -> Optional[TcpStartEvent]:
        best: Optional[TcpStartEvent] = None
        best_dt = 10_000.0
        for ev in reversed(self._tcp_start_queue):
            dt = now_ts - ev.ts
            if dt < 0:
                continue
            if dt > 120.0:
                break
            if dt < best_dt:
                best = ev
                best_dt = dt
        if consume and best is not None:
            # One ProxyGuard tunnel maps to exactly one peer: claim it so a second
            # peer can't be matched to the same src ip:port.
            try:
                self._tcp_start_queue.remove(best)
            except ValueError:
                pass
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
            if ip == "127.0.0.1":
                tcp = self._match_tcp_start(ts, consume=True)
                if tcp is not None:
                    self._pubkey_src[pubkey] = (ts, tcp.src_ip, tcp.src_port, "tcp")
                else:
                    self._pubkey_src[pubkey] = (ts, "-", "-", "tcp")
                    if pubkey not in self._emitted_connect_ts and pubkey not in self._pending_connect:
                        info = self._conn_info.get(pubkey)
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
                        info = ConnectEvent(
                            ts=ts,
                            user=info.user,
                            profile=info.profile,
                            device=info.device,
                            conn=pubkey,
                            ip4=info.ip4,
                            ip6=info.ip6,
                        )
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

            if ip == "127.0.0.1":
                transport = "tcp"
                tcp = self._match_tcp_start(ts, consume=True)
                if tcp is not None:
                    ip = tcp.src_ip
                    port = tcp.src_port
                else:
                    if src_ip_old not in ("-", "127.0.0.1"):
                        ip = src_ip_old
                        port = src_port_old
                    else:
                        ip = "-"
                        port = "-"
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
                if (ts - self._emitted_disconnect_ts.get(pubkey, 0.0)) < 300.0:
                    self._pubkey_src.pop(pubkey, None)
                    self._pending_connect.pop(pubkey, None)
                    self._conn_info.pop(pubkey, None)
                    self._emitted_connect_ts.pop(pubkey, None)
                    self._peer_last_handshake.pop(pubkey, None)
                    self._wg_bytes_baseline.pop(pubkey, None)
                    self._wg_bytes_baseline_pending.discard(pubkey)
                    self._virtual_peers.pop(pubkey, None)
                    self._virtual_due.pop(pubkey, None)
                    self._prune_locked(ts)
                    return

                src = self._pubkey_src.get(pubkey)
                if src is None:
                    ip, port = _split_endpoint(endpoint)
                    if ip and ip != "127.0.0.1":
                        src_ip, src_port, transport = ip, port or "-", "udp"
                    elif ip == "127.0.0.1":
                        tcp = self._match_tcp_start(ts)
                        if tcp is not None:
                            src_ip, src_port, transport = tcp.src_ip, tcp.src_port, "tcp"
                        else:
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
                self._emit_disconnect(ts, user, profile, pubkey, bytes_in, bytes_out, src_ip, src_port, transport)
                self._emitted_disconnect_ts[pubkey] = ts
                self._peer_last_handshake.pop(pubkey, None)

                self._pubkey_src.pop(pubkey, None)
                self._pending_connect.pop(pubkey, None)
                self._conn_info.pop(pubkey, None)
                self._emitted_connect_ts.pop(pubkey, None)
                self._wg_bytes_baseline.pop(pubkey, None)
                self._virtual_peers.pop(pubkey, None)
                self._virtual_due.pop(pubkey, None)
            self._prune_locked(ts)
            return

    def on_portal(self, ts: float, message: str) -> None:
        with self._lock:
            self._on_portal_locked(ts, message)

    def _on_portal_locked(self, ts: float, message: str) -> None:
        if message.startswith("CONNECT "):
            kv = _split_kv(message[len("CONNECT ") :])
            user = kv.get("USER", "-")
            profile = kv.get("PROFILE", "-")
            conn = kv.get("CONN", "-")
            ip4 = kv.get("IP4", "-")
            ip6 = kv.get("IP6", "-")

            device = "-"
            db = self._db.lookup(conn)
            if db is not None:
                device = _device_from_client_marker(db.client_id, db.display_name)
            ev = ConnectEvent(ts=ts, user=user, profile=profile, device=device, conn=conn, ip4=ip4, ip6=ip6)
            self._conn_info[conn] = ev

            src = self._pubkey_src.get(conn)
            if src is None or (ts - src[0]) > 60.0:
                src_ip, src_port, transport = self._wg_peer_endpoint(ts, conn, consume=True)
                if transport != "unknown":
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
            if transport == "tcp" and (src_ip == "-" or src_ip == "127.0.0.1"):
                self._pending_connect[conn] = (ts, ev)
                self._prune_locked(ts)
                return
            if conn not in self._emitted_connect_ts:
                self._emit_connect(ev, src_ip, src_port, transport)
                self._emitted_connect_ts[conn] = ts
            self._prune_locked(ts)
            return

        if message.startswith("DISCONNECT "):
            kv = _split_kv(message[len("DISCONNECT ") :])
            user = kv.get("USER", "-")
            profile = kv.get("PROFILE", "-")
            conn = kv.get("CONN", "-")
            bytes_in = kv.get("BYTES_IN", "-")
            bytes_out = kv.get("BYTES_OUT", "-")
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
            src = self._pubkey_src.get(conn)
            if src is None:
                src_ip, src_port, transport = self._wg_peer_endpoint(ts, conn)
                self._emit_disconnect(ts, user, profile, conn, bytes_in, bytes_out, src_ip, src_port, transport)
                self._emitted_disconnect_ts[conn] = ts
                self._peer_last_handshake.pop(conn, None)
                self._conn_info.pop(conn, None)
                self._virtual_peers.pop(conn, None)
                self._virtual_due.pop(conn, None)
                self._prune_locked(ts)
                return
            _ts2, src_ip, src_port, transport = src
            self._emit_disconnect(ts, user, profile, conn, bytes_in, bytes_out, src_ip, src_port, transport)
            self._emitted_disconnect_ts[conn] = ts
            self._peer_last_handshake.pop(conn, None)
            self._conn_info.pop(conn, None)
            self._pubkey_src.pop(conn, None)
            self._wg_bytes_baseline.pop(conn, None)
            self._virtual_peers.pop(conn, None)
            self._virtual_due.pop(conn, None)
            self._prune_locked(ts)
            return

        if message.startswith("AUTH OK") or message.startswith("AUTH FAIL"):
            self._prune_locked(ts)
            return


def _reader_journal(cmd: list[str], q: "queue.Queue[Tuple[str, float, str]]", source: str) -> None:
    while True:
        p = None
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            assert p.stdout is not None
            for line in p.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception:
                    continue
                ts = _parse_journal_realtime_ts(entry)
                if ts is None:
                    ts = time.time()
                msg = entry.get("MESSAGE")
                if not isinstance(msg, str) or not msg:
                    continue
                q.put((source, ts, msg))
        except Exception as e:
            _log_err(f"journal reader ({source})", e)
        finally:
            if p is not None:
                try:
                    p.terminate()
                except Exception:
                    pass
        time.sleep(1.0)


def _reader_proxyguard_start(q: "queue.Queue[Tuple[str, float, str]]") -> None:
    cmd = ["tail", "-n", "0", "-F", PROXYGUARD_START_LOG]
    while True:
        p = None
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            assert p.stdout is not None
            for raw in p.stdout:
                line = raw.strip()
                if not line:
                    continue
                parsed = _parse_proxyguard_start_line(line)
                if parsed is None:
                    continue
                ts, src_ip, src_port = parsed
                q.put(("proxyguard_start", ts, f"{src_ip} {src_port}"))
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
        self._langs = [s.strip() for s in GEOIP_LANG.split(",") if s.strip()] or ["en"]
        try:
            import maxminddb  # type: ignore
        except Exception:
            return

        paths = (GEOIP_DB,) if GEOIP_DB else GEOIP_DEFAULT_PATHS
        for p in paths:
            try:
                if p and os.path.exists(p):
                    self._reader = maxminddb.open_database(p)  # type: ignore
                    return
            except Exception:
                self._reader = None

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
    q: "queue.Queue[Tuple[str, float, str]]" = queue.Queue()
    corr = Correlator()

    # WireGuard connect/roam/disconnect events are synthesized internally by the
    # wg poller (_synthesize_wg_events) — no external WireGuard logger required.
    t_portal = threading.Thread(
        target=_reader_journal,
        args=(["journalctl", "-n", "0", "-f", "-o", "json", "-t", "vpn-user-portal", "--no-pager"], q, "portal"),
        daemon=True,
    )
    t_pg = threading.Thread(target=_reader_proxyguard_start, args=(q,), daemon=True)
    t_poll = threading.Thread(target=_wg_poller, args=(corr,), daemon=True)

    t_portal.start()
    t_pg.start()
    t_poll.start()

    while True:
        source, ts, msg = q.get()
        try:
            if source == "portal":
                corr.on_portal(ts, msg)
            elif source == "proxyguard_start":
                src_ip, src_port = msg.split(" ", 1)
                corr.on_tcp_start(ts, src_ip, src_port)
        except Exception as e:
            _log_err(f"event handling ({source})", e)


if __name__ == "__main__":
    main()
