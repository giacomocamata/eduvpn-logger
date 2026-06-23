# eduvpn-logger

*🇮🇹 [Leggi in italiano](README.it.md)*

Unified, correlated session logging for **eduVPN v3** (WireGuard).

eduVPN spreads the facts about a single VPN session across three independent
logs, and **none of them alone tells the full story**:

| Source | Provides | Where |
|---|---|---|
| `vpn-user-portal` | user, profile, WG public key, assigned VPN IPs, bytes | journald (`-t vpn-user-portal`) |
| **WireGuard** (`wg show`) | WG public key ↔ **public source IP:port**, connect/roam/disconnect | polled internally (no external daemon) |
| Apache **ProxyGuard** | public source IP:port for TCP-443 sessions | file (`proxyguard_start.log`) |

The portal knows *who* connected but not *from where*; WireGuard is stateless and
silently updates a peer's endpoint without logging it. This daemon stitches the
sources together — keyed on the **WireGuard public key** — and emits **one
structured line per session event**:

```
2026-04-15T09:58:03+02:00 event=connect user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" src_ip="203.0.113.45" src_port=48049 transport=tcp country="Italy" city="Trieste"
2026-04-21T10:57:22+02:00 event=roam user=alice profile=staff conn=GUUepz8z...= tunnel_ip4="10.20.0.5" src_ip_old="203.0.113.45" src_port_old=45851 src_ip="198.51.100.12" src_port=45851 transport=udp
2026-04-15T09:58:20+02:00 event=disconnect user=alice profile=staff conn=soAQTNO...= bytes_in=227252 bytes_out=49292 src_ip="203.0.113.45" transport=tcp
```

Output goes to a log file **and** to syslog (`local0` by default) for SIEM ingestion.

> **Scope:** this tool covers **WireGuard** sessions only. OpenVPN is intentionally
> left out — eduVPN's official OpenVPN logs already expose user, profile and public
> source IP, so no extra correlation is needed there.

## Features

- **One line per CONNECT / ROAM / DISCONNECT**, structured key=value.
- **Public source IP** resolution for both UDP and TCP (ProxyGuard) sessions.
- **GeoIP** enrichment (MaxMind GeoLite2 City) — optional, degrades gracefully if absent.
- **SQLite fallback**: when a session has no portal CONNECT event, user/profile are
  resolved from the portal DB (read-only) by WireGuard public key — provided the
  portal still holds a peer row for that key.
- **Device detection**: tags `device=android|ios|windows|macos|linux` when the
  official eduVPN app marker is present.
- **No external WireGuard logger**: connect/roam/disconnect are detected internally
  by polling `wg show` — no `wglogger`/netlink daemon to install or keep running.
- **Crash recovery**: on restart, reconciles still-active peers from `wg show`.

## Requirements

- Linux with `systemd`, `journalctl`, and the `wg` tool (`wireguard-tools`).
- An eduVPN v3 deployment (`vpn-user-portal`) using WireGuard.
- Apache with ProxyGuard (ships with eduVPN's TCP-443 fallback) — see below.
- Python 3.9+ (stdlib only). GeoIP needs `maxminddb` (optional).

## Quick start

```bash
git clone https://github.com/giacomocamata/eduvpn-logger.git
cd eduvpn-logger
chmod +x install.sh
sudo ./install.sh
```

`install.sh` is idempotent: it installs dependencies, copies both scripts to
`/usr/local/sbin`, installs and enables the systemd units, creates `/var/log/eduvpn`,
and drops the rsyslog snippet. It then prints the two steps that can't be safely
automated — the MaxMind GeoIP license and the Apache VirtualHost edit (both below).

For a manual install instead, see [Manual install](#manual-install).

## WireGuard event detection (built-in)

There is no "connection" concept in WireGuard, so connect/roam/disconnect have to
be inferred. The well-known [`wglogger`](https://codeberg.org/flaruina/wglogger)
does this via conntrack netlink events, but to associate a flow to a peer it simply
queries `wg show` (`wgctrl`) — the very same data this correlator already polls.

So instead of depending on an external daemon, the correlator reconstructs the
events itself: every `EDUVPN_WG_POLL_SEC` seconds it reads each peer's endpoint and
last-handshake from `wg show` and emits:

- **connect** — a peer becomes active (recent handshake) with a new endpoint. The
  connect is briefly deferred (`EDUVPN_CONNECT_GRACE_SEC`, default 10 s) and emitted
  as soon as the portal event or the portal DB attributes it to a user, so connect
  lines aren't logged with `user=-` for attributable sessions;
- **roam** — an active peer's endpoint changes;
- **disconnect** — for eduVPN-app sessions the portal's DISCONNECT fires immediately
  and is used. For a **WireGuard profile downloaded and imported into a generic
  WireGuard client** (i.e. *not* the eduVPN app) there is no portal event, so the
  disconnect is synthesized after the handshake stays silent for
  `EDUVPN_DISCONNECT_AFTER_SEC` — **default 180 s (~3 minutes)**, configurable. In
  that case expect the `disconnect` line about 3 minutes after the client stops.

Trade-off vs. a netlink logger: detection happens at the poll resolution (default
2 s) rather than instantly, and a session shorter than one poll interval may be
missed. For eduVPN's long-lived sessions this is not a concern; lower
`EDUVPN_WG_POLL_SEC` if you need finer granularity.

## Apache / ProxyGuard logging

ProxyGuard tunnels WireGuard over TCP/443. The kernel sees those packets as coming
from `127.0.0.1`, so the client's real public IP is **only** visible to Apache. Two
pieces recover it (full snippet in [`examples/apache-proxyguard.conf`](examples/apache-proxyguard.conf)):

1. **START events** — raise the proxy log level for `/proxyguard/` only:

   ```apache
   <LocationMatch "^/proxyguard/">
       LogLevel warn proxy:trace1
   </LocationMatch>
   ```

   This makes Apache emit a `tunnel running` trace line (with `[client IP:port]`)
   into the VirtualHost **ErrorLog** at tunnel setup. `proxyguard-watcher.py` tails
   that ErrorLog and rewrites it as compact `event=start` lines in
   `proxyguard_start.log`, which the correlator reads.

2. **END events** — a `CustomLog` with bytes and duration, written when the tunnel closes.

Apply the snippet, then point the watcher at *your* VirtualHost ErrorLog by editing
`ExecStart` in `/etc/systemd/system/proxyguard-watcher.service` (default
`/var/log/apache2/error.log`), and reload:

```bash
apache2ctl configtest && sudo systemctl reload apache2
sudo systemctl enable --now proxyguard-watcher.service
```

## GeoIP (optional)

```bash
sudo apt install -y python3-maxminddb geoipupdate   # Debian/Ubuntu
# Put YOUR MaxMind account ID + license key in /etc/GeoIP.conf with
#   EditionIDs GeoLite2-City
sudo geoipupdate -v
```

Without a database the correlator runs fine and simply omits `country`/`city`.

## Configuration

Everything is set through environment variables (all optional). Put overrides in
the systemd unit. Defaults match a stock Debian eduVPN install.

| Variable | Default | Meaning |
|---|---|---|
| `EDUVPN_LOG` | `/var/log/eduvpn/eduvpn.log` | Unified output log file |
| `EDUVPN_PORTAL_DB` | `/var/lib/vpn-user-portal/db.sqlite` | Portal DB (read-only fallback) |
| `EDUVPN_PROXYGUARD_START_LOG` | `/var/log/apache2/proxyguard_start.log` | ProxyGuard START events |
| `EDUVPN_GEOIP_DB` | *(auto-detect)* | Explicit path to GeoLite2-City.mmdb |
| `EDUVPN_GEOIP_LANG` | `en` | Preferred name language(s), comma-separated (e.g. `it,en`) |
| `EDUVPN_SYSLOG_IDENT` | `eduvpn-logger` | syslog program name |
| `EDUVPN_SYSLOG_FACILITY` | `local0` | syslog facility (`local0`..`local7`) |
| `EDUVPN_WG_POLL_SEC` | `2.0` | `wg show` polling interval (seconds) |
| `EDUVPN_DISCONNECT_AFTER_SEC` | `180.0` | handshake silence before a synthesized disconnect |
| `EDUVPN_CONNECT_GRACE_SEC` | `10.0` | max wait to attribute a connect to a user before emitting |

The portal DB schema is **auto-detected** (columns are matched by name), so the
tool adapts across eduVPN versions without configuration.

Optional: route correlator syslog to its own file with
[`examples/rsyslog-10-eduvpn.conf`](examples/rsyslog-10-eduvpn.conf)
(installed automatically by `install.sh`).

## Output fields

| Field | Events | Notes |
|---|---|---|
| `event` | all | `connect` / `roam` / `disconnect` |
| `user`, `profile` | all | from portal or DB fallback (`-` if unknown) |
| `device` | when known | `android`/`ios`/`windows`/`macos`/`linux` |
| `conn` | all | WireGuard public key (correlation key) |
| `tunnel_ip4`, `tunnel_ip6` | connect/roam | assigned VPN IPs |
| `src_ip`, `src_port` | all | public source endpoint |
| `transport` | all | `udp` (direct) / `tcp` (ProxyGuard) / `unknown` |
| `bytes_in`, `bytes_out` | disconnect | session totals |
| `country`, `city` | when GeoIP available and IP is public | |

## Manual install

```bash
sudo install -m 0755 eduvpn-logger.py /usr/local/sbin/eduvpn-logger.py
sudo install -m 0755 proxyguard-watcher.py /usr/local/sbin/proxyguard-watcher.py
sudo install -m 0644 systemd/eduvpn-logger.service /etc/systemd/system/
sudo install -m 0644 systemd/proxyguard-watcher.service /etc/systemd/system/
sudo install -m 0644 examples/rsyslog-10-eduvpn.conf /etc/rsyslog.d/10-eduvpn.conf
sudo mkdir -p /var/log/eduvpn
sudo systemctl daemon-reload
sudo systemctl enable --now eduvpn-logger.service
```

Then do the Apache and GeoIP steps above and enable `proxyguard-watcher.service`.

## Testing

```bash
python3 test_eduvpn_logger.py
```

Covers the pure parsing helpers (endpoint/IPv6 splitting, key=value, device
markers, ProxyGuard line parsing).

## License

MIT — see [LICENSE](LICENSE).
