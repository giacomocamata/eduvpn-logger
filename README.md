# eduvpn-logger

*🇮🇹 [Leggi in italiano](README.it.md)*

**Unified, correlated session logging for [eduVPN v3](https://www.eduvpn.org/) (WireGuard).**

## Motivation

In an eduVPN v3 deployment, the facts that describe a single VPN session are
scattered across three independent log sources, and **no source alone is
sufficient** to answer the operationally and forensically essential question
*"who connected, from where, and when?"*:

| Source | Provides | Where |
|---|---|---|
| `vpn-user-portal` | identity: user, profile, WG public key, assigned VPN IPs, transferred bytes | journald (`-t vpn-user-portal`) |
| **WireGuard** (`wg show`) | network endpoint: WG public key ↔ **public source IP:port**; liveness | polled internally |
| Apache **ProxyGuard** | public source IP:port for TCP-443 fallback sessions | file (`proxyguard_start.log`) |

The portal records *who* authenticated but never the public address they came
from; WireGuard, being a stateless protocol with no notion of a "connection",
knows the source endpoint but silently rebinds it on roaming and logs nothing.
Bridging the two is therefore a correlation problem, and the **WireGuard public
key** is the only identifier shared by all three sources.

`eduvpn-logger` is a single-file Python daemon (standard library only) that
performs this correlation in real time and emits **one structured `key=value`
line per session event** — `connect`, `roam`, `disconnect` — to a log file and,
in parallel, to syslog for SIEM ingestion:

```
2026-04-15T09:58:03+02:00 event=connect user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" src_ip="203.0.113.45" src_port=48049 transport=tcp country="Italy" city="Trieste"
2026-04-21T10:57:22+02:00 event=roam user=alice profile=staff conn=GUUepz8z...= tunnel_ip4="10.20.0.5" src_ip_old="203.0.113.45" src_port_old=45851 src_ip="198.51.100.12" src_port=45851 transport=udp
2026-04-15T09:58:20+02:00 event=disconnect user=alice profile=staff conn=soAQTNO...= bytes_in=227252 bytes_out=49292 src_ip="203.0.113.45" transport=tcp
```

> **Scope.** Only **WireGuard** sessions are correlated. OpenVPN is deliberately
> excluded: eduVPN's native OpenVPN logs already expose user, profile, and public
> source IP in a single record, so no additional correlation is warranted there.

## Design highlights

The daemon was extracted from a production deployment (University of Trieste)
and generalised. Its design rests on four decisions worth emphasising:

- **Correlation keyed on the WireGuard public key.** Identity (from the portal)
  and network endpoint (from WireGuard / ProxyGuard) are joined on the one stable
  identifier they share, so the linkage holds even across endpoint roaming and
  across the TCP fallback path.

- **WireGuard events are synthesised internally — no external logger.** WireGuard
  exposes no connect/disconnect notion, so these have to be inferred. The widely
  used [`wglogger`](https://codeberg.org/flaruina/wglogger) infers them from
  conntrack netlink events but, to map a flow back to a peer, ultimately queries
  the same `wg show` data this daemon already polls. The dependency is therefore
  redundant: `eduvpn-logger` reconstructs the events itself from periodic
  snapshots, leaving nothing extra to install or keep alive.

- **Graceful degradation.** Every enrichment is optional and fails safe. With no
  GeoIP database the `country`/`city` fields are simply omitted; when a session
  carries no portal CONNECT event, user and profile are recovered from the portal
  SQLite DB (read-only) by public key. The portal schema is auto-detected by
  column name, so the tool adapts across eduVPN versions without configuration.

- **SIEM-safe output.** User- and profile-derived fields are sanitised before
  serialisation, so a hostile value from the IdP or portal cannot break the line
  format or forge spurious key=value pairs. Roaming events that reflect mere NAT
  port rebinds are suppressed, and the rest are rate-limited per peer to avoid
  flooding the SIEM from flapping mobile clients.

## How WireGuard events are derived

Because WireGuard has no connection concept, every `EDUVPN_WG_POLL_SEC` seconds
the daemon reads each peer's endpoint and last-handshake time from `wg show` and
derives:

- **connect** — a peer becomes active (recent handshake) on a new endpoint. The
  event is briefly deferred (`EDUVPN_CONNECT_GRACE_SEC`, default 10 s) and emitted
  as soon as the portal event or the portal DB attributes the peer to a user, so
  attributable sessions are never logged with `user=-`.
- **roam** — an active peer's endpoint changes (subject to the throttling above).
- **disconnect** — for eduVPN-app sessions the portal's own DISCONNECT is used
  directly. For a **WireGuard profile imported into a generic WireGuard client**
  (i.e. not the eduVPN app) the portal emits nothing, so the disconnect is
  synthesised once the handshake has been silent for `EDUVPN_DISCONNECT_AFTER_SEC`
  (default 180 s ≈ 3 minutes). Expect the `disconnect` line about three minutes
  after such a client stops.

The trade-off against a netlink-based logger is resolution: detection happens at
the poll granularity (default 2 s) rather than instantaneously, and a session
shorter than one poll interval may be missed. For eduVPN's long-lived sessions
this is immaterial; lower `EDUVPN_WG_POLL_SEC` if finer granularity is required.
On restart the daemon reconciles the still-active peers reported by `wg show`,
so it recovers cleanly from a crash.

## Requirements

- Linux with `systemd`, `journalctl`, and the `wg` tool (`wireguard-tools`).
- An eduVPN v3 deployment (`vpn-user-portal`) using WireGuard.
- Apache with ProxyGuard (eduVPN's TCP-443 fallback) — see below.
- Python 3.9+ (standard library only). GeoIP enrichment needs `maxminddb`.

## Quick start

```bash
git clone https://github.com/giacomocamata/eduvpn-logger.git
cd eduvpn-logger
chmod +x install.sh
sudo ./install.sh
```

`install.sh` is idempotent: it installs dependencies, copies both scripts to
`/usr/local/sbin`, installs and enables the systemd units, creates
`/var/log/eduvpn`, and drops the rsyslog snippet. When it finishes, the
`eduvpn-logger` daemon is **already running** with default settings — verify with
`journalctl -fu eduvpn-logger.service`. To complete the setup, follow the
post-install steps below. For a manual install, see
[Manual install](#manual-install).

## Post-install steps

`install.sh` configures everything it safely can; the rest depends on your site
and is done by hand. UDP-only deployments without GeoIP can stop after step 3
(or skip it and keep the defaults).

### 1. Apache / ProxyGuard logging

ProxyGuard tunnels WireGuard over TCP/443, so the kernel sees those packets as
originating from `127.0.0.1`; the client's real public IP is visible **only** to
Apache. Two pieces recover it (full snippet in
[`examples/apache-proxyguard.conf`](examples/apache-proxyguard.conf)):

1. **START events** — raise the proxy log level for `/proxyguard/` only:

   ```apache
   <LocationMatch "^/proxyguard/">
       LogLevel warn proxy:trace1
   </LocationMatch>
   ```

   Apache then emits a `tunnel running` trace line (carrying `[client IP:port]`)
   into the VirtualHost **ErrorLog** at tunnel setup. `proxyguard-watcher.py`
   tails that ErrorLog and rewrites it as compact `event=start` lines in
   `proxyguard_start.log`, which the daemon reads.

2. **END events** — a `CustomLog` recording bytes and duration at tunnel close.

Apply the snippet, point the watcher at *your* VirtualHost ErrorLog by editing
`ExecStart` in `/etc/systemd/system/proxyguard-watcher.service` (default
`/var/log/apache2/error.log`), and reload:

```bash
apache2ctl configtest && sudo systemctl reload apache2
sudo systemctl enable --now proxyguard-watcher.service
```

### 2. GeoIP enrichment (optional)

```bash
sudo apt install -y python3-maxminddb geoipupdate   # Debian/Ubuntu
# Put YOUR MaxMind account ID + license key in /etc/GeoIP.conf with
#   EditionIDs GeoLite2-City
sudo geoipupdate -v
```

Without a database the daemon runs unchanged and simply omits `country`/`city`.
`install.sh` already installs the packages; only the license key is manual.

### 3. Customising the configuration

The daemon is configured entirely through environment variables, all optional
(see the [reference table](#configuration-reference)). Defaults match a stock
Debian eduVPN install, so most deployments need no changes.

To override a value, edit the systemd unit installed at
`/etc/systemd/system/eduvpn-logger.service`. It ships with every variable listed
as a commented `Environment=` line at its default — uncomment the ones you want
and edit them:

```ini
[Service]
# example: prefer Italian GeoIP names and a faster poll
Environment=EDUVPN_GEOIP_LANG=it,en
Environment=EDUVPN_WG_POLL_SEC=1.0
```

Then reload systemd and restart the daemon for the change to take effect:

```bash
sudo systemctl daemon-reload
sudo systemctl restart eduvpn-logger.service
```

(For a one-off test you can instead run the script directly with the variables
inline, e.g. `sudo EDUVPN_LOG=/tmp/test.log eduvpn-logger.py`, leaving the
installed service untouched.)

## Configuration reference

All variables are optional. Defaults match a stock Debian eduVPN install.

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
| `EDUVPN_DISCONNECT_AFTER_SEC` | `180.0` | handshake silence before a synthesised disconnect |
| `EDUVPN_CONNECT_GRACE_SEC` | `10.0` | max wait to attribute a connect to a user before emitting |
| `EDUVPN_ROAM_MIN_INTERVAL_SEC` | `30.0` | minimum interval between roam events per peer (throttle) |

Optionally route the daemon's syslog to a dedicated file with
[`examples/rsyslog-10-eduvpn.conf`](examples/rsyslog-10-eduvpn.conf) (installed
automatically by `install.sh`).

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

Then complete the Apache and GeoIP steps above and enable `proxyguard-watcher.service`.

## Testing

```bash
python3 test_eduvpn_logger.py
```

Covers the pure parsing helpers (endpoint/IPv6 splitting, key=value, device
markers, ProxyGuard line parsing), with no external framework.

## License

MIT — see [LICENSE](LICENSE).
