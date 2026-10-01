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
2026-04-15T09:58:03.412871+02:00 event=connect user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" src_ip="203.0.113.45" src_port=48049 transport=udp country="Italy" city="Trieste"
2026-04-15T10:41:22.090113+02:00 event=roam user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" src_ip_old="203.0.113.45" src_port_old=48049 src_ip="198.51.100.12" src_port=51234 transport=udp
2026-04-15T11:02:57.731204+02:00 event=disconnect user=alice profile=staff device=ios conn=soAQTNO...= bytes_in=227252 bytes_out=49292 src_ip="198.51.100.12" src_port=51234 transport=udp
2026-04-15T12:10:05.000000+02:00 event=connect user=bob profile=staff conn=GUUepz8z...= tunnel_ip4="10.20.0.9" tunnel_ip6="fd00:20::9" src_ip="192.0.2.77" src_port=40112 transport=tcp inferred=1
```

(Country/city appear only when GeoIP is configured and the source IP is public.)

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
- **disconnect** — when the eduVPN app disconnects, the portal's own DISCONNECT
  is used directly (with the portal's byte counters). Otherwise — a **WireGuard
  profile imported into a generic WireGuard client**, or *any* peer, app
  included, that stays silent — the disconnect is synthesised once the handshake
  has been silent for `EDUVPN_DISCONNECT_AFTER_SEC` (default 180 s ≈ 3 minutes);
  WireGuard re-handshakes at least every ~2 minutes while traffic flows, so
  silence means the tunnel is idle or gone. Such a line carries `inferred=1` and
  arrives about three minutes after the client stops; if the peer becomes active
  again, a new `connect` follows.

Every line that is **not** backed by a portal event (a connect seen only in
WireGuard and attributed through the portal DB, or a disconnect from handshake
silence) is marked `inferred=1`, so a SIEM can tell observed from derived facts.

The trade-off against a netlink-based logger is resolution: detection happens at
the poll granularity (default 2 s) rather than instantaneously, and a session
shorter than one poll interval may be missed. For eduVPN's long-lived sessions
this is immaterial; lower `EDUVPN_WG_POLL_SEC` if finer granularity is required.

**Restarts.** The daemon persists its position in the journal (the journald
cursor, in `EDUVPN_STATE_DIR`, default `/var/lib/eduvpn-logger`). On start it
resumes right after the last portal entry it processed, so CONNECT/DISCONNECT
events logged while it was down are **replayed with their original
timestamps** (delivery is at-least-once: a crash between processing an entry and
saving the cursor can repeat that one entry). If the saved cursor is unusable
(journal vacuumed, machine-id changed) it logs a warning and starts from "now".

Session state itself is in memory: after a restart, peers that are still active
are re-announced with a `connect` line marked `inferred=1` (timestamped with
their latest handshake, byte counters restarting from there); for TCP sessions
the original ProxyGuard source is not recoverable, so that line has
`src_ip="-"` — the pre-restart `connect` line carries it.

## Requirements

- Linux with `systemd`, `journalctl`, and the `wg` tool (`wireguard-tools`).
- An eduVPN v3 deployment (`vpn-user-portal`) using WireGuard.
- Python 3.9+ (standard library only). GeoIP enrichment needs `maxminddb`.
- *Optional:* Apache with ProxyGuard (eduVPN's TCP-443 fallback) — only needed to
  attribute the real source IP of TCP-fallback sessions; UDP-only deployments can
  skip it entirely (see below).

## Quick start

```bash
git clone https://github.com/giacomocamata/eduvpn-logger.git
cd eduvpn-logger
chmod +x install.sh
sudo ./install.sh
```

`install.sh` is idempotent: it installs dependencies, copies both scripts to
`/usr/local/sbin`, installs both systemd units (enabling `eduvpn-logger`), creates
`/var/log/eduvpn`, and drops the logrotate policy and (if rsyslog is present)
the rsyslog snippet. When it finishes, the
`eduvpn-logger` daemon is **already running** with default settings — verify with
`journalctl -fu eduvpn-logger.service`. To complete the setup, follow the
post-install steps below. For a manual install, see
[Manual install](#manual-install).

## Post-install steps

`install.sh` configures everything it safely can; the rest depends on your site
and is done by hand. Step 1 is required; UDP-only deployments without GeoIP can
skip steps 2–3 and keep the defaults of step 4.

### 1. Portal logging (required)

The portal must write its CONNECT/DISCONNECT events to syslog. In
`/etc/vpn-user-portal/config.php`:

```php
'Log' => [
    'syslogConnectionEvents' => true,
    // Recommended (vpn-user-portal >= 3.5.0): key=value templates, which also
    // carry the portal's byte counters on disconnect.
    'connectLogTemplate'    => 'CONNECT USER={{USER_ID}} PROFILE={{PROFILE_ID}} PROTO={{VPN_PROTO}} CONN={{CONNECTION_ID}} IP4={{IP_FOUR}} IP6={{IP_SIX}}',
    'disconnectLogTemplate' => 'DISCONNECT USER={{USER_ID}} PROFILE={{PROFILE_ID}} PROTO={{VPN_PROTO}} CONN={{CONNECTION_ID}} BYTES_IN={{BYTES_IN}} BYTES_OUT={{BYTES_OUT}}',
],
```

then `sudo vpn-maint-apply-changes`. Without the templates the portal's default
format is parsed too, but its DISCONNECT has no byte counters. Custom templates
must keep the `USER=`, `PROFILE=`, `CONN=` keys (and `IP4=`/`IP6=`, `BYTES_IN=`/
`BYTES_OUT=`); events whose `CONN` is not a WireGuard public key (OpenVPN) are
ignored. Only entries logged by a system account (root, `www-data`, `apache`, …:
UID ≤ `SYS_UID_MAX`) are trusted — see [Limitations](#limitations-and-threat-model).

### 2. Apache / ProxyGuard logging

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

Apply the snippet and reload Apache. The watcher reads
`/var/log/apache2/error.log` by default; if your VirtualHost has its own
ErrorLog, override the command with `sudo systemctl edit proxyguard-watcher`:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'exec tail -n 0 -F /var/log/apache2/vpn.example.org_error.log | python3 -u /usr/local/sbin/proxyguard-watcher.py'
```

```bash
apache2ctl configtest && sudo systemctl reload apache2
sudo systemctl enable --now proxyguard-watcher.service
```

### 3. GeoIP enrichment (optional)

```bash
sudo apt install -y python3-maxminddb geoipupdate   # Debian/Ubuntu
# Put YOUR MaxMind account ID + license key in /etc/GeoIP.conf with
#   EditionIDs GeoLite2-City
sudo geoipupdate -v
```

Without a database the daemon runs unchanged and simply omits `country`/`city`.
`install.sh` already installs the packages; only the license key is manual.

### 4. Customising the configuration

The daemon is configured entirely through environment variables, all optional
(see the [reference table](#configuration-reference)). Defaults match a stock
Debian eduVPN install, so most deployments need no changes.

To override a value, create a systemd drop-in — **do not edit the installed unit**,
`install.sh` replaces it on every run. The unit lists every variable as a
commented `Environment=` line for reference:

```bash
sudo systemctl edit eduvpn-logger.service
```

```ini
[Service]
# example: prefer Italian GeoIP names and a faster poll
Environment=EDUVPN_GEOIP_LANG=it,en
Environment=EDUVPN_WG_POLL_SEC=1.0
```

`systemctl edit` reloads systemd on save; restart the daemon to apply:

```bash
sudo systemctl restart eduvpn-logger.service
```

(For a one-off test you can instead run the script directly with the variables
inline, leaving the installed service untouched — note the separate state
directory, so the test does not move the service's journal cursor:
`sudo EDUVPN_LOG=/tmp/test.log EDUVPN_STATE_DIR=/tmp/eduvpn-test EDUVPN_SYSLOG_IDENT=eduvpn-logger-test eduvpn-logger.py`.)

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
| `EDUVPN_DISCONNECT_AFTER_SEC` | `180.0` | handshake silence before a synthesised disconnect; **minimum 180** (WireGuard's key lifetime — lower values would cut live sessions and are raised, with a warning) |
| `EDUVPN_CONNECT_GRACE_SEC` | `10.0` | max wait to attribute a connect to a user before emitting |
| `EDUVPN_ROAM_MIN_INTERVAL_SEC` | `30.0` | minimum interval between roam events per peer (throttle) |
| `EDUVPN_STATE_DIR` | `/var/lib/eduvpn-logger` | persistent state (journald cursor). **Give a test instance its own directory**, or it will move the production instance's cursor |

Optionally route the daemon's syslog to a dedicated file with
[`examples/rsyslog-10-eduvpn.conf`](examples/rsyslog-10-eduvpn.conf) (installed
by `install.sh` when rsyslog is present; otherwise the events are in the
journal under `-t eduvpn-logger`).

## Output fields

Each line is `<ISO-8601 timestamp with µs and UTC offset> key=value ...`; values
that may contain `:` or spaces are double-quoted. The timestamp is when the event
happened (portal event time, or the WireGuard handshake time for a synthesised
connect), not when the line was written. New keys may be appended in future
versions; parsers should ignore unknown keys.

| Field | Events | Notes |
|---|---|---|
| `event` | all | `connect` / `roam` / `disconnect` |
| `user`, `profile` | all | from portal or DB fallback (`-` if unknown); sanitised |
| `device` | when known | `android`/`ios`/`windows`/`macos`/`linux` |
| `conn` | all | WireGuard public key (correlation key) |
| `tunnel_ip4`, `tunnel_ip6` | connect/roam | assigned VPN IPs |
| `src_ip`, `src_port` | all | public source endpoint (`-` if unknown) |
| `src_ip_old`, `src_port_old` | roam | endpoint before the roam |
| `transport` | all | `udp` (direct) / `tcp` (ProxyGuard) / `unknown` |
| `tcp_candidates` | connect/roam, `tcp` | how many ProxyGuard starts the source was chosen among: `1` = unambiguous, `>1` = the closest in time was picked (see Limitations) |
| `bytes_in`, `bytes_out` | disconnect | server's perspective: `in` = received from the client. From the portal when it reports the disconnect, otherwise the WireGuard counter delta since the connect was observed |
| `inferred` | when `1` | line derived from WireGuard state, not reported by the portal (see above) |
| `country`, `city` | when GeoIP available and IP is public | |

## Limitations and threat model

The output is used as evidence ("who had this IP, from where, when"), so the
assumptions behind each field matter:

- **TCP (ProxyGuard) source IP is a time-based match.** Apache's start event and
  WireGuard's handshake share no identifier, so the closest start in time is
  attributed to the new peer, and each start is used at most once. Two clients
  opening TCP tunnels within the same few seconds can be swapped, and since the
  `/proxyguard/` endpoint is reachable without authentication, a third party can
  add noise by opening tunnels. Every TCP line therefore says how many starts
  were in the window (`tcp_candidates`): treat values above 1 as probable, not
  certain. UDP source IPs come straight from the kernel and are exact. A
  disconnect never borrows a start: if the source is unknown it says
  `src_ip="-"`.
- **Portal events are trusted by journald UID.** `SYSLOG_IDENTIFIER` can be set by
  any local user (`logger -t vpn-user-portal …`), so only entries whose
  journald-stamped `_UID` is a system account (≤ `SYS_UID_MAX` in
  `/etc/login.defs`, normally 999 — root, `www-data`, `apache`) are accepted;
  others are dropped with a warning naming the UID. A compromised *system*
  account can still forge events.
- **Poll granularity.** Endpoints and handshakes are sampled every
  `EDUVPN_WG_POLL_SEC`; a roam and back within one interval is not seen, and
  roams are throttled (`EDUVPN_ROAM_MIN_INTERVAL_SEC`; port-only changes are
  suppressed).
- **Restarts** — portal events are replayed from the journal, session state is
  not; see *Restarts* above.
- **Disconnect time of inferred disconnects** is the moment the silence threshold
  was crossed, i.e. up to `EDUVPN_DISCONNECT_AFTER_SEC` after the last activity.

## Security and privacy

The log holds personal data (user identifiers, public IP addresses, approximate
location). Under the GDPR it needs a purpose, a legal basis and a retention
period, defined by your institution with its DPO.

- **Access.** The unit runs with `UMask=0027` and `install.sh` creates
  `/var/log/eduvpn` as `0750 root:adm`, so the logs are not world-readable.
- **Retention.** [`examples/logrotate-eduvpn`](examples/logrotate-eduvpn) (installed
  by `install.sh`) rotates `/var/log/eduvpn/*.log` daily and keeps 180 days; set
  `rotate` to your policy. `proxyguard_start.log` (client IPs too) lives in
  `/var/log/apache2` and follows the distribution's Apache policy (14 days on
  Debian). Programs that follow `eduvpn.log` must reopen it by name after
  rotation and read the new file from its start (`tail -F` does).
- **Minimisation.** GeoIP is optional; leave it off if location is not needed.
- **Integrity.** A local file can be altered by anyone with root on the VPN server.
  For evidential use, forward the syslog stream to a remote collector/SIEM in
  real time (e.g. rsyslog `omfwd` over TLS, or RELP).
- **Hardening.** The daemon runs as root but its capability bounding set is cut
  to `CAP_NET_ADMIN` (for `wg show`) and `CAP_DAC_READ_SEARCH`/`CAP_DAC_OVERRIDE`
  (to read the `www-data`-owned portal DB, also in WAL mode), with systemd
  sandboxing (`ProtectSystem`, `PrivateDevices`, `RestrictAddressFamilies`,
  `SystemCallFilter`, `MemoryDenyWriteExecute`, …). `proxyguard-watcher` has no
  capabilities and no network at all; check them with
  `systemd-analyze security <unit>`.

## Manual install

```bash
sudo install -m 0755 eduvpn-logger.py /usr/local/sbin/eduvpn-logger.py
sudo install -m 0755 proxyguard-watcher.py /usr/local/sbin/proxyguard-watcher.py
sudo install -m 0644 systemd/eduvpn-logger.service /etc/systemd/system/
sudo install -m 0644 systemd/proxyguard-watcher.service /etc/systemd/system/
sudo install -m 0644 examples/rsyslog-10-eduvpn.conf /etc/rsyslog.d/10-eduvpn.conf   # if rsyslog is installed
sudo install -m 0644 examples/logrotate-eduvpn /etc/logrotate.d/eduvpn-logger
sudo install -d -m 0750 -o root -g adm /var/log/eduvpn
sudo systemctl daemon-reload
sudo systemctl enable --now eduvpn-logger.service
```

Then complete the portal, Apache and GeoIP steps above and enable `proxyguard-watcher.service`.

## License

MIT — see [LICENSE](LICENSE).
