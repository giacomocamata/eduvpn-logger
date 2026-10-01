# eduvpn-logger

*🇮🇹 [Leggi in italiano](README.it.md)*

**Correlated session logging for [eduVPN v3](https://www.eduvpn.org/) servers using WireGuard.**

On an eduVPN server no single log answers *"which user connected, from which
public IP, and when?"*: the portal knows the user but not the source address,
WireGuard knows the source address but not the user and logs nothing.
`eduvpn-logger` joins the two in real time and writes **one `key=value` line per
session event** (`connect`, `roam`, `disconnect`) to a file and to syslog, ready
for a SIEM:

```
2026-04-15T09:58:03.412871+02:00 event=connect user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" src_ip="203.0.113.45" src_port=48049 transport=udp country="Italy" city="Trieste"
2026-04-15T10:41:22.090113+02:00 event=roam user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" src_ip_old="203.0.113.45" src_port_old=48049 src_ip="198.51.100.12" src_port=51234 transport=udp
2026-04-15T11:02:57.731204+02:00 event=disconnect user=alice profile=staff device=ios conn=soAQTNO...= bytes_in=227252 bytes_out=49292 src_ip="198.51.100.12" src_port=51234 transport=udp
2026-04-15T12:10:05.000000+02:00 event=connect user=bob profile=staff conn=GUUepz8z...= tunnel_ip4="10.20.0.9" tunnel_ip6="fd00:20::9" src_ip="192.0.2.77" src_port=40112 transport=tcp tcp_candidates=1 inferred=1
```

A single-file Python daemon (standard library only), running in production at
the University of Trieste. Only **WireGuard** sessions are handled: for OpenVPN
the portal already logs the source IP itself.

## How it works

The daemon reads the following sources and joins them on the **WireGuard
public key**, the only identifier they share:

| Source | What it provides | How it is read |
|---|---|---|
| `vpn-user-portal` | user, profile, public key, tunnel IPs, byte counters | journald, `SYSLOG_IDENTIFIER=vpn-user-portal` |
| portal database | user/profile/device for a public key (fallback) | `/var/lib/vpn-user-portal/db.sqlite`, table `wg_peers`, read-only |
| WireGuard | public key → public source `IP:port`, last handshake | `wg show all dump`, every 2 s |
| ProxyGuard *(optional)* | real client `IP:port` of TCP/443 sessions | Apache `ErrorLog` → `proxyguard-watcher` → `proxyguard_start.log` |

WireGuard has no notion of a connection, so events are derived from the polled
peer state:

- **connect**: a peer completes a handshake on a new endpoint. The line is held
  for up to 10 s until the portal event or the portal DB names the user.
- **roam**: the source IP of an active peer changes. Port-only changes (NAT
  rebinding) are ignored; roams are limited to one per peer every 30 s.
- **disconnect**: taken from the portal's DISCONNECT when the eduVPN app
  disconnects; otherwise (generic WireGuard client, or an idle tunnel) emitted
  after 180 s without a handshake, WireGuard's key lifetime.

Lines not backed by a portal event carry **`inferred=1`**. With ProxyGuard the
kernel sees every client as `127.0.0.1`: the real IP is taken from the Apache
tunnel-start event closest in time, and `tcp_candidates` reports how many
starts were candidates (see [Limitations](#limitations)).

The daemon saves its journal position in `/var/lib/eduvpn-logger`: portal
events logged while it was stopped are processed on the next start, with their
original timestamps.

## Requirements

- eduVPN v3 server (`vpn-user-portal`) with WireGuard, on a systemd-based Linux.
  Tested on Debian/Ubuntu; Fedora/EL need the path adjustments noted below.
- `wireguard-tools` (`wg`) and Python ≥ 3.9, standard library only (both
  installed by `install.sh`).
- *Optional:* `python3-maxminddb` and a MaxMind GeoLite2-City database for
  `country`/`city`.

## Installation

### 1. Enable portal connection logging (required)

In `/etc/vpn-user-portal/config.php`, inside the `Log` section:

```php
'Log' => [
    'syslogConnectionEvents' => true,
    // recommended (vpn-user-portal >= 3.5.0): parsed reliably and carries byte counters
    'connectLogTemplate'    => 'CONNECT USER={{USER_ID}} PROFILE={{PROFILE_ID}} PROTO={{VPN_PROTO}} CONN={{CONNECTION_ID}} IP4={{IP_FOUR}} IP6={{IP_SIX}}',
    'disconnectLogTemplate' => 'DISCONNECT USER={{USER_ID}} PROFILE={{PROFILE_ID}} PROTO={{VPN_PROTO}} CONN={{CONNECTION_ID}} BYTES_IN={{BYTES_IN}} BYTES_OUT={{BYTES_OUT}}',
],
```

The setting is read on the next portal request; `vpn-maint-apply-changes` is not
needed. Without the two templates the portal's default format is used and also
understood, but disconnects then carry no byte counters. Custom templates must
keep the `USER=`, `PROFILE=` and `CONN=` keys. Reference:
[eduVPN logging](https://docs.eduvpn.org/server/v3/logging.html).

Check that events arrive (connect a client first):

```bash
journalctl -t vpn-user-portal -n 5
```

### 2. Install the daemon

```bash
git clone https://github.com/giacomocamata/eduvpn-logger.git
cd eduvpn-logger
sudo ./install.sh
```

`install.sh` is idempotent and does the following:

| Item | Path |
|---|---|
| packages | `wireguard-tools`, `python3` (required); `python3-maxminddb`, `geoipupdate` (optional, skipped if unavailable) |
| programs | `/usr/local/sbin/eduvpn-logger.py`, `/usr/local/sbin/proxyguard-watcher.py` |
| systemd units | `/etc/systemd/system/eduvpn-logger.service` (enabled and started), `proxyguard-watcher.service` (installed, not enabled) |
| log directory | `/var/log/eduvpn`, `2750 root:adm` (setgid: new files get group `adm`) |
| state | `/var/lib/eduvpn-logger` (journal cursor) |
| log rotation | `/etc/logrotate.d/eduvpn-logger` |
| syslog routing | `/etc/rsyslog.d/10-eduvpn.conf`, only if rsyslog is installed and runs as root (Debian, Fedora/EL; not Ubuntu, where it runs as `syslog` and could not write to `/var/log/eduvpn`) |

<details>
<summary>Manual installation (without <code>install.sh</code>)</summary>

```bash
sudo apt install -y wireguard-tools python3    # dnf on Fedora/EL
sudo install -m 0755 eduvpn-logger.py proxyguard-watcher.py /usr/local/sbin/
sudo install -m 0644 systemd/eduvpn-logger.service systemd/proxyguard-watcher.service /etc/systemd/system/
sudo install -m 0644 examples/logrotate-eduvpn /etc/logrotate.d/eduvpn-logger
sudo install -m 0644 examples/rsyslog-10-eduvpn.conf /etc/rsyslog.d/10-eduvpn.conf   # only with rsyslog
sudo install -d -m 2750 -o root -g adm /var/log/eduvpn
sudo systemctl daemon-reload
sudo systemctl enable --now eduvpn-logger.service
```

</details>

### 3. ProxyGuard source IPs (only if ProxyGuard is enabled)

With [ProxyGuard](https://docs.eduvpn.org/server/v3/wireguard.html) clients
reach WireGuard through Apache, so only Apache knows their address. Add to the
eduVPN VirtualHost (full snippet:
[`examples/apache-proxyguard.conf`](examples/apache-proxyguard.conf)):

```apache
<LocationMatch "^/proxyguard/">
    LogLevel warn proxy:trace1
</LocationMatch>
```

Apache then writes one `AH10212 ... tunnel running` line with `[client IP:port]`
to the VirtualHost `ErrorLog` when a tunnel opens; `proxyguard-watcher` turns it
into `/var/log/apache2/proxyguard_start.log`, which the daemon reads. The
`CustomLog` part of the snippet is optional and not used by the daemon.

```bash
sudo apache2ctl configtest && sudo systemctl reload apache2
sudo systemctl enable --now proxyguard-watcher.service
```

The watcher reads `/var/log/apache2/error.log`. If the VirtualHost has its own
`ErrorLog`, or on Fedora/EL (`/var/log/httpd/`), override the command:

```bash
sudo systemctl edit proxyguard-watcher.service
```

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'exec tail -n 0 -F /var/log/httpd/vpn.example.org_ssl_error_log | python3 -u /usr/local/sbin/proxyguard-watcher.py'
Environment=EDUVPN_PROXYGUARD_START_LOG=/var/log/httpd/proxyguard_start.log
```

On Fedora/EL set the same `EDUVPN_PROXYGUARD_START_LOG` for `eduvpn-logger` too
(see [Configuration](#configuration)).

### 4. GeoIP (optional)

Requires a free [MaxMind](https://www.maxmind.com/en/geolite2/signup) account.
Put the account ID and license key in `/etc/GeoIP.conf` with
`EditionIDs GeoLite2-City`, then:

```bash
sudo geoipupdate -v      # on Debian the package is in "contrib"
sudo systemctl restart eduvpn-logger.service
```

The database is found in `/usr/local/share/GeoIP`, `/usr/share/GeoIP` or
`/var/lib/GeoIP`. Without it, `country` and `city` are simply omitted.

### 5. Verify

Connect a client with the eduVPN app and watch the output:

```bash
sudo tail -f /var/log/eduvpn/eduvpn.log
```

A `connect` line with the user and the public source IP should appear within a
few seconds of the tunnel coming up. Warnings from the daemon are in
`journalctl -u eduvpn-logger.service`.

| Symptom | Likely cause |
|---|---|
| no lines at all | portal logging not enabled (step 1), or service not running: `systemctl status eduvpn-logger` |
| `user=-` on connect lines | portal DB not found or not readable: check `EDUVPN_PORTAL_DB` |
| `transport=tcp src_ip="-"` | ProxyGuard step missing, or watcher reading the wrong `ErrorLog`: `systemctl status proxyguard-watcher`, `tail /var/log/apache2/proxyguard_start.log` |
| warning `ignoring unparsable/non-WireGuard event` | custom log template without `CONN=`, or an OpenVPN event (ignored by design) |
| warning `untrusted _UID=…` | a portal event logged by a non-system account was rejected (see [Limitations](#limitations)) |

## Configuration

All settings are environment variables with defaults for a standard Debian
eduVPN server. Change them with a systemd drop-in, which survives re-installs
(the unit file itself lists every variable for reference):

```bash
sudo systemctl edit eduvpn-logger.service
```

```ini
[Service]
Environment=EDUVPN_GEOIP_LANG=it,en
```

```bash
sudo systemctl restart eduvpn-logger.service
```

| Variable | Default | Meaning |
|---|---|---|
| `EDUVPN_LOG` | `/var/log/eduvpn/eduvpn.log` | output file |
| `EDUVPN_PORTAL_DB` | `/var/lib/vpn-user-portal/db.sqlite` | portal database (read-only) |
| `EDUVPN_PROXYGUARD_START_LOG` | `/var/log/apache2/proxyguard_start.log` | file written by `proxyguard-watcher` |
| `EDUVPN_STATE_DIR` | `/var/lib/eduvpn-logger` | journal cursor |
| `EDUVPN_GEOIP_DB` | *(searched)* | path of `GeoLite2-City.mmdb` |
| `EDUVPN_GEOIP_LANG` | `en` | language(s) of place names, e.g. `it,en` |
| `EDUVPN_SYSLOG_IDENT` | `eduvpn-logger` | syslog program name |
| `EDUVPN_SYSLOG_FACILITY` | `local0` | syslog facility |
| `EDUVPN_WG_POLL_SEC` | `2.0` | `wg show` polling interval, seconds |
| `EDUVPN_CONNECT_GRACE_SEC` | `10.0` | max wait for user attribution before writing a connect |
| `EDUVPN_DISCONNECT_AFTER_SEC` | `180.0` | handshake silence before an inferred disconnect; values below 180 are raised to 180 |
| `EDUVPN_ROAM_MIN_INTERVAL_SEC` | `30.0` | minimum interval between roam lines per peer |

The syslog copy goes to the journal (`journalctl -t eduvpn-logger`) and, with
rsyslog, to `/var/log/eduvpn/eduvpn-syslog.log`; forward it to your SIEM from
there. To try settings without touching the service, run a second instance with
its own output and state directory:

```bash
sudo EDUVPN_LOG=/tmp/test.log EDUVPN_STATE_DIR=/tmp/eduvpn-test EDUVPN_SYSLOG_IDENT=eduvpn-logger-test /usr/local/sbin/eduvpn-logger.py
```

## Log format

`<ISO-8601 timestamp, µs, UTC offset> key=value ...`. The timestamp is when the
event happened, not when the line was written. Values that may contain `:` or
spaces are double-quoted; `user` and `profile` are sanitised so they cannot
inject extra keys. New keys may be added in future versions: ignore unknown ones.

| Field | Events | Meaning |
|---|---|---|
| `event` | all | `connect`, `roam`, `disconnect` |
| `user`, `profile` | all | from the portal or its DB; `-` if unknown |
| `device` | when known | `android`, `ios`, `windows`, `macos`, `linux` (eduVPN app) |
| `conn` | all | WireGuard public key |
| `tunnel_ip4`, `tunnel_ip6` | connect, roam | addresses assigned inside the VPN |
| `src_ip`, `src_port` | all | public source address; `-` if unknown |
| `src_ip_old`, `src_port_old` | roam | source address before the roam |
| `transport` | all | `udp`, `tcp` (ProxyGuard) or `unknown` |
| `tcp_candidates` | connect, roam over `tcp` | tunnel starts the source IP was chosen among; `1` = unambiguous |
| `bytes_in`, `bytes_out` | disconnect | seen from the server (`in` = sent by the client); from the portal, or WireGuard counters for inferred disconnects |
| `inferred` | when `1` | derived from WireGuard state, not reported by the portal |
| `country`, `city` | with GeoIP, public IPs | location of `src_ip` |

## Limitations

- **ProxyGuard source IPs are matched by time.** Apache's tunnel start and the
  WireGuard handshake share no identifier, so the closest start is used, once.
  Clients opening TCP tunnels within the same few seconds can be swapped, and
  `/proxyguard/` is reachable without authentication. Treat `tcp_candidates`
  above 1 as probable, not certain. UDP source IPs come from the kernel and are
  exact.
- **Portal events are trusted by sender.** Any local user can write to the
  journal with `logger -t vpn-user-portal`; only entries whose `_UID` (set by
  journald) is a system account (≤ `SYS_UID_MAX`, normally 999: root,
  `www-data`, `apache`) are accepted.
- **Inferred disconnects** are written when the 180 s silence threshold is
  crossed, i.e. up to 3 minutes after the last activity.
- **After a restart** the daemon does not know which sessions it had already
  logged: active peers get a new `connect` with `inferred=1` (for ProxyGuard
  sessions with `src_ip="-"`; the line written before the restart has the IP).
- Events are sampled every `EDUVPN_WG_POLL_SEC`: a roam and back within one
  interval is not seen.

## Security and privacy

The log contains personal data (user IDs, public IPs, location): define purpose,
legal basis and retention with your Data Protection Officer.

- **Access**: logs are created `0640 root:adm` in a `2750` directory.
- **Retention**: `/etc/logrotate.d/eduvpn-logger` rotates daily and keeps 180
  days; change `rotate` to your policy. `proxyguard_start.log` follows the
  distribution's Apache rotation (14 days on Debian).
- **Integrity**: anyone with root on the server can alter a local file; for
  evidential use, forward the syslog stream to a remote collector in real time
  (rsyslog `omfwd` over TLS, or RELP).
- **Privileges**: both services run as root inside a systemd sandbox.
  `eduvpn-logger` keeps only `CAP_NET_ADMIN` (`wg show`) and
  `CAP_DAC_READ_SEARCH`/`CAP_DAC_OVERRIDE` (reading the portal DB);
  `proxyguard-watcher` has no capabilities and no network. Inspect with
  `systemd-analyze security eduvpn-logger.service`.

## Upgrade and removal

Upgrade (drop-ins and logs are kept; running services are restarted, a
service you stopped or disabled is left alone):

```bash
cd eduvpn-logger && git pull && sudo ./install.sh
```

Removal (logs in `/var/log/eduvpn` are left in place):

```bash
sudo systemctl disable --now eduvpn-logger.service proxyguard-watcher.service
sudo rm -f /usr/local/sbin/eduvpn-logger.py /usr/local/sbin/proxyguard-watcher.py \
    /etc/systemd/system/eduvpn-logger.service /etc/systemd/system/proxyguard-watcher.service \
    /etc/logrotate.d/eduvpn-logger /etc/rsyslog.d/10-eduvpn.conf
sudo rm -rf /etc/systemd/system/eduvpn-logger.service.d \
    /etc/systemd/system/proxyguard-watcher.service.d /var/lib/eduvpn-logger
sudo systemctl daemon-reload
```

Then remove the `LocationMatch` block from the Apache VirtualHost if you added it.

## License

MIT, see [LICENSE](LICENSE).
