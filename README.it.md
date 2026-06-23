# eduvpn-logger

*🇬🇧 [Read in English](README.md) (versione principale)*

Logging di sessione unificato e correlato per **eduVPN v3** (WireGuard).

eduVPN distribuisce le informazioni su una singola sessione VPN su tre log
indipendenti, e **nessuno di essi da solo racconta la storia completa**:

| Sorgente | Fornisce | Dove |
|---|---|---|
| `vpn-user-portal` | utente, profilo, public key WG, IP VPN assegnati, byte | journald (`-t vpn-user-portal`) |
| **WireGuard** (`wg show`) | public key WG ↔ **IP:porta pubblici sorgente**, connect/roam/disconnect | polling interno (nessun daemon esterno) |
| Apache **ProxyGuard** | IP:porta pubblici per sessioni TCP-443 | file (`proxyguard_start.log`) |

Il portale sa *chi* si è connesso ma non *da dove*; WireGuard è stateless e aggiorna
silenziosamente l'endpoint del peer senza registrarlo. Questo daemon unisce le
sorgenti — usando come chiave la **public key WireGuard** — ed emette **una riga
strutturata per evento di sessione**:

```
2026-04-15T09:58:03+02:00 event=connect user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" src_ip="203.0.113.45" src_port=48049 transport=tcp country="Italy" city="Trieste"
2026-04-21T10:57:22+02:00 event=roam user=alice profile=staff conn=GUUepz8z...= tunnel_ip4="10.20.0.5" src_ip_old="203.0.113.45" src_port_old=45851 src_ip="198.51.100.12" src_port=45851 transport=udp
2026-04-15T09:58:20+02:00 event=disconnect user=alice profile=staff conn=soAQTNO...= bytes_in=227252 bytes_out=49292 src_ip="203.0.113.45" transport=tcp
```

L'output va su un file di log **e** su syslog (`local0` di default) per integrazione SIEM.

> **Ambito:** questo strumento copre solo le sessioni **WireGuard**. OpenVPN è escluso
> di proposito — i log OpenVPN ufficiali di eduVPN espongono già utente, profilo e IP
> pubblico sorgente, quindi lì non serve alcuna correlazione aggiuntiva.

## Funzionalità

- **Una riga per CONNECT / ROAM / DISCONNECT**, strutturata key=value.
- **Risoluzione dell'IP pubblico sorgente** sia per sessioni UDP che TCP (ProxyGuard).
- **GeoIP** (MaxMind GeoLite2 City) — opzionale, degrada con grazia se assente.
- **Fallback SQLite**: quando una sessione non ha un evento CONNECT del portale,
  utente/profilo sono risolti dal DB del portale (sola lettura) tramite public key
  WireGuard — purché il portale abbia ancora una riga per quella chiave.
- **Rilevamento dispositivo**: aggiunge `device=android|ios|windows|macos|linux`
  quando è presente il marker dell'app eduVPN ufficiale.
- **Nessun logger WireGuard esterno**: connect/roam/disconnect sono rilevati
  internamente con il polling di `wg show` — niente daemon `wglogger`/netlink da
  installare o mantenere.
- **Recovery dopo crash**: al riavvio ricostruisce i peer ancora attivi da `wg show`.

## Requisiti

- Linux con `systemd`, `journalctl` e il comando `wg` (`wireguard-tools`).
- Un deployment eduVPN v3 (`vpn-user-portal`) basato su WireGuard.
- Apache con ProxyGuard (incluso nel fallback TCP-443 di eduVPN) — vedi sotto.
- Python 3.9+ (solo stdlib). GeoIP richiede `maxminddb` (opzionale).

## Avvio rapido

```bash
git clone https://github.com/giacomocamata/eduvpn-logger.git
cd eduvpn-logger
chmod +x install.sh
sudo ./install.sh
```

`install.sh` è idempotente: installa le dipendenze, copia entrambi gli script in
`/usr/local/sbin`, installa e abilita le unit systemd, crea `/var/log/eduvpn` e
inserisce lo snippet rsyslog. Alla fine stampa i due passaggi che non possono essere
automatizzati in sicurezza — la licenza GeoIP MaxMind e la modifica del VirtualHost
Apache (entrambi sotto).

Per l'installazione manuale vedi [Installazione manuale](#installazione-manuale).

## Rilevamento eventi WireGuard (integrato)

In WireGuard non esiste il concetto di "connessione", quindi connect/roam/disconnect
vanno dedotti. Il noto [`wglogger`](https://codeberg.org/flaruina/wglogger) lo fa con
gli eventi netlink di conntrack, ma per associare un flusso a un peer interroga
semplicemente `wg show` (`wgctrl`) — gli stessi dati che questo correlatore già polla.

Perciò, invece di dipendere da un daemon esterno, il correlatore ricostruisce gli
eventi da solo: ogni `EDUVPN_WG_POLL_SEC` secondi legge endpoint e ultimo handshake di
ogni peer da `wg show` ed emette:

- **connect** — un peer diventa attivo (handshake recente) con un nuovo endpoint. La
  connect è brevemente differita (`EDUVPN_CONNECT_GRACE_SEC`, default 10 s) ed emessa
  appena l'evento del portale o il DB del portale la attribuiscono a un utente, così le
  righe di connect non escono con `user=-` per le sessioni attribuibili;
- **roam** — l'endpoint di un peer attivo cambia;
- **disconnect** — per le sessioni con app eduVPN il DISCONNECT del portale arriva
  subito e viene usato. Per un **profilo WireGuard scaricato e importato in un client
  WireGuard generico** (cioè *senza* l'app eduVPN) non c'è alcun evento dal portale,
  quindi il disconnect è sintetizzato dopo che l'handshake tace per
  `EDUVPN_DISCONNECT_AFTER_SEC` — **default 180 s (~3 minuti)**, configurabile. In quel
  caso l'`event=disconnect` arriva circa 3 minuti dopo che il client smette.

Compromesso rispetto a un logger netlink: il rilevamento avviene alla risoluzione del
poll (default 2 s) invece che istantaneamente, e una sessione più breve di un intervallo
di poll può sfuggire. Per le sessioni a lunga durata di eduVPN non è un problema;
abbassa `EDUVPN_WG_POLL_SEC` se ti serve maggiore granularità.

## Logging Apache / ProxyGuard

ProxyGuard incapsula WireGuard su TCP/443. Il kernel vede quei pacchetti come
provenienti da `127.0.0.1`, quindi l'IP pubblico reale del client è visibile **solo**
ad Apache. Due meccanismi lo recuperano (snippet completo in
[`examples/apache-proxyguard.conf`](examples/apache-proxyguard.conf)):

1. **Eventi START** — alza il log level del proxy solo per `/proxyguard/`:

   ```apache
   <LocationMatch "^/proxyguard/">
       LogLevel warn proxy:trace1
   </LocationMatch>
   ```

   Così Apache emette una riga di trace `tunnel running` (con `[client IP:porta]`)
   nell'**ErrorLog** del VirtualHost all'avvio del tunnel. `proxyguard-watcher.py`
   segue quell'ErrorLog e la riscrive come righe compatte `event=start` in
   `proxyguard_start.log`, che il correlatore legge.

2. **Eventi END** — un `CustomLog` con byte e durata, scritto alla chiusura del tunnel.

Applica lo snippet, poi punta il watcher sull'ErrorLog del *tuo* VirtualHost
modificando `ExecStart` in `/etc/systemd/system/proxyguard-watcher.service` (default
`/var/log/apache2/error.log`), e ricarica:

```bash
apache2ctl configtest && sudo systemctl reload apache2
sudo systemctl enable --now proxyguard-watcher.service
```

## GeoIP (opzionale)

```bash
sudo apt install -y python3-maxminddb geoipupdate   # Debian/Ubuntu
# Inserisci il TUO account ID + license key MaxMind in /etc/GeoIP.conf con
#   EditionIDs GeoLite2-City
sudo geoipupdate -v
```

Senza database il correlatore funziona comunque e omette semplicemente
`country`/`city`.

## Configurazione

Tutto è impostato tramite variabili d'ambiente (tutte opzionali). Metti gli override
nella unit systemd. I default corrispondono a un'installazione eduVPN Debian standard.

| Variabile | Default | Significato |
|---|---|---|
| `EDUVPN_LOG` | `/var/log/eduvpn/eduvpn.log` | File di log unificato |
| `EDUVPN_PORTAL_DB` | `/var/lib/vpn-user-portal/db.sqlite` | DB portale (fallback in sola lettura) |
| `EDUVPN_PROXYGUARD_START_LOG` | `/var/log/apache2/proxyguard_start.log` | Eventi START ProxyGuard |
| `EDUVPN_GEOIP_DB` | *(auto-detect)* | Percorso esplicito a GeoLite2-City.mmdb |
| `EDUVPN_GEOIP_LANG` | `en` | Lingua/e dei nomi, separate da virgola (es. `it,en`) |
| `EDUVPN_SYSLOG_IDENT` | `eduvpn-logger` | Nome programma syslog |
| `EDUVPN_SYSLOG_FACILITY` | `local0` | Facility syslog (`local0`..`local7`) |
| `EDUVPN_WG_POLL_SEC` | `2.0` | Intervallo di polling di `wg show` (secondi) |
| `EDUVPN_DISCONNECT_AFTER_SEC` | `180.0` | Silenzio dell'handshake prima di un disconnect sintetizzato |
| `EDUVPN_CONNECT_GRACE_SEC` | `10.0` | Attesa massima per attribuire la connect a un utente prima di emetterla |

Lo schema del DB del portale viene **auto-rilevato** (le colonne sono individuate per
nome), quindi il tool si adatta tra versioni di eduVPN senza configurazione.

Opzionale: instrada il syslog del correlatore su un file dedicato con
[`examples/rsyslog-10-eduvpn.conf`](examples/rsyslog-10-eduvpn.conf)
(installato automaticamente da `install.sh`).

## Campi di output

| Campo | Eventi | Note |
|---|---|---|
| `event` | tutti | `connect` / `roam` / `disconnect` |
| `user`, `profile` | tutti | dal portale o dal fallback DB (`-` se sconosciuto) |
| `device` | quando noto | `android`/`ios`/`windows`/`macos`/`linux` |
| `conn` | tutti | public key WireGuard (chiave di correlazione) |
| `tunnel_ip4`, `tunnel_ip6` | connect/roam | IP VPN assegnati |
| `src_ip`, `src_port` | tutti | endpoint pubblico sorgente |
| `transport` | tutti | `udp` (diretto) / `tcp` (ProxyGuard) / `unknown` |
| `bytes_in`, `bytes_out` | disconnect | totali di sessione |
| `country`, `city` | se GeoIP disponibile e IP pubblico | |

## Installazione manuale

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

Poi esegui i passaggi Apache e GeoIP sopra e abilita `proxyguard-watcher.service`.

## Test

```bash
python3 test_eduvpn_logger.py
```

Copre le funzioni di parsing pure (split endpoint/IPv6, key=value, marker device,
parsing riga ProxyGuard).

## Licenza

MIT — vedi [LICENSE](LICENSE).
