# eduvpn-logger

*🇬🇧 [Read in English](README.md) (versione principale)*

**Logging di sessione unificato e correlato per [eduVPN v3](https://www.eduvpn.org/) (WireGuard).**

## Motivazione

In un deployment eduVPN v3 le informazioni che descrivono una singola sessione
VPN sono distribuite su tre sorgenti di log indipendenti, e **nessuna sorgente da
sola è sufficiente** a rispondere alla domanda — operativamente e forensicamente
essenziale — *"chi si è connesso, da dove e quando?"*:

| Sorgente | Fornisce | Dove |
|---|---|---|
| `vpn-user-portal` | identità: utente, profilo, public key WG, IP VPN assegnati, byte trasferiti | journald (`-t vpn-user-portal`) |
| **WireGuard** (`wg show`) | endpoint di rete: public key WG ↔ **IP:porta pubblici sorgente**; liveness | polling interno |
| Apache **ProxyGuard** | IP:porta pubblici per le sessioni di fallback TCP-443 | file (`proxyguard_start.log`) |

Il portale registra *chi* si è autenticato ma mai l'indirizzo pubblico di
provenienza; WireGuard, protocollo stateless privo di un concetto di
"connessione", conosce l'endpoint sorgente ma lo riassegna silenziosamente durante
il roaming senza registrare nulla. Collegare le due cose è quindi un problema di
correlazione, e la **public key WireGuard** è l'unico identificatore condiviso da
tutte e tre le sorgenti.

`eduvpn-logger` è un daemon Python in un singolo file (solo standard library) che
esegue questa correlazione in tempo reale ed emette **una riga strutturata
`chiave=valore` per evento di sessione** — `connect`, `roam`, `disconnect` — su un
file di log e, in parallelo, su syslog per l'integrazione con un SIEM:

```
2026-04-15T09:58:03+02:00 event=connect user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" src_ip="203.0.113.45" src_port=48049 transport=tcp country="Italy" city="Trieste"
2026-04-21T10:57:22+02:00 event=roam user=alice profile=staff conn=GUUepz8z...= tunnel_ip4="10.20.0.5" src_ip_old="203.0.113.45" src_port_old=45851 src_ip="198.51.100.12" src_port=45851 transport=udp
2026-04-15T09:58:20+02:00 event=disconnect user=alice profile=staff conn=soAQTNO...= bytes_in=227252 bytes_out=49292 src_ip="203.0.113.45" transport=tcp
```

> **Ambito.** Sono correlate solo le sessioni **WireGuard**. OpenVPN è escluso di
> proposito: i log OpenVPN nativi di eduVPN espongono già utente, profilo e IP
> pubblico sorgente in un unico record, quindi lì non serve correlazione aggiuntiva.

## Punti salienti del design

Il daemon è stato estratto da un deployment in produzione (Università di Trieste)
e generalizzato. Il suo design poggia su quattro scelte che vale la pena evidenziare:

- **Correlazione sulla public key WireGuard.** L'identità (dal portale) e
  l'endpoint di rete (da WireGuard / ProxyGuard) sono uniti sull'unico
  identificatore stabile che condividono: il legame regge anche attraverso il
  roaming dell'endpoint e attraverso il percorso di fallback TCP.

- **Gli eventi WireGuard sono sintetizzati internamente — nessun logger esterno.**
  WireGuard non espone alcun concetto di connect/disconnect, che vanno quindi
  dedotti. Il diffuso [`wglogger`](https://codeberg.org/flaruina/wglogger) li
  deduce dagli eventi netlink di conntrack ma, per mappare un flusso al peer
  corrispondente, interroga gli stessi dati di `wg show` che questo daemon già
  polla. La dipendenza è dunque ridondante: `eduvpn-logger` ricostruisce gli
  eventi da sé a partire da snapshot periodici, senza nulla in più da installare o
  mantenere attivo.

- **Degradazione graziosa.** Ogni arricchimento è opzionale e fallisce in
  sicurezza. Senza database GeoIP i campi `country`/`city` sono semplicemente
  omessi; quando una sessione non ha un evento CONNECT del portale, utente e
  profilo sono recuperati dal DB SQLite del portale (sola lettura) tramite public
  key. Lo schema del DB è auto-rilevato per nome di colonna, così il tool si adatta
  tra versioni di eduVPN senza configurazione.

- **Output sicuro per il SIEM.** I campi derivati da utente e profilo sono
  sanificati prima della serializzazione, così un valore ostile proveniente
  dall'IdP o dal portale non può rompere il formato della riga né forgiare coppie
  chiave=valore spurie. Gli eventi di roaming che riflettono un semplice rebind di
  porta NAT sono soppressi, e i restanti sono limitati per peer per non inondare il
  SIEM con client mobili instabili.

## Come vengono dedotti gli eventi WireGuard

Poiché WireGuard non ha un concetto di connessione, ogni `EDUVPN_WG_POLL_SEC`
secondi il daemon legge endpoint e ultimo handshake di ogni peer da `wg show` e
deduce:

- **connect** — un peer diventa attivo (handshake recente) su un nuovo endpoint.
  L'evento è brevemente differito (`EDUVPN_CONNECT_GRACE_SEC`, default 10 s) ed
  emesso appena l'evento del portale o il DB del portale attribuiscono il peer a un
  utente, così le sessioni attribuibili non vengono mai registrate con `user=-`.
- **roam** — l'endpoint di un peer attivo cambia (con il throttling di cui sopra).
- **disconnect** — per le sessioni con app eduVPN si usa direttamente il DISCONNECT
  del portale. Per un **profilo WireGuard importato in un client WireGuard
  generico** (cioè non l'app eduVPN) il portale non emette nulla, quindi il
  disconnect è sintetizzato quando l'handshake tace per
  `EDUVPN_DISCONNECT_AFTER_SEC` (default 180 s ≈ 3 minuti). In quel caso la riga
  `disconnect` arriva circa tre minuti dopo che il client smette.

Il compromesso rispetto a un logger basato su netlink è la risoluzione: il
rilevamento avviene alla granularità del poll (default 2 s) anziché
istantaneamente, e una sessione più breve di un intervallo di poll può sfuggire.
Per le sessioni a lunga durata di eduVPN è irrilevante; abbassa
`EDUVPN_WG_POLL_SEC` se serve maggiore granularità. Al riavvio il daemon
riconcilia i peer ancora attivi riportati da `wg show`, recuperando in modo pulito
dopo un crash.

## Requisiti

- Linux con `systemd`, `journalctl` e il comando `wg` (`wireguard-tools`).
- Un deployment eduVPN v3 (`vpn-user-portal`) basato su WireGuard.
- Apache con ProxyGuard (il fallback TCP-443 di eduVPN) — vedi sotto.
- Python 3.9+ (solo standard library). L'arricchimento GeoIP richiede `maxminddb`.

## Avvio rapido

```bash
git clone https://github.com/giacomocamata/eduvpn-logger.git
cd eduvpn-logger
chmod +x install.sh
sudo ./install.sh
```

`install.sh` è idempotente: installa le dipendenze, copia entrambi gli script in
`/usr/local/sbin`, installa e abilita le unit systemd, crea `/var/log/eduvpn` e
inserisce lo snippet rsyslog. Alla fine stampa i due passaggi che non possono
essere automatizzati in sicurezza — la licenza GeoIP MaxMind e la modifica del
VirtualHost Apache (entrambi sotto). Per l'installazione manuale vedi
[Installazione manuale](#installazione-manuale).

## Logging Apache / ProxyGuard

ProxyGuard incapsula WireGuard su TCP/443, quindi il kernel vede quei pacchetti
come provenienti da `127.0.0.1`; l'IP pubblico reale del client è visibile **solo**
ad Apache. Due meccanismi lo recuperano (snippet completo in
[`examples/apache-proxyguard.conf`](examples/apache-proxyguard.conf)):

1. **Eventi START** — alza il log level del proxy solo per `/proxyguard/`:

   ```apache
   <LocationMatch "^/proxyguard/">
       LogLevel warn proxy:trace1
   </LocationMatch>
   ```

   Apache emette così una riga di trace `tunnel running` (con `[client IP:porta]`)
   nell'**ErrorLog** del VirtualHost all'avvio del tunnel. `proxyguard-watcher.py`
   segue quell'ErrorLog e la riscrive come righe compatte `event=start` in
   `proxyguard_start.log`, che il daemon legge.

2. **Eventi END** — un `CustomLog` con byte e durata, scritto alla chiusura del tunnel.

Applica lo snippet, punta il watcher sull'ErrorLog del *tuo* VirtualHost
modificando `ExecStart` in `/etc/systemd/system/proxyguard-watcher.service`
(default `/var/log/apache2/error.log`), e ricarica:

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

Senza database il daemon funziona invariato e omette semplicemente `country`/`city`.

## Configurazione

Tutta la configurazione è via variabili d'ambiente (tutte opzionali); metti gli
override nella unit systemd. I default corrispondono a un'installazione eduVPN
Debian standard.

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
| `EDUVPN_ROAM_MIN_INTERVAL_SEC` | `30.0` | Intervallo minimo tra eventi roam per peer (throttle) |

Opzionale: instrada il syslog del daemon su un file dedicato con
[`examples/rsyslog-10-eduvpn.conf`](examples/rsyslog-10-eduvpn.conf) (installato
automaticamente da `install.sh`).

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

Poi completa i passaggi Apache e GeoIP sopra e abilita `proxyguard-watcher.service`.

## Test

```bash
python3 test_eduvpn_logger.py
```

Copre le funzioni di parsing pure (split endpoint/IPv6, key=value, marker device,
parsing riga ProxyGuard), senza framework esterni.

## Licenza

MIT — vedi [LICENSE](LICENSE).
