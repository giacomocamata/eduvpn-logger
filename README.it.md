# eduvpn-logger

*🇬🇧 [Read in English](README.md)*

**Log di sessione correlati per server [eduVPN v3](https://www.eduvpn.org/) con WireGuard.**

Su un server eduVPN nessun log risponde da solo alla domanda *"quale utente si è
connesso, da quale IP pubblico e quando?"*: il portale conosce l'utente ma non
l'indirizzo di provenienza, WireGuard conosce l'indirizzo di provenienza ma non
l'utente e non registra nulla. `eduvpn-logger` unisce le due informazioni in
tempo reale e scrive **una riga `chiave=valore` per evento di sessione**
(`connect`, `roam`, `disconnect`) su file e su syslog, pronta per un SIEM:

```
2026-04-15T09:58:03.412871+02:00 event=connect user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" src_ip="203.0.113.45" src_port=48049 transport=udp country="Italy" city="Trieste"
2026-04-15T10:41:22.090113+02:00 event=roam user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" src_ip_old="203.0.113.45" src_port_old=48049 src_ip="198.51.100.12" src_port=51234 transport=udp
2026-04-15T11:02:57.731204+02:00 event=disconnect user=alice profile=staff device=ios conn=soAQTNO...= bytes_in=227252 bytes_out=49292 src_ip="198.51.100.12" src_port=51234 transport=udp
2026-04-15T12:10:05.000000+02:00 event=connect user=bob profile=staff conn=GUUepz8z...= tunnel_ip4="10.20.0.9" tunnel_ip6="fd00:20::9" src_ip="192.0.2.77" src_port=40112 transport=tcp tcp_candidates=1 inferred=1
```

È un daemon Python in un solo file (solo standard library), in produzione
all'Università di Trieste. Gestisce solo sessioni **WireGuard**: per OpenVPN il
portale registra già da sé l'IP di provenienza.

## Come funziona

Il daemon legge le sorgenti seguenti e le unisce sulla **public key WireGuard**,
l'unico identificatore che hanno in comune:

| Sorgente | Cosa fornisce | Come viene letta |
|---|---|---|
| `vpn-user-portal` | utente, profilo, public key, IP del tunnel, contatori di byte | journald, `SYSLOG_IDENTIFIER=vpn-user-portal` |
| database del portale | utente/profilo/dispositivo di una public key (fallback) | `/var/lib/vpn-user-portal/db.sqlite`, tabella `wg_peers`, sola lettura |
| WireGuard | public key → `IP:porta` pubblici di provenienza, ultimo handshake | `wg show all dump`, ogni 2 s |
| ProxyGuard *(opzionale)* | `IP:porta` reali del client per le sessioni TCP/443 | `ErrorLog` di Apache → `proxyguard-watcher` → `proxyguard_start.log` |

WireGuard non ha il concetto di connessione, quindi gli eventi sono dedotti dallo
stato dei peer letto periodicamente:

- **connect**: un peer completa un handshake su un nuovo endpoint. La riga viene
  trattenuta fino a 10 s, finché l'evento del portale o il suo database indicano
  l'utente.
- **roam**: cambia l'IP di provenienza di un peer attivo. I cambi della sola porta
  (rebinding NAT) sono ignorati; i roam sono limitati a uno per peer ogni 30 s.
- **disconnect**: preso dal DISCONNECT del portale quando l'app eduVPN si
  disconnette; altrimenti (client WireGuard generico, o tunnel inattivo) emesso
  dopo 180 s senza handshake, la durata delle chiavi di WireGuard.

Le righe non supportate da un evento del portale hanno **`inferred=1`**. Con
ProxyGuard il kernel vede ogni client come `127.0.0.1`: l'IP reale è preso
dall'evento di apertura tunnel di Apache più vicino nel tempo, e `tcp_candidates`
indica quante aperture erano candidate (vedi [Limiti](#limiti)).

Il daemon salva la sua posizione nel journal in `/var/lib/eduvpn-logger`: gli
eventi del portale registrati mentre era fermo vengono elaborati al successivo
avvio, con il loro timestamp originale.

## Requisiti

- Server eduVPN v3 (`vpn-user-portal`) con WireGuard, su Linux con systemd.
  Testato su Debian/Ubuntu; Fedora/EL richiedono gli adattamenti di percorso
  indicati sotto.
- `wireguard-tools` (`wg`) e Python ≥ 3.9, solo standard library (entrambi
  installati da `install.sh`).
- *Opzionale:* `python3-maxminddb` e un database MaxMind GeoLite2-City per
  `country`/`city`.

## Installazione

### 1. Abilitare il logging delle connessioni nel portale (obbligatorio)

In `/etc/vpn-user-portal/config.php`, nella sezione `Log`:

```php
'Log' => [
    'syslogConnectionEvents' => true,
    // consigliato (vpn-user-portal >= 3.5.0): interpretato in modo affidabile e con i contatori di byte
    'connectLogTemplate'    => 'CONNECT USER={{USER_ID}} PROFILE={{PROFILE_ID}} PROTO={{VPN_PROTO}} CONN={{CONNECTION_ID}} IP4={{IP_FOUR}} IP6={{IP_SIX}}',
    'disconnectLogTemplate' => 'DISCONNECT USER={{USER_ID}} PROFILE={{PROFILE_ID}} PROTO={{VPN_PROTO}} CONN={{CONNECTION_ID}} BYTES_IN={{BYTES_IN}} BYTES_OUT={{BYTES_OUT}}',
],
```

L'impostazione viene letta alla richiesta successiva al portale; non serve
`vpn-maint-apply-changes`. Senza i due template il portale usa il suo formato di
default, anch'esso riconosciuto, ma i disconnect non hanno i contatori di byte. I
template personalizzati devono mantenere le chiavi `USER=`, `PROFILE=` e `CONN=`.
Riferimento: [eduVPN logging](https://docs.eduvpn.org/server/v3/logging.html).

Verifica che gli eventi arrivino (dopo aver connesso un client):

```bash
journalctl -t vpn-user-portal -n 5
```

### 2. Installare il daemon

```bash
git clone https://github.com/giacomocamata/eduvpn-logger.git
cd eduvpn-logger
sudo ./install.sh
```

`install.sh` è idempotente e fa quanto segue:

| Elemento | Percorso |
|---|---|
| pacchetti | `wireguard-tools`, `python3` (obbligatori); `python3-maxminddb`, `geoipupdate` (opzionali, saltati se non disponibili) |
| programmi | `/usr/local/sbin/eduvpn-logger.py`, `/usr/local/sbin/proxyguard-watcher.py` |
| unit systemd | `/etc/systemd/system/eduvpn-logger.service` (abilitata e avviata), `proxyguard-watcher.service` (installata, non abilitata) |
| directory dei log | `/var/log/eduvpn`, `2750 root:adm` (setgid: i nuovi file hanno gruppo `adm`) |
| stato | `/var/lib/eduvpn-logger` (cursore del journal) |
| rotazione dei log | `/etc/logrotate.d/eduvpn-logger` |
| instradamento syslog | `/etc/rsyslog.d/10-eduvpn.conf`, solo se rsyslog è installato e gira come root (Debian, Fedora/EL; non Ubuntu, dove gira come `syslog` e non potrebbe scrivere in `/var/log/eduvpn`) |

<details>
<summary>Installazione manuale (senza <code>install.sh</code>)</summary>

```bash
sudo apt install -y wireguard-tools python3    # dnf su Fedora/EL
sudo install -m 0755 eduvpn-logger.py proxyguard-watcher.py /usr/local/sbin/
sudo install -m 0644 systemd/eduvpn-logger.service systemd/proxyguard-watcher.service /etc/systemd/system/
sudo install -m 0644 examples/logrotate-eduvpn /etc/logrotate.d/eduvpn-logger
sudo install -m 0644 examples/rsyslog-10-eduvpn.conf /etc/rsyslog.d/10-eduvpn.conf   # solo con rsyslog
sudo install -d -m 2750 -o root -g adm /var/log/eduvpn
sudo systemctl daemon-reload
sudo systemctl enable --now eduvpn-logger.service
```

</details>

### 3. IP di provenienza ProxyGuard (solo se ProxyGuard è abilitato)

Con [ProxyGuard](https://docs.eduvpn.org/server/v3/wireguard.html) i client
raggiungono WireGuard attraverso Apache, quindi solo Apache conosce il loro
indirizzo. Aggiungi al VirtualHost di eduVPN (snippet completo:
[`examples/apache-proxyguard.conf`](examples/apache-proxyguard.conf)):

```apache
<LocationMatch "^/proxyguard/">
    LogLevel warn proxy:trace1
</LocationMatch>
```

All'apertura di un tunnel Apache scrive allora nell'`ErrorLog` del VirtualHost una
riga `AH10212 ... tunnel running` con `[client IP:porta]`; `proxyguard-watcher` la
trasforma in `/var/log/apache2/proxyguard_start.log`, che il daemon legge. La
parte `CustomLog` dello snippet è opzionale e non usata dal daemon.

```bash
sudo apache2ctl configtest && sudo systemctl reload apache2
sudo systemctl enable --now proxyguard-watcher.service
```

Il watcher legge `/var/log/apache2/error.log`. Se il VirtualHost ha un `ErrorLog`
proprio, o su Fedora/EL (`/var/log/httpd/`), sovrascrivi il comando:

```bash
sudo systemctl edit proxyguard-watcher.service
```

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'exec tail -n 0 -F /var/log/httpd/vpn.example.org_ssl_error_log | python3 -u /usr/local/sbin/proxyguard-watcher.py'
Environment=EDUVPN_PROXYGUARD_START_LOG=/var/log/httpd/proxyguard_start.log
```

Su Fedora/EL imposta lo stesso `EDUVPN_PROXYGUARD_START_LOG` anche per
`eduvpn-logger` (vedi [Configurazione](#configurazione)).

### 4. GeoIP (opzionale)

Richiede un account [MaxMind](https://www.maxmind.com/en/geolite2/signup)
gratuito. Inserisci account ID e license key in `/etc/GeoIP.conf` con
`EditionIDs GeoLite2-City`, poi:

```bash
sudo geoipupdate -v      # su Debian il pacchetto è in "contrib"
sudo systemctl restart eduvpn-logger.service
```

Il database viene cercato in `/usr/local/share/GeoIP`, `/usr/share/GeoIP` o
`/var/lib/GeoIP`. Senza database, `country` e `city` vengono semplicemente omessi.

### 5. Verifica

Connetti un client con l'app eduVPN e osserva l'output:

```bash
sudo tail -f /var/log/eduvpn/eduvpn.log
```

Entro pochi secondi dall'apertura del tunnel deve comparire una riga `connect` con
l'utente e l'IP pubblico di provenienza. Gli avvisi del daemon sono in
`journalctl -u eduvpn-logger.service`.

| Sintomo | Causa probabile |
|---|---|
| nessuna riga | logging del portale non abilitato (passo 1), o servizio non attivo: `systemctl status eduvpn-logger` |
| `user=-` nelle righe connect | database del portale non trovato o non leggibile: controlla `EDUVPN_PORTAL_DB` |
| `transport=tcp src_ip="-"` | passo ProxyGuard mancante, o watcher che legge l'`ErrorLog` sbagliato: `systemctl status proxyguard-watcher`, `tail /var/log/apache2/proxyguard_start.log` |
| avviso `ignoring unparsable/non-WireGuard event` | template personalizzato senza `CONN=`, o evento OpenVPN (ignorato di proposito) |
| avviso `untrusted _UID=…` | scartato un evento del portale registrato da un account non di sistema (vedi [Limiti](#limiti)) |

## Configurazione

Tutte le impostazioni sono variabili d'ambiente con default adatti a un server
eduVPN Debian standard. Modificale con un drop-in systemd, che sopravvive alle
reinstallazioni (il file della unit elenca tutte le variabili come riferimento):

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

| Variabile | Default | Significato |
|---|---|---|
| `EDUVPN_LOG` | `/var/log/eduvpn/eduvpn.log` | file di output |
| `EDUVPN_PORTAL_DB` | `/var/lib/vpn-user-portal/db.sqlite` | database del portale (sola lettura) |
| `EDUVPN_PROXYGUARD_START_LOG` | `/var/log/apache2/proxyguard_start.log` | file scritto da `proxyguard-watcher` |
| `EDUVPN_STATE_DIR` | `/var/lib/eduvpn-logger` | cursore del journal |
| `EDUVPN_GEOIP_DB` | *(cercato)* | percorso di `GeoLite2-City.mmdb` |
| `EDUVPN_GEOIP_LANG` | `en` | lingua/e dei nomi dei luoghi, es. `it,en` |
| `EDUVPN_SYSLOG_IDENT` | `eduvpn-logger` | nome del programma in syslog |
| `EDUVPN_SYSLOG_FACILITY` | `local0` | facility syslog |
| `EDUVPN_WG_POLL_SEC` | `2.0` | intervallo di lettura di `wg show`, secondi |
| `EDUVPN_CONNECT_GRACE_SEC` | `10.0` | attesa massima dell'attribuzione utente prima di scrivere una connect |
| `EDUVPN_DISCONNECT_AFTER_SEC` | `180.0` | silenzio dell'handshake prima di un disconnect dedotto; valori sotto 180 vengono portati a 180 |
| `EDUVPN_ROAM_MIN_INTERVAL_SEC` | `30.0` | intervallo minimo tra righe roam dello stesso peer |

La copia syslog va nel journal (`journalctl -t eduvpn-logger`) e, con rsyslog, in
`/var/log/eduvpn/eduvpn-syslog.log`; inoltrala da lì al tuo SIEM. Per provare
impostazioni senza toccare il servizio, avvia una seconda istanza con output e
directory di stato propri:

```bash
sudo EDUVPN_LOG=/tmp/test.log EDUVPN_STATE_DIR=/tmp/eduvpn-test EDUVPN_SYSLOG_IDENT=eduvpn-logger-test /usr/local/sbin/eduvpn-logger.py
```

## Formato del log

`<timestamp ISO-8601, µs, offset UTC> chiave=valore ...`. Il timestamp è il
momento in cui l'evento è avvenuto, non quello in cui la riga è stata scritta. I
valori che possono contenere `:` o spazi sono tra virgolette; `user` e `profile`
sono sanificati, così non possono iniettare chiavi aggiuntive. Versioni future
possono aggiungere chiavi: ignora quelle sconosciute.

| Campo | Eventi | Significato |
|---|---|---|
| `event` | tutti | `connect`, `roam`, `disconnect` |
| `user`, `profile` | tutti | dal portale o dal suo database; `-` se ignoti |
| `device` | quando noto | `android`, `ios`, `windows`, `macos`, `linux` (app eduVPN) |
| `conn` | tutti | public key WireGuard |
| `tunnel_ip4`, `tunnel_ip6` | connect, roam | indirizzi assegnati dentro la VPN |
| `src_ip`, `src_port` | tutti | indirizzo pubblico di provenienza; `-` se ignoto |
| `src_ip_old`, `src_port_old` | roam | indirizzo di provenienza prima del roam |
| `transport` | tutti | `udp`, `tcp` (ProxyGuard) o `unknown` |
| `tcp_candidates` | connect, roam su `tcp` | aperture di tunnel fra cui è stato scelto l'IP; `1` = non ambiguo |
| `bytes_in`, `bytes_out` | disconnect | dal punto di vista del server (`in` = inviati dal client); dal portale, o dai contatori WireGuard per i disconnect dedotti |
| `inferred` | quando `1` | dedotto dallo stato di WireGuard, non riportato dal portale |
| `country`, `city` | con GeoIP, IP pubblici | posizione di `src_ip` |

## Limiti

- **Gli IP di provenienza ProxyGuard sono abbinati per tempo.** L'apertura del
  tunnel in Apache e l'handshake WireGuard non condividono alcun identificatore,
  quindi si usa l'apertura più vicina, una sola volta. Client che aprono tunnel TCP
  negli stessi pochi secondi possono essere scambiati, e `/proxyguard/` è
  raggiungibile senza autenticazione. Considera `tcp_candidates` maggiore di 1
  come probabile, non certo. Gli IP di provenienza UDP arrivano dal kernel e sono
  esatti.
- **Gli eventi del portale sono attendibili in base al mittente.** Qualunque utente
  locale può scrivere nel journal con `logger -t vpn-user-portal`; sono accettate
  solo le voci il cui `_UID` (impostato da journald) è un account di sistema
  (≤ `SYS_UID_MAX`, normalmente 999: root, `www-data`, `apache`).
- **I disconnect dedotti** vengono scritti quando si supera la soglia di 180 s di
  silenzio, cioè fino a 3 minuti dopo l'ultima attività.
- **Dopo un riavvio** il daemon non sa quali sessioni aveva già registrato: i peer
  attivi ricevono una nuova `connect` con `inferred=1` (per le sessioni ProxyGuard
  con `src_ip="-"`; la riga scritta prima del riavvio contiene l'IP).
- Gli eventi sono campionati ogni `EDUVPN_WG_POLL_SEC`: un roam con ritorno dentro
  lo stesso intervallo non viene visto.

## Sicurezza e privacy

Il log contiene dati personali (identificativi utente, IP pubblici, posizione):
definisci finalità, base giuridica e conservazione con il tuo Responsabile della
protezione dei dati (DPO).

- **Accesso**: i log sono creati `0640 root:adm` in una directory `2750`.
- **Conservazione**: `/etc/logrotate.d/eduvpn-logger` ruota ogni giorno e tiene
  180 giorni; modifica `rotate` secondo la tua policy. `proxyguard_start.log`
  segue la rotazione Apache della distribuzione (14 giorni su Debian).
- **Integrità**: chiunque abbia root sul server può alterare un file locale; per un
  uso probatorio inoltra in tempo reale il flusso syslog a un collettore remoto
  (rsyslog `omfwd` su TLS, oppure RELP).
- **Privilegi**: entrambi i servizi girano come root dentro una sandbox systemd.
  `eduvpn-logger` mantiene solo `CAP_NET_ADMIN` (`wg show`) e
  `CAP_DAC_READ_SEARCH`/`CAP_DAC_OVERRIDE` (lettura del database del portale);
  `proxyguard-watcher` non ha capability né rete. Verifica con
  `systemd-analyze security eduvpn-logger.service`.

## Aggiornamento e rimozione

Aggiornamento (drop-in e log vengono mantenuti; i servizi attivi vengono
riavviati, un servizio fermato o disabilitato a mano resta com'è):

```bash
cd eduvpn-logger && git pull && sudo ./install.sh
```

Rimozione (i log in `/var/log/eduvpn` restano al loro posto):

```bash
sudo systemctl disable --now eduvpn-logger.service proxyguard-watcher.service
sudo rm -f /usr/local/sbin/eduvpn-logger.py /usr/local/sbin/proxyguard-watcher.py \
    /etc/systemd/system/eduvpn-logger.service /etc/systemd/system/proxyguard-watcher.service \
    /etc/logrotate.d/eduvpn-logger /etc/rsyslog.d/10-eduvpn.conf
sudo rm -rf /etc/systemd/system/eduvpn-logger.service.d \
    /etc/systemd/system/proxyguard-watcher.service.d /var/lib/eduvpn-logger
sudo systemctl daemon-reload
```

Poi rimuovi dal VirtualHost di Apache il blocco `LocationMatch`, se l'avevi aggiunto.

## Licenza

MIT, vedi [LICENSE](LICENSE).
