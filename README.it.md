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
2026-04-15T09:58:03.412871+02:00 event=connect user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" src_ip="203.0.113.45" src_port=48049 transport=udp country="Italy" city="Trieste"
2026-04-15T10:41:22.090113+02:00 event=roam user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" src_ip_old="203.0.113.45" src_port_old=48049 src_ip="198.51.100.12" src_port=51234 transport=udp
2026-04-15T11:02:57.731204+02:00 event=disconnect user=alice profile=staff device=ios conn=soAQTNO...= bytes_in=227252 bytes_out=49292 src_ip="198.51.100.12" src_port=51234 transport=udp
2026-04-15T12:10:05.000000+02:00 event=connect user=bob profile=staff conn=GUUepz8z...= tunnel_ip4="10.20.0.9" tunnel_ip6="fd00:20::9" src_ip="192.0.2.77" src_port=40112 transport=tcp inferred=1
```

(Country/city compaiono solo se GeoIP è configurato e l'IP sorgente è pubblico.)

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
- **disconnect** — quando l'app eduVPN si disconnette si usa direttamente il
  DISCONNECT del portale (con i contatori di byte del portale). Altrimenti — un
  **profilo WireGuard importato in un client WireGuard generico**, oppure
  *qualsiasi* peer, app compresa, che resta in silenzio — il disconnect è
  sintetizzato quando l'handshake tace per `EDUVPN_DISCONNECT_AFTER_SEC` (default
  180 s ≈ 3 minuti); WireGuard rifà l'handshake almeno ogni ~2 minuti finché passa
  traffico, quindi il silenzio significa tunnel inattivo o chiuso. Questa riga ha
  `inferred=1` e arriva circa tre minuti dopo che il client smette; se il peer
  torna attivo segue una nuova `connect`.

Ogni riga **non** supportata da un evento del portale (una connect vista solo in
WireGuard e attribuita tramite il DB del portale, o un disconnect da silenzio
dell'handshake) è marcata `inferred=1`, così un SIEM distingue i fatti osservati
da quelli dedotti.

Il compromesso rispetto a un logger basato su netlink è la risoluzione: il
rilevamento avviene alla granularità del poll (default 2 s) anziché
istantaneamente, e una sessione più breve di un intervallo di poll può sfuggire.
Per le sessioni a lunga durata di eduVPN è irrilevante; abbassa
`EDUVPN_WG_POLL_SEC` se serve maggiore granularità.

**Riavvii.** Il daemon salva la sua posizione nel journal (il cursore journald,
in `EDUVPN_STATE_DIR`, default `/var/lib/eduvpn-logger`). All'avvio riparte
subito dopo l'ultima voce del portale elaborata, quindi gli eventi
CONNECT/DISCONNECT registrati mentre era fermo vengono **rielaborati con il loro
timestamp originale** (consegna at-least-once: un crash tra l'elaborazione di una
voce e il salvataggio del cursore può ripetere quella sola voce). Se il cursore
salvato non è utilizzabile (journal ripulito, machine-id cambiato) registra un
avviso e riparte da "adesso".

Lo stato delle sessioni invece è in memoria: dopo un riavvio i peer ancora attivi
vengono riannunciati con una riga `connect` marcata `inferred=1` (con il
timestamp del loro ultimo handshake e contatori di byte che ripartono da lì); per
le sessioni TCP la sorgente ProxyGuard originale non è recuperabile, quindi
quella riga ha `src_ip="-"`: la riga `connect` precedente al riavvio la contiene.

## Requisiti

- Linux con `systemd`, `journalctl` e il comando `wg` (`wireguard-tools`).
- Un deployment eduVPN v3 (`vpn-user-portal`) basato su WireGuard.
- Python 3.9+ (solo standard library). L'arricchimento GeoIP richiede `maxminddb`.
- *Opzionale:* Apache con ProxyGuard (il fallback TCP-443 di eduVPN) — serve solo
  ad attribuire l'IP sorgente reale delle sessioni in fallback TCP; i deployment
  solo-UDP possono ometterlo del tutto (vedi sotto).

## Avvio rapido

```bash
git clone https://github.com/giacomocamata/eduvpn-logger.git
cd eduvpn-logger
chmod +x install.sh
sudo ./install.sh
```

`install.sh` è idempotente: installa le dipendenze, copia entrambi gli script in
`/usr/local/sbin`, installa entrambe le unit systemd (abilitando `eduvpn-logger`),
crea `/var/log/eduvpn` e inserisce la policy logrotate e (se rsyslog è presente)
lo snippet rsyslog. Al termine il daemon `eduvpn-logger` è **già in
esecuzione** con le impostazioni di default — verifica con
`journalctl -fu eduvpn-logger.service`. Per completare la configurazione segui i
passaggi post-installazione qui sotto. Per l'installazione manuale vedi
[Installazione manuale](#installazione-manuale).

## Passaggi post-installazione

`install.sh` configura tutto ciò che può fare in sicurezza; il resto dipende dal
tuo sito e va fatto a mano. Il passaggio 1 è obbligatorio; i deployment solo-UDP
senza GeoIP possono saltare i passaggi 2–3 e tenere i default del passaggio 4.

### 1. Logging del portale (obbligatorio)

Il portale deve scrivere i suoi eventi CONNECT/DISCONNECT su syslog. In
`/etc/vpn-user-portal/config.php`:

```php
'Log' => [
    'syslogConnectionEvents' => true,
    // Consigliato (vpn-user-portal >= 3.5.0): template chiave=valore, che portano
    // anche i contatori di byte del portale sul disconnect.
    'connectLogTemplate'    => 'CONNECT USER={{USER_ID}} PROFILE={{PROFILE_ID}} PROTO={{VPN_PROTO}} CONN={{CONNECTION_ID}} IP4={{IP_FOUR}} IP6={{IP_SIX}}',
    'disconnectLogTemplate' => 'DISCONNECT USER={{USER_ID}} PROFILE={{PROFILE_ID}} PROTO={{VPN_PROTO}} CONN={{CONNECTION_ID}} BYTES_IN={{BYTES_IN}} BYTES_OUT={{BYTES_OUT}}',
],
```

poi `sudo vpn-maint-apply-changes`. Senza template viene interpretato anche il
formato di default del portale, ma il suo DISCONNECT non ha i contatori di byte. I
template personalizzati devono mantenere le chiavi `USER=`, `PROFILE=`, `CONN=` (e
`IP4=`/`IP6=`, `BYTES_IN=`/`BYTES_OUT=`); gli eventi il cui `CONN` non è una public
key WireGuard (OpenVPN) sono ignorati. Sono considerate attendibili solo le voci
registrate da un account di sistema (root, `www-data`, `apache`, …: UID ≤
`SYS_UID_MAX`) — vedi [Limiti](#limiti-e-modello-di-minaccia).

### 2. Logging Apache / ProxyGuard

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

Applica lo snippet e ricarica Apache. Il watcher legge di default
`/var/log/apache2/error.log`; se il tuo VirtualHost ha un ErrorLog dedicato,
sovrascrivi il comando con `sudo systemctl edit proxyguard-watcher`:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'exec tail -n 0 -F /var/log/apache2/vpn.example.org_error.log | python3 -u /usr/local/sbin/proxyguard-watcher.py'
```

```bash
apache2ctl configtest && sudo systemctl reload apache2
sudo systemctl enable --now proxyguard-watcher.service
```

### 3. Arricchimento GeoIP (opzionale)

```bash
sudo apt install -y python3-maxminddb geoipupdate   # Debian/Ubuntu
# Inserisci il TUO account ID + license key MaxMind in /etc/GeoIP.conf con
#   EditionIDs GeoLite2-City
sudo geoipupdate -v
```

Senza database il daemon funziona invariato e omette semplicemente `country`/`city`.
`install.sh` installa già i pacchetti; manuale è solo la license key.

### 4. Personalizzare la configurazione

Il daemon è configurato interamente tramite variabili d'ambiente, tutte opzionali
(vedi la [tabella di riferimento](#riferimento-configurazione)). I default
corrispondono a un'installazione eduVPN Debian standard, quindi la maggior parte
dei deployment non richiede modifiche.

Per cambiare un valore crea un drop-in systemd — **non modificare la unit
installata**, `install.sh` la sostituisce a ogni esecuzione. La unit elenca ogni
variabile come riga `Environment=` commentata, come riferimento:

```bash
sudo systemctl edit eduvpn-logger.service
```

```ini
[Service]
# esempio: nomi GeoIP in italiano e poll più frequente
Environment=EDUVPN_GEOIP_LANG=it,en
Environment=EDUVPN_WG_POLL_SEC=1.0
```

`systemctl edit` ricarica systemd al salvataggio; riavvia il daemon per applicare:

```bash
sudo systemctl restart eduvpn-logger.service
```

(Per un test estemporaneo puoi invece lanciare lo script direttamente con le
variabili inline, senza toccare il servizio installato — nota la directory di
stato separata, così il test non sposta il cursore journal del servizio:
`sudo EDUVPN_LOG=/tmp/test.log EDUVPN_STATE_DIR=/tmp/eduvpn-test EDUVPN_SYSLOG_IDENT=eduvpn-logger-test eduvpn-logger.py`.)

## Riferimento configurazione

Tutte le variabili sono opzionali. I default corrispondono a un'installazione
eduVPN Debian standard.

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
| `EDUVPN_DISCONNECT_AFTER_SEC` | `180.0` | Silenzio dell'handshake prima di un disconnect sintetizzato; **minimo 180** (durata delle chiavi WireGuard — valori più bassi taglierebbero sessioni vive e vengono alzati, con un avviso) |
| `EDUVPN_CONNECT_GRACE_SEC` | `10.0` | Attesa massima per attribuire la connect a un utente prima di emetterla |
| `EDUVPN_ROAM_MIN_INTERVAL_SEC` | `30.0` | Intervallo minimo tra eventi roam per peer (throttle) |
| `EDUVPN_STATE_DIR` | `/var/lib/eduvpn-logger` | Stato persistente (cursore journald). **Dai a un'istanza di test una directory propria**, altrimenti sposta il cursore di quella di produzione |

Opzionale: instrada il syslog del daemon su un file dedicato con
[`examples/rsyslog-10-eduvpn.conf`](examples/rsyslog-10-eduvpn.conf) (installato
da `install.sh` se rsyslog è presente; altrimenti gli eventi sono nel journal
sotto `-t eduvpn-logger`).

## Campi di output

Ogni riga è `<timestamp ISO-8601 con µs e offset UTC> chiave=valore ...`; i valori
che possono contenere `:` o spazi sono tra virgolette. Il timestamp è il momento
dell'evento (ora dell'evento del portale, o dell'handshake WireGuard per una
connect sintetizzata), non quello di scrittura. Versioni future possono aggiungere
chiavi in coda; i parser devono ignorare le chiavi sconosciute.

| Campo | Eventi | Note |
|---|---|---|
| `event` | tutti | `connect` / `roam` / `disconnect` |
| `user`, `profile` | tutti | dal portale o dal fallback DB (`-` se sconosciuto); sanificati |
| `device` | quando noto | `android`/`ios`/`windows`/`macos`/`linux` |
| `conn` | tutti | public key WireGuard (chiave di correlazione) |
| `tunnel_ip4`, `tunnel_ip6` | connect/roam | IP VPN assegnati |
| `src_ip`, `src_port` | tutti | endpoint pubblico sorgente (`-` se ignoto) |
| `src_ip_old`, `src_port_old` | roam | endpoint prima del roam |
| `transport` | tutti | `udp` (diretto) / `tcp` (ProxyGuard) / `unknown` |
| `tcp_candidates` | connect/roam, `tcp` | fra quanti START ProxyGuard è stata scelta la sorgente: `1` = non ambiguo, `>1` = scelto il più vicino nel tempo (vedi Limiti) |
| `bytes_in`, `bytes_out` | disconnect | dal punto di vista del server: `in` = ricevuti dal client. Dal portale quando è lui a riportare il disconnect, altrimenti delta dei contatori WireGuard dalla connect osservata |
| `inferred` | quando `1` | riga dedotta dallo stato WireGuard, non riportata dal portale (vedi sopra) |
| `country`, `city` | se GeoIP disponibile e IP pubblico | |

## Limiti e modello di minaccia

L'output è usato come evidenza ("chi aveva questo IP, da dove, quando"), quindi
contano le assunzioni dietro ogni campo:

- **L'IP sorgente TCP (ProxyGuard) è un abbinamento temporale.** L'evento di start
  di Apache e l'handshake WireGuard non condividono alcun identificatore, quindi al
  nuovo peer viene attribuito lo start più vicino nel tempo, e ogni start è usato
  al massimo una volta. Due client che aprono tunnel TCP negli stessi pochi secondi
  possono essere scambiati e, poiché l'endpoint `/proxyguard/` è raggiungibile
  senza autenticazione, un terzo può aggiungere rumore aprendo tunnel. Per questo
  ogni riga TCP indica quanti start c'erano nella finestra (`tcp_candidates`):
  valori sopra 1 vanno letti come probabili, non certi. Gli IP sorgente UDP
  arrivano direttamente dal kernel e sono esatti. Un disconnect non prende mai in
  prestito uno start: se la sorgente è ignota riporta `src_ip="-"`.
- **Gli eventi del portale sono attendibili in base all'UID journald.**
  `SYSLOG_IDENTIFIER` può essere impostato da qualunque utente locale
  (`logger -t vpn-user-portal …`), quindi sono accettate solo le voci il cui `_UID`
  (impostato da journald) è un account di sistema (≤ `SYS_UID_MAX` in
  `/etc/login.defs`, normalmente 999 — root, `www-data`, `apache`); le altre sono
  scartate con un avviso che riporta l'UID. Un account *di sistema* compromesso può
  comunque falsificare eventi.
- **Granularità del poll.** Endpoint e handshake sono campionati ogni
  `EDUVPN_WG_POLL_SEC`; un roam con ritorno dentro lo stesso intervallo non si
  vede, e i roam sono limitati (`EDUVPN_ROAM_MIN_INTERVAL_SEC`; i cambi di sola
  porta sono soppressi).
- **Riavvii** — gli eventi del portale vengono rielaborati dal journal, lo stato
  delle sessioni no; vedi *Riavvii* sopra.
- **L'orario dei disconnect dedotti** è il momento in cui è stata superata la
  soglia di silenzio, cioè fino a `EDUVPN_DISCONNECT_AFTER_SEC` dopo l'ultima attività.

## Sicurezza e privacy

Il log contiene dati personali (identificativi utente, IP pubblici, posizione
approssimativa). Secondo il GDPR servono finalità, base giuridica e periodo di
conservazione, da definire con l'ateneo e il suo DPO.

- **Accesso.** La unit gira con `UMask=0027` e `install.sh` crea `/var/log/eduvpn`
  come `0750 root:adm`, così i log non sono leggibili da tutti.
- **Conservazione.** [`examples/logrotate-eduvpn`](examples/logrotate-eduvpn)
  (installato da `install.sh`) ruota `/var/log/eduvpn/*.log` ogni giorno e tiene
  180 giorni; imposta `rotate` secondo la tua policy. `proxyguard_start.log`
  (anch'esso con IP dei client) sta in `/var/log/apache2` e segue la policy Apache
  della distribuzione (14 giorni su Debian). I programmi che seguono `eduvpn.log`
  devono riaprirlo per nome dopo la rotazione e leggere il nuovo file dall'inizio
  (`tail -F` lo fa).
- **Minimizzazione.** GeoIP è opzionale; lascialo spento se la posizione non serve.
- **Integrità.** Un file locale può essere alterato da chiunque abbia root sul
  server VPN. Per un uso probatorio inoltra in tempo reale il flusso syslog a un
  collettore/SIEM remoto (es. rsyslog `omfwd` su TLS, oppure RELP).
- **Hardening.** Il daemon gira come root ma il suo bounding set di capability è
  ridotto a `CAP_NET_ADMIN` (per `wg show`) e `CAP_DAC_READ_SEARCH`/`CAP_DAC_OVERRIDE`
  (per leggere il DB del portale di `www-data`, anche in modalità WAL), con il
  sandboxing systemd (`ProtectSystem`, `PrivateDevices`, `RestrictAddressFamilies`,
  `SystemCallFilter`, `MemoryDenyWriteExecute`, …). `proxyguard-watcher` non ha
  alcuna capability né rete. Entrambi sono verificati dal test end-to-end qui
  sotto; controllali con `systemd-analyze security <unit>`.

## Installazione manuale

```bash
sudo install -m 0755 eduvpn-logger.py /usr/local/sbin/eduvpn-logger.py
sudo install -m 0755 proxyguard-watcher.py /usr/local/sbin/proxyguard-watcher.py
sudo install -m 0644 systemd/eduvpn-logger.service /etc/systemd/system/
sudo install -m 0644 systemd/proxyguard-watcher.service /etc/systemd/system/
sudo install -m 0644 examples/rsyslog-10-eduvpn.conf /etc/rsyslog.d/10-eduvpn.conf   # se rsyslog è installato
sudo install -m 0644 examples/logrotate-eduvpn /etc/logrotate.d/eduvpn-logger
sudo install -d -m 0750 -o root -g adm /var/log/eduvpn
sudo systemctl daemon-reload
sudo systemctl enable --now eduvpn-logger.service
```

Poi completa i passaggi portale, Apache e GeoIP sopra e abilita `proxyguard-watcher.service`.

## Test

Due livelli, senza framework esterni.

**Test unitari e di scenario** — qualunque OS, senza privilegi, Python 3.9+:

```bash
python3 test_eduvpn_logger.py
```

Copre le funzioni pure (split endpoint/IPv6, key=value, tutti i formati degli
eventi del portale, marker device, parsing ProxyGuard e dell'ErrorLog Apache,
output `wg show` dump/transfer, regola degli UID attendibili, I/O del cursore
journal) e scenari della macchina a stati di correlazione, guidata da un orologio
e un `wg show` finti (attribuzione TCP delle sessioni lunghe e `tcp_candidates`,
connect pendenti, riconnessioni con la stessa chiave, insieme di peer vuoto).

**Test end-to-end** — una macchina Linux *usa e getta* con systemd (VM, WSL2,
runner CI), come root:

```bash
sudo EDUVPN_E2E_DISPOSABLE=1 bash e2e_test.sh
```

Esegue `install.sh` (tre volte, verificando idempotenza e sopravvivenza dei
drop-in), poi pilota i servizi installati e in sandbox con componenti reali:
client WireGuard in network namespace (UDP, roaming, e un percorso TCP/ProxyGuard
tramite un relay UDP su loopback che fa vedere al server `127.0.0.1`, con lo START
letto da `proxyguard-watcher` nell'`error.log` di Apache), eventi del portale
scritti nel journal come `www-data`, tentativi di spoofing da UID non di sistema,
uno START falsificato nel path di una richiesta, un DB del portale `wg_peers`,
riavvii del daemon (replay del journal, cursore inutilizzabile), `logrotate` e
disconnect da silenzio dell'handshake. Installa pacchetti, un utente di test e un
DB finto del portale, quindi si rifiuta di partire se
`/var/lib/vpn-user-portal/db.sqlite` esiste già. Circa 5 minuti.

## Licenza

MIT — vedi [LICENSE](LICENSE).
