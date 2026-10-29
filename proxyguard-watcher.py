#!/usr/bin/env python3
"""proxyguard-watcher — extract ProxyGuard tunnel START events from Apache's
error log and write them, one compact line per event, to a dedicated file that
eduvpn-logger tails.

Reads the Apache error log from stdin (fed by `tail -n 0 -F`), keeps only the
"tunnel running" trace lines, and emits the client's real source IP:port, plus
the local port of Apache's connection to proxyguard-server when the ErrorLogFormat
set by install.sh logs it. This is needed because Apache's CustomLog only logs a
ProxyGuard request when it ends, which for a long-lived tunnel can be days later.

Output path is overridable via EDUVPN_PROXYGUARD_START_LOG.
"""
import ipaddress
import os
import re
import sys
from datetime import datetime, timezone
from typing import Optional, Tuple

# Next to Apache's logs: /var/log/apache2 (Debian/Ubuntu) or /var/log/httpd (EL,
# Fedora). eduvpn-logger.py applies the same rule: both must agree.
_APACHE_LOG_DIR = ("/var/log/httpd" if os.path.isdir("/var/log/httpd") and not os.path.isdir("/var/log/apache2")
                   else "/var/log/apache2")
OUT_PATH = os.environ.get("EDUVPN_PROXYGUARD_START_LOG", os.path.join(_APACHE_LOG_DIR, "proxyguard_start.log"))
MATCH = "AH10212: proxy: UoTLV/1: tunnel running"
# Between the client tag and the message, with install.sh's ErrorLogFormat: the
# local port of Apache's connection to proxyguard-server (proxy-source-port).
PGPORT = re.compile(r" \[pgport ([0-9]{1,5})\]")


def parse_line(line: str) -> Optional[Tuple[str, str, str]]:
    # Apache writes "... [client <ip>:<port>] [pgport <port>] AH10212: proxy: UoTLV/1:
    # tunnel running" (IPv4 and IPv6 alike, no brackets around v6 here; [pgport] only
    # with install.sh's ErrorLogFormat). Only the FIRST "[client ...]" is Apache's own;
    # text further on can come from the request (e.g. a 404 path), so the marker must
    # follow that first tag directly — otherwise anyone could forge START events with
    # a crafted URL. Returns (ip, port, pgport or "").
    start = line.find("[client ")
    if start < 0:
        return None
    end = line.find("]", start)
    if end < 0:
        return None
    pg = PGPORT.match(line, end + 1)
    if not line.startswith(MATCH, (pg.end() if pg else end + 1) + 1):
        return None
    ip, sep, port = line[start + 8 : end].rpartition(":")
    if not sep or not ip or not (port.isascii() and port.isdigit()):
        return None  # no port (rare; some Apache configs)
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None  # not an address: not Apache's own tag
    if "%" in ip:
        return None  # a zone would let any text through
    return ip, port, pg.group(1) if pg else ""


def main() -> None:
    # Bytes, decoded leniently: one invalid UTF-8 sequence in Apache's log must
    # not crash the watcher (strict decoding of stdin would).
    warned = False
    for raw in sys.stdin.buffer:
        parsed = parse_line(raw.decode("utf-8", "replace"))
        if parsed is None:
            continue
        ip, port, pgport = parsed
        ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="microseconds")
        out_line = f"{ts} product=eduVPN proto=proxyguard event=start src_ip={ip} src_port={port}"
        out_line += f" pgport={pgport}\n" if pgport else "\n"
        try:
            with open(OUT_PATH, "a", encoding="utf-8") as f:
                f.write(out_line)
            warned = False
        except OSError as e:
            # Disk full, directory gone: say it once, keep reading (a crash would
            # restart `tail -n 0` and lose the lines in between).
            if not warned:
                warned = True
                print(f"[proxyguard-watcher] cannot write {OUT_PATH}: {e!r}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
