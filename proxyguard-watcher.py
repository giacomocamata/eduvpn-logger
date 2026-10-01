#!/usr/bin/env python3
"""proxyguard-watcher — extract ProxyGuard tunnel START events from Apache's
error log and write them, one compact line per event, to a dedicated file that
eduvpn-logger tails.

Reads the Apache error log from stdin (fed by `tail -n 0 -F`), keeps only the
"tunnel running" trace lines, and emits the client's real source IP:port. This
is needed because Apache's CustomLog only logs a ProxyGuard request when it
ends, which for a long-lived tunnel can be days later.

Output path is overridable via EDUVPN_PROXYGUARD_START_LOG.
"""
import os
import sys
from datetime import datetime, timezone
from typing import Optional, Tuple

OUT_PATH = os.environ.get("EDUVPN_PROXYGUARD_START_LOG", "/var/log/apache2/proxyguard_start.log")
MATCH = "AH10212: proxy: UoTLV/1: tunnel running"


def parse_line(line: str) -> Optional[Tuple[str, str]]:
    # Apache writes "... [client <ip>:<port>] AH10212: proxy: UoTLV/1: tunnel running"
    # (IPv4 and IPv6 alike, no brackets around v6 here). Only the FIRST "[client ...]"
    # is Apache's own; text further on can come from the request (e.g. a 404 path),
    # so the marker must follow that first tag directly — otherwise anyone could
    # forge START events with a crafted URL.
    start = line.find("[client ")
    if start < 0:
        return None
    end = line.find("]", start)
    if end < 0 or not line.startswith(MATCH, end + 2):
        return None
    ip, sep, port = line[start + 8 : end].rpartition(":")
    if not sep or not ip or not port.isdigit():
        return None  # no port (rare; some Apache configs)
    return ip, port


def main() -> None:
    # Bytes, decoded leniently: one invalid UTF-8 sequence in Apache's log must
    # not crash the watcher (strict decoding of stdin would).
    for raw in sys.stdin.buffer:
        parsed = parse_line(raw.decode("utf-8", "replace"))
        if parsed is None:
            continue
        ip, port = parsed
        ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="microseconds")
        out_line = f"{ts} product=eduVPN proto=proxyguard event=start src_ip={ip} src_port={port}\n"
        with open(OUT_PATH, "a", encoding="utf-8") as f:
            f.write(out_line)
            f.flush()


if __name__ == "__main__":
    main()
