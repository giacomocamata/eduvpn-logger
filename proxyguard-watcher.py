#!/usr/bin/env python3
"""proxyguard-watcher — extract ProxyGuard tunnel START events from Apache's
error log and write them, one compact line per event, to a dedicated file that
eduvpn-logger tails.

Reads the Apache error log from stdin (fed by `tail -F`), keeps only the
"tunnel running" trace lines, and emits the client's real source IP:port. This
is needed because Apache's CustomLog only logs a ProxyGuard request when it
ends, which for a long-lived tunnel can be days later.

Output path is overridable via EDUVPN_PROXYGUARD_START_LOG.
"""
import os
import sys
from datetime import datetime, timezone

OUT_PATH = os.environ.get("EDUVPN_PROXYGUARD_START_LOG", "/var/log/apache2/proxyguard_start.log")
MATCH = "AH10212: proxy: UoTLV/1: tunnel running"


def main() -> None:
    for line in sys.stdin:
        if MATCH not in line or "[client " not in line:
            continue
        try:
            start_idx = line.index("[client ") + 8
            end_idx = line.index("]", start_idx)
            ip_port = line[start_idx:end_idx]
            # Apache logs "[client <ip>:<port>]" (IPv4 and IPv6 alike, no brackets
            # around v6 here). A line without a port has no ":" -> rsplit yields one
            # field, the unpack raises, and we skip it (rare; some Apache configs).
            ip, port = ip_port.rsplit(":", 1)
        except Exception:
            continue

        ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="microseconds")
        out_line = f"{ts} product=eduVPN proto=proxyguard event=start src_ip={ip} src_port={port}\n"
        with open(OUT_PATH, "a", encoding="utf-8") as f:
            f.write(out_line)
            f.flush()


if __name__ == "__main__":
    main()
