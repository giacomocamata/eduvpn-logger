#!/usr/bin/env python3
"""Self-checks for the pure parsing helpers. No framework, no fixtures.

Run: python3 test_eduvpn_logger.py
"""
import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    "eduvpn_logger", os.path.join(os.path.dirname(__file__), "eduvpn-logger.py")
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def test_split_endpoint():
    assert mod._split_endpoint("10.0.0.1:51820") == ("10.0.0.1", "51820")
    assert mod._split_endpoint("127.0.0.1:47814") == ("127.0.0.1", "47814")
    # IPv6 with brackets and port
    assert mod._split_endpoint("[2001:db8::dead]:48049") == ("2001:db8::dead", "48049")
    # bare IPv6 (no brackets, no port) must not be mistaken for host:port
    assert mod._split_endpoint("2001:db8::dead") == ("2001:db8::dead", None)
    # host without port
    assert mod._split_endpoint("10.0.0.1") == ("10.0.0.1", None)
    assert mod._split_endpoint("") == (None, None)
    assert mod._split_endpoint("(none)".replace("(none)", "")) == (None, None)


def test_split_kv():
    kv = mod._split_kv("USER=alice PROFILE=staff CONN=abc= IP4=10.20.0.5")
    assert kv["USER"] == "alice"
    assert kv["PROFILE"] == "staff"
    assert kv["CONN"] == "abc="
    assert kv["IP4"] == "10.20.0.5"
    assert mod._split_kv("no kv here") == {}


def test_device_from_client_marker():
    assert mod._device_from_client_marker("org.eduvpn.app.android") == "android"
    assert mod._device_from_client_marker("-", "org.eduvpn.app.ios") == "ios"
    assert mod._device_from_client_marker("some-random-client") == "-"
    assert mod._device_from_client_marker("", "-") == "-"


def test_parse_proxyguard_start_line():
    line = "2026-04-15T09:58:01.111546+02:00 product=eduVPN proto=proxyguard event=start src_ip=1.2.3.4 src_port=48049"
    out = mod._parse_proxyguard_start_line(line)
    assert out is not None
    _ts, ip, port = out
    assert ip == "1.2.3.4" and port == "48049"
    # wrong event type -> ignored
    assert mod._parse_proxyguard_start_line("2026-04-15T09:58:01+02:00 event=end src_ip=1.2.3.4") is None
    # missing src_ip -> ignored
    assert mod._parse_proxyguard_start_line("2026-04-15T09:58:01+02:00 event=start") is None


def test_parse_wg_dump_output():
    # interface header (fewer fields) + one peer line, tab-separated
    text = (
        "wg0\tPRIVKEY=\tSRVPUB=\t51820\toff\n"
        "wg0\tPEER1=\t(none)\t203.0.113.45:48049\t10.20.0.5/32\t1713168000\t1111\t2222\toff\n"
        "wg0\tPEER2=\t(none)\t(none)\t10.20.0.6/32\t0\t0\t0\toff\n"
    )
    snap, hs, ep = mod._parse_wg_dump_output(text)
    assert snap == {"PEER1=": (1111, 2222), "PEER2=": (0, 0)}
    assert hs == {"PEER1=": 1713168000, "PEER2=": 0}
    assert ep["PEER1="] == "203.0.113.45:48049"
    assert ep["PEER2="] == "(none)"
    # garbage lines are skipped
    assert mod._parse_wg_dump_output("not\ta\tpeer\tline") == ({}, {}, {})


def test_parse_wg_transfer_output():
    # `wg show all transfer`: <iface>\t<pubkey>\t<rx>\t<tx>
    text = "wg0\tPEER1=\t1111\t2222\nwg0\tPEER2=\t0\t0\nnoise line\n"
    snap = mod._parse_wg_transfer_output(text)
    assert snap == {"PEER1=": (1111, 2222), "PEER2=": (0, 0)}
    assert mod._parse_wg_transfer_output("") == {}


def test_active_window_never_exceeds_disconnect_threshold():
    # Otherwise a peer past the synth-disconnect threshold would still count as
    # "active" and flap connect/disconnect (see ACTIVE_HANDSHAKE_MAX_AGE_SEC).
    assert mod.ACTIVE_HANDSHAKE_MAX_AGE_SEC <= mod.SYNTH_DISCONNECT_AFTER_SEC


def test_is_global_ip():
    assert mod._is_global_ip("8.8.8.8") is True
    assert mod._is_global_ip("127.0.0.1") is False
    assert mod._is_global_ip("10.0.0.1") is False
    assert mod._is_global_ip("not-an-ip") is False


def test_san():
    assert mod._san("alice") == "alice"
    assert mod._san("-") == "-"
    assert mod._san("") == ""
    # whitespace / kv delimiters / control chars collapse to "_" (no forged kv pairs)
    assert mod._san("a b") == "a_b"
    assert mod._san('x" event=fake user=root') == "x_event_fake_user_root"
    assert mod._san("line\nbreak") == "line_break"


def test_reconcile_drops_stale_peers():
    # A long-running daemon must not accumulate state for peers that have left wg.
    import tempfile

    mod.OUT_PATH = os.path.join(tempfile.gettempdir(), "eduvpn-logger-selftest.log")
    c = mod.Correlator()
    c._wg_bytes_last = {"A": (1, 2), "B": (3, 4)}
    c._wg_endpoint_last = {"A": "1.1.1.1:1", "B": "2.2.2.2:2"}
    c._peer_last_handshake = {"A": 100, "B": 100}
    c._wg_bytes_baseline = {"A": (0, 0), "B": (0, 0)}
    c._roam_last = {"A": 1.0, "B": 1.0}

    # Only peer A is still present in wg; B is gone and not awaiting a synth disconnect.
    c._wg_dump = lambda: ({"A": (5, 6)}, {}, {"A": "1.1.1.1:1"}, True)
    c.update_wg_counters()

    for d in (c._wg_bytes_last, c._wg_endpoint_last, c._peer_last_handshake,
              c._wg_bytes_baseline, c._roam_last):
        assert "A" in d, d
        assert "B" not in d, d

    # A failed poll (ok=False) must NOT wipe live state.
    c._wg_dump = lambda: ({}, {}, {}, False)
    c.update_wg_counters()
    assert "A" in c._wg_bytes_last


# --------------------------------------------------------------------------- #
# Scenario checks: drive the Correlator state machine with a fake clock and a
# fake `wg show`, then assert on the lines it writes.
# --------------------------------------------------------------------------- #
import tempfile
import types

K1, K2, K3 = ("A" * 43 + "=", "B" * 43 + "=", "C" * 43 + "=")


class _Sim:
    def __init__(self):
        self.now = 1_000_000.0
        self.peers = {}  # pubkey -> (endpoint, last_handshake)
        mod.time = types.SimpleNamespace(time=lambda: self.now)
        mod._syslog = None
        fd, mod.OUT_PATH = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        self.c = mod.Correlator()
        self.c._db = mod.PortalDb(os.path.join(tempfile.gettempdir(), "no-such-db.sqlite"))
        self.c._wg_dump = lambda: (
            {k: (0, 0) for k in self.peers},
            {k: hs for k, (_ep, hs) in self.peers.items()},
            {k: ep for k, (ep, _hs) in self.peers.items()},
            True,
        )

    def poll(self, advance=2.0):
        self.now += advance
        self.c.update_wg_counters()

    def portal(self, msg):
        self.c.on_portal(self.now, msg)

    def lines(self):
        with open(mod.OUT_PATH, encoding="utf-8") as f:
            return [l.split(" ", 1)[1] for l in f.read().splitlines()]


def test_parse_portal_event():
    tpl = f"CONNECT USER=alice PROFILE=staff PROTO=wireguard CONN={K1} IP4=10.20.0.5 IP6=fd00::5"
    kind, kv = mod._parse_portal_event(tpl)
    assert kind == "CONNECT" and kv["USER"] == "alice" and kv["CONN"] == K1 and kv["IP4"] == "10.20.0.5"
    # the portal's default format (no connectLogTemplate configured)
    kind, kv = mod._parse_portal_event(f"CONNECT alice (staff:{K1}) [* => 10.20.0.5,fd00::5]")
    assert (kind, kv["USER"], kv["PROFILE"], kv["CONN"], kv["IP6"]) == ("CONNECT", "alice", "staff", K1, "fd00::5")
    kind, kv = mod._parse_portal_event(f"DISCONNECT alice (staff:{K1})")
    assert kind == "DISCONNECT" and kv["CONN"] == K1
    # older default variant, verbatim from the eduVPN geo-ip docs: "[ip4,ip6] [CC:..]"
    k = "/mlU99+TkOUqUvvqg5LdqoY/sKwQY0NvFxDie6fwVRY="
    kind, kv = mod._parse_portal_event(f"CONNECT fkooman (default-o:{k}) [10.114.241.4,fd52:e2d1:97a:d5ad::4] [CC:DK]")
    assert (kv["CONN"], kv["IP4"], kv["IP6"]) == (k, "10.114.241.4", "fd52:e2d1:97a:d5ad::4"), kv
    # default format with AUTH_DATA suffix
    kind, kv = mod._parse_portal_event(f"CONNECT foo (p:{K1}) [* => 10.0.0.2,fd00::2] [AUTH_DATA=eyJ1c2VySWQiOiJmb28ifQo]")
    assert (kv["USER"], kv["IP4"]) == ("foo", "10.0.0.2"), kv
    # OpenVPN and non-pubkey CONN values are not WireGuard sessions
    assert mod._parse_portal_event(f"CONNECT USER=a PROFILE=p PROTO=openvpn CONN={K1}") is None
    assert mod._parse_portal_event("CONNECT USER=a PROFILE=p CONN=-") is None
    assert mod._parse_portal_event("AUTH OK alice") is None


def test_watcher_parse_line():
    spec = importlib.util.spec_from_file_location(
        "pg_watcher", os.path.join(os.path.dirname(__file__), "proxyguard-watcher.py")
    )
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    real = ("[Wed Apr 15 09:58:01.111546 2026] [proxy:trace1] [pid 1:tid 2] proxy_util.c(5645): "
            "[client 2001:db8::1:48049] AH10212: proxy: UoTLV/1: tunnel running (timeout 300.000000)")
    assert w.parse_line(real) == ("2001:db8::1", "48049")
    assert w.parse_line(real.replace("2001:db8::1:48049", "192.0.2.7:5555")) == ("192.0.2.7", "5555")
    # a request path echoed in a 404 line must not forge a START
    forged = ("[Wed Apr 15 09:58:01 2026] [core:info] [pid 1:tid 2] [client 192.0.2.66:1234] AH00128: "
              "File does not exist: /var/www/[client 198.51.100.1:1] AH10212: proxy: UoTLV/1: tunnel running")
    assert w.parse_line(forged) is None


def test_tcp_disconnect_after_1h_keeps_own_source():
    # Regression: _pubkey_src used to expire after 1h, and the disconnect then
    # time-matched the most recent START of ANOTHER client.
    s = _Sim()
    s.c.on_tcp_start(s.now - 0.5, "198.51.100.7", "40000")
    s.portal(f"CONNECT USER=alice PROFILE=staff PROTO=wireguard CONN={K1} IP4=10.20.0.5 IP6=fd00::5")
    s.peers[K1] = ("127.0.0.1:5000", int(s.now))
    s.poll()
    s.poll()
    assert any("event=connect user=alice" in l and 'src_ip="198.51.100.7"' in l for l in s.lines()), s.lines()
    s.now += 4000
    s.peers[K1] = ("127.0.0.1:5000", int(s.now))
    s.poll()
    s.c.on_tcp_start(s.now, "203.0.113.99", "1")  # someone else's tunnel
    s.portal(f"DISCONNECT USER=alice PROFILE=staff PROTO=wireguard CONN={K1} BYTES_IN=1 BYTES_OUT=2")
    disc = [l for l in s.lines() if l.startswith("event=disconnect")]
    assert len(disc) == 1 and 'src_ip="198.51.100.7"' in disc[0], disc


def test_portal_disconnect_flushes_pending_and_allows_reconnect():
    s = _Sim()
    s.portal(f"CONNECT USER=bob PROFILE=staff PROTO=wireguard CONN={K2} IP4=10.20.0.6 IP6=fd00::6")
    s.poll()  # no handshake ever
    s.portal(f"DISCONNECT USER=bob PROFILE=staff PROTO=wireguard CONN={K2} BYTES_IN=0 BYTES_OUT=0")
    s.poll(30.0)
    events = [l.split()[0] for l in s.lines()]
    assert events == ["event=connect", "event=disconnect"], s.lines()
    # same key again: a new session must get its own connect line
    s.portal(f"CONNECT USER=bob PROFILE=staff PROTO=wireguard CONN={K2} IP4=10.20.0.6 IP6=fd00::6")
    s.peers[K2] = ("192.0.2.10:1111", int(s.now))
    s.poll()
    s.poll()
    events = [l.split()[0] for l in s.lines()]
    assert events == ["event=connect", "event=disconnect", "event=connect"], s.lines()
    assert "inferred=1" not in s.lines()[-1]


def test_empty_fleet_still_synthesizes_disconnect():
    s = _Sim()
    s.peers[K3] = ("192.0.2.20:2222", int(s.now))
    s.poll()
    s.poll(mod.CONNECT_GRACE_SEC + 1)  # grace expires: unattributed connect
    assert [l.split()[0] for l in s.lines()] == ["event=connect"], s.lines()
    assert "inferred=1" in s.lines()[0]
    s.peers.clear()  # wg0 recreated / last peer gone: `wg show` ok, zero peers
    s.poll(mod.SYNTH_DISCONNECT_AFTER_SEC + 1)
    disc = [l for l in s.lines() if l.startswith("event=disconnect")]
    assert len(disc) == 1 and "inferred=1" in disc[0], s.lines()


def test_tcp_candidates_marker():
    # Two ProxyGuard starts in the window: the first TCP peer is attributed among 2
    # candidates, the second (after the first start is consumed) among 1.
    s = _Sim()
    s.c.on_tcp_start(s.now - 1.0, "198.51.100.1", "1000")
    s.c.on_tcp_start(s.now - 0.5, "198.51.100.2", "2000")
    s.peers[K1] = ("127.0.0.1:5001", int(s.now))
    s.poll()
    s.poll(mod.CONNECT_GRACE_SEC + 1)
    s.peers[K2] = ("127.0.0.1:5002", int(s.now))
    s.poll()
    s.poll(mod.CONNECT_GRACE_SEC + 1)
    conns = [l for l in s.lines() if l.startswith("event=connect")]
    assert len(conns) == 2, s.lines()
    assert 'src_ip="198.51.100.2"' in conns[0] and "tcp_candidates=2" in conns[0], conns
    assert 'src_ip="198.51.100.1"' in conns[1] and "tcp_candidates=1" in conns[1], conns
    # UDP lines never carry it
    s.peers[K3] = ("192.0.2.9:9", int(s.now))
    s.poll()
    s.poll(mod.CONNECT_GRACE_SEC + 1)
    assert "tcp_candidates" not in s.lines()[-1], s.lines()


def test_trusted_portal_uid():
    ok = mod._trusted_portal_entry
    assert ok({"_UID": "0"}, 999) and ok({"_UID": "33"}, 999) and ok({"_UID": "48"}, 999)
    assert not ok({"_UID": "1000"}, 999)  # a regular login account: `logger -t` spoofing
    assert not ok({}, 999) and not ok({"_UID": "x"}, 999) and not ok({"_UID": 33}, 999)
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        f.write("# comment\nSYS_UID_MAX\t\t499\nUID_MIN 1000\n")
    try:
        assert mod._sys_uid_max(path) == 499
    finally:
        os.remove(path)
    assert mod._sys_uid_max(os.path.join(tempfile.gettempdir(), "no-such-login.defs")) == 999


def test_journal_cursor_roundtrip_and_cmd():
    d = tempfile.mkdtemp()
    old = mod.CURSOR_PATH
    mod.CURSOR_PATH = os.path.join(d, "sub", "journal.cursor")
    try:
        assert mod._load_cursor() is None
        assert mod._portal_journal_cmd(None)[-2:] == ["-n", "0"]
        mod._save_cursor("s=abc;i=1")  # creates the missing directory
        mod._save_cursor("s=abc;i=2")
        assert mod._load_cursor() == "s=abc;i=2"
        assert not os.path.exists(mod.CURSOR_PATH + ".tmp")
        cmd = mod._portal_journal_cmd(mod._load_cursor())
        assert cmd[-1] == "--after-cursor=s=abc;i=2" and "-n" not in cmd, cmd
    finally:
        mod.CURSOR_PATH = old


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
