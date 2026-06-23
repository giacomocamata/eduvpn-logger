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


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
