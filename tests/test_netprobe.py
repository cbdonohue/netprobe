"""
tests/test_netprobe.py — Unit tests for netprobe.py event parsing and output.

Uses mock_bcc to avoid any kernel dependency.
"""

import json
import socket
import struct
import sys
import time
import unittest
from io import StringIO
from unittest.mock import patch, MagicMock

# Install BCC mock before importing netprobe
import tests.mock_bcc  # noqa: F401

import netprobe
from filters import ConnEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pack_ip(dotted: str) -> int:
    """Return 32-bit network-byte-order integer for a dotted-quad IP."""
    return struct.unpack("I", socket.inet_aton(dotted))[0]


class _FakeRawEvent:
    """Simulates the ctypes struct returned by BCC's perf buffer."""

    def __init__(self, ts_ns=12345, pid=100, uid=0,
                 comm=b"curl\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                 saddr_str="10.0.0.1", daddr_str="8.8.8.8",
                 sport=54321, dport=53,
                 proto=netprobe.PROTO_UDP, direction=0):
        self.ts_ns     = ts_ns
        self.pid       = pid
        self.uid       = uid
        self.comm      = comm if isinstance(comm, bytes) else comm.encode()
        self.saddr     = _pack_ip(saddr_str)
        self.daddr     = _pack_ip(daddr_str)
        self.sport     = sport
        self.dport     = dport
        self.proto     = proto
        self.direction = direction


# ---------------------------------------------------------------------------
# _ip_to_str
# ---------------------------------------------------------------------------

class TestIpToStr(unittest.TestCase):
    def test_loopback(self):
        packed = _pack_ip("127.0.0.1")
        self.assertEqual(netprobe._ip_to_str(packed), "127.0.0.1")

    def test_public(self):
        packed = _pack_ip("93.184.216.34")
        self.assertEqual(netprobe._ip_to_str(packed), "93.184.216.34")

    def test_zeros(self):
        self.assertEqual(netprobe._ip_to_str(0), "0.0.0.0")


# ---------------------------------------------------------------------------
# _parse_event
# ---------------------------------------------------------------------------

class TestParseEvent(unittest.TestCase):
    def _make_bpf_mock(self, raw_event):
        """Return a fake BPF object whose perf buffer returns *raw_event*."""
        buf_mock = MagicMock()
        buf_mock.event.return_value = raw_event
        bpf_mock = MagicMock()
        bpf_mock.__getitem__ = MagicMock(return_value=buf_mock)
        return bpf_mock

    def test_tcp_outbound(self):
        raw = _FakeRawEvent(
            saddr_str="192.168.1.1", daddr_str="1.2.3.4",
            sport=11111, dport=443,
            proto=netprobe.PROTO_TCP, direction=0,
            comm=b"curl\x00" * 3 + b"\x00",
        )
        b = self._make_bpf_mock(raw)
        evt = netprobe._parse_event(0, None, 0, b)

        self.assertEqual(evt.proto, "TCP")
        self.assertEqual(evt.direction, "OUT")
        self.assertEqual(evt.saddr, "192.168.1.1")
        self.assertEqual(evt.daddr, "1.2.3.4")
        self.assertEqual(evt.sport, 11111)
        self.assertEqual(evt.dport, 443)
        self.assertEqual(evt.pid, 100)

    def test_udp_outbound(self):
        raw = _FakeRawEvent(
            proto=netprobe.PROTO_UDP, direction=0,
        )
        b = self._make_bpf_mock(raw)
        evt = netprobe._parse_event(0, None, 0, b)
        self.assertEqual(evt.proto, "UDP")
        self.assertEqual(evt.direction, "OUT")

    def test_tcp_inbound(self):
        raw = _FakeRawEvent(proto=netprobe.PROTO_TCP, direction=1)
        b = self._make_bpf_mock(raw)
        evt = netprobe._parse_event(0, None, 0, b)
        self.assertEqual(evt.direction, "IN")

    def test_comm_decoded(self):
        raw = _FakeRawEvent(comm=b"nginx\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        b = self._make_bpf_mock(raw)
        evt = netprobe._parse_event(0, None, 0, b)
        self.assertEqual(evt.comm, "nginx")


# ---------------------------------------------------------------------------
# _emit_json
# ---------------------------------------------------------------------------

class TestEmitJson(unittest.TestCase):
    def _make_evt(self, **kw) -> ConnEvent:
        defaults = dict(
            ts_ns=999, pid=42, uid=0, comm="test",
            saddr="1.2.3.4", daddr="5.6.7.8",
            sport=1111, dport=2222,
            proto="TCP", direction="OUT",
            ts_epoch=1700000000.0,
        )
        defaults.update(kw)
        return ConnEvent(**defaults)

    def test_json_structure(self):
        evt = self._make_evt()
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            netprobe._emit_json(evt)
            output = mock_out.getvalue().strip()

        data = json.loads(output)
        self.assertEqual(data["pid"], 42)
        self.assertEqual(data["comm"], "test")
        self.assertEqual(data["proto"], "TCP")
        self.assertEqual(data["direction"], "OUT")
        self.assertEqual(data["src"]["ip"], "1.2.3.4")
        self.assertEqual(data["src"]["port"], 1111)
        self.assertEqual(data["dst"]["ip"], "5.6.7.8")
        self.assertEqual(data["dst"]["port"], 2222)
        self.assertIn("timestamp", data)
        self.assertIn("ts_ns", data)

    def test_json_valid(self):
        """Every emitted line must be valid JSON."""
        evt = self._make_evt(comm="python3", proto="UDP", direction="OUT")
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            netprobe._emit_json(evt)
            for line in mock_out.getvalue().splitlines():
                json.loads(line)  # must not raise


# ---------------------------------------------------------------------------
# _emit_text
# ---------------------------------------------------------------------------

class TestEmitText(unittest.TestCase):
    def _make_evt(self) -> ConnEvent:
        return ConnEvent(
            ts_ns=0, pid=1001, uid=0, comm="ssh",
            saddr="10.0.0.1", daddr="10.0.0.2",
            sport=22222, dport=22,
            proto="TCP", direction="OUT",
            ts_epoch=time.time(),
        )

    def test_contains_key_fields(self):
        evt = self._make_evt()
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            netprobe._emit_text(evt)
            output = mock_out.getvalue()

        self.assertIn("ssh", output)
        self.assertIn("TCP", output)
        self.assertIn("10.0.0.1", output)
        self.assertIn("10.0.0.2", output)
        self.assertIn("22", output)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

class TestArgParser(unittest.TestCase):
    def setUp(self):
        self.parser = netprobe._build_parser()

    def test_defaults(self):
        args = self.parser.parse_args([])
        self.assertFalse(args.json)
        self.assertFalse(args.text)
        self.assertIsNone(args.pid)
        self.assertIsNone(args.comm)
        self.assertIsNone(args.port)
        self.assertIsNone(args.ip)

    def test_json_flag(self):
        args = self.parser.parse_args(["--json"])
        self.assertTrue(args.json)
        self.assertFalse(args.text)

    def test_text_flag(self):
        args = self.parser.parse_args(["--text"])
        self.assertTrue(args.text)

    def test_json_text_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--json", "--text"])

    def test_pid_multiple(self):
        args = self.parser.parse_args(["--pid", "123", "--pid", "456"])
        self.assertEqual(args.pid, [123, 456])

    def test_comm_multiple(self):
        args = self.parser.parse_args(["--comm", "curl", "--comm", "nginx"])
        self.assertEqual(args.comm, ["curl", "nginx"])

    def test_port(self):
        args = self.parser.parse_args(["--port", "443"])
        self.assertEqual(args.port, [443])

    def test_ip(self):
        args = self.parser.parse_args(["--ip", "10.0.0.0/8"])
        self.assertEqual(args.ip, ["10.0.0.0/8"])

    def test_proto(self):
        args = self.parser.parse_args(["--proto", "TCP"])
        self.assertEqual(args.proto, ["TCP"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
