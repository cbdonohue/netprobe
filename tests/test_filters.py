"""
tests/test_filters.py — Unit tests for filters.py

No BCC / kernel required.
"""

import time
import unittest

from filters import (
    ConnEvent,
    FilterChain,
    pid_filter,
    comm_filter,
    port_filter,
    ip_filter,
    proto_filter,
    direction_filter,
    build_filter_chain,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _evt(**overrides) -> ConnEvent:
    defaults = dict(
        ts_ns=0,
        pid=1234,
        uid=1000,
        comm="curl",
        saddr="192.168.1.10",
        daddr="93.184.216.34",
        sport=54321,
        dport=443,
        proto="TCP",
        direction="OUT",
        ts_epoch=time.time(),
    )
    defaults.update(overrides)
    return ConnEvent(**defaults)


class _MockArgs:
    """Fake argparse Namespace."""
    pid = None
    comm = None
    comm_regex = False
    port = None
    ip = None
    proto = None
    direction = None


# ---------------------------------------------------------------------------
# pid_filter
# ---------------------------------------------------------------------------

class TestPidFilter(unittest.TestCase):
    def test_match(self):
        f = pid_filter([1234, 5678])
        self.assertTrue(f(_evt(pid=1234)))
        self.assertTrue(f(_evt(pid=5678)))

    def test_no_match(self):
        f = pid_filter([9999])
        self.assertFalse(f(_evt(pid=1234)))

    def test_empty_list_matches_nothing(self):
        f = pid_filter([])
        self.assertFalse(f(_evt()))


# ---------------------------------------------------------------------------
# comm_filter
# ---------------------------------------------------------------------------

class TestCommFilter(unittest.TestCase):
    def test_substring_match(self):
        f = comm_filter(["cur"])
        self.assertTrue(f(_evt(comm="curl")))

    def test_case_insensitive(self):
        f = comm_filter(["CURL"])
        self.assertTrue(f(_evt(comm="curl")))

    def test_no_match(self):
        f = comm_filter(["nginx"])
        self.assertFalse(f(_evt(comm="curl")))

    def test_regex_match(self):
        f = comm_filter([r"^curl$"], regex=True)
        self.assertTrue(f(_evt(comm="curl")))
        self.assertFalse(f(_evt(comm="curl2")))

    def test_regex_partial(self):
        f = comm_filter([r"py(thon)?"], regex=True)
        self.assertTrue(f(_evt(comm="python3")))
        self.assertTrue(f(_evt(comm="py")))
        self.assertFalse(f(_evt(comm="ruby")))


# ---------------------------------------------------------------------------
# port_filter
# ---------------------------------------------------------------------------

class TestPortFilter(unittest.TestCase):
    def test_dst_port_match(self):
        f = port_filter([443])
        self.assertTrue(f(_evt(dport=443)))

    def test_src_port_match(self):
        f = port_filter([54321])
        self.assertTrue(f(_evt(sport=54321, dport=80)))

    def test_no_match(self):
        f = port_filter([22])
        self.assertFalse(f(_evt(sport=54321, dport=443)))

    def test_dst_only(self):
        f = port_filter([54321], match_src=False, match_dst=True)
        self.assertFalse(f(_evt(sport=54321, dport=443)))

    def test_src_only(self):
        f = port_filter([443], match_src=True, match_dst=False)
        self.assertFalse(f(_evt(sport=54321, dport=443)))


# ---------------------------------------------------------------------------
# ip_filter
# ---------------------------------------------------------------------------

class TestIpFilter(unittest.TestCase):
    def test_exact_src(self):
        f = ip_filter(["192.168.1.10"])
        self.assertTrue(f(_evt(saddr="192.168.1.10")))

    def test_exact_dst(self):
        f = ip_filter(["93.184.216.34"])
        self.assertTrue(f(_evt(daddr="93.184.216.34")))

    def test_cidr_match(self):
        f = ip_filter(["192.168.0.0/16"])
        self.assertTrue(f(_evt(saddr="192.168.1.10")))
        self.assertFalse(f(_evt(saddr="10.0.0.1", daddr="8.8.8.8")))

    def test_no_match(self):
        f = ip_filter(["10.0.0.0/8"])
        self.assertFalse(f(_evt(saddr="192.168.1.10", daddr="93.184.216.34")))

    def test_multiple(self):
        f = ip_filter(["10.0.0.0/8", "93.184.216.34"])
        self.assertTrue(f(_evt(daddr="93.184.216.34")))
        self.assertTrue(f(_evt(saddr="10.5.5.5")))


# ---------------------------------------------------------------------------
# proto_filter
# ---------------------------------------------------------------------------

class TestProtoFilter(unittest.TestCase):
    def test_tcp(self):
        f = proto_filter(["TCP"])
        self.assertTrue(f(_evt(proto="TCP")))
        self.assertFalse(f(_evt(proto="UDP")))

    def test_udp(self):
        f = proto_filter(["UDP"])
        self.assertTrue(f(_evt(proto="UDP")))

    def test_case_insensitive(self):
        f = proto_filter(["tcp"])
        self.assertTrue(f(_evt(proto="TCP")))


# ---------------------------------------------------------------------------
# direction_filter
# ---------------------------------------------------------------------------

class TestDirectionFilter(unittest.TestCase):
    def test_out(self):
        f = direction_filter(["OUT"])
        self.assertTrue(f(_evt(direction="OUT")))
        self.assertFalse(f(_evt(direction="IN")))

    def test_in(self):
        f = direction_filter(["IN"])
        self.assertTrue(f(_evt(direction="IN")))


# ---------------------------------------------------------------------------
# FilterChain
# ---------------------------------------------------------------------------

class TestFilterChain(unittest.TestCase):
    def test_empty_chain_passes_all(self):
        chain = FilterChain()
        self.assertTrue(chain.matches(_evt()))

    def test_single_filter(self):
        chain = FilterChain()
        chain.add(pid_filter([1234]))
        self.assertTrue(chain.matches(_evt(pid=1234)))
        self.assertFalse(chain.matches(_evt(pid=9999)))

    def test_and_semantics(self):
        chain = FilterChain()
        chain.add(pid_filter([1234]))
        chain.add(proto_filter(["TCP"]))
        self.assertTrue(chain.matches(_evt(pid=1234, proto="TCP")))
        self.assertFalse(chain.matches(_evt(pid=1234, proto="UDP")))
        self.assertFalse(chain.matches(_evt(pid=9999, proto="TCP")))

    def test_chaining_returns_self(self):
        chain = FilterChain()
        result = chain.add(pid_filter([1]))
        self.assertIs(result, chain)

    def test_len(self):
        chain = FilterChain()
        self.assertEqual(len(chain), 0)
        chain.add(pid_filter([1]))
        self.assertEqual(len(chain), 1)


# ---------------------------------------------------------------------------
# build_filter_chain
# ---------------------------------------------------------------------------

class TestBuildFilterChain(unittest.TestCase):
    def test_no_filters(self):
        args = _MockArgs()
        chain = build_filter_chain(args)
        self.assertEqual(len(chain), 0)
        self.assertTrue(chain.matches(_evt()))

    def test_pid_filter_built(self):
        args = _MockArgs()
        args.pid = [1234]
        chain = build_filter_chain(args)
        self.assertEqual(len(chain), 1)
        self.assertTrue(chain.matches(_evt(pid=1234)))
        self.assertFalse(chain.matches(_evt(pid=9)))

    def test_combined_filters(self):
        args = _MockArgs()
        args.pid = [1234]
        args.proto = ["TCP"]
        chain = build_filter_chain(args)
        self.assertEqual(len(chain), 2)
        self.assertTrue(chain.matches(_evt(pid=1234, proto="TCP")))
        self.assertFalse(chain.matches(_evt(pid=1234, proto="UDP")))


# ---------------------------------------------------------------------------
# ConnEvent str representation
# ---------------------------------------------------------------------------

class TestConnEventStr(unittest.TestCase):
    def test_outbound_str(self):
        evt = _evt(comm="curl", pid=42, proto="TCP",
                   saddr="1.2.3.4", sport=1111,
                   daddr="5.6.7.8", dport=443,
                   direction="OUT")
        s = str(evt)
        self.assertIn("TCP", s)
        self.assertIn("curl", s)
        self.assertIn("→", s)

    def test_inbound_str(self):
        evt = _evt(direction="IN")
        self.assertIn("←", str(evt))


if __name__ == "__main__":
    unittest.main(verbosity=2)
