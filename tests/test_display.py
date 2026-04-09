"""
tests/test_display.py — Unit tests for display.py (non-curses parts).

The curses loop itself is not tested here (it requires a real terminal).
We test the Display data model and thread safety.
"""

import time
import threading
import unittest
from unittest.mock import patch

from filters import ConnEvent
from display import Display, _fmt_addr, _elapsed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _evt(**kw) -> ConnEvent:
    defaults = dict(
        ts_ns=0, pid=100, uid=0, comm="curl",
        saddr="1.2.3.4", daddr="5.6.7.8",
        sport=12345, dport=443,
        proto="TCP", direction="OUT",
        ts_epoch=time.time(),
    )
    defaults.update(kw)
    return ConnEvent(**defaults)


# ---------------------------------------------------------------------------
# _fmt_addr
# ---------------------------------------------------------------------------

class TestFmtAddr(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(_fmt_addr("1.2.3.4", 80), "1.2.3.4:80")

    def test_high_port(self):
        self.assertEqual(_fmt_addr("10.0.0.1", 65535), "10.0.0.1:65535")


# ---------------------------------------------------------------------------
# _elapsed
# ---------------------------------------------------------------------------

class TestElapsed(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(_elapsed(time.time()), "00:00:00")

    def test_one_minute(self):
        start = time.time() - 60
        self.assertEqual(_elapsed(start), "00:01:00")

    def test_one_hour(self):
        start = time.time() - 3600
        self.assertEqual(_elapsed(start), "01:00:00")

    def test_format(self):
        start = time.time() - (2 * 3600 + 3 * 60 + 7)
        self.assertEqual(_elapsed(start), "02:03:07")


# ---------------------------------------------------------------------------
# Display data model
# ---------------------------------------------------------------------------

class TestDisplayDataModel(unittest.TestCase):
    def _make_display(self, max_rows=100):
        # Don't start the curses thread
        return Display(max_rows=max_rows, filter_desc="test")

    def test_initial_state(self):
        d = self._make_display()
        self.assertEqual(d._total, 0)
        self.assertEqual(len(d._events), 0)

    def test_add_increments_total(self):
        d = self._make_display()
        d.add(_evt())
        d.add(_evt())
        self.assertEqual(d._total, 2)

    def test_add_appends_event(self):
        d = self._make_display()
        evt = _evt(pid=42)
        d.add(evt)
        self.assertEqual(d._events[-1].pid, 42)

    def test_max_rows_ring_buffer(self):
        d = self._make_display(max_rows=5)
        for i in range(10):
            d.add(_evt(pid=i))
        # deque maxlen keeps only the last 5
        self.assertEqual(len(d._events), 5)
        pids = [e.pid for e in d._events]
        self.assertEqual(pids, [5, 6, 7, 8, 9])

    def test_thread_safety(self):
        """Add events from multiple threads; total must be accurate."""
        d = self._make_display(max_rows=10000)
        n_threads = 10
        n_per_thread = 100

        def worker():
            for _ in range(n_per_thread):
                d.add(_evt())

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(d._total, n_threads * n_per_thread)

    def test_filter_desc_stored(self):
        d = Display(max_rows=10, filter_desc="pid=1234")
        self.assertEqual(d._filter_desc, "pid=1234")


if __name__ == "__main__":
    unittest.main(verbosity=2)
