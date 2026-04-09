"""
mock_bcc.py — Minimal BCC mock for unit testing without kernel BPF support.

Patches sys.modules so that `from bcc import BPF` succeeds in test
environments where bcc-tools is not installed.

Usage in tests::

    import tests.mock_bcc  # noqa: F401  (side-effect: installs mock)
    # now import netprobe or any module that imports bcc
"""

import sys
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Fake BPF class
# ---------------------------------------------------------------------------

class FakePerfEvent:
    """Mimics the object returned by bpf["map"].event(data)."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class FakePerfBuffer:
    def __init__(self):
        self._callback = None
        self._events = []

    def open_perf_buffer(self, callback, page_cnt=64):
        self._callback = callback

    def inject(self, cpu, data, size):
        """Simulate an arriving perf event (test helper)."""
        if self._callback:
            self._callback(cpu, data, size)


class FakeBPF:
    """Fake BPF loader — does not touch the kernel."""

    def __init__(self, src_file=None, text=None, debug=0):
        self._src = src_file or "<text>"
        self._perf_buffers: dict = {}
        self._tables: dict = {}
        self._perf_buf = FakePerfBuffer()

    def __getitem__(self, name: str):
        return self._perf_buf

    def perf_buffer_poll(self, timeout=10):
        pass  # no-op in tests; inject events manually via FakePerfBuffer.inject


# ---------------------------------------------------------------------------
# Install mock into sys.modules
# ---------------------------------------------------------------------------

_bcc_mock = MagicMock()
_bcc_mock.BPF = FakeBPF

sys.modules.setdefault("bcc", _bcc_mock)
