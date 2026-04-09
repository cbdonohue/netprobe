"""
display.py — Curses-based live TUI for netprobe.

Maintains a fixed-size ring buffer of ConnEvents and redraws the terminal
each time a new event arrives.  Designed to be driven by netprobe.py via
the Display class.

Layout
------
┌─────────────────────────────────────────────────────────────────────────┐
│  netprobe — eBPF network connection tracker       [q] quit  [c] clear  │
├──────┬───────────────────┬────────────────────────────────┬─────┬───────┤
│ PROTO│ PROCESS (PID)     │ SOURCE                         │     │ DEST  │
├──────┼───────────────────┼────────────────────────────────┼─────┼───────┤
│ TCP  │ curl (12345)      │ 192.168.1.10:54321        →    │     │ 93.18…│
…
└──────┴───────────────────┴────────────────────────────────┴─────┴───────┘
Status bar: total events seen, active filters, uptime
"""

from __future__ import annotations

import curses
import time
import threading
from collections import deque
from typing import Deque, Optional

from filters import ConnEvent

# Column widths (characters)
_COL_PROTO = 5
_COL_DIR   = 3
_COL_COMM  = 18   # "process (pid)"
_COL_SRC   = 22   # "ip:port"
_COL_ARROW = 3
_COL_DST   = 22


def _fmt_addr(ip: str, port: int) -> str:
    return f"{ip}:{port}"


def _elapsed(start: float) -> str:
    secs = int(time.time() - start)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


class Display:
    """Thread-safe curses display.

    Usage::

        disp = Display(max_rows=500)
        disp.start()          # spawns curses in a background thread
        disp.add(event)       # call from any thread
        disp.stop()           # clean shutdown
    """

    def __init__(self, max_rows: int = 1000, filter_desc: str = "") -> None:
        self._max_rows = max_rows
        self._filter_desc = filter_desc
        self._events: Deque[ConnEvent] = deque(maxlen=max_rows)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._total = 0
        self._start_time = time.time()
        self._thread: Optional[threading.Thread] = None
        self._stdscr = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the curses loop in a daemon thread."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the curses thread to exit and wait for it."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def add(self, evt: ConnEvent) -> None:
        """Add an event (called from the BCC callback thread)."""
        with self._lock:
            self._events.append(evt)
            self._total += 1

    # ------------------------------------------------------------------
    # Internal curses loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        curses.wrapper(self._main_loop)

    def _main_loop(self, stdscr) -> None:
        self._stdscr = stdscr
        curses.curs_set(0)
        stdscr.nodelay(True)  # non-blocking getch
        curses.start_color()
        curses.use_default_colors()

        # Colour pairs
        curses.init_pair(1, curses.COLOR_CYAN,    -1)   # header
        curses.init_pair(2, curses.COLOR_GREEN,   -1)   # TCP OUT
        curses.init_pair(3, curses.COLOR_YELLOW,  -1)   # TCP IN
        curses.init_pair(4, curses.COLOR_MAGENTA, -1)   # UDP
        curses.init_pair(5, curses.COLOR_WHITE,   -1)   # normal
        curses.init_pair(6, curses.COLOR_BLACK,   curses.COLOR_CYAN)  # title bar

        TITLE    = curses.color_pair(6) | curses.A_BOLD
        HEADER   = curses.color_pair(1) | curses.A_BOLD
        NORMAL   = curses.color_pair(5)
        TCP_OUT  = curses.color_pair(2)
        TCP_IN   = curses.color_pair(3)
        UDP_CLR  = curses.color_pair(4)

        refresh_interval = 0.1  # seconds

        while not self._stop_event.is_set():
            key = stdscr.getch()
            if key in (ord("q"), ord("Q")):
                self._stop_event.set()
                break
            elif key in (ord("c"), ord("C")):
                with self._lock:
                    self._events.clear()

            rows, cols = stdscr.getmaxyx()
            stdscr.erase()

            # ── Title bar ─────────────────────────────────────────────
            title = " netprobe — eBPF network connection tracker"
            hints = "[q] quit  [c] clear "
            pad = cols - len(title) - len(hints)
            stdscr.addstr(0, 0, title + " " * max(pad, 0) + hints, TITLE)

            # ── Column headers ─────────────────────────────────────────
            hdr = (
                f"{'PROTO':<{_COL_PROTO}} "
                f"{'DIR':<{_COL_DIR}} "
                f"{'PROCESS (PID)':<{_COL_COMM}} "
                f"{'SOURCE':<{_COL_SRC}} "
                f"{'':>{_COL_ARROW}} "
                f"{'DESTINATION':<{_COL_DST}}"
            )
            if rows > 2:
                stdscr.addstr(1, 0, hdr[:cols - 1], HEADER)

            # ── Separator ─────────────────────────────────────────────
            if rows > 3:
                stdscr.addstr(2, 0, "─" * (cols - 1), HEADER)

            # ── Event rows ────────────────────────────────────────────
            max_event_rows = rows - 5  # leave room for title, header, sep, status
            if max_event_rows > 0:
                with self._lock:
                    visible = list(self._events)[-max_event_rows:]

                for row_idx, evt in enumerate(visible):
                    y = 3 + row_idx
                    if y >= rows - 2:
                        break

                    comm_pid = f"{evt.comm[:14]} ({evt.pid})"
                    src = _fmt_addr(evt.saddr, evt.sport)
                    dst = _fmt_addr(evt.daddr, evt.dport)
                    arrow = "→" if evt.direction == "OUT" else "←"

                    line = (
                        f"{evt.proto:<{_COL_PROTO}} "
                        f"{evt.direction:<{_COL_DIR}} "
                        f"{comm_pid:<{_COL_COMM}} "
                        f"{src:<{_COL_SRC}} "
                        f"{arrow:>{_COL_ARROW}} "
                        f"{dst:<{_COL_DST}}"
                    )

                    if evt.proto == "UDP":
                        attr = UDP_CLR
                    elif evt.direction == "IN":
                        attr = TCP_IN
                    else:
                        attr = TCP_OUT

                    stdscr.addstr(y, 0, line[:cols - 1], attr)

            # ── Status bar ────────────────────────────────────────────
            if rows > 1:
                with self._lock:
                    total = self._total
                flt = f"  filters: {self._filter_desc}" if self._filter_desc else ""
                status = (
                    f" events: {total}  uptime: {_elapsed(self._start_time)}{flt}"
                )
                stdscr.addstr(rows - 1, 0, status[:cols - 1],
                              curses.color_pair(6))

            stdscr.refresh()
            time.sleep(refresh_interval)

        # Restore terminal on exit
        curses.endwin()


# ---------------------------------------------------------------------------
# Standalone test / demo mode
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import random
    import socket
    import struct
    import datetime

    def rand_ip() -> str:
        return socket.inet_ntoa(struct.pack(">I", random.randint(0x01000001, 0xFEFFFFFE)))

    protos = ["TCP", "UDP"]
    dirs   = ["OUT", "IN"]
    comms  = ["curl", "python3", "nginx", "ssh", "wget", "firefox"]

    disp = Display(max_rows=200, filter_desc="demo mode")
    disp.start()

    try:
        for i in range(200):
            evt = ConnEvent(
                ts_ns=0,
                pid=random.randint(100, 65535),
                uid=1000,
                comm=random.choice(comms),
                saddr=rand_ip(),
                daddr=rand_ip(),
                sport=random.randint(1024, 65535),
                dport=random.choice([80, 443, 22, 53, 8080]),
                proto=random.choice(protos),
                direction=random.choice(dirs),
                ts_epoch=time.time(),
            )
            disp.add(evt)
            time.sleep(0.15)
    except KeyboardInterrupt:
        pass
    finally:
        disp.stop()
