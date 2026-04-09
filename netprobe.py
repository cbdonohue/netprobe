#!/usr/bin/env python3
"""
netprobe.py — eBPF network connection tracker

Loads netprobe.bpf.c via BCC, attaches kprobes/kretprobes, and streams
connection events to either:
  • a live curses TUI  (default)
  • JSON lines on stdout  (--json)
  • plain text on stdout  (--text)

Requires root / CAP_BPF + CAP_SYS_ADMIN.

Usage
-----
    sudo python3 netprobe.py
    sudo python3 netprobe.py --json | jq .
    sudo python3 netprobe.py --text --pid 1234 --pid 5678
    sudo python3 netprobe.py --comm nginx --comm curl
    sudo python3 netprobe.py --port 443 --port 80
    sudo python3 netprobe.py --ip 10.0.0.0/8
    sudo python3 netprobe.py --proto TCP --direction OUT

See --help for all options.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Optional

# BCC import — will fail gracefully when running tests with mock
try:
    from bcc import BPF
    _BCC_AVAILABLE = True
except ImportError:
    _BCC_AVAILABLE = False

from filters import ConnEvent, FilterChain, build_filter_chain
from display import Display

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_HERE = Path(__file__).parent.resolve()
_BPF_SRC = _HERE / "netprobe.bpf.c"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROTO_TCP = 6
PROTO_UDP = 17


# ---------------------------------------------------------------------------
# BPF event → ConnEvent
# ---------------------------------------------------------------------------

def _ip_to_str(addr_int: int) -> str:
    """Convert a 32-bit integer (network byte order) to dotted-quad string."""
    # The kernel stores addresses in network byte order; Python's socket module
    # expects a bytes object in network byte order.
    return socket.inet_ntoa(struct.pack("I", addr_int))


def _parse_event(cpu, data, size, bpf) -> ConnEvent:
    """Parse a raw perf event into a ConnEvent."""
    raw = bpf["conn_events"].event(data)
    proto = "TCP" if raw.proto == PROTO_TCP else "UDP"
    direction = "OUT" if raw.direction == 0 else "IN"
    comm = raw.comm.decode("utf-8", errors="replace").rstrip("\x00")

    return ConnEvent(
        ts_ns=raw.ts_ns,
        pid=raw.pid,
        uid=raw.uid,
        comm=comm,
        saddr=_ip_to_str(raw.saddr),
        daddr=_ip_to_str(raw.daddr),
        sport=raw.sport,
        dport=raw.dport,
        proto=proto,
        direction=direction,
        ts_epoch=time.time(),
    )


# ---------------------------------------------------------------------------
# Output modes
# ---------------------------------------------------------------------------

def _emit_json(evt: ConnEvent) -> None:
    data = {
        "timestamp": evt.ts_epoch,
        "ts_ns": evt.ts_ns,
        "pid": evt.pid,
        "uid": evt.uid,
        "comm": evt.comm,
        "proto": evt.proto,
        "direction": evt.direction,
        "src": {"ip": evt.saddr, "port": evt.sport},
        "dst": {"ip": evt.daddr, "port": evt.dport},
    }
    print(json.dumps(data), flush=True)


def _emit_text(evt: ConnEvent) -> None:
    ts = time.strftime("%H:%M:%S", time.localtime(evt.ts_epoch))
    print(f"{ts}  {evt}", flush=True)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netprobe",
        description="eBPF network connection tracker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Output mode
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--json", action="store_true",
        help="Emit JSON lines (one per event) to stdout"
    )
    mode.add_argument(
        "--text", action="store_true",
        help="Emit plain text lines to stdout (no curses TUI)"
    )

    # Filters
    p.add_argument("--pid",  type=int, action="append", metavar="PID",
                   help="Filter by PID (repeatable)")
    p.add_argument("--comm", type=str, action="append", metavar="NAME",
                   help="Filter by process name substring (repeatable)")
    p.add_argument("--comm-regex", action="store_true",
                   help="Treat --comm values as regular expressions")
    p.add_argument("--port", type=int, action="append", metavar="PORT",
                   help="Filter by port number (src or dst, repeatable)")
    p.add_argument("--ip",   type=str, action="append", metavar="IP/CIDR",
                   help="Filter by IP address or CIDR range (repeatable)")
    p.add_argument("--proto", type=str, action="append", metavar="PROTO",
                   choices=["TCP", "UDP", "tcp", "udp"],
                   help="Filter by protocol: TCP or UDP")
    p.add_argument("--direction", type=str, action="append", metavar="DIR",
                   choices=["IN", "OUT", "in", "out"],
                   help="Filter by direction: IN or OUT")

    # TUI options
    p.add_argument("--max-rows", type=int, default=1000,
                   help="Maximum number of events to keep in TUI history (default: 1000)")

    # Debug / dev
    p.add_argument("--bpf-src", type=Path, default=_BPF_SRC,
                   help=f"Path to BPF C source (default: {_BPF_SRC})")
    p.add_argument("--debug", action="store_true",
                   help="Print BPF debug output")

    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    # Must be root
    if os.geteuid() != 0:
        print("netprobe requires root privileges (or CAP_BPF + CAP_SYS_ADMIN).",
              file=sys.stderr)
        print("Re-run with: sudo python3 netprobe.py", file=sys.stderr)
        return 1

    if not _BCC_AVAILABLE:
        print("BCC Python bindings not found. Install bcc-tools and python3-bcc.",
              file=sys.stderr)
        return 1

    bpf_src_path: Path = args.bpf_src
    if not bpf_src_path.exists():
        print(f"BPF source not found: {bpf_src_path}", file=sys.stderr)
        return 1

    # Build filter chain
    chain = build_filter_chain(args)

    # Describe active filters for TUI status bar
    filter_parts = []
    if args.pid:
        filter_parts.append(f"pid={args.pid}")
    if args.comm:
        filter_parts.append(f"comm={args.comm}")
    if args.port:
        filter_parts.append(f"port={args.port}")
    if args.ip:
        filter_parts.append(f"ip={args.ip}")
    if args.proto:
        filter_parts.append(f"proto={args.proto}")
    if args.direction:
        filter_parts.append(f"dir={args.direction}")
    filter_desc = "  ".join(filter_parts)

    # ── Load BPF ────────────────────────────────────────────────────────────
    debug_level = 4 if args.debug else 0
    print("Loading eBPF program…", file=sys.stderr)
    try:
        b = BPF(src_file=str(bpf_src_path), debug=debug_level)
    except Exception as exc:
        print(f"Failed to load BPF program: {exc}", file=sys.stderr)
        return 1

    # BCC auto-attaches kprobes named kprobe__<fn> / kretprobe__<fn>
    print("eBPF probes attached. Monitoring network connections…", file=sys.stderr)
    print("Probes: tcp_v4_connect, inet_csk_accept, udp_sendmsg", file=sys.stderr)

    # ── Set up output / display ──────────────────────────────────────────────
    display: Optional[Display] = None

    if not args.json and not args.text:
        display = Display(max_rows=args.max_rows, filter_desc=filter_desc)
        display.start()

    # ── Perf event callback ──────────────────────────────────────────────────
    def handle_event(cpu, data, size):
        try:
            evt = _parse_event(cpu, data, size, b)
        except Exception:
            return

        if chain.matches(evt):
            if args.json:
                _emit_json(evt)
            elif args.text:
                _emit_text(evt)
            else:
                if display:
                    display.add(evt)

    b["conn_events"].open_perf_buffer(handle_event, page_cnt=256)

    # ── Signal handling ──────────────────────────────────────────────────────
    running = True

    def _sig_handler(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT,  _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    # ── Poll loop ────────────────────────────────────────────────────────────
    try:
        while running:
            try:
                b.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
    finally:
        if display:
            display.stop()
        print("\nnetprobe stopped.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
