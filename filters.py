"""
filters.py — Connection event filtering for netprobe.

Each filter is a callable that accepts a ConnEvent and returns True if the
event should be kept (displayed / emitted) or False if it should be dropped.

FilterChain applies all registered filters with AND semantics.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional


# ---------------------------------------------------------------------------
# Event dataclass (shared between netprobe.py and display.py)
# ---------------------------------------------------------------------------

@dataclass
class ConnEvent:
    ts_ns: int          # kernel timestamp (nanoseconds)
    pid: int
    uid: int
    comm: str           # process name
    saddr: str          # source IP as dotted-quad string
    daddr: str          # destination IP
    sport: int          # source port
    dport: int          # destination port
    proto: str          # "TCP" or "UDP"
    direction: str      # "OUT" or "IN"

    # Computed at construction time for display convenience
    ts_epoch: float = field(default=0.0)  # wall-clock seconds (set by loader)

    def __str__(self) -> str:
        arrow = "→" if self.direction == "OUT" else "←"
        return (
            f"[{self.proto:<3}] {self.comm:<16} pid={self.pid:<6} "
            f"{self.saddr}:{self.sport} {arrow} {self.daddr}:{self.dport}"
        )


# ---------------------------------------------------------------------------
# Individual filter predicates
# ---------------------------------------------------------------------------

FilterFn = Callable[[ConnEvent], bool]


def pid_filter(pids: List[int]) -> FilterFn:
    """Keep only events from the specified PIDs."""
    pid_set = set(pids)

    def _f(evt: ConnEvent) -> bool:
        return evt.pid in pid_set

    _f.__name__ = f"pid_filter({pids})"
    return _f


def comm_filter(patterns: List[str], regex: bool = False) -> FilterFn:
    """Keep events whose comm matches any of the given names/patterns.

    If *regex* is True the patterns are treated as regular expressions
    (case-insensitive); otherwise exact substring matching is used.
    """
    if regex:
        compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

        def _f(evt: ConnEvent) -> bool:
            return any(rx.search(evt.comm) for rx in compiled)
    else:
        lower = [p.lower() for p in patterns]

        def _f(evt: ConnEvent) -> bool:
            comm_l = evt.comm.lower()
            return any(p in comm_l for p in lower)

    _f.__name__ = f"comm_filter({patterns})"
    return _f


def port_filter(ports: List[int], match_src: bool = True,
                match_dst: bool = True) -> FilterFn:
    """Keep events that involve at least one of the given ports.

    By default checks both source and destination ports.
    """
    port_set = set(ports)

    def _f(evt: ConnEvent) -> bool:
        if match_src and evt.sport in port_set:
            return True
        if match_dst and evt.dport in port_set:
            return True
        return False

    _f.__name__ = f"port_filter({ports})"
    return _f


def ip_filter(addrs: List[str]) -> FilterFn:
    """Keep events that involve at least one of the given IPs or CIDR ranges.

    Entries can be bare IPs ("192.168.1.1") or CIDR networks ("10.0.0.0/8").
    """
    networks: List[ipaddress.IPv4Network] = []
    exact: set = set()

    for a in addrs:
        if "/" in a:
            networks.append(ipaddress.ip_network(a, strict=False))
        else:
            exact.add(a)

    def _matches(ip_str: str) -> bool:
        if ip_str in exact:
            return True
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(addr in net for net in networks)

    def _f(evt: ConnEvent) -> bool:
        return _matches(evt.saddr) or _matches(evt.daddr)

    _f.__name__ = f"ip_filter({addrs})"
    return _f


def proto_filter(protocols: List[str]) -> FilterFn:
    """Keep events matching the given protocols ("TCP", "UDP")."""
    upper = {p.upper() for p in protocols}

    def _f(evt: ConnEvent) -> bool:
        return evt.proto.upper() in upper

    _f.__name__ = f"proto_filter({protocols})"
    return _f


def direction_filter(directions: List[str]) -> FilterFn:
    """Keep events matching the given directions ("IN", "OUT")."""
    upper = {d.upper() for d in directions}

    def _f(evt: ConnEvent) -> bool:
        return evt.direction.upper() in upper

    _f.__name__ = f"direction_filter({directions})"
    return _f


# ---------------------------------------------------------------------------
# Filter chain
# ---------------------------------------------------------------------------

class FilterChain:
    """Applies multiple filter predicates with AND semantics.

    An empty chain passes all events.
    """

    def __init__(self) -> None:
        self._filters: List[FilterFn] = []

    def add(self, fn: FilterFn) -> "FilterChain":
        """Register a filter predicate. Returns self for chaining."""
        self._filters.append(fn)
        return self

    def matches(self, evt: ConnEvent) -> bool:
        """Return True if *evt* passes all registered filters."""
        return all(f(evt) for f in self._filters)

    def __len__(self) -> int:
        return len(self._filters)

    def __repr__(self) -> str:
        names = [getattr(f, "__name__", str(f)) for f in self._filters]
        return f"FilterChain([{', '.join(names)}])"


# ---------------------------------------------------------------------------
# Helper: build a FilterChain from CLI args namespace
# ---------------------------------------------------------------------------

def build_filter_chain(args) -> FilterChain:
    """Construct a FilterChain from an argparse Namespace.

    Expected optional attributes on *args*:
        pid    : List[int]  — filter by PID(s)
        comm   : List[str]  — filter by process name substrings
        port   : List[int]  — filter by port number (src or dst)
        ip     : List[str]  — filter by IP/CIDR
        proto  : List[str]  — "TCP", "UDP"
        direction : List[str] — "IN", "OUT"
    """
    chain = FilterChain()

    pid_list: Optional[List[int]] = getattr(args, "pid", None)
    if pid_list:
        chain.add(pid_filter(pid_list))

    comm_list: Optional[List[str]] = getattr(args, "comm", None)
    if comm_list:
        chain.add(comm_filter(comm_list, regex=getattr(args, "comm_regex", False)))

    port_list: Optional[List[int]] = getattr(args, "port", None)
    if port_list:
        chain.add(port_filter(port_list))

    ip_list: Optional[List[str]] = getattr(args, "ip", None)
    if ip_list:
        chain.add(ip_filter(ip_list))

    proto_list: Optional[List[str]] = getattr(args, "proto", None)
    if proto_list:
        chain.add(proto_filter(proto_list))

    dir_list: Optional[List[str]] = getattr(args, "direction", None)
    if dir_list:
        chain.add(direction_filter(dir_list))

    return chain
