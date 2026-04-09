# netprobe

**eBPF network connection tracker with live TUI display**

`netprobe` uses [BCC](https://github.com/iovisor/bcc) to attach eBPF kprobes
to the Linux kernel's TCP and UDP stack, logging every outbound TCP connect,
inbound TCP accept, and outbound UDP send — in real time, with zero packet
capture overhead.

```
 netprobe — eBPF network connection tracker       [q] quit  [c] clear
 PROTO DIR  PROCESS (PID)      SOURCE                   →   DESTINATION
 ─────────────────────────────────────────────────────────────────────
 TCP   OUT  curl (12345)        192.168.1.10:54321       →   93.184.216.34:443
 TCP   IN   nginx (999)         0.0.0.0:0                ←   10.0.0.5:52001
 UDP   OUT  python3 (44321)     192.168.1.10:54400       →   8.8.8.8:53
```

---

## Features

| Feature | Details |
|---|---|
| **eBPF hooks** | `tcp_v4_connect`, `inet_csk_accept`, `udp_sendmsg` |
| **Event data** | timestamp, PID, UID, process name, src/dst IP:port, protocol, direction |
| **Live TUI** | Curses display, colour-coded by protocol/direction, scrolling ring buffer |
| **JSON mode** | `--json` streams newline-delimited JSON — pipe to `jq`, `grep`, etc. |
| **Plain text** | `--text` for simple human-readable stdout logging |
| **Filters** | By PID, process name (substring or regex), port, IP/CIDR, protocol, direction |
| **Tests** | Pure-Python unit tests with mocked BCC — no kernel required |

---

## Requirements

### OS

- Linux kernel **4.9+** (BPF perf buffers, `kretprobe`)
- Tested on: Ubuntu 20.04+, Debian 11+, Fedora 35+, Arch Linux

### Kernel config

The following kernel options must be enabled (they are on most distros):

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_EVENTS=y
CONFIG_KPROBES=y
CONFIG_HAVE_KPROBES=y
CONFIG_PERF_EVENTS=y
```

Check with:
```bash
grep -E 'CONFIG_(BPF|KPROBE|PERF_EVENTS)' /boot/config-$(uname -r)
```

### Privileges

Root or the following capabilities are required:

```
CAP_BPF          # load BPF programs
CAP_SYS_ADMIN    # attach kprobes
CAP_NET_ADMIN    # (optional, for some eBPF network operations)
```

---

## Installation

### 1. Install BCC

BCC (BPF Compiler Collection) provides both the kernel-side BPF compiler and
the Python bindings. **Do not install via pip** — it requires kernel headers
and native compilation, so use your distro's package manager.

**Ubuntu / Debian:**
```bash
sudo apt-get update
sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
```

> On older Ubuntu (≤ 20.04) the package may be called `bcc-tools` +
> `python3-bcc`.  Check with `apt-cache search bcc`.

**Fedora / RHEL / Rocky Linux:**
```bash
sudo dnf install bcc bcc-tools python3-bcc kernel-devel
```

**Arch Linux:**
```bash
sudo pacman -S bcc bcc-tools python-bcc
```

**From source** (if distro packages are too old):
```bash
# See: https://github.com/iovisor/bcc/blob/master/INSTALL.md
```

Verify the install:
```bash
python3 -c "from bcc import BPF; print('BCC OK')"
```

### 2. Install pyroute2

```bash
pip3 install pyroute2
# or
sudo apt-get install python3-pyroute2
```

### 3. Clone netprobe

```bash
git clone https://github.com/cbdonohue/netprobe.git
cd netprobe
```

No additional `pip install` is required for the core tool.

---

## Usage

All modes require root (or CAP_BPF + CAP_SYS_ADMIN):

```bash
sudo python3 netprobe.py [OPTIONS]
```

### Live TUI (default)

```bash
sudo python3 netprobe.py
```

Keybindings inside the TUI:
- **q** — quit
- **c** — clear event history

### JSON output

```bash
sudo python3 netprobe.py --json
```

Each event is emitted as a single JSON object on stdout:

```json
{
  "timestamp": 1700000000.123,
  "ts_ns": 1234567890123,
  "pid": 12345,
  "uid": 1000,
  "comm": "curl",
  "proto": "TCP",
  "direction": "OUT",
  "src": {"ip": "192.168.1.10", "port": 54321},
  "dst": {"ip": "93.184.216.34", "port": 443}
}
```

Pipe to `jq` for filtering:
```bash
sudo python3 netprobe.py --json | jq 'select(.dst.port == 443)'
sudo python3 netprobe.py --json | jq 'select(.proto == "UDP")'
sudo python3 netprobe.py --json | jq '[.comm, .src.ip, .dst.ip] | @tsv'
```

### Plain text output

```bash
sudo python3 netprobe.py --text
```

Output format:
```
14:32:01  [TCP] curl             pid=12345  192.168.1.10:54321 → 93.184.216.34:443
```

---

## Filtering

Filters can be combined; all conditions must match (AND semantics).
Filters can be repeated to add multiple values (OR within the same filter type).

### By PID

```bash
# Only events from PID 1234
sudo python3 netprobe.py --pid 1234

# Multiple PIDs
sudo python3 netprobe.py --pid 1234 --pid 5678
```

### By process name

```bash
# Substring match (case-insensitive)
sudo python3 netprobe.py --comm curl
sudo python3 netprobe.py --comm nginx --comm apache

# Regex match
sudo python3 netprobe.py --comm '^python' --comm-regex
sudo python3 netprobe.py --comm 'py(thon)?\d?' --comm-regex
```

### By port

```bash
# Match either source or destination port
sudo python3 netprobe.py --port 443
sudo python3 netprobe.py --port 80 --port 443 --port 8080
```

### By IP address / CIDR

```bash
# Exact IP
sudo python3 netprobe.py --ip 8.8.8.8

# CIDR range
sudo python3 netprobe.py --ip 10.0.0.0/8

# Multiple
sudo python3 netprobe.py --ip 10.0.0.0/8 --ip 172.16.0.0/12
```

### By protocol

```bash
sudo python3 netprobe.py --proto TCP
sudo python3 netprobe.py --proto UDP
```

### By direction

```bash
sudo python3 netprobe.py --direction OUT   # outbound only
sudo python3 netprobe.py --direction IN    # inbound only
```

### Combined example

```bash
# Show only outbound HTTPS traffic from curl or wget
sudo python3 netprobe.py \
  --proto TCP \
  --direction OUT \
  --port 443 \
  --comm curl \
  --comm wget
```

---

## Project Structure

```
netprobe/
├── netprobe.bpf.c    # eBPF C source — kprobes for tcp/udp kernel functions
├── netprobe.py       # Main entry point: BCC loader, event loop, output modes
├── display.py        # Curses TUI — live scrolling event display
├── filters.py        # Filter predicates and FilterChain
├── requirements.txt  # Python deps (pyroute2; BCC is OS-package only)
├── tests/
│   ├── __init__.py
│   ├── mock_bcc.py         # BCC mock — enables testing without kernel BPF
│   ├── test_filters.py     # Unit tests for all filter predicates
│   ├── test_netprobe.py    # Unit tests for event parsing and JSON/text output
│   └── test_display.py     # Unit tests for Display data model
└── README.md
```

### Module overview

**`netprobe.bpf.c`**  
eBPF C code compiled at runtime by BCC. Defines a `conn_event_t` struct and
submits events to a `BPF_PERF_OUTPUT` ring buffer on each network call.

**`netprobe.py`**  
Loads the BPF program, attaches probes (BCC auto-discovers `kprobe__*` /
`kretprobe__*` functions), polls the perf buffer, and dispatches events to the
configured output mode.

**`display.py`**  
Thread-safe curses display. Maintains a `deque` ring buffer of `ConnEvent`
objects. Runs in a daemon thread; the main thread feeds it via `Display.add()`.
Can be tested standalone: `python3 display.py` runs a demo with random events.

**`filters.py`**  
Pure-Python filter predicates (no BCC dependency). Each filter is a callable
`(ConnEvent) -> bool`. `FilterChain` composes them with AND logic. Also defines
the `ConnEvent` dataclass shared across all modules.

---

## Running Tests

Tests use the standard library `unittest` runner — no pytest required (though
pytest works too).

```bash
# From the repo root
python3 -m pytest tests/ -v
# or
python3 -m unittest discover -s tests -v
```

All tests pass without root and without bcc-tools installed.

```
test_comm_decoded (tests.test_netprobe.TestParseEvent) ... ok
test_tcp_inbound (tests.test_netprobe.TestParseEvent) ... ok
test_tcp_outbound (tests.test_netprobe.TestParseEvent) ... ok
test_udp_outbound (tests.test_netprobe.TestParseEvent) ... ok
test_json_structure (tests.test_netprobe.TestEmitJson) ... ok
test_json_valid (tests.test_netprobe.TestEmitJson) ... ok
...
Ran 42 tests in 0.031s
OK
```

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'bcc'`**  
Install bcc-tools via your OS package manager. See [Installation](#installation).

**`Exception: Failed to load BPF program`**  
- Kernel headers must match the running kernel: `linux-headers-$(uname -r)`
- Must run as root
- Check `dmesg` for verifier errors

**`OSError: [Errno 1] Operation not permitted`**  
Root or appropriate capabilities (CAP_BPF, CAP_SYS_ADMIN) are required.

**`kprobe__tcp_v4_connect not found`**  
Some kernels inline `tcp_v4_connect`. Try:
```bash
grep tcp_v4_connect /proc/kallsyms
```
If missing, the kernel may require `CONFIG_KPROBES_ON_FTRACE`.

**Events for UDP are very noisy**  
Use `--pid` or `--comm` to narrow scope. DNS traffic alone can generate
hundreds of events per minute on a busy system.

---

## Security Considerations

- **Root access**: eBPF kprobes require elevated privileges. Run only on
  systems you own/administer.
- **Data sensitivity**: Event logs may contain IP addresses, ports, and process
  names. Treat JSON output accordingly.
- **Kernel stability**: BCC kprobes are safe (copy-on-write, read-only), but
  always test on non-production systems first.

---

## License

MIT — see [LICENSE](LICENSE) (not included; add your own).

---

## Contributing

PRs welcome. Run `python3 -m pytest tests/` before submitting. No kernel
required for the test suite.
