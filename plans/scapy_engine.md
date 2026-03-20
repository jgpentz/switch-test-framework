# Scapy Engine

## Purpose

The Scapy engine gives the framework precise control over individual frames at
Layer 2. Where iperf3 measures bulk throughput, Scapy lets you construct a
specific frame — setting every field manually — send it through the switch, and
observe exactly what comes back.

This is how the framework tests whether the switch is **behaving correctly at
the protocol level**, not just how fast it forwards traffic. iperf3 cannot do
this — it only speaks TCP/UDP and has no awareness of Layer 2 fields like MAC
addresses or VLAN tags.

---

## Requirements

- Scapy scripts are **developed on the orchestrator** alongside all other
  project code, version controlled in Git
- Scripts are **SCP'd to the generator and analyzer** before execution — the
  orchestrator is the single source of truth for all code
- Must send frames out the correct test interface on the generator (172.16.0.1)
- Must capture frames on the analyzer (172.16.0.2)
- The orchestrator passes test parameters (src/dst MAC, VLAN, payload size)
  as arguments to the remote scripts — it controls *what* gets sent, the
  generator handles the actual construction and transmission
- Must support frame construction at the following layers:
  - Ethernet (src/dst MAC, ethertype)
  - 802.1Q VLAN tagging (single and double-tagged / QinQ)
  - IPv4 / IPv6
  - TCP / UDP
  - ICMP
- Results must be structured dicts — consistent with the iperf3 engine output
  so the test runner handles both in the same way
- Must raise descriptive exceptions on failure rather than returning silent
  empty results

---

## Development & Deployment Workflow

All code is written and committed on the orchestrator. Before running a test,
the orchestrator SCPs the relevant scripts to the generator and analyzer, then
SSHes in to trigger execution.

```
1. Write code on orchestrator
       └── framework/traffic/scapy_send.py
       └── framework/traffic/scapy_capture.py

2. SCP to remote VMs
       scp framework/traffic/scapy_send.py     user@10.0.0.11:~/
       scp framework/traffic/scapy_capture.py  user@10.0.0.12:~/

3. Orchestrator SSHes in and triggers execution
       SSH ──► generator  ──► python3 scapy_send.py --vlan 10 --size 1500
       SSH ──► analyzer   ──► python3 scapy_capture.py --timeout 5

4. Results returned to orchestrator and parsed
```

A deploy helper in the orchestrator automates steps 2 and 3 so tests run
with a single command.

---

## What We Are Implementing

### `scapy_send.py` (runs on generator)
Accepts parameters via CLI arguments — src/dst MAC, VLAN tag, IP addresses,
payload size, protocol. Constructs and sends the frame on the test interface.

**Arguments:** `--src-mac`, `--dst-mac`, `--vlan`, `--src-ip`, `--dst-ip`,
`--protocol`, `--size`, `--count`

**Returns:** JSON to stdout — frames sent, timestamp, interface used

---

### `scapy_capture.py` (runs on analyzer)
Listens on the test interface for incoming frames matching a filter. Captures
for a configurable timeout and returns what it saw.

**Arguments:** `--interface`, `--timeout`, `--filter`, `--expected-vlan`

**Returns:** JSON to stdout — frames received, src/dst MACs seen, VLAN tags
observed, timestamps

---

### `scapy_engine.py` (runs on orchestrator)
The orchestrator-side coordinator. Handles SCP deployment, SSH execution,
result collection, and pass/fail scoring. Exposes the high-level test methods
that the test runner calls.

**Methods:**

`send_frame()` — deploy and trigger a single frame send, return confirmation

`send_and_capture()` — trigger send on generator and capture on analyzer
simultaneously, return both results and RTT

`send_burst()` — send a rapid sequence of frames for MAC learning tests

`check_vlan_isolation()` — send on one VLAN, confirm frame does not arrive
on a different VLAN

`measure_rtt()` — send ICMP probes and return min/avg/max latency

---

## How It Fits Into the Framework

```
orchestrator (10.0.0.10)
    │
    ├── SCP scapy_send.py ────────────► traffic-generator (10.0.0.11)
    ├── SCP scapy_capture.py ─────────► traffic-analyzer  (10.0.0.12)
    │
    ├── SSH ──► traffic-generator
    │               └── python3 scapy_send.py --vlan 10 --size 1500
    │                       └── sends frame out eth0 (172.16.0.1)
    │                                   │
    │                               Gi1/0/5
    │                                   │
    │                            Cisco 3750 (DUT)
    │                                   │
    │                               Gi1/0/6
    │                                   │
    └── SSH ──► traffic-analyzer    eth0 (172.16.0.2)
                    └── python3 scapy_capture.py --timeout 5
                            └── results returned as JSON to orchestrator
```

---

## Files

| File | Location | Runs On |
|------|----------|---------|
| `scapy_engine.py` | `framework/traffic/` | Orchestrator |
| `scapy_send.py` | `framework/traffic/` | Generator (SCP'd) |
| `scapy_capture.py` | `framework/traffic/` | Analyzer (SCP'd) |
| `test_scapy_engine.py` | `tests/` | Orchestrator |

---

## Dependencies

Scapy is **not** needed on the orchestrator — it never crafts or sends packets
directly.

Install on generator and analyzer only:
```bash
sudo apt install -y python3-scapy
```

Scapy requires elevated privileges for raw socket access on the generator
and analyzer:
```bash
# Option 1 — run with sudo
sudo python3 scapy_send.py

# Option 2 — grant capabilities to avoid full sudo
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

