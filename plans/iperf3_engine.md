# iperf3 Engine

## Purpose

The iperf3 engine measures how well the switch forwards traffic under load. It
drives iperf3 via subprocess from the orchestrator, fires sustained TCP or UDP
streams from the generator through the 3750 to the analyzer, and returns
structured results — throughput, packet loss, jitter, retransmits.

This is the **performance measurement** tool. Every RFC 2544 benchmark test
(throughput, frame loss, latency) is built on top of this engine. It answers
the question: *how well is the switch forwarding traffic?*

---

## Requirements

- iperf3 server runs permanently on the **traffic-analyzer** (172.16.0.2) as
  a systemd service on port 5201 — no action needed on the analyzer during
  test runs
- Orchestrator SSHes into the **traffic-generator** (10.0.0.11) and runs
  iperf3 client, which drives the full test and returns complete results
- iperf3 is called via `subprocess` with `--json` flag — no screen scraping,
  no regex, clean structured output
- Results must be consistent structured dicts so the test runner can score
  them against pass/fail thresholds defined in YAML profiles
- Must raise descriptive exceptions on non-zero exit codes or JSON parse
  failures

---

## Workflow

iperf3 is simpler than Scapy — no SCP needed. The iperf3 binary is already
installed on the generator and analyzer. The orchestrator SSHes into the
generator, runs the client command, and reads the JSON output. The analyzer
server is always listening and never needs to be touched during a test.

```
1. Analyzer iperf3 server — always running as systemd service on port 5201

2. Orchestrator SSHes into generator and runs iperf3 client
       SSH ──► traffic-generator (10.0.0.11)
                   └── iperf3 --client 172.16.0.2 --udp --bitrate 500M --json

3. iperf3 client fires traffic through the switch
       172.16.0.1 ──► Gi1/0/5 ──► Cisco 3750 ──► Gi1/0/6 ──► 172.16.0.2

4. Client collects results from both ends and returns complete JSON
       └── orchestrator parses JSON and returns structured result dict
```

---

## How It Fits Into the Framework

```
orchestrator (10.0.0.10)
    │
    └── SSH ──► traffic-generator (10.0.0.11)
                    └── iperf3 client ──► 172.16.0.1
                                              │
                                          Gi1/0/5
                                              │
                                       Cisco 3750 (DUT)
                                              │
                                          Gi1/0/6
                                              │
                                 traffic-analyzer (172.16.0.2)
                                     iperf3 server :5201
                                     (always listening)
                                              │
                        results returned to client as JSON
                                              │
                        orchestrator parses and scores results
```

---

## What We Are Implementing

### `IPerf3Engine` class

#### `run_tcp(server_ip, duration, parallel)`
Runs a TCP throughput test. Parallel streams saturate the link. Retransmits
indicate switch-induced congestion or drops.

**Returns:** throughput in bps, retransmits, duration, timestamp

---

#### `run_udp(server_ip, bitrate, duration, parallel)`
Runs a UDP test at a fixed bitrate (e.g. `"500M"`, `"1G"`). UDP mode injects
traffic at a controlled rate and reports exactly how much was lost — this is
how RFC 2544 frame loss tests work.

**Returns:** throughput in bps, lost packets, loss percent, jitter, duration,
timestamp

---

#### `run_stepwise_udp(server_ip, bitrate_steps, duration)`
Iterates through a list of bitrate strings and runs a UDP test at each one.
Used to produce the RFC 2544 frame loss curve — how loss changes as load
increases from 10% to 100%.

**Returns:** list of result dicts, one per bitrate step

---

## Result Dict Format

Every method returns a dict with the following keys:

| Key | Type | Description |
|-----|------|-------------|
| `bitrate_bps` | float | Achieved throughput in bits per second |
| `retransmits` | int | TCP retransmits (0 for UDP) |
| `lost_packets` | int | UDP lost packets (0 for TCP) |
| `lost_percent` | float | UDP loss percentage (0 for TCP) |
| `jitter_ms` | float | UDP jitter in milliseconds (0 for TCP) |
| `protocol` | str | `"tcp"` or `"udp"` |
| `requested_bitrate` | str | Bitrate requested (UDP only, else None) |
| `duration_sec` | float | Actual test duration in seconds |
| `timestamp` | str | ISO 8601 timestamp of when the test ran |

---

## TCP vs UDP Modes

| Mode | Use Case |
|------|----------|
| TCP | Throughput measurement with retransmit tracking. Retransmits indicate switch-induced congestion. Parallel streams (-P 4+) saturate the link. |
| UDP | Fixed-rate traffic injection for frame loss and latency. --bitrate controls the load level. Reports loss % and jitter directly. |

---

## Traffic Profile YAML

Test parameters are defined in YAML and passed to the engine by the test
runner — engineers can modify what gets tested without touching Python code:

```yaml
traffic_profile:
  name: RFC2544_Throughput_1G
  tool: iperf3
  mode: udp
  parallel_streams: 4
  duration_sec: 30
  bitrate_steps:
    - 100M
    - 250M
    - 500M
    - 750M
    - 900M
    - 950M
  acceptable_loss_pct: 0.0
  vlan: 10
  server_ip: 172.16.0.2
```

---

## Files

| File | Location | Runs On |
|------|----------|---------|
| `iperf3_engine.py` | `framework/traffic/` | Orchestrator (via SSH to generator) |
| `test_iperf3_engine.py` | `tests/` | Orchestrator |

---

## Dependencies

iperf3 must be installed on the **generator and analyzer** VMs:

```bash
sudo apt install -y iperf3
```

iperf3 server must run as a systemd service on the **analyzer**:

```ini
# /etc/systemd/system/iperf3.service
[Unit]
Description=iperf3 server

[Service]
ExecStart=/usr/bin/iperf3 --server --port 5201
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable iperf3
sudo systemctl start iperf3
```

iperf3 is **not** needed on the orchestrator — it never sends traffic
directly.
