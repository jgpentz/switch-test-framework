i# Phase 3 — Test Suite

## Status
- [x] Telemetry module (`cisco_snmp.py`) — SNMP interface counters + Netmiko MAC table
- [ ] RFC 2544 benchmark tests (`rfc2544.py`)
- [ ] Functional tests (`functional.py`)
- [ ] Telemetry wired into every test

---

## Overview

Phase 3 builds the actual tests that exercise the switch. Two tracks:

- **RFC 2544 Benchmarks** — uses the iperf3 engine to characterize switch
  performance. Produces the numbers that define what the switch can and
  cannot handle.
- **Functional Tests** — uses the Scapy engine to verify the switch is
  behaving correctly at the protocol level. Produces pass/fail results.

Both tracks snapshot SNMP counters before and after every test and attach
the delta to the result.

---

## File Structure

```
framework/
├── tests/
│   ├── __init__.py
│   ├── rfc2544.py         ← iperf3 engine
│   └── functional.py      ← scapy engine
├── telemetry/
│   ├── __init__.py
│   └── cisco_snmp.py      ← DONE — SNMP counters + Netmiko MAC table
```

---

## Part 1 — RFC 2544 Benchmarks

### Background

RFC 2544 (March 1999) is the industry standard for benchmarking network
devices. It defines four specific tests so results are comparable across
vendors and platforms. The four tests must be run in this order — each
builds on the previous.

### Frame Rates

Frame sizes to be used on Ethernet

64, 128, 256, 512, 1024, 1280, 1518


---

### Test 1 — Throughput

**Purpose:** Find the maximum rate at which the switch forwards frames with
zero packet loss. This is the reference number everything else is measured
against.

**How it works:**
- Use a binary search algorithm
- Start at 100% of link capacity
- If loss is detected, reduce rate. If no loss, increase rate.
- Converge within 0.5% tolerance
- Report the zero-loss maximum in bps and as a percentage of link capacity

**Inputs:** server IP, tolerance %, duration per trial, link capacity

**Outputs:**
```json
{
  "test": "throughput",
  "zero_loss_bitrate_bps": 950000000,
  "zero_loss_bitrate_pct": 95.0,
  "trials": [],
  "switch_counter_delta": {},
  "timestamp": "..."
}
```

---

### Test 2 — Latency

**Purpose:** Measure how long the switch takes to forward traffic at
different load levels. Shows whether forwarding delay grows under load.

**How it works:**
- Requires throughput result from Test 1
- Run UDP at 10%, 50%, and 100% of the zero-loss throughput rate
- Record jitter at each level as the latency proxy
- Repeat 20 times per load level per RFC 2544, report average

**Inputs:** server IP, throughput rate (from Test 1), duration per trial

**Outputs:**
```json
{
  "test": "latency",
  "results": [
    { "load_pct": 10, "jitter_ms_avg": 0.010 },
    { "load_pct": 50, "jitter_ms_avg": 0.014 },
    { "load_pct": 100, "jitter_ms_avg": 0.021 }
  ],
  "switch_counter_delta": {},
  "timestamp": "..."
}
```

---

### Test 3 — Frame Loss Rate

**Purpose:** Map how loss increases as load exceeds the switch's forwarding
capacity. Produces a loss curve across the full range of input rates.

**How it works:**
- Start at 100% of link capacity, step down in 10% increments
- At each step, calculate loss using RFC 2544 formula:
  ((input_count - output_count) * 100) / input_count
- Stop after two successive trials with zero loss
- Plot loss % vs input rate %

**Inputs:** server IP, bitrate steps, duration per step

**Outputs:**
```json
{
  "test": "frame_loss",
  "results": [
    { "bitrate_pct": 100, "loss_pct": 4.2 },
    { "bitrate_pct": 90,  "loss_pct": 0.8 },
    { "bitrate_pct": 80,  "loss_pct": 0.0 },
    { "bitrate_pct": 70,  "loss_pct": 0.0 }
  ],
  "switch_counter_delta": {},
  "timestamp": "..."
}
```

---

### Test 4 — Back-to-Back (Burst)

**Purpose:** Find the maximum burst of frames the switch can absorb without
dropping. Characterizes the switch's buffer depth.

**How it works:**
- Send bursts of frames at line rate with minimum inter-frame gaps
- If no loss — increase burst size and rerun
- If loss detected — reduce burst size and rerun
- RFC 2544 requires trial length of at least 2 seconds, repeated 50 times
- Report the average maximum burst size across all trials

**Inputs:** server IP, initial burst size, step size, trials

**Outputs:**
```json
{
  "test": "back_to_back",
  "max_burst_frames": 1250,
  "trials": 50,
  "std_deviation": 12.4,
  "switch_counter_delta": {},
  "timestamp": "..."
}
```

---

## Part 2 — Functional Tests

### Background

Functional tests verify the switch is doing what it is configured to do.
These use the Scapy engine to craft specific frames and observe the switch's
exact response. Results are pass/fail with evidence — frames sent and
received are logged.

Build order is from simplest to most complex.

---

### Test 1 — VLAN Isolation

**Purpose:** Confirm traffic on one VLAN cannot be seen on another VLAN.
Fundamental security and segmentation guarantee.

**How it works:**
- Send a frame tagged with VLAN 10 from the generator
- Listen on the analyzer which is on a different VLAN
- Pass if frame does NOT arrive. Fail if it does.

**Uses:** `scapy_engine.check_vlan_isolation()`

**Pass condition:** Zero frames received on the wrong VLAN

---

### Test 2 — MAC Learning

**Purpose:** Verify the switch learns source MAC addresses and stops
flooding after the first frame.

**How it works:**
- Send a burst of frames from a known source MAC
- Query the MAC table via Netmiko (`get_mac_table()`)
- Confirm the source MAC appears in the table on the correct port
- Send a second frame — confirm it is forwarded directly, not flooded

**Uses:** `scapy_engine.send_burst()` + `cisco_snmp.get_mac_table()`

**Pass condition:** MAC appears in table on correct port, flooding stops
after learning

---

### Test 3 — Jumbo Frames

**Purpose:** Confirm 9000-byte frames are forwarded without fragmentation
or drops when jumbo MTU is configured.

**How it works:**
- Send a single 9000-byte frame from generator to analyzer
- Confirm it arrives intact and unmodified on the analyzer
- Check switch interface counters for any giant/error increments

**Uses:** `scapy_engine.send_and_capture()`

**Pass condition:** Frame arrives at full size, no error counters increment

---

### Test 4 — 802.1Q Tagging

**Purpose:** Verify VLAN tags are preserved correctly on trunk ports and
stripped/added correctly on access ports.

**How it works:**
- Send a frame with a specific VLAN tag from generator
- Capture on analyzer and inspect the tag in the received frame
- Confirm tag is present and correct

**Uses:** `scapy_engine.send_and_capture()`

**Pass condition:** Received frame contains correct VLAN tag

---

### Test 5 — STP Convergence

**Purpose:** Measure how long it takes the switch to resume forwarding
after a link failure. Verify RSTP converges in under 1 second vs 802.1D
30 seconds.

**How it works:**
- Start continuous traffic between generator and analyzer
- Simulate a link failure (manually disconnect or use switch CLI)
- Measure time from link failure to traffic resumption
- Compare against 802.1D (30s) and RSTP (<1s) targets

**Uses:** `iperf3_engine.run_udp()` + `cisco_snmp.get_interface_counters()`

**Pass condition:** Convergence time within expected threshold for
configured STP mode

---

### Test 6 — ACL Enforcement

**Purpose:** Verify that ACL permit and deny rules produce the correct
forwarding behavior.

**How it works:**
- Push a test ACL to the switch via Ansible (permit rule + deny rule)
- Send frames that match the permit rule — confirm they arrive
- Send frames that match the deny rule — confirm they do not arrive
- Roll back ACL config via Ansible after test

**Uses:** `scapy_engine.send_and_capture()` + Ansible pre/post playbooks

**Pass condition:** Permitted frames arrive, denied frames do not

---

## Telemetry Integration

Every test — RFC 2544 and functional — follows the same wrapper pattern:

```
1. Snapshot switch interface counters (before)
2. Run test
3. Snapshot switch interface counters (after)
4. Calculate delta (tx/rx packets, errors, drops)
5. Attach delta to result dict
```

This correlates test-side observations with switch-side ground truth. When
iperf3 reports loss, you can see exactly which port dropped frames and why.

---

## Result Structure (All Tests)

Every test result — regardless of type — includes:

| Field | Description |
|-------|-------------|
| `test` | Test name |
| `passed` | Boolean pass/fail |
| `timestamp` | ISO 8601 when test ran |
| `duration_sec` | How long the test took |
| `switch_counter_delta` | SNMP counter delta before/after |
| `details` | Test-specific result data |
| `evidence` | Frames sent/received, raw iperf3 JSON |

---

## Build Order

| Order | Test | Track | Depends On |
|-------|------|-------|------------|
| 1 | Throughput | RFC 2544 | iperf3 engine |
| 2 | Latency | RFC 2544 | Throughput result |
| 3 | Frame Loss | RFC 2544 | iperf3 engine |
| 4 | Back-to-Back | RFC 2544 | iperf3 engine |
| 5 | VLAN Isolation | Functional | Scapy engine |
| 6 | MAC Learning | Functional | Scapy engine + Netmiko |
| 7 | Jumbo Frames | Functional | Scapy engine |
| 8 | 802.1Q Tagging | Functional | Scapy engine |
| 9 | STP Convergence | Functional | iperf3 engine + SNMP |
| 10 | ACL Enforcement | Functional | Scapy engine + Ansible |