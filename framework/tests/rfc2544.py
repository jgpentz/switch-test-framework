"""RFC 2544 benchmark tests built on the iperf3 engine.

Four ordered tests per RFC 2544 (March 1999):
  1. Throughput  — binary search for zero-loss maximum bitrate
  2. Latency     — jitter at multiple fractions of zero-loss throughput
  3. Frame Loss  — loss curve stepping down from 100 % of link capacity
  4. Back-to-Back — burst absorption at line rate
"""

from __future__ import annotations

import statistics
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Generator

from framework.telemetry.cisco_snmp import poll_interface_counters
from framework.traffic.iperf3_engine import IPerf3Engine

RFC2544_FRAME_SIZES: tuple[int, ...] = (64, 128, 256, 512, 1024, 1280, 1472, 8972)

# Preamble (7) + SFD (1) + IFG (12) = 20 bytes per-frame Ethernet overhead
_ETHERNET_OVERHEAD_BYTES = 20


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class TelemetryConfig:
    """SNMP settings for optional before/after counter snapshots."""

    switch_ip: str
    community: str
    interface: str


@dataclass
class RFC2544Config:
    """Parameterises all four RFC 2544 benchmarks.

    ``link_capacity_bps`` anchors every %-of-line calculation.
    """

    link_capacity_bps: float = 1_000_000_000
    duration_sec: int = 5

    # Throughput
    throughput_tolerance_pct: float = 0.5
    throughput_max_iterations: int = 32

    # Latency
    latency_load_pcts: tuple[int, ...] = (10, 50, 100)
    latency_repeats_per_level: int = 5

    # Frame loss
    frame_loss_start_pct: int = 100
    frame_loss_step_pct: int = 10
    frame_loss_stop_after_zero_steps: int = 2
    frame_loss_bitrate_pcts: list[int] | None = field(default=None)

    # Back-to-back
    back_to_back_trials: int = 10
    back_to_back_trial_duration_sec: int = 2
    back_to_back_line_rate_pct: int = 100


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def bps_to_iperf_bitrate(bps: float) -> str:
    """Format a bits-per-second value as an iperf3 ``-b`` bitrate string.

    Prefers compact units — ``"1G"`` over ``"1000M"`` when the value is an
    exact multiple of 1 Gbps.
    """
    if bps >= 1_000_000_000 and bps % 1_000_000_000 == 0:
        return f"{int(bps // 1_000_000_000)}G"
    if bps >= 1_000_000:
        m = bps / 1_000_000
        return f"{int(m)}M" if m == int(m) else f"{m:.2f}M"
    if bps >= 1_000:
        k = bps / 1_000
        return f"{int(k)}K" if k == int(k) else f"{k:.2f}K"
    return str(int(bps))


def counter_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compute per-key integer difference between two SNMP counter snapshots."""
    delta: dict[str, Any] = {}
    for key in after:
        a, b = after[key], before.get(key)
        if isinstance(a, int) and isinstance(b, int):
            delta[key] = a - b
    return delta


@contextmanager
def snapshot_telemetry(
    telemetry: TelemetryConfig | None,
) -> Generator[dict[str, Any], None, None]:
    """Snapshot SNMP counters before/after the enclosed block.

    Yields a mutable dict whose ``switch_counter_delta`` key is populated on
    exit.  When *telemetry* is ``None`` the delta stays ``{}``.
    """
    ctx: dict[str, Any] = {"switch_counter_delta": {}}
    if telemetry is None:
        yield ctx
        return
    before = poll_interface_counters(
        telemetry.switch_ip, telemetry.community, telemetry.interface
    )
    yield ctx
    after = poll_interface_counters(
        telemetry.switch_ip, telemetry.community, telemetry.interface
    )
    ctx["switch_counter_delta"] = counter_delta(before, after)


# ---------------------------------------------------------------------------
# Test 1 — Throughput (binary search for zero-loss maximum)
# ---------------------------------------------------------------------------


def throughput(
    engine: IPerf3Engine,
    server_ip: str,
    config: RFC2544Config | None = None,
    telemetry: TelemetryConfig | None = None,
) -> dict[str, Any]:
    """RFC 2544 throughput — binary search for zero-loss maximum bitrate.

    Converges within ``throughput_tolerance_pct`` of link capacity or
    ``throughput_max_iterations`` trials, whichever comes first.
    """
    cfg = config or RFC2544Config()
    t0 = time.monotonic()

    with snapshot_telemetry(telemetry) as telem:
        per_frame_size_results: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []

        for frame_size in RFC2544_FRAME_SIZES:
            print(f"  Throughput @ {frame_size} B")
            low = 0.0
            high = cfg.link_capacity_bps
            best_zero_loss_bps = 0.0
            trials: list[dict[str, Any]] = []

            for iteration in range(cfg.throughput_max_iterations):
                mid = (low + high) / 2
                bitrate_str = bps_to_iperf_bitrate(mid)

                result = engine.run_udp(
                    server_ip=server_ip,
                    bitrate=bitrate_str,
                    duration=cfg.duration_sec,
                    length=frame_size,
                    include_raw_json=True,
                )
                result["frame_size"] = frame_size
                evidence.append(result)

                lost = result["lost_percent"]
                trials.append(
                    {
                        "frame_size": frame_size,
                        "iteration": iteration + 1,
                        "offered_bitrate_bps": mid,
                        "offered_bitrate_pct": round(
                            mid / cfg.link_capacity_bps * 100, 4
                        ),
                        "achieved_bitrate_bps": result["bitrate_bps"],
                        "lost_percent": lost,
                    }
                )

                if lost == 0.0:
                    best_zero_loss_bps = mid
                    low = mid
                else:
                    high = mid

                bracket_pct = (high - low) / cfg.link_capacity_bps * 100
                if bracket_pct <= cfg.throughput_tolerance_pct:
                    break

            per_frame_size_results.append(
                {
                    "frame_size": frame_size,
                    "zero_loss_bitrate_bps": best_zero_loss_bps,
                    "zero_loss_bitrate_pct": round(
                        best_zero_loss_bps / cfg.link_capacity_bps * 100, 2
                    ),
                    "trials": trials,
                }
            )

        best_overall = max(
            per_frame_size_results,
            key=lambda item: item["zero_loss_bitrate_bps"],
        )

    elapsed = time.monotonic() - t0
    return {
        "test": "throughput",
        "passed": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(elapsed, 3),
        "switch_counter_delta": telem["switch_counter_delta"],
        "details": {
            "best_frame_size": best_overall["frame_size"],
            "zero_loss_bitrate_bps": best_overall["zero_loss_bitrate_bps"],
            "zero_loss_bitrate_pct": best_overall["zero_loss_bitrate_pct"],
            "trials": best_overall["trials"],
            "per_frame_size_results": per_frame_size_results,
        },
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Test 2 — Latency (jitter at multiple load levels)
# ---------------------------------------------------------------------------


def latency(
    engine: IPerf3Engine,
    server_ip: str,
    throughput_results: dict[int, float],
    config: RFC2544Config | None = None,
    telemetry: TelemetryConfig | None = None,
) -> dict[str, Any]:
    """RFC 2544 latency — jitter per frame size at that size's throughput rate.

    *throughput_results* maps frame size to zero-loss bitrate (bps).  For each
    frame size the test runs ``latency_repeats_per_level`` trials at each load
    level in ``latency_load_pcts``.
    """
    cfg = config or RFC2544Config()
    t0 = time.monotonic()

    with snapshot_telemetry(telemetry) as telem:
        per_frame_size_results: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []

        for frame_size in RFC2544_FRAME_SIZES:
            throughput_bps = throughput_results.get(frame_size, 0.0)
            if throughput_bps <= 0:
                continue
            print(
                f"  Latency @ {frame_size} B  (throughput {throughput_bps / 1e6:.1f} Mbps)"
            )

            load_results: list[dict[str, Any]] = []
            for load_pct in cfg.latency_load_pcts:
                target_bps = throughput_bps * load_pct / 100
                bitrate_str = bps_to_iperf_bitrate(target_bps)

                jitter_samples: list[float] = []
                for _ in range(cfg.latency_repeats_per_level):
                    result = engine.run_udp(
                        server_ip=server_ip,
                        bitrate=bitrate_str,
                        duration=cfg.duration_sec,
                        length=frame_size,
                        include_raw_json=True,
                    )
                    result["frame_size"] = frame_size
                    evidence.append(result)
                    jitter_samples.append(result["jitter_ms"])

                avg = statistics.mean(jitter_samples)
                std = (
                    statistics.stdev(jitter_samples) if len(jitter_samples) > 1 else 0.0
                )
                load_results.append(
                    {
                        "load_pct": load_pct,
                        "jitter_ms_avg": round(avg, 6),
                        "jitter_ms_std": round(std, 6),
                        "jitter_ms_samples": jitter_samples,
                    }
                )

            per_frame_size_results.append(
                {
                    "frame_size": frame_size,
                    "throughput_bps": throughput_bps,
                    "results": load_results,
                }
            )

    elapsed = time.monotonic() - t0
    return {
        "test": "latency",
        "passed": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(elapsed, 3),
        "switch_counter_delta": telem["switch_counter_delta"],
        "details": {"per_frame_size_results": per_frame_size_results},
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Test 3 — Frame Loss Rate (step-down curve)
# ---------------------------------------------------------------------------


def frame_loss(
    engine: IPerf3Engine,
    server_ip: str,
    config: RFC2544Config | None = None,
    telemetry: TelemetryConfig | None = None,
) -> dict[str, Any]:
    """RFC 2544 frame loss — loss curve per frame size.

    Runs the stepwise sweep independently for each frame size in
    ``RFC2544_FRAME_SIZES``.  Stops each sweep after
    ``frame_loss_stop_after_zero_steps`` consecutive zero-loss results.
    """
    cfg = config or RFC2544Config()
    t0 = time.monotonic()

    if cfg.frame_loss_bitrate_pcts is not None:
        pct_steps = list(cfg.frame_loss_bitrate_pcts)
    else:
        pct_steps = list(
            range(
                cfg.frame_loss_start_pct,
                0,
                -cfg.frame_loss_step_pct,
            )
        )

    with snapshot_telemetry(telemetry) as telem:
        per_frame_size_results: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []

        for frame_size in RFC2544_FRAME_SIZES:
            print(f"  Frame loss @ {frame_size} B")
            sweep_results: list[dict[str, Any]] = []
            consecutive_zero = 0

            for pct in pct_steps:
                target_bps = cfg.link_capacity_bps * pct / 100
                bitrate_str = bps_to_iperf_bitrate(target_bps)

                result = engine.run_udp(
                    server_ip=server_ip,
                    bitrate=bitrate_str,
                    duration=cfg.duration_sec,
                    length=frame_size,
                    include_raw_json=True,
                )
                result["frame_size"] = frame_size
                evidence.append(result)

                loss_pct = result["lost_percent"]
                sweep_results.append(
                    {
                        "bitrate_pct": pct,
                        "bitrate_bps": target_bps,
                        "loss_pct": loss_pct,
                    }
                )

                if loss_pct == 0.0:
                    consecutive_zero += 1
                else:
                    consecutive_zero = 0

                if consecutive_zero >= cfg.frame_loss_stop_after_zero_steps:
                    break

            per_frame_size_results.append(
                {
                    "frame_size": frame_size,
                    "results": sweep_results,
                }
            )

    elapsed = time.monotonic() - t0
    return {
        "test": "frame_loss",
        "passed": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(elapsed, 3),
        "switch_counter_delta": telem["switch_counter_delta"],
        "details": {"per_frame_size_results": per_frame_size_results},
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Test 4 — Back-to-Back (burst tolerance at line rate)
# ---------------------------------------------------------------------------


def back_to_back(
    engine: IPerf3Engine,
    server_ip: str,
    config: RFC2544Config | None = None,
    telemetry: TelemetryConfig | None = None,
) -> dict[str, Any]:
    """RFC 2544 back-to-back — burst absorption at line rate per frame size.

    Runs ``back_to_back_trials`` UDP trials at line rate for each frame size
    in ``RFC2544_FRAME_SIZES``.  Frame count is *estimated* from achieved
    bitrate and frame size.
    """
    cfg = config or RFC2544Config()
    t0 = time.monotonic()

    line_rate_bps = cfg.link_capacity_bps * cfg.back_to_back_line_rate_pct / 100
    bitrate_str = bps_to_iperf_bitrate(line_rate_bps)

    with snapshot_telemetry(telemetry) as telem:
        per_frame_size_results: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []

        for frame_size in RFC2544_FRAME_SIZES:
            print(f"  Back-to-back @ {frame_size} B")
            bytes_per_frame = frame_size + _ETHERNET_OVERHEAD_BYTES
            burst_frames: list[int] = []

            for _ in range(cfg.back_to_back_trials):
                result = engine.run_udp(
                    server_ip=server_ip,
                    bitrate=bitrate_str,
                    duration=cfg.back_to_back_trial_duration_sec,
                    length=frame_size,
                    include_raw_json=True,
                )
                result["frame_size"] = frame_size
                evidence.append(result)

                total_bits = result["bitrate_bps"] * result["duration_sec"]
                total_frames = int(total_bits / 8 / bytes_per_frame)
                no_loss_frames = max(0, total_frames - result["lost_packets"])
                burst_frames.append(no_loss_frames)

            avg = statistics.mean(burst_frames) if burst_frames else 0.0
            std = statistics.stdev(burst_frames) if len(burst_frames) > 1 else 0.0

            per_frame_size_results.append(
                {
                    "frame_size": frame_size,
                    "max_burst_frames": max(burst_frames) if burst_frames else 0,
                    "avg_burst_frames": round(avg, 1),
                    "std_deviation": round(std, 1),
                    "trials": cfg.back_to_back_trials,
                }
            )

    elapsed = time.monotonic() - t0
    return {
        "test": "back_to_back",
        "passed": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(elapsed, 3),
        "switch_counter_delta": telem["switch_counter_delta"],
        "details": {"per_frame_size_results": per_frame_size_results},
        "evidence": evidence,
    }
