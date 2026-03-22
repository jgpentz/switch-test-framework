"""Tests for RFC 2544 benchmark functions.

All tests use a mocked IPerf3Engine — no real SSH or iperf3 invocations.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from framework.tests.rfc2544 import (
    RFC2544Config,
    back_to_back,
    bps_to_iperf_bitrate,
    counter_delta,
    frame_loss,
    latency,
    throughput,
)


# ---------------------------------------------------------------------------
# bps_to_iperf_bitrate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("bps", "expected"),
    [
        (1_000_000_000, "1G"),
        (2_000_000_000, "2G"),
        (10_000_000_000, "10G"),
        (500_000_000, "500M"),
        (950_000_000, "950M"),
        (100_000_000, "100M"),
        (1_500_000_000, "1500M"),
        (750_000, "750K"),
        (1_234_000, "1.23M"),
        (500, "500"),
    ],
    ids=["1G", "2G", "10G", "500M", "950M", "100M", "1.5G-as-M", "750K", "1.23M", "500bps"],
)
def test_bps_to_iperf_bitrate(bps: float, expected: str) -> None:
    assert bps_to_iperf_bitrate(bps) == expected


@pytest.mark.parametrize(
    "link_capacity_bps",
    [1_000_000_000, 10_000_000_000],
    ids=["1G", "10G"],
)
def test_bps_half_capacity_formats_cleanly(link_capacity_bps: float) -> None:
    """50 % of link capacity should produce a string ending with a unit."""
    result = bps_to_iperf_bitrate(link_capacity_bps / 2)
    assert result[-1] in ("G", "M", "K")


# ---------------------------------------------------------------------------
# counter_delta
# ---------------------------------------------------------------------------


def test_counter_delta_basic() -> None:
    before = {"rx_packets": 100, "tx_packets": 50, "interface": "Gi1/0/5"}
    after = {"rx_packets": 250, "tx_packets": 80, "interface": "Gi1/0/5"}
    delta = counter_delta(before, after)
    assert delta == {"rx_packets": 150, "tx_packets": 30}


def test_counter_delta_skips_non_int() -> None:
    before = {"rx_packets": 100, "label": "a"}
    after = {"rx_packets": 200, "label": "b"}
    delta = counter_delta(before, after)
    assert delta == {"rx_packets": 100}


# ---------------------------------------------------------------------------
# Mock engine helper
# ---------------------------------------------------------------------------


def _parse_bitrate_str(s: str) -> float:
    """Reverse ``bps_to_iperf_bitrate`` for test thresholding."""
    s = s.strip()
    if s.endswith("G"):
        return float(s[:-1]) * 1_000_000_000
    if s.endswith("M"):
        return float(s[:-1]) * 1_000_000
    if s.endswith("K"):
        return float(s[:-1]) * 1_000
    return float(s)


def _make_mock_engine(
    loss_threshold_bps: float = 800_000_000,
    loss_above_threshold_pct: float = 2.0,
    jitter_ms: float = 0.015,
) -> MagicMock:
    """Return a mock ``IPerf3Engine`` whose ``run_udp`` returns scripted results.

    Traffic above *loss_threshold_bps* reports *loss_above_threshold_pct* loss;
    traffic at or below the threshold reports zero loss.
    """
    engine = MagicMock(spec=["run_udp"])

    def fake_run_udp(
        server_ip: str,
        bitrate: str,
        duration: int = 30,
        length: int | None = None,
        include_raw_json: bool = False,
        **_: Any,
    ) -> dict[str, Any]:
        bps = _parse_bitrate_str(bitrate)
        lost = loss_above_threshold_pct if bps > loss_threshold_bps else 0.0
        result: dict[str, Any] = {
            "bitrate_bps": bps * 0.99 if lost else bps,
            "lost_percent": lost,
            "lost_packets": int(100 * lost) if lost else 0,
            "jitter_ms": jitter_ms,
            "duration_sec": float(duration),
            "protocol": "udp",
            "requested_bitrate": bitrate,
            "retransmits": 0,
            "timestamp": "2026-01-01T00:00:00+00:00",
        }
        if include_raw_json:
            result["raw_json"] = "{}"
        return result

    engine.run_udp.side_effect = fake_run_udp
    return engine


# ---------------------------------------------------------------------------
# test_throughput
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "link_capacity_bps",
    [1_000_000_000, 10_000_000_000],
    ids=["1G", "10G"],
)
def test_throughput_converges(link_capacity_bps: float) -> None:
    threshold = link_capacity_bps * 0.8
    engine = _make_mock_engine(loss_threshold_bps=threshold)
    cfg = RFC2544Config(
        link_capacity_bps=link_capacity_bps,
        duration_sec=1,
        throughput_tolerance_pct=1.0,
        throughput_max_iterations=30,
    )

    result = throughput(engine, "172.16.0.2", config=cfg)

    assert result["test"] == "throughput"
    assert result["passed"] is True
    details = result["details"]
    assert details["zero_loss_bitrate_bps"] > 0
    assert 70 < details["zero_loss_bitrate_pct"] < 85
    assert len(details["trials"]) > 0
    assert len(result["evidence"]) == len(details["trials"])


def test_throughput_zero_loss_everywhere() -> None:
    """When no loss exists at any rate, throughput converges near 100 %."""
    engine = _make_mock_engine(loss_threshold_bps=2_000_000_000)
    cfg = RFC2544Config(
        link_capacity_bps=1_000_000_000,
        duration_sec=1,
        throughput_tolerance_pct=1.0,
    )

    result = throughput(engine, "172.16.0.2", config=cfg)

    assert result["details"]["zero_loss_bitrate_pct"] > 95


# ---------------------------------------------------------------------------
# test_latency
# ---------------------------------------------------------------------------


def test_latency_structure() -> None:
    engine = _make_mock_engine(jitter_ms=0.020)
    cfg = RFC2544Config(
        duration_sec=1,
        latency_load_pcts=(10, 50, 100),
        latency_repeats_per_level=3,
    )

    result = latency(
        engine, "172.16.0.2", throughput_bps=800_000_000, config=cfg
    )

    assert result["test"] == "latency"
    assert len(result["details"]["results"]) == 3
    for level in result["details"]["results"]:
        assert level["load_pct"] in (10, 50, 100)
        assert level["jitter_ms_avg"] == pytest.approx(0.020, abs=0.001)
        assert len(level["jitter_ms_samples"]) == 3
    # 3 load levels × 3 repeats = 9 total engine calls
    assert len(result["evidence"]) == 9


# ---------------------------------------------------------------------------
# test_frame_loss
# ---------------------------------------------------------------------------


def test_frame_loss_stops_after_two_zero() -> None:
    """Should stop after two successive zero-loss steps."""
    engine = _make_mock_engine(
        loss_threshold_bps=750_000_000, loss_above_threshold_pct=3.0
    )
    cfg = RFC2544Config(
        link_capacity_bps=1_000_000_000,
        duration_sec=1,
        frame_loss_step_pct=10,
        frame_loss_stop_after_zero_steps=2,
    )

    result = frame_loss(engine, "172.16.0.2", config=cfg)

    assert result["test"] == "frame_loss"
    steps = result["details"]["results"]
    # 100 %→loss, 90 %→loss, 80 %→loss, 70 %→0, 60 %→0 → stop
    loss_values = [s["loss_pct"] for s in steps]
    assert loss_values[-1] == 0.0
    assert loss_values[-2] == 0.0
    assert len(steps) < 10


def test_frame_loss_custom_pcts() -> None:
    """Override ``frame_loss_bitrate_pcts`` replaces generated steps."""
    engine = _make_mock_engine(loss_threshold_bps=500_000_000)
    cfg = RFC2544Config(
        link_capacity_bps=1_000_000_000,
        duration_sec=1,
        frame_loss_bitrate_pcts=[80, 40, 20],
        frame_loss_stop_after_zero_steps=2,
    )

    result = frame_loss(engine, "172.16.0.2", config=cfg)

    pcts = [s["bitrate_pct"] for s in result["details"]["results"]]
    # 80 %→loss; 40 %→0; 20 %→0 → stop
    assert pcts == [80, 40, 20]


# ---------------------------------------------------------------------------
# test_back_to_back
# ---------------------------------------------------------------------------


def test_back_to_back_structure() -> None:
    engine = _make_mock_engine(loss_threshold_bps=2_000_000_000)
    cfg = RFC2544Config(
        link_capacity_bps=1_000_000_000,
        duration_sec=1,
        back_to_back_trials=5,
        back_to_back_trial_duration_sec=2,
    )

    result = back_to_back(engine, "172.16.0.2", config=cfg)

    assert result["test"] == "back_to_back"
    d = result["details"]
    assert d["trials"] == 5
    assert d["max_burst_frames"] > 0
    assert d["avg_burst_frames"] > 0
    assert d["frame_size"] == 1518
    assert len(result["evidence"]) == 5


@pytest.mark.parametrize(
    "frame_length",
    [64, 512, 1518],
    ids=["64B", "512B", "1518B"],
)
def test_back_to_back_respects_frame_length(frame_length: int) -> None:
    engine = _make_mock_engine(loss_threshold_bps=2_000_000_000)
    cfg = RFC2544Config(
        link_capacity_bps=1_000_000_000,
        duration_sec=1,
        back_to_back_trials=3,
        back_to_back_trial_duration_sec=2,
        frame_length=frame_length,
    )

    result = back_to_back(engine, "172.16.0.2", config=cfg)

    assert result["details"]["frame_size"] == frame_length
    assert result["details"]["max_burst_frames"] > 0
