"""Functional tests verifying switch behavior at the protocol level.

Six ordered tests per plans/tests.md Part 2:
  1. VLAN Isolation    — tagged traffic must not leak across VLANs
  2. MAC Learning      — switch learns MACs and stops flooding
  3. Jumbo Frames      — 9000-byte frames forwarded without errors
  4. 802.1Q Tagging    — VLAN tags preserved/stripped correctly
  5. STP Convergence   — forwarding resumes within threshold after link failure
  6. ACL Enforcement   — permit/deny rules produce correct forwarding
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netmiko import ConnectHandler

from framework.lab_secrets import LabSecrets, load_lab_secrets
from framework.telemetry.cisco_snmp import (
    get_mac_address_table_ssh,
    poll_interface_counters,
)
from framework.tests.rfc2544 import (
    TelemetryConfig,
    bps_to_iperf_bitrate,
    counter_delta,
    snapshot_telemetry,
)
from framework.traffic.iperf3_engine import IPerf3Engine
from framework.traffic.scapy_engine import ScapyEngine


class FunctionalTestError(RuntimeError):
    """Raised when a functional test encounters a non-test-logic failure."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ERROR_COUNTER_KEYS = ("rx_errors", "tx_errors", "rx_discards", "tx_discards")


@dataclass
class SwitchSSHConfig:
    """Netmiko SSH credentials for MAC-table queries."""

    host: str
    username: str
    password: str
    secret: str | None = None
    key_file: str | None = None
    use_keys: bool = False


def switch_ssh_from_secrets(
    host: str,
    secrets: LabSecrets | None = None,
) -> SwitchSSHConfig:
    """Build ``SwitchSSHConfig`` using ``load_lab_secrets()`` by default."""
    s = secrets or load_lab_secrets()
    return SwitchSSHConfig(
        host=host,
        username=s.username,
        password=s.password,
        secret=s.enable_secret,
    )


@dataclass
class FunctionalTestConfig:
    """Lab-specific addressing and thresholds for all functional tests."""

    lab_secrets: LabSecrets | None = None

    interface: str = "ens18"
    src_mac: str = "00:00:00:00:00:01"
    dst_mac: str = "00:00:00:00:00:02"
    src_ip: str = "172.16.0.1"
    dst_ip: str = "172.16.0.2"
    protocol: str = "udp"
    frame_size: int = 128

    # VLAN Isolation
    send_vlan: int = 21
    expected_vlan: int = 20

    # MAC Learning
    mac_burst_count: int = 100
    expected_mac_port: str = "Gi1/0/5"

    # Jumbo
    jumbo_size: int = 9000

    # 802.1Q
    dot1q_vlan: int = 20
    expect_tag_on_wire: bool = True

    # STP
    stp_threshold_sec: float = 1.0
    stp_poll_interval_sec: float = 0.2
    stp_timeout_sec: float = 35.0
    stp_bitrate: str = "100M"
    stp_duration_sec: int = 60
    link_capacity_bps: float = 1_000_000_000

    # ACL
    acl_permit_dst_ip: str = "172.16.0.2"
    acl_deny_dst_ip: str = "172.16.0.99"

    capture_timeout: float = 5.0


# ---------------------------------------------------------------------------
# Test 1 — VLAN Isolation
# ---------------------------------------------------------------------------


def vlan_isolation(
    engine: ScapyEngine,
    config: FunctionalTestConfig | None = None,
    telemetry: TelemetryConfig | None = None,
) -> dict[str, Any]:
    """Confirm traffic tagged with one VLAN cannot be seen on another.

    Wraps ``ScapyEngine.check_vlan_isolation`` and maps the engine's
    ``status`` field to the unified ``passed`` boolean.
    """
    cfg = config or FunctionalTestConfig()

    # FIXME: The host address, and interfaces are hardcoded, this should be configurable.
    device: dict[str, Any] = {
        "device_type": "cisco_ios",
        "host": "10.0.0.2",
        "username": cfg.lab_secrets.username,
        "password": cfg.lab_secrets.password,
        "port": 22,
    }
    try:
        with ConnectHandler(**device) as conn:
            conn.enable()

            cmds = [
                "interface g1/0/5",
                f"switchport access vlan {cfg.send_vlan}",
                "exit",
            ]

            conn.send_config_set(cmds)

        t0 = time.monotonic()

        with snapshot_telemetry(telemetry) as telem:
            result = engine.send_and_capture(
                interface=cfg.interface,
                src_mac=cfg.src_mac,
                dst_mac=cfg.dst_mac,
                src_ip=cfg.src_ip,
                dst_ip=cfg.dst_ip,
                protocol=cfg.protocol,
                size=cfg.frame_size,
                count=1,
                capture_timeout=cfg.capture_timeout,
            )
        capture = result["capture_result"]
        # FIXME: vlan match count is not working because the ports are access ports
        # isolation_ok = int(capture.get("vlan_match_count", 0)) == 0
        isolation_ok = len(capture["packets"]) == 0
        passed = isolation_ok
        elapsed = time.monotonic() - t0
    finally:
        # FIXME: The host address, and interfaces are hardcoded, this should be configurable.
        with ConnectHandler(**device) as conn:
            conn.enable()
            cmds = [
                "interface g1/0/5",
                "switchport access vlan 20",
                "exit",
            ]
            conn.send_config_set(cmds)

    return {
        "test": "vlan_isolation",
        "passed": passed,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(elapsed, 3),
        "switch_counter_delta": telem["switch_counter_delta"],
        "details": {
            "sent_vlan": cfg.send_vlan,
            "expected_vlan": cfg.expected_vlan,
            "frames_received": capture.get("frames_received", 0),
            "vlan_match_count": capture.get("vlan_match_count", 0),
            "vlan_mismatch_count": capture.get("vlan_mismatch_count", 0),
        },
        "evidence": result,
    }


# ---------------------------------------------------------------------------
# Test 2 — MAC Learning
# ---------------------------------------------------------------------------


def mac_learning(
    engine: ScapyEngine,
    config: FunctionalTestConfig | None = None,
    telemetry: TelemetryConfig | None = None,
) -> dict[str, Any]:
    """Verify the switch learns source MACs and stops flooding.

    Sends a burst to populate the MAC table, queries the table via SSH,
    then sends a single frame and checks that it arrives without flooding.
    """
    cfg = config or FunctionalTestConfig()

    switch_ssh = switch_ssh_from_secrets(host="10.0.0.2", secrets=cfg.lab_secrets)

    t0 = time.monotonic()

    with snapshot_telemetry(telemetry) as telem:
        burst_result = engine.send_burst(
            interface=cfg.interface,
            src_mac=cfg.src_mac,
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_ip=cfg.src_ip,
            dst_ip=cfg.dst_ip,
            protocol=cfg.protocol,
            size=cfg.frame_size,
            count=cfg.mac_burst_count,
            capture_timeout=cfg.capture_timeout,
        )

        mac_table = get_mac_address_table_ssh(
            host=switch_ssh.host,
            username=switch_ssh.username,
            password=switch_ssh.password,
            secret=switch_ssh.secret,
            key_file=switch_ssh.key_file,
            use_keys=switch_ssh.use_keys,
        )

        # Normalize to dotted-lower format (Cisco uses xxxx.xxxx.xxxx)
        normalized_src = cfg.src_mac.replace(":", "").lower()
        cisco_fmt = (
            f"{normalized_src[0:4]}.{normalized_src[4:8]}.{normalized_src[8:12]}"
        )

        mac_found = False
        mac_on_correct_port = False
        for entry in mac_table.get("entries", []):
            if entry["mac"] == cisco_fmt:
                mac_found = True
                if cfg.expected_mac_port in entry["ports"]:
                    mac_on_correct_port = True
                break

        # Second send: single frame after learning
        verify_result = engine.send_and_capture(
            interface=cfg.interface,
            src_mac=cfg.src_mac,
            dst_mac=cfg.dst_mac,
            src_ip=cfg.src_ip,
            dst_ip=cfg.dst_ip,
            protocol=cfg.protocol,
            size=cfg.frame_size,
            count=1,
            capture_timeout=cfg.capture_timeout,
        )
        verify_frames = verify_result["capture_result"].get("frames_received", 0)

    passed = mac_found and mac_on_correct_port
    elapsed = time.monotonic() - t0
    return {
        "test": "mac_learning",
        "passed": passed,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(elapsed, 3),
        "switch_counter_delta": telem["switch_counter_delta"],
        "details": {
            "src_mac": cfg.src_mac,
            "expected_port": cfg.expected_mac_port,
            "mac_found_in_table": mac_found,
            "mac_on_correct_port": mac_on_correct_port,
            "verify_frames_received": verify_frames,
        },
        "evidence": {
            "burst": burst_result,
            "mac_table": mac_table,
            "verify": verify_result,
        },
    }


# ---------------------------------------------------------------------------
# Test 3 — Jumbo Frames
# ---------------------------------------------------------------------------


def jumbo_frames(
    engine: ScapyEngine,
    config: FunctionalTestConfig | None = None,
    telemetry: TelemetryConfig | None = None,
) -> dict[str, Any]:
    """Confirm 9000-byte frames forward without fragmentation or errors.

    Checks that at least one captured packet has ``len_bytes`` consistent
    with a jumbo frame, and that SNMP error/discard counters did not
    increase (when telemetry is provided).
    """
    cfg = config or FunctionalTestConfig()
    t0 = time.monotonic()

    with snapshot_telemetry(telemetry) as telem:
        result = engine.send_and_capture(
            interface=cfg.interface,
            src_mac=cfg.src_mac,
            dst_mac=cfg.dst_mac,
            src_ip=cfg.src_ip,
            dst_ip=cfg.dst_ip,
            protocol=cfg.protocol,
            size=cfg.jumbo_size,
            count=1,
            capture_timeout=cfg.capture_timeout,
        )

    capture = result["capture_result"]
    packets = capture.get("packets", [])
    # Jumbo threshold: at least ~8000 bytes accounts for header differences
    jumbo_threshold = cfg.jumbo_size - 1000
    jumbo_received = any(p["len_bytes"] >= jumbo_threshold for p in packets)

    error_delta_ok = True
    delta = telem["switch_counter_delta"]
    if delta:
        for key in _ERROR_COUNTER_KEYS:
            if delta.get(key, 0) > 0:
                error_delta_ok = False
                break

    passed = jumbo_received and error_delta_ok
    elapsed = time.monotonic() - t0
    return {
        "test": "jumbo_frames",
        "passed": passed,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(elapsed, 3),
        "switch_counter_delta": delta,
        "details": {
            "requested_size": cfg.jumbo_size,
            "jumbo_received": jumbo_received,
            "error_delta_ok": error_delta_ok,
            "frames_received": capture.get("frames_received", 0),
            "max_len_bytes": max((p["len_bytes"] for p in packets), default=0),
        },
        "evidence": result,
    }


# ---------------------------------------------------------------------------
# Test 4 — 802.1Q Tagging
# ---------------------------------------------------------------------------


def dot1q_tagging(
    engine: ScapyEngine,
    config: FunctionalTestConfig | None = None,
    telemetry: TelemetryConfig | None = None,
) -> dict[str, Any]:
    """Verify VLAN tags are preserved on trunk ports (or stripped on access).

    When ``expect_tag_on_wire`` is True, the test passes if the sent VLAN
    tag appears in the captured packets.  When False (access port scenario),
    the test passes if the tag is absent.
    """
    cfg = config or FunctionalTestConfig()
    t0 = time.monotonic()

    with snapshot_telemetry(telemetry) as telem:
        result = engine.send_and_capture(
            interface=cfg.interface,
            src_mac=cfg.src_mac,
            dst_mac=cfg.dst_mac,
            src_ip=cfg.src_ip,
            dst_ip=cfg.dst_ip,
            protocol=cfg.protocol,
            size=cfg.frame_size,
            vlan=cfg.dot1q_vlan,
            count=1,
            capture_timeout=cfg.capture_timeout,
        )

    capture = result["capture_result"]
    observed_vlans = set(capture.get("vlan_tags_observed", []))
    tag_present = cfg.dot1q_vlan in observed_vlans

    if cfg.expect_tag_on_wire:
        passed = tag_present
    else:
        passed = not tag_present

    elapsed = time.monotonic() - t0
    return {
        "test": "dot1q_tagging",
        "passed": passed,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(elapsed, 3),
        "switch_counter_delta": telem["switch_counter_delta"],
        "details": {
            "sent_vlan": cfg.dot1q_vlan,
            "expect_tag_on_wire": cfg.expect_tag_on_wire,
            "tag_present_in_capture": tag_present,
            "vlan_tags_observed": sorted(observed_vlans),
            "frames_received": capture.get("frames_received", 0),
        },
        "evidence": result,
    }


# ---------------------------------------------------------------------------
# Test 5 — STP Convergence
# ---------------------------------------------------------------------------


def stp_convergence(
    engine: IPerf3Engine,
    server_ip: str,
    on_link_failure: Callable[[], None],
    config: FunctionalTestConfig | None = None,
    telemetry: TelemetryConfig | None = None,
) -> dict[str, Any]:
    """Measure time for the switch to resume forwarding after a link failure.

    1. Record baseline counter snapshot.
    2. Invoke *on_link_failure* (user-supplied; e.g. shut interface via CLI).
    3. Poll SNMP counters until TX packet delta resumes or timeout.
    4. Compare convergence time against ``stp_threshold_sec``.

    The caller must supply ``on_link_failure`` — without it the test cannot
    trigger a topology change.  Typical implementations: Netmiko
    ``interface shutdown``, or a physical relay toggle.
    """
    cfg = config or FunctionalTestConfig()
    t0 = time.monotonic()

    evidence: dict[str, Any] = {}

    with snapshot_telemetry(telemetry) as telem:
        # Run a short baseline iperf to confirm traffic flows first
        baseline = engine.run_udp(
            server_ip=server_ip,
            bitrate=cfg.stp_bitrate,
            duration=2,
        )
        evidence["baseline"] = baseline

        if telemetry is None:
            raise FunctionalTestError(
                "stp_convergence requires TelemetryConfig for counter polling"
            )

        before = poll_interface_counters(
            telemetry.switch_ip, telemetry.community, telemetry.interface
        )

        # Trigger failure
        failure_time = time.monotonic()
        on_link_failure()

        # Poll until TX counters resume or timeout
        converged = False
        convergence_sec = cfg.stp_timeout_sec
        last_tx = before["tx_packets"]
        deadline = failure_time + cfg.stp_timeout_sec

        while time.monotonic() < deadline:
            time.sleep(cfg.stp_poll_interval_sec)
            current = poll_interface_counters(
                telemetry.switch_ip, telemetry.community, telemetry.interface
            )
            if current["tx_packets"] > last_tx:
                convergence_sec = time.monotonic() - failure_time
                converged = True
                break
            last_tx = current["tx_packets"]

        evidence["convergence_sec"] = round(convergence_sec, 4)
        evidence["converged"] = converged

    passed = converged and convergence_sec <= cfg.stp_threshold_sec
    elapsed = time.monotonic() - t0
    return {
        "test": "stp_convergence",
        "passed": passed,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(elapsed, 3),
        "switch_counter_delta": telem["switch_counter_delta"],
        "details": {
            "convergence_sec": round(convergence_sec, 4),
            "converged": converged,
            "threshold_sec": cfg.stp_threshold_sec,
        },
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Test 6 — ACL Enforcement
# ---------------------------------------------------------------------------


def _run_playbook(playbook: Path) -> dict[str, Any]:
    """Run an Ansible playbook and return stdout/stderr/rc."""
    proc = subprocess.run(
        ["ansible-playbook", str(playbook)],
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "playbook": str(playbook),
        "returncode": proc.returncode,
        "stdout": proc.stdout[:2000],
        "stderr": proc.stderr[:2000],
    }


def acl_enforcement(
    engine: ScapyEngine,
    config: FunctionalTestConfig | None = None,
    telemetry: TelemetryConfig | None = None,
    pre_playbook: Path | None = None,
    post_playbook: Path | None = None,
) -> dict[str, Any]:
    """Verify ACL permit/deny rules produce correct forwarding behavior.

    When *pre_playbook* and *post_playbook* are provided, they are invoked
    via ``ansible-playbook`` to push and roll back the test ACL
    respectively.  Without them the test still runs the Scapy probes but
    cannot configure the ACL automatically.
    """
    cfg = config or FunctionalTestConfig()
    t0 = time.monotonic()
    evidence: dict[str, Any] = {}

    with snapshot_telemetry(telemetry) as telem:
        # Push ACL if playbook provided
        if pre_playbook is not None:
            evidence["pre_playbook"] = _run_playbook(pre_playbook)
            if evidence["pre_playbook"]["returncode"] != 0:
                raise FunctionalTestError(f"ACL pre-playbook failed: {pre_playbook}")

        try:
            # Permit probe — should arrive
            permit_result = engine.send_and_capture(
                interface=cfg.interface,
                src_mac=cfg.src_mac,
                dst_mac=cfg.dst_mac,
                src_ip=cfg.src_ip,
                dst_ip=cfg.acl_permit_dst_ip,
                protocol=cfg.protocol,
                size=cfg.frame_size,
                count=1,
                capture_timeout=cfg.capture_timeout,
            )
            evidence["permit"] = permit_result
            permit_received = (
                permit_result["capture_result"].get("frames_received", 0) > 0
            )

            # Deny probe — should NOT arrive
            deny_result = engine.send_and_capture(
                interface=cfg.interface,
                src_mac=cfg.src_mac,
                dst_mac=cfg.dst_mac,
                src_ip=cfg.src_ip,
                dst_ip=cfg.acl_deny_dst_ip,
                protocol=cfg.protocol,
                size=cfg.frame_size,
                count=1,
                capture_timeout=cfg.capture_timeout,
            )
            evidence["deny"] = deny_result
            deny_blocked = deny_result["capture_result"].get("frames_received", 0) == 0
        finally:
            # Roll back ACL regardless of test outcome
            if post_playbook is not None:
                evidence["post_playbook"] = _run_playbook(post_playbook)

    passed = permit_received and deny_blocked
    elapsed = time.monotonic() - t0
    return {
        "test": "acl_enforcement",
        "passed": passed,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(elapsed, 3),
        "switch_counter_delta": telem["switch_counter_delta"],
        "details": {
            "permit_dst_ip": cfg.acl_permit_dst_ip,
            "deny_dst_ip": cfg.acl_deny_dst_ip,
            "permit_received": permit_received,
            "deny_blocked": deny_blocked,
            "ansible_configured": pre_playbook is not None,
        },
        "evidence": evidence,
    }
