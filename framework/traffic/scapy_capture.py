"""Analyzer-side Scapy capture CLI.

This script is copied to the traffic-analyzer and executed remotely.
It captures frames and prints structured JSON to stdout.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from typing import Any

from scapy.all import Dot1Q, Ether, ICMP, IP, IPv6, TCP, UDP, sniff  # type: ignore


class ScapyCaptureError(RuntimeError):
    """Raised when capture arguments or sniff execution fails."""


def _build_parser() -> argparse.ArgumentParser:
    """Create CLI parser for capture arguments.

    Returns:
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Scapy frame capture")
    parser.add_argument("--interface", required=True, help="Interface to sniff on")
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="Capture timeout seconds"
    )
    parser.add_argument("--filter", default="", help="Optional BPF filter")
    parser.add_argument(
        "--expected-vlan", type=int, default=None, help="Expected VLAN ID"
    )
    parser.add_argument(
        "--max-packets", type=int, default=0, help="Optional max packets to capture"
    )
    return parser


def _extract_vlans(packet: Any) -> list[int]:
    """Extract all Dot1Q VLAN tags from a packet.

    Args:
        packet: Scapy packet object.

    Returns:
        Ordered VLAN IDs found in the packet.
    """
    vlans: list[int] = []
    layer = packet
    while layer is not None:
        if layer.haslayer(Dot1Q):
            dot = layer[Dot1Q]
            vlans.append(int(dot.vlan))
            layer = dot.payload
        else:
            break
    return vlans


def _packet_summary(packet: Any) -> dict[str, Any]:
    """Build a compact packet summary record.

    Args:
        packet: Scapy packet.

    Returns:
        Packet summary dictionary with key L2/L3/L4 fields.
    """
    src_mac = packet[Ether].src if packet.haslayer(Ether) else None
    dst_mac = packet[Ether].dst if packet.haslayer(Ether) else None
    src_ip = None
    dst_ip = None
    ip_version = None
    proto = "unknown"
    sport = None
    dport = None

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ip_version = "ipv4"
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        ip_version = "ipv6"

    if packet.haslayer(TCP):
        proto = "tcp"
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        proto = "udp"
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        proto = "icmp"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "len_bytes": int(len(bytes(packet))),
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ip_version": ip_version,
        "protocol": proto,
        "sport": sport,
        "dport": dport,
        "vlan_tags": _extract_vlans(packet),
    }


def capture_frames(args: argparse.Namespace) -> dict[str, Any]:
    """Capture packets and return structured observations.

    Args:
        args: Parsed CLI arguments.

    Returns:
        JSON-serializable capture result dict.

    Raises:
        ScapyCaptureError: If capture settings are invalid or sniff fails.
    """
    if args.timeout <= 0:
        raise ScapyCaptureError("--timeout must be greater than zero")
    if args.max_packets < 0:
        raise ScapyCaptureError("--max-packets cannot be negative")

    capture_started = datetime.now(timezone.utc)
    sniff_kwargs: dict[str, Any] = {"iface": args.interface, "timeout": args.timeout}
    if args.filter:
        sniff_kwargs["filter"] = args.filter
    if args.max_packets > 0:
        sniff_kwargs["count"] = args.max_packets

    packets = sniff(**sniff_kwargs)
    capture_finished = datetime.now(timezone.utc)

    summaries = [_packet_summary(packet) for packet in packets]
    vlan_tags_observed = sorted(
        {vlan for item in summaries for vlan in item["vlan_tags"]},
    )

    vlan_match_count = 0
    vlan_mismatch_count = 0
    if args.expected_vlan is not None:
        for item in summaries:
            if args.expected_vlan in item["vlan_tags"]:
                vlan_match_count += 1
            else:
                vlan_mismatch_count += 1

    return {
        "status": "ok",
        "interface": args.interface,
        "timeout_sec": float(args.timeout),
        "filter": args.filter or None,
        "expected_vlan": args.expected_vlan,
        "frames_received": int(len(summaries)),
        "timestamps": [item["timestamp"] for item in summaries],
        "src_macs": sorted({item["src_mac"] for item in summaries if item["src_mac"]}),
        "dst_macs": sorted({item["dst_mac"] for item in summaries if item["dst_mac"]}),
        "vlan_tags_observed": vlan_tags_observed,
        "vlan_match_count": int(vlan_match_count),
        "vlan_mismatch_count": int(vlan_mismatch_count),
        "packets": summaries,
        "capture_start_ts": capture_started.isoformat(),
        "capture_end_ts": capture_finished.isoformat(),
        "timestamp": capture_finished.isoformat(),
    }


def main() -> None:
    """CLI entrypoint that prints JSON capture output."""
    parser = _build_parser()
    args = parser.parse_args()
    result = capture_frames(args)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
