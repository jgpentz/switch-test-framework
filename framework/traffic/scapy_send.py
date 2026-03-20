"""Generator-side Scapy sender CLI.

This script is copied to the traffic-generator and executed remotely.
It builds a frame from CLI arguments and prints JSON results to stdout.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from typing import Any

from scapy.all import Dot1Q, Ether, ICMP, IP, IPv6, Raw, TCP, UDP, sendp  # type: ignore


class ScapySendError(RuntimeError):
    """Raised when sender input or send operation is invalid."""


def _build_parser() -> argparse.ArgumentParser:
    """Create CLI parser for sender arguments.

    Returns:
        Configured `argparse.ArgumentParser` instance.
    """
    parser = argparse.ArgumentParser(description="Scapy frame sender")
    parser.add_argument(
        "--interface", required=True, help="Egress interface (e.g. eth0)"
    )
    parser.add_argument("--src-mac", required=True, help="Source MAC address")
    parser.add_argument("--dst-mac", required=True, help="Destination MAC address")
    parser.add_argument(
        "--vlan", type=int, default=None, help="Outer VLAN ID (optional)"
    )
    parser.add_argument(
        "--inner-vlan", type=int, default=None, help="Inner VLAN ID for QinQ"
    )
    parser.add_argument("--src-ip", required=True, help="Source IP address")
    parser.add_argument("--dst-ip", required=True, help="Destination IP address")
    parser.add_argument(
        "--ip-version",
        choices=("ipv4", "ipv6"),
        default="ipv4",
        help="IP header version",
    )
    parser.add_argument(
        "--protocol",
        choices=("tcp", "udp", "icmp"),
        required=True,
        help="L4 protocol to encapsulate",
    )
    parser.add_argument(
        "--size", type=int, required=True, help="Target frame size in bytes"
    )
    parser.add_argument("--count", type=int, default=1, help="Number of frames to send")
    parser.add_argument(
        "--sport", type=int, default=12345, help="Source port for TCP/UDP"
    )
    parser.add_argument(
        "--dport", type=int, default=12345, help="Destination port for TCP/UDP"
    )
    parser.add_argument(
        "--interval", type=float, default=0.0, help="Inter-packet gap seconds"
    )
    return parser


def _make_base_packet(args: argparse.Namespace) -> Any:
    """Build Ethernet/VLAN/IP/L4 headers from CLI arguments.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Scapy packet object without payload padding.

    Raises:
        ScapySendError: If VLAN/IP/protocol combination is invalid.
    """
    if args.inner_vlan is not None and args.vlan is None:
        raise ScapySendError("--inner-vlan requires --vlan")

    pkt = Ether(src=args.src_mac, dst=args.dst_mac)

    if args.vlan is not None:
        pkt = pkt / Dot1Q(vlan=args.vlan)
    if args.inner_vlan is not None:
        pkt = pkt / Dot1Q(vlan=args.inner_vlan)

    if args.ip_version == "ipv4":
        pkt = pkt / IP(src=args.src_ip, dst=args.dst_ip)
    else:
        pkt = pkt / IPv6(src=args.src_ip, dst=args.dst_ip)

    if args.protocol == "tcp":
        pkt = pkt / TCP(sport=args.sport, dport=args.dport)
    elif args.protocol == "udp":
        pkt = pkt / UDP(sport=args.sport, dport=args.dport)
    elif args.protocol == "icmp":
        pkt = pkt / ICMP()
    else:
        raise ScapySendError(f"Unsupported protocol: {args.protocol}")

    return pkt


def _pad_to_size(pkt: Any, size: int) -> Any:
    """Pad packet with raw payload bytes up to target frame size.

    Args:
        pkt: Packet headers built by `_make_base_packet`.
        size: Requested frame size in bytes.

    Returns:
        Packet padded to requested size.

    Raises:
        ScapySendError: If the requested size is smaller than header length.
    """
    header_len = len(bytes(pkt))
    if size < header_len:
        raise ScapySendError(
            f"Requested size {size} is smaller than header size {header_len}."
        )
    payload_len = size - header_len
    if payload_len:
        pkt = pkt / Raw(load=b"X" * payload_len)
    return pkt


def send_frames(args: argparse.Namespace) -> dict[str, Any]:
    """Build and send frames with Scapy.

    Args:
        args: Parsed sender arguments.

    Returns:
        JSON-serializable result dictionary with send metadata.

    Raises:
        ScapySendError: If arguments are invalid or send operation fails.
    """
    if args.count <= 0:
        raise ScapySendError("--count must be greater than zero")
    if args.size <= 0:
        raise ScapySendError("--size must be greater than zero")

    packet = _pad_to_size(_make_base_packet(args), args.size)
    started_at = datetime.now(timezone.utc)

    sendp(
        packet,
        iface=args.interface,
        count=args.count,
        inter=args.interval,
        verbose=False,
    )

    finished_at = datetime.now(timezone.utc)
    return {
        "status": "ok",
        "frames_sent": int(args.count),
        "interface": args.interface,
        "protocol": args.protocol,
        "ip_version": args.ip_version,
        "requested_size": int(args.size),
        "actual_size": int(len(bytes(packet))),
        "src_mac": args.src_mac,
        "dst_mac": args.dst_mac,
        "vlan": args.vlan,
        "inner_vlan": args.inner_vlan,
        "src_ip": args.src_ip,
        "dst_ip": args.dst_ip,
        "sport": int(args.sport),
        "dport": int(args.dport),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "timestamp": finished_at.isoformat(),
    }


def main() -> None:
    """CLI entrypoint that prints JSON results."""
    parser = _build_parser()
    args = parser.parse_args()
    result = send_frames(args)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
