"""Cisco switch telemetry: SNMP interface counters and SSH MAC table."""

from __future__ import annotations

import re
from typing import Any
import json

import easysnmp
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


class CiscoSnmpError(RuntimeError):
    """Raised when SNMP operations fail or data is missing."""


def _snmp_int(session: easysnmp.Session, oid: str) -> int:
    """Get a single OID and return its value as int."""
    try:
        var = session.get(oid)
    except Exception as exc:  # easysnmp may raise on timeout / no such object
        raise CiscoSnmpError(f"SNMP get failed for {oid}: {exc}") from exc
    if var.value in (None, "NULL", ""):
        raise CiscoSnmpError(f"SNMP get returned empty value for {oid}")
    try:
        return int(var.value)
    except (TypeError, ValueError) as exc:
        raise CiscoSnmpError(
            f"SNMP value not an integer for {oid}: {var.value!r}"
        ) from exc


def _resolve_ifindex(session: easysnmp.Session, interface_name: str) -> int:
    """Walk IF-MIB ifDescr and return ifIndex for the given interface name."""
    try:
        rows = session.walk("IF-MIB::ifDescr")
    except Exception as exc:
        raise CiscoSnmpError(f"SNMP walk IF-MIB::ifDescr failed: {exc}") from exc
    for row in rows:
        if row.value == interface_name:
            return int(row.oid_index)
    raise CiscoSnmpError(f"Interface not found in SNMP ifDescr: {interface_name!r}")


def poll_interface_counters(
    switch_ip: str,
    community: str,
    interface: str,
    *,
    snmp_version: int = 2,
    timeout: int = 2,
    retries: int = 2,
) -> dict[str, Any]:
    """Poll TX/RX packet counters, errors, and discards for one interface via SNMP (IF-MIB).

    Uses 64-bit HC counters where available. Packet totals are the sum of
    unicast + multicast + broadcast for RX and TX respectively.

    Args:
        switch_ip: Switch management IP reachable via SNMP.
        community: SNMPv2c community string.
        interface: Exact IF-MIB interface name (e.g. ``GigabitEthernet1/0/5``).
        snmp_version: SNMP version (2 for SNMPv2c).
        timeout: Per-request timeout in seconds.
        retries: SNMP retries.

    Returns:
        Dict with keys including ``if_index``, ``interface``, ``rx_packets``,
        ``tx_packets``, ``rx_errors``, ``tx_errors``, ``rx_discards``,
        ``tx_discards``, ``rx_octets``, ``tx_octets`` (all integers where applicable).

    Raises:
        CiscoSnmpError: If the interface is not found or SNMP fails.
    """
    session = easysnmp.Session(
        hostname=switch_ip,
        community=community,
        version=snmp_version,
        timeout=timeout,
        retries=retries,
    )
    idx = _resolve_ifindex(session, interface)

    # 64-bit packet counters (preferred on Gigabit interfaces)
    rx_ucast = _snmp_int(session, f"IF-MIB::ifHCInUcastPkts.{idx}")
    rx_mcast = _snmp_int(session, f"IF-MIB::ifHCInMulticastPkts.{idx}")
    rx_bcast = _snmp_int(session, f"IF-MIB::ifHCInBroadcastPkts.{idx}")
    tx_ucast = _snmp_int(session, f"IF-MIB::ifHCOutUcastPkts.{idx}")
    tx_mcast = _snmp_int(session, f"IF-MIB::ifHCOutMulticastPkts.{idx}")
    tx_bcast = _snmp_int(session, f"IF-MIB::ifHCOutBroadcastPkts.{idx}")

    rx_errors = _snmp_int(session, f"IF-MIB::ifInErrors.{idx}")
    tx_errors = _snmp_int(session, f"IF-MIB::ifOutErrors.{idx}")
    rx_discards = _snmp_int(session, f"IF-MIB::ifInDiscards.{idx}")
    tx_discards = _snmp_int(session, f"IF-MIB::ifOutDiscards.{idx}")

    rx_octets = _snmp_int(session, f"IF-MIB::ifHCInOctets.{idx}")
    tx_octets = _snmp_int(session, f"IF-MIB::ifHCOutOctets.{idx}")

    return {
        "switch_ip": switch_ip,
        "interface": interface,
        "if_index": idx,
        "rx_packets": rx_ucast + rx_mcast + rx_bcast,
        "tx_packets": tx_ucast + tx_mcast + tx_bcast,
        "rx_unicast_packets": rx_ucast,
        "rx_multicast_packets": rx_mcast,
        "rx_broadcast_packets": rx_bcast,
        "tx_unicast_packets": tx_ucast,
        "tx_multicast_packets": tx_mcast,
        "tx_broadcast_packets": tx_bcast,
        "rx_errors": rx_errors,
        "tx_errors": tx_errors,
        "rx_discards": rx_discards,
        "tx_discards": tx_discards,
        "rx_octets": rx_octets,
        "tx_octets": tx_octets,
    }


def get_mac_address_table_ssh(
    host: str,
    username: str,
    password: str,
    *,
    device_type: str = "cisco_ios",
    port: int = 22,
    secret: str | None = None,
    key_file: str | None = None,
    use_keys: bool = False,
    command: str | None = None,
    parse: bool = True,
) -> dict[str, Any]:
    """Retrieve the MAC address table from a Cisco switch via Netmiko (SSH).

    Runs ``show mac address-table`` (default). If that fails (older IOS), tries
    ``show mac-address-table``.

    Args:
        host: Switch management IP or hostname.
        username: SSH username.
        password: SSH password (or empty if using key-only auth).
        device_type: Netmiko device type (default ``cisco_ios`` for Catalyst).
        port: SSH port.
        secret: Optional enable secret for privileged commands (usually not needed).
        key_file: Path to private key for key-based login.
        use_keys: If True, allow SSH agent / default keys (with ``key_file`` if set).
        command: Override CLI command (default: auto ``show mac address-table``).
        parse: If True, parse table rows into ``entries``; always includes ``raw``.

    Returns:
        Dict with ``host``, ``command``, ``raw`` (CLI output), and if ``parse`` is
        True, ``entries`` as a list of dicts with ``vlan``, ``mac``, ``type``, ``ports``.

    Raises:
        NetmikoAuthenticationException: SSH auth failure.
        NetmikoTimeoutException: Connection timeout.
        RuntimeError: If both MAC table commands fail or output is empty unexpectedly.
    """
    device: dict[str, Any] = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    if secret:
        device["secret"] = secret
    if key_file:
        device["key_file"] = key_file
    if use_keys:
        device["use_keys"] = True
        device["allow_agent"] = True

    raw = ""
    cmd_used = command
    try:
        with ConnectHandler(**device) as conn:
            if command:
                raw = conn.send_command(
                    command, strip_prompt=False, strip_command=False
                )
            else:
                raw = conn.send_command(
                    "show mac address-table",
                    strip_prompt=False,
                    strip_command=False,
                )
                if not raw.strip() or "Invalid" in raw or "%" in raw[:200]:
                    raw = conn.send_command(
                        "show mac-address-table",
                        strip_prompt=False,
                        strip_command=False,
                    )
                    cmd_used = "show mac-address-table"
                else:
                    cmd_used = "show mac address-table"
    except (NetmikoAuthenticationException, NetmikoTimeoutException):
        raise
    except Exception as exc:
        raise RuntimeError(f"Netmiko SSH session failed to {host!r}: {exc}") from exc

    result: dict[str, Any] = {
        "host": host,
        "command": cmd_used or command,
        "raw": raw,
    }
    if parse:
        result["entries"] = _parse_cisco_mac_table(raw)
    return result


# Typical IOS line: "  10    bc24.1111.850c    DYNAMIC     Gi1/0/5"
_MAC_LINE_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<type>\S+)\s+(?P<ports>.+?)\s*$"
)


def _parse_cisco_mac_table(raw: str) -> list[dict[str, str]]:
    """Parse ``show mac address-table`` style output into row dicts."""
    entries: list[dict[str, str]] = []
    for line in raw.splitlines():
        line = line.strip()
        if (
            not line
            or line.startswith("---")
            or "Mac Address" in line
            or "Vlan" == line[:4]
        ):
            continue
        m = _MAC_LINE_RE.match(line)
        if m:
            entries.append(
                {
                    "vlan": m.group("vlan"),
                    "mac": m.group("mac").lower(),
                    "type": m.group("type"),
                    "ports": m.group("ports").strip(),
                }
            )
    return entries


# Backwards-compatible names
def get_interface_counters(
    switch_ip: str,
    community: str,
    interface: str,
) -> dict[str, Any]:
    """Alias for :func:`poll_interface_counters` returning the full counter dict."""
    return poll_interface_counters(switch_ip, community, interface)


if __name__ == "__main__":
    # Example: SNMP counters (adjust IP/community/interface)
    counters = poll_interface_counters(
        "10.0.0.2", "network-test", "GigabitEthernet1/0/5"
    )
    # Print nicely formatted JSON
    mac_table = get_mac_address_table_ssh("10.0.0.2", "jimmy", "lab123", secret="lab123")
    print(json.dumps(mac_table['entries'], indent=4))
    # interface_counters = get_interface_counters("10.0.0.2", "network-test", "GigabitEthernet1/0/5")
    # print(json.dumps(interface_counters, indent=4))