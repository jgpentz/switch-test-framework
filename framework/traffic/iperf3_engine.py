"""iperf3 traffic engine for RFC 2544 benchmarking."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from typing import Any


class IPerf3EngineError(RuntimeError):
    """Raised when remote iperf3 execution or JSON parsing fails."""


class IPerf3Engine:
    """Run iperf3 tests remotely over SSH and return structured results.

    The orchestrator executes iperf3 on a traffic-generator host via SSH.
    iperf3 then connects to the traffic-analyzer server IP/port.
    """

    def __init__(
        self,
        port: int = 5201,
        server_ip: str | None = None,
        iperf3_path: str = "iperf3",
        generator_host: str = "10.0.0.11",
        generator_user: str | None = None,
        ssh_path: str = "ssh",
        ssh_options: list[str] | None = None,
    ) -> None:
        """Initialize a new iperf3 engine.

        Args:
            port: iperf3 server port (default: 5201).
            server_ip: Most recently used server IP (updated by run methods).
            iperf3_path: Path to iperf3 executable on traffic-generator host.
            generator_host: Hostname/IP of the traffic-generator machine.
            generator_user: Optional SSH username for traffic-generator.
            ssh_path: Path to SSH binary (default: ``ssh``).
            ssh_options: Optional extra SSH args (e.g. key/checking options).
        """

        self.port: int = port
        self.server_ip: str | None = server_ip
        self.iperf3_path: str = iperf3_path
        self.generator_host: str = generator_host
        self.generator_user: str | None = generator_user
        self.ssh_path: str = ssh_path
        self.ssh_options: list[str] = ssh_options or []

    def __repr__(self) -> str:
        """Return object representation showing server IP and port."""

        return (
            f"{self.__class__.__name__}("
            f"server_ip={self.server_ip!r}, port={self.port!r}, "
            f"generator_host={self.generator_host!r})"
        )

    def _run_iperf3(self, iperf3_cmd: list[str]) -> str:
        """Execute iperf3 on traffic-generator over SSH.

        Args:
            iperf3_cmd: iperf3 command + arguments to run remotely.

        Returns:
            Raw stdout (expected to be JSON due to ``--json`` flag).

        Raises:
            IPerf3EngineError: If command exits non-zero or stdout is empty.
        """

        ssh_target = (
            f"{self.generator_user}@{self.generator_host}"
            if self.generator_user
            else self.generator_host
        )
        cmd = [self.ssh_path, *self.ssh_options, ssh_target, *iperf3_cmd]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        if proc.returncode != 0:
            raise IPerf3EngineError(
                "iperf3 command failed on traffic-generator "
                f"(host={self.generator_host!r}, exit_code={proc.returncode}). "
                f"stdout={stdout[:500]!r} stderr={stderr[:500]!r}"
            )
        if not stdout.strip():
            raise IPerf3EngineError(
                "iperf3 returned empty stdout while --json was requested. "
                f"host={self.generator_host!r} stderr={stderr[:500]!r}"
            )
        return stdout

    def _parse_json(self, stdout: str) -> dict[str, Any]:
        """Parse iperf3 JSON output string.

        Args:
            stdout: Raw stdout string from iperf3.

        Returns:
            Parsed JSON object as a dictionary.

        Raises:
            IPerf3EngineError: If JSON parsing fails or top-level object is not a dict.
        """

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise IPerf3EngineError(
                "Failed to parse iperf3 JSON output. "
                f"error={exc} stdout_snippet={stdout[:500]!r}"
            ) from exc

        if not isinstance(data, dict):
            raise IPerf3EngineError(
                f"Unexpected iperf3 JSON type: {type(data).__name__}; expected dict."
            )
        return data

    def _get_first(self, data: dict[str, Any], *paths: tuple[str, ...]) -> Any:
        """Return the first available value from candidate JSON paths.

        Args:
            data: Parsed JSON dictionary.
            *paths: Candidate access paths, each as tuple of keys/index strings.

        Returns:
            The first found value.

        Raises:
            IPerf3EngineError: If none of the candidate paths exist.
        """

        for path in paths:
            cur: Any = data
            ok = True
            for key in path:
                if isinstance(cur, dict):
                    if key in cur:
                        cur = cur[key]
                    else:
                        ok = False
                        break
                elif isinstance(cur, list):
                    if key.isdigit():
                        idx = int(key)
                        if 0 <= idx < len(cur):
                            cur = cur[idx]
                        else:
                            ok = False
                            break
                    else:
                        ok = False
                        break
                else:
                    ok = False
                    break
            if ok:
                return cur
        raise IPerf3EngineError(
            f"Unable to locate required iperf3 field. paths={paths!r}"
        )

    def _get_optional_first(
        self, data: dict[str, Any], *paths: tuple[str, ...]
    ) -> Any | None:
        """Return first matching field value or None if all paths are missing.

        Args:
            data: Parsed JSON dictionary.
            *paths: Candidate access paths.

        Returns:
            The first resolved value, otherwise ``None``.
        """

        try:
            return self._get_first(data, *paths)
        except IPerf3EngineError:
            return None

    def _extract_end_sum_metrics(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extract common throughput/loss/jitter metrics from iperf3 JSON.

        Args:
            data: Parsed iperf3 JSON output.

        Returns:
            A dictionary of raw metric values from candidate JSON locations.
        """

        return {
            "bits_per_second": self._get_first(
                data,
                ("end", "sum", "bits_per_second"),
                ("end", "sum_received", "bits_per_second"),
                ("end", "sum_sent", "bits_per_second"),
            ),
            "retransmits": self._get_optional_first(
                data,
                ("end", "sum", "retransmits"),
                ("end", "streams", "0", "retransmits"),
            ),
            "lost_packets": self._get_optional_first(
                data,
                ("end", "sum", "lost_packets"),
                ("end", "streams", "0", "lost_packets"),
            ),
            "lost_percent": self._get_optional_first(
                data,
                ("end", "sum", "lost_percent"),
                ("end", "streams", "0", "lost_percent"),
            ),
            "jitter_ms": self._get_optional_first(
                data,
                ("end", "sum", "jitter_ms"),
                ("end", "streams", "0", "jitter_ms"),
            ),
            "duration_sec": self._get_optional_first(
                data,
                ("end", "sum", "seconds"),
                ("end", "sum_received", "seconds"),
                ("end", "sum_sent", "seconds"),
            ),
            "bytes": self._get_optional_first(
                data,
                ("end", "sum", "bytes"),
                ("end", "sum_received", "bytes"),
                ("end", "sum_sent", "bytes"),
            ),
            "packets": self._get_optional_first(
                data,
                ("end", "sum", "packets"),
                ("end", "sum_received", "packets"),
                ("end", "sum_sent", "packets"),
            ),
        }

    def run_tcp(
        self,
        server_ip: str,
        duration: int = 30,
        parallel: int = 4,
        include_raw_json: bool = False,
    ) -> dict[str, Any]:
        """Run an iperf3 TCP throughput test.

        Args:
            server_ip: iperf3 server IP to connect to.
            duration: Test duration in seconds.
            parallel: Number of parallel TCP streams (`-P`).
            include_raw_json: If True, attach raw iperf3 JSON stdout as ``raw_json``.

        Returns:
            Structured result dict with required fields:
            bitrate_bps, retransmits, lost_packets, lost_percent, jitter_ms,
            protocol, requested_bitrate, duration_sec, timestamp.
        """

        self.server_ip = server_ip
        timestamp = datetime.now(timezone.utc).isoformat()

        iperf3_cmd = [
            self.iperf3_path,
            "-c",
            server_ip,
            "-p",
            str(self.port),
            "-t",
            str(duration),
            "-P",
            str(parallel),
            "--json",
        ]
        raw_stdout = self._run_iperf3(iperf3_cmd)
        data = self._parse_json(raw_stdout)
        metrics = self._extract_end_sum_metrics(data)

        try:
            bitrate_bps = float(metrics["bits_per_second"])
        except (TypeError, ValueError) as exc:
            raise IPerf3EngineError(
                f"Non-numeric bits_per_second in TCP result: {metrics['bits_per_second']!r}"
            ) from exc

        retransmits_raw = metrics.get("retransmits")
        retransmits = int(retransmits_raw) if retransmits_raw is not None else 0

        duration_raw = metrics.get("duration_sec")
        duration_sec = (
            float(duration_raw) if duration_raw is not None else float(duration)
        )

        result = {
            "bitrate_bps": bitrate_bps,
            "retransmits": retransmits,
            "lost_packets": 0,
            "lost_percent": 0.0,
            "jitter_ms": 0.0,
            "protocol": "tcp",
            "requested_bitrate": None,
            "duration_sec": duration_sec,
            "timestamp": timestamp,
        }
        if include_raw_json:
            result["raw_json"] = raw_stdout
        return result

    def run_udp(
        self,
        server_ip: str,
        bitrate: str,
        duration: int = 30,
        parallel: int = 1,
        length: int | None = None,
        include_raw_json: bool = False,
    ) -> dict[str, Any]:
        """Run an iperf3 UDP test at a requested bitrate.

        Args:
            server_ip: iperf3 server IP to connect to.
            bitrate: Requested UDP bitrate string (e.g. ``"500M"``, ``"1G"``).
            duration: Test duration in seconds.
            parallel: Number of parallel UDP streams (`-P`).
            length: UDP datagram payload size in bytes (iperf3 ``-l``).
            include_raw_json: If True, attach raw iperf3 JSON stdout as ``raw_json``.

        Returns:
            Structured result dict with required fields:
            bitrate_bps, retransmits, lost_packets, lost_percent, jitter_ms,
            protocol, requested_bitrate, duration_sec, timestamp.
        """

        self.server_ip = server_ip
        timestamp = datetime.now(timezone.utc).isoformat()

        iperf3_cmd = [
            self.iperf3_path,
            "-c",
            server_ip,
            "-p",
            str(self.port),
            "-u",
            "-b",
            bitrate,
            "-t",
            str(duration),
            "-P",
            str(parallel),
            "--json",
        ]
        if length is not None:
            iperf3_cmd.extend(["-l", str(length)])
        raw_stdout = self._run_iperf3(iperf3_cmd)
        data = self._parse_json(raw_stdout)
        metrics = self._extract_end_sum_metrics(data)

        try:
            bitrate_bps = float(metrics["bits_per_second"])
        except (TypeError, ValueError) as exc:
            raise IPerf3EngineError(
                f"Non-numeric bits_per_second in UDP result: {metrics['bits_per_second']!r}"
            ) from exc

        lost_packets_raw = metrics.get("lost_packets")
        lost_packets = int(lost_packets_raw) if lost_packets_raw is not None else 0

        lost_percent_raw = metrics.get("lost_percent")
        lost_percent = float(lost_percent_raw) if lost_percent_raw is not None else 0.0

        jitter_ms_raw = metrics.get("jitter_ms")
        jitter_ms = float(jitter_ms_raw) if jitter_ms_raw is not None else 0.0

        duration_raw = metrics.get("duration_sec")
        duration_sec = (
            float(duration_raw) if duration_raw is not None else float(duration)
        )

        result = {
            "bitrate_bps": bitrate_bps,
            "retransmits": 0,
            "lost_packets": lost_packets,
            "lost_percent": lost_percent,
            "jitter_ms": jitter_ms,
            "protocol": "udp",
            "requested_bitrate": bitrate,
            "duration_sec": duration_sec,
            "timestamp": timestamp,
        }
        if include_raw_json:
            result["raw_json"] = raw_stdout
        return result

    def run_stepwise_udp(
        self,
        server_ip: str,
        bitrate_steps: list[str],
        duration: int = 30,
        length: int | None = None,
        include_raw_json: bool = False,
    ) -> list[dict[str, Any]]:
        """Run a UDP test for each bitrate step and return all step results.

        Args:
            server_ip: iperf3 server IP to connect to.
            bitrate_steps: Ordered list of requested UDP bitrate strings.
            duration: Duration (seconds) for each step.
            length: UDP datagram payload size in bytes (iperf3 ``-l``).
            include_raw_json: If True, attach raw iperf3 JSON stdout as ``raw_json``.

        Returns:
            List of UDP result dicts (one per bitrate step), suitable for
            RFC 2544 frame-loss curve processing.
        """

        results: list[dict[str, Any]] = []
        for step in bitrate_steps:
            results.append(
                self.run_udp(
                    server_ip=server_ip,
                    bitrate=step,
                    duration=duration,
                    length=length,
                    include_raw_json=include_raw_json,
                )
            )
        return results


if __name__ == "__main__":
    ssh_options = ["-i", "/home/jimmy/.ssh/id_gen"]
    engine = IPerf3Engine(ssh_options=ssh_options)
    results = engine.run_tcp("172.16.0.2", duration=3, parallel=4)
    print(results)

    results = engine.run_udp("172.16.0.2", bitrate="500M", duration=3, parallel=4)
    print(results)

    results = engine.run_stepwise_udp(
        "172.16.0.2", bitrate_steps=["500M", "1G", "2G"], duration=3
    )
    print(results)
