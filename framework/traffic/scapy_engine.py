"""Orchestrator-side Scapy engine for remote send/capture workflows."""

from __future__ import annotations

import json
import shlex
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any

import paramiko


class ScapyEngineError(RuntimeError):
    """Raised when SSH/SCP execution fails or remote JSON is invalid."""


@dataclass(slots=True)
class SSHHostConfig:
    """Connection settings for a remote host."""

    host: str
    username: str
    port: int = 22


class ScapyEngine:
    """Coordinate Scapy sender/capture scripts running on remote hosts.

    This engine deploys scripts over SCP (SFTP), executes them with SSH, and
    returns structured dictionaries suitable for the framework test runner.
    """

    def __init__(
        self,
        generator: SSHHostConfig = SSHHostConfig(host="10.0.0.11", username="jimmy"),
        analyzer: SSHHostConfig = SSHHostConfig(host="10.0.0.12", username="jimmy"),
        ssh_key_path: str | None = None,
        strict_host_key_checking: bool = False,
        remote_dir: str = ".",
        local_send_script: str = "framework/traffic/scapy_send.py",
        local_capture_script: str = "framework/traffic/scapy_capture.py",
        remote_send_script_name: str = "scapy_send.py",
        remote_capture_script_name: str = "scapy_capture.py",
    ) -> None:
        """Initialize a Scapy orchestrator engine.

        Args:
            generator: SSH settings for traffic-generator host.
            analyzer: SSH settings for traffic-analyzer host.
            ssh_key_path: Optional private key path for key-based auth.
            strict_host_key_checking: Enforce known-host validation if true.
            remote_dir: Remote directory where scripts are uploaded/executed.
            local_send_script: Local path to sender script.
            local_capture_script: Local path to capture script.
            remote_send_script_name: Remote filename for sender script.
            remote_capture_script_name: Remote filename for capture script.
        """
        self.generator = generator
        self.analyzer = analyzer
        self.ssh_key_path = ssh_key_path
        self.strict_host_key_checking = strict_host_key_checking
        self.remote_dir = remote_dir
        self.local_send_script = Path(local_send_script)
        self.local_capture_script = Path(local_capture_script)
        self.remote_send_script_path = (
            f"{self.remote_dir.rstrip('/')}/{remote_send_script_name}"
        )
        self.remote_capture_script_path = (
            f"{self.remote_dir.rstrip('/')}/{remote_capture_script_name}"
        )

    def __repr__(self) -> str:
        """Return concise engine representation."""
        return (
            f"{self.__class__.__name__}(generator={self.generator.host!r}, "
            f"analyzer={self.analyzer.host!r}, remote_dir={self.remote_dir!r})"
        )

    def _connect(self, cfg: SSHHostConfig) -> paramiko.SSHClient:
        """Open an SSH client connection.

        Args:
            cfg: Host configuration to connect to.

        Returns:
            Connected Paramiko SSH client.

        Raises:
            ScapyEngineError: If SSH connection fails.
        """
        client = paramiko.SSHClient()
        if self.strict_host_key_checking:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=cfg.host,
                port=cfg.port,
                username=cfg.username,
                key_filename=self.ssh_key_path,
                look_for_keys=True,
                allow_agent=True,
                timeout=10,
            )
        except Exception as exc:  # pragma: no cover - network runtime path
            raise ScapyEngineError(f"SSH connect failed to {cfg.host}: {exc}") from exc
        return client

    def _upload_script(
        self, client: paramiko.SSHClient, local_path: Path, remote_path: str
    ) -> None:
        """Upload a local script to a remote path over SFTP.

        Args:
            client: Connected SSH client.
            local_path: Local file to upload.
            remote_path: Destination path on remote host.

        Raises:
            ScapyEngineError: If file is missing or upload fails.
        """
        if not local_path.exists():
            raise ScapyEngineError(f"Local script not found: {local_path}")
        try:
            sftp = client.open_sftp()
            sftp.put(str(local_path), remote_path)
            sftp.close()
        except Exception as exc:  # pragma: no cover - network runtime path
            raise ScapyEngineError(
                f"SCP/SFTP upload failed {local_path} -> {remote_path}: {exc}"
            ) from exc

    def deploy_scripts(self) -> dict[str, Any]:
        """Deploy sender and capture scripts to generator/analyzer.

        Returns:
            Deployment status dictionary with timestamp and remote targets.
        """
        generator_client = self._connect(self.generator)
        analyzer_client = self._connect(self.analyzer)
        try:
            self._upload_script(
                generator_client,
                self.local_send_script,
                self.remote_send_script_path,
            )
            self._upload_script(
                analyzer_client,
                self.local_capture_script,
                self.remote_capture_script_path,
            )
        finally:
            generator_client.close()
            analyzer_client.close()

        ts = datetime.now(timezone.utc).isoformat()
        return {
            "status": "ok",
            "deployed_at": ts,
            "generator_host": self.generator.host,
            "analyzer_host": self.analyzer.host,
            "remote_send_script_path": self.remote_send_script_path,
            "remote_capture_script_path": self.remote_capture_script_path,
        }

    def _run_remote_json(
        self,
        cfg: SSHHostConfig,
        command: str,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Run a remote command and parse stdout as JSON.

        Args:
            cfg: SSH host to run command on.
            command: Shell command to execute remotely.
            timeout: Optional command timeout seconds.

        Returns:
            Parsed stdout JSON object.

        Raises:
            ScapyEngineError: On command failure, timeout, or JSON parse error.
        """
        client = self._connect(cfg)
        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
        finally:
            client.close()

        if exit_code != 0:
            raise ScapyEngineError(
                f"Remote command failed on {cfg.host} exit={exit_code}. "
                f"command={command!r} stderr={err[:400]!r} stdout={out[:400]!r}"
            )
        if not out:
            raise ScapyEngineError(
                f"Remote command on {cfg.host} produced empty stdout."
            )

        try:
            parsed = json.loads(out)
        except json.JSONDecodeError as exc:
            raise ScapyEngineError(
                f"Failed parsing remote JSON from {cfg.host}. "
                f"stdout_snippet={out[:400]!r} stderr_snippet={err[:400]!r}"
            ) from exc
        if not isinstance(parsed, dict):
            raise ScapyEngineError(
                f"Unexpected remote JSON type from {cfg.host}: {type(parsed).__name__}"
            )
        return parsed

    def _build_send_command(
        self,
        interface: str,
        src_mac: str,
        dst_mac: str,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        size: int,
        count: int,
        vlan: int | None = None,
        inner_vlan: int | None = None,
        ip_version: str = "ipv4",
    ) -> str:
        """Build remote sender CLI command line."""
        args: list[str] = [
            "python3",
            self.remote_send_script_path,
            "--interface",
            interface,
            "--src-mac",
            src_mac,
            "--dst-mac",
            dst_mac,
            "--src-ip",
            src_ip,
            "--dst-ip",
            dst_ip,
            "--protocol",
            protocol,
            "--size",
            str(size),
            "--count",
            str(count),
            "--ip-version",
            ip_version,
        ]
        if vlan is not None:
            args.extend(["--vlan", str(vlan)])
        if inner_vlan is not None:
            args.extend(["--inner-vlan", str(inner_vlan)])
        return " ".join(shlex.quote(x) for x in args)

    def _build_capture_command(
        self,
        interface: str,
        timeout: float,
        capture_filter: str | None,
        expected_vlan: int | None,
        max_packets: int = 0,
    ) -> str:
        """Build remote capture CLI command line."""
        args: list[str] = [
            "python3",
            self.remote_capture_script_path,
            "--interface",
            interface,
            "--timeout",
            str(timeout),
            "--max-packets",
            str(max_packets),
        ]
        if capture_filter:
            args.extend(["--filter", capture_filter])
        if expected_vlan is not None:
            args.extend(["--expected-vlan", str(expected_vlan)])
        return " ".join(shlex.quote(x) for x in args)

    def send_frame(
        self,
        interface: str,
        src_mac: str,
        dst_mac: str,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        size: int,
        count: int = 1,
        vlan: int | None = None,
        inner_vlan: int | None = None,
        ip_version: str = "ipv4",
        deploy: bool = True,
    ) -> dict[str, Any]:
        """Deploy scripts (optional) and trigger remote frame send.

        Returns:
            Sender result dictionary wrapped with orchestrator metadata.
        """
        if deploy:
            self.deploy_scripts()

        command = self._build_send_command(
            interface=interface,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            size=size,
            count=count,
            vlan=vlan,
            inner_vlan=inner_vlan,
            ip_version=ip_version,
        )
        send_result = self._run_remote_json(self.generator, command)
        return {
            "status": "ok",
            "method": "send_frame",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "generator_host": self.generator.host,
            "result": send_result,
        }

    def send_and_capture(
        self,
        interface: str,
        src_mac: str,
        dst_mac: str,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        size: int,
        count: int = 1,
        vlan: int | None = None,
        inner_vlan: int | None = None,
        ip_version: str = "ipv4",
        capture_timeout: float = 5.0,
        capture_filter: str | None = None,
        expected_vlan: int | None = None,
        readiness_delay: float = 0.3,
        deploy: bool = True,
    ) -> dict[str, Any]:
        """Start capture first, then send traffic, then merge results.

        Returns:
            Dict containing sender/capture payloads and timing metadata including
            `capture_started_at` and `send_started_at`.
        """
        if deploy:
            self.deploy_scripts()

        capture_command = self._build_capture_command(
            interface=interface,
            timeout=capture_timeout,
            capture_filter=capture_filter,
            expected_vlan=expected_vlan,
        )
        send_command = self._build_send_command(
            interface=interface,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            size=size,
            count=count,
            vlan=vlan,
            inner_vlan=inner_vlan,
            ip_version=ip_version,
        )

        analyzer_client = self._connect(self.analyzer)
        try:
            _, capture_stdout, capture_stderr = analyzer_client.exec_command(
                capture_command
            )
            capture_started_at = datetime.now(timezone.utc).isoformat()

            # Capture is launched first; brief delay helps ensure sniff loop is active.
            time.sleep(max(0.0, readiness_delay))
            send_started_at = datetime.now(timezone.utc).isoformat()
            send_result = self._run_remote_json(self.generator, send_command)

            capture_exit = capture_stdout.channel.recv_exit_status()
            capture_out = (
                capture_stdout.read().decode("utf-8", errors="replace").strip()
            )
            capture_err = (
                capture_stderr.read().decode("utf-8", errors="replace").strip()
            )
        finally:
            analyzer_client.close()

        if capture_exit != 0:
            raise ScapyEngineError(
                "Capture command failed on analyzer "
                f"exit={capture_exit} stderr={capture_err[:400]!r} stdout={capture_out[:400]!r}"
            )
        if not capture_out:
            raise ScapyEngineError("Capture command produced empty stdout.")

        try:
            capture_result = json.loads(capture_out)
        except json.JSONDecodeError as exc:
            raise ScapyEngineError(
                f"Failed to parse capture JSON. stdout={capture_out[:400]!r}"
            ) from exc
        if not isinstance(capture_result, dict):
            raise ScapyEngineError("Capture JSON must be an object.")

        rtt_ms = self._estimate_rtt_ms(send_result, capture_result)
        return {
            "status": "ok",
            "method": "send_and_capture",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "capture_started_at": capture_started_at,
            "send_started_at": send_started_at,
            "rtt_ms": rtt_ms,
            "generator_host": self.generator.host,
            "analyzer_host": self.analyzer.host,
            "send_result": send_result,
            "capture_result": capture_result,
        }

    def send_burst(
        self,
        interface: str,
        src_mac: str,
        dst_mac: str,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        size: int,
        count: int = 1000,
        vlan: int | None = None,
        inner_vlan: int | None = None,
        ip_version: str = "ipv4",
        capture_timeout: float = 5.0,
        capture_filter: str | None = None,
        expected_vlan: int | None = None,
        deploy: bool = True,
    ) -> dict[str, Any]:
        """Send a rapid burst and capture corresponding receive-side observations."""
        return self.send_and_capture(
            interface=interface,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            size=size,
            count=count,
            vlan=vlan,
            inner_vlan=inner_vlan,
            ip_version=ip_version,
            capture_timeout=capture_timeout,
            capture_filter=capture_filter,
            expected_vlan=expected_vlan,
            deploy=deploy,
        )

    def check_vlan_isolation(
        self,
        interface: str,
        src_mac: str,
        dst_mac: str,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        size: int,
        vlan: int,
        expected_vlan: int,
        count: int = 1,
        capture_timeout: float = 5.0,
        capture_filter: str | None = None,
        deploy: bool = True,
    ) -> dict[str, Any]:
        """Send tagged traffic and verify isolation against expected analyzer VLAN.

        Returns:
            Dict with pass/fail status and packet evidence fields.
        """
        result = self.send_and_capture(
            interface=interface,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            size=size,
            count=count,
            vlan=vlan,
            expected_vlan=expected_vlan,
            capture_timeout=capture_timeout,
            capture_filter=capture_filter,
            deploy=deploy,
        )
        capture = result["capture_result"]
        isolation_ok = int(capture.get("vlan_match_count", 0)) == 0
        return {
            "status": "pass" if isolation_ok else "fail",
            "method": "check_vlan_isolation",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sent_vlan": vlan,
            "expected_vlan": expected_vlan,
            "frames_received": int(capture.get("frames_received", 0)),
            "vlan_match_count": int(capture.get("vlan_match_count", 0)),
            "vlan_mismatch_count": int(capture.get("vlan_mismatch_count", 0)),
            "evidence": result,
        }

    def measure_rtt(
        self,
        interface: str,
        src_mac: str,
        dst_mac: str,
        src_ip: str,
        dst_ip: str,
        probes: int = 3,
        size: int = 128,
        vlan: int | None = None,
        capture_timeout: float = 3.0,
        deploy: bool = True,
    ) -> dict[str, Any]:
        """Send ICMP probes and return min/avg/max RTT metrics in milliseconds."""
        if probes <= 0:
            raise ScapyEngineError("probes must be greater than zero")

        samples: list[float] = []
        probe_results: list[dict[str, Any]] = []
        for _ in range(probes):
            result = self.send_and_capture(
                interface=interface,
                src_mac=src_mac,
                dst_mac=dst_mac,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="icmp",
                size=size,
                count=1,
                vlan=vlan,
                capture_timeout=capture_timeout,
                deploy=deploy if not probe_results else False,
            )
            probe_results.append(result)
            if result["rtt_ms"] is not None:
                samples.append(float(result["rtt_ms"]))

        return {
            "status": "ok",
            "method": "measure_rtt",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "samples_count": len(samples),
            "min_rtt_ms": min(samples) if samples else None,
            "avg_rtt_ms": mean(samples) if samples else None,
            "max_rtt_ms": max(samples) if samples else None,
            "samples": samples,
            "probes": probe_results,
        }

    def _estimate_rtt_ms(
        self, send_result: dict[str, Any], capture_result: dict[str, Any]
    ) -> float | None:
        """Estimate RTT from sender finished timestamp and first capture timestamp.

        Args:
            send_result: Parsed sender JSON payload.
            capture_result: Parsed capture JSON payload.

        Returns:
            Non-negative RTT estimate in milliseconds if timestamps are present.
        """
        send_ts = send_result.get("finished_at") or send_result.get("timestamp")
        capture_timestamps = capture_result.get("timestamps", [])
        if not isinstance(send_ts, str) or not capture_timestamps:
            return None
        first_capture_ts = capture_timestamps[0]
        if not isinstance(first_capture_ts, str):
            return None
        try:
            t_send = datetime.fromisoformat(send_ts)
            t_capture = datetime.fromisoformat(first_capture_ts)
        except ValueError:
            return None
        delta_ms = (t_capture - t_send).total_seconds() * 1000.0
        return max(0.0, delta_ms)


if __name__ == "__main__":
    engine = ScapyEngine(ssh_key_path="/home/jimmy/.ssh/test-framework")
    engine.deploy_scripts()
    # capture = engine.send_and_capture(
    #     interface="ens18",
    #     src_mac="bc:24:11:11:85:0c",
    #     dst_mac="bc:24:11:0f:6a:d6",
    #     src_ip="172.16.0.1",
    #     dst_ip="172.16.0.2",
    #     protocol="tcp",
    #     size=100,
    #     count=1,
    # )
    # print(capture)

    # # Test ping
    # capture = engine.send_and_capture(
    #     interface="ens18",
    #     src_mac="bc:24:11:11:85:0c",
    #     dst_mac="bc:24:11:0f:6a:d6",
    #     src_ip="172.16.0.1",
    #     dst_ip="172.16.0.2",
    #     protocol="icmp",
    #     size=100,
    #     count=1,
    # )
    # print(capture)

    # # test burst
    # capture = engine.send_burst(
    #     interface="ens18",
    #     src_mac="bc:24:11:11:85:0c",
    #     dst_mac="bc:24:11:0f:6a:d6",
    #     src_ip="172.16.0.1",
    #     dst_ip="172.16.0.2",
    #     protocol="icmp",
    #     size=100,
    #     count=1000,
    # )
    # print(capture)

    # # test udp
    # capture = engine.send_and_capture(
    #     interface="ens18",
    #     src_mac="bc:24:11:11:85:0c",
    #     dst_mac="bc:24:11:0f:6a:d6",
    #     src_ip="172.16.0.1",
    #     dst_ip="172.16.0.2",
    #     protocol="udp",
    #     size=100,
    #     count=1,
    # )

    # print(capture)

    result = engine.send_and_capture(
        interface="ens18",
        src_mac="bc:24:11:11:85:0c",
        dst_mac="bc:24:11:0f:6a:d6",
        src_ip="172.16.0.1",
        dst_ip="172.16.0.2",
        protocol="udp",
        size=9000,
        count=5,
        deploy=False,
    )
    print(result)
