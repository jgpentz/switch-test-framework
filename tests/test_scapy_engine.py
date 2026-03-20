"""Unit tests for ScapyEngine orchestration logic.

These tests avoid real SSH/network activity by mocking client objects and
engine internals.
"""

from __future__ import annotations

import json
import sys
import types
import unittest
from unittest.mock import patch

# Allow tests to run even when paramiko is not installed locally.
if "paramiko" not in sys.modules:
    paramiko_stub = types.SimpleNamespace(
        SSHClient=object,
        AutoAddPolicy=object,
        RejectPolicy=object,
    )
    sys.modules["paramiko"] = paramiko_stub

from framework.traffic.scapy_engine import SSHHostConfig, ScapyEngine, ScapyEngineError


class _FakeChannel:
    def __init__(self, exit_code: int = 0) -> None:
        self._exit_code = exit_code

    def recv_exit_status(self) -> int:
        return self._exit_code


class _FakeStream:
    def __init__(self, text: str, exit_code: int = 0) -> None:
        self._text = text
        self.channel = _FakeChannel(exit_code=exit_code)

    def read(self) -> bytes:
        return self._text.encode("utf-8")


class _FakeAnalyzerClient:
    def __init__(self, capture_json: dict[str, object]) -> None:
        self.capture_started = False
        self.capture_command = ""
        self.closed = False
        self._capture_json = capture_json

    def exec_command(self, command: str, timeout=None):  # noqa: ANN001
        self.capture_started = True
        self.capture_command = command
        stdout = _FakeStream(json.dumps(self._capture_json), exit_code=0)
        stderr = _FakeStream("", exit_code=0)
        return None, stdout, stderr

    def close(self) -> None:
        self.closed = True


class _FakeRemoteClient:
    def __init__(
        self, stdout_text: str, stderr_text: str = "", exit_code: int = 0
    ) -> None:
        self._stdout_text = stdout_text
        self._stderr_text = stderr_text
        self._exit_code = exit_code
        self.closed = False

    def exec_command(self, command: str, timeout=None):  # noqa: ANN001
        stdout = _FakeStream(self._stdout_text, exit_code=self._exit_code)
        stderr = _FakeStream(self._stderr_text, exit_code=self._exit_code)
        return None, stdout, stderr

    def close(self) -> None:
        self.closed = True


class ScapyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = ScapyEngine(
            generator=SSHHostConfig(host="10.0.0.11", username="jimmy"),
            analyzer=SSHHostConfig(host="10.0.0.12", username="jimmy"),
            ssh_key_path="/tmp/test_key",
            remote_dir=".",
        )

    def test_build_send_command_includes_vlan_and_inner_vlan(self) -> None:
        command = self.engine._build_send_command(
            interface="eth0",
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:aa:bb",
            src_ip="172.16.0.1",
            dst_ip="172.16.0.2",
            protocol="udp",
            size=256,
            count=5,
            vlan=10,
            inner_vlan=20,
            ip_version="ipv4",
        )
        self.assertIn("--vlan 10", command)
        self.assertIn("--inner-vlan 20", command)
        self.assertIn("--count 5", command)
        self.assertIn("--protocol udp", command)

    def test_run_remote_json_parses_stdout(self) -> None:
        fake_client = _FakeRemoteClient(stdout_text='{"status":"ok","frames_sent":1}')
        with patch.object(self.engine, "_connect", return_value=fake_client):
            result = self.engine._run_remote_json(
                self.engine.generator, "python3 foo.py"
            )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["frames_sent"], 1)

    def test_run_remote_json_raises_on_bad_json(self) -> None:
        fake_client = _FakeRemoteClient(stdout_text="not-json")
        with patch.object(self.engine, "_connect", return_value=fake_client):
            with self.assertRaises(ScapyEngineError):
                self.engine._run_remote_json(self.engine.generator, "python3 foo.py")

    def test_send_and_capture_starts_capture_before_send(self) -> None:
        capture_payload = {
            "status": "ok",
            "timestamps": ["2026-03-20T00:00:01+00:00"],
            "frames_received": 1,
            "vlan_match_count": 0,
            "vlan_mismatch_count": 1,
        }
        analyzer_client = _FakeAnalyzerClient(capture_payload)

        def fake_connect(cfg: SSHHostConfig):  # noqa: ANN001
            if cfg.host == self.engine.analyzer.host:
                return analyzer_client
            raise AssertionError(
                "Unexpected direct _connect call to generator in this test"
            )

        def fake_run_remote_json(cfg: SSHHostConfig, command: str, timeout=None):  # noqa: ANN001
            self.assertTrue(analyzer_client.capture_started)
            self.assertIn("scapy_send.py", command)
            return {
                "status": "ok",
                "finished_at": "2026-03-20T00:00:00+00:00",
                "frames_sent": 1,
            }

        with (
            patch.object(self.engine, "_connect", side_effect=fake_connect),
            patch.object(
                self.engine, "_run_remote_json", side_effect=fake_run_remote_json
            ),
            patch.object(self.engine, "deploy_scripts", return_value={"status": "ok"}),
            patch("framework.traffic.scapy_engine.time.sleep", return_value=None),
        ):
            result = self.engine.send_and_capture(
                interface="eth0",
                src_mac="00:11:22:33:44:55",
                dst_mac="66:77:88:99:aa:bb",
                src_ip="172.16.0.1",
                dst_ip="172.16.0.2",
                protocol="icmp",
                size=128,
                deploy=True,
            )

        self.assertEqual(result["status"], "ok")
        self.assertIn("capture_started_at", result)
        self.assertIn("send_started_at", result)
        self.assertEqual(result["capture_result"]["frames_received"], 1)
        self.assertTrue(analyzer_client.closed)

    def test_measure_rtt_aggregates_samples(self) -> None:
        synthetic = [
            {"rtt_ms": 1.0},
            {"rtt_ms": 2.5},
            {"rtt_ms": 0.5},
        ]
        with patch.object(self.engine, "send_and_capture", side_effect=synthetic):
            result = self.engine.measure_rtt(
                interface="eth0",
                src_mac="00:11:22:33:44:55",
                dst_mac="66:77:88:99:aa:bb",
                src_ip="172.16.0.1",
                dst_ip="172.16.0.2",
                probes=3,
                deploy=False,
            )
        self.assertEqual(result["samples_count"], 3)
        self.assertEqual(result["min_rtt_ms"], 0.5)
        self.assertEqual(result["max_rtt_ms"], 2.5)

    def test_check_vlan_isolation_reports_fail_when_matches_seen(self) -> None:
        evidence = {
            "capture_result": {
                "frames_received": 3,
                "vlan_match_count": 2,
                "vlan_mismatch_count": 1,
            }
        }
        with patch.object(self.engine, "send_and_capture", return_value=evidence):
            result = self.engine.check_vlan_isolation(
                interface="eth0",
                src_mac="00:11:22:33:44:55",
                dst_mac="66:77:88:99:aa:bb",
                src_ip="172.16.0.1",
                dst_ip="172.16.0.2",
                protocol="udp",
                size=256,
                vlan=10,
                expected_vlan=10,
                deploy=False,
            )
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["vlan_match_count"], 2)


if __name__ == "__main__":
    unittest.main()
