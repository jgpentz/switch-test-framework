import argparse
import copy
import json
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler

from framework.lab_secrets import load_lab_secrets
from framework.reporting.report_generator import ReportGenerator
from framework.tests.rfc2544 import (
    TelemetryConfig,
    back_to_back,
    frame_loss,
    latency,
    RFC2544Config,
    throughput,
)
from framework.traffic.iperf3_engine import IPerf3Engine
from framework.tests.functional import (
    acl_enforcement,
    vlan_isolation,
    mac_learning,
    jumbo_frames,
    dot1q_tagging,
    stp_convergence,
    FunctionalTestConfig,
)
from framework.traffic.scapy_engine import ScapyEngine


def on_link_failure() -> None:
    lab_secrets = load_lab_secrets()

    # Netmiko into device and shutdown interface then no shutdown to restore
    device = {
        "device_type": "cisco_ios",
        "host": "10.0.0.2",
        "username": lab_secrets.username,
        "password": lab_secrets.password,
        "port": 22,
    }
    with ConnectHandler(**device) as conn:
        conn.enable()
        cmds = [
            "interface GigabitEthernet1/0/5",
            "shutdown",
        ]
        conn.send_config_set(cmds)
        cmds = [
            "interface GigabitEthernet1/0/5",
            "no shutdown",
        ]
        conn.send_config_set(cmds)


def save_result(result: dict, path: Path) -> None:
    clean = copy.deepcopy(result)
    for item in clean.get("evidence", []):
        if "raw_json" in item:
            item.pop("raw_json", None)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(clean, f, indent=2)


def run_rfc2544_tests(
    engine: IPerf3Engine, config: RFC2544Config, results_dir: Path
) -> None:
    # ----- Throughput test -----
    print("Running throughput test...")
    throughput_result = throughput(engine, "172.16.0.2", config=config)
    save_result(throughput_result, results_dir / "throughput.json")

    # Build per-frame throughput map for latency
    throughput_by_frame: dict[int, float] = {
        entry["frame_size"]: entry["zero_loss_bitrate_bps"]
        for entry in throughput_result["details"]["per_frame_size_results"]
    }

    # ----- Latency test -----
    print("Running latency test...")
    latency_result = latency(
        engine,
        "172.16.0.2",
        throughput_results=throughput_by_frame,
        config=config,
    )
    save_result(latency_result, results_dir / "latency.json")

    # ----- Frame loss test -----
    print("Running frame loss test...")
    frame_loss_result = frame_loss(engine, "172.16.0.2", config=config)
    save_result(frame_loss_result, results_dir / "frame_loss.json")

    # ----- Back-to-back test -----
    print("Running back-to-back test...")
    back_to_back_result = back_to_back(engine, "172.16.0.2", config=config)
    save_result(back_to_back_result, results_dir / "back_to_back.json")


def run_functional_tests(
    engine: ScapyEngine,
    iperf3_engine: IPerf3Engine,
    config: FunctionalTestConfig,
    results_dir: Path,
) -> None:
    # ----- VLAN Isolation test -----
    print("Running VLAN Isolation test...")
    vlan_isolation_result = vlan_isolation(engine, config)
    vlan_isolation_result_file = results_dir / "vlan_isolation.json"
    save_result(vlan_isolation_result, vlan_isolation_result_file)

    # ----- MAC Learning test -----
    print("Running MAC Learning test...")
    mac_learning_result = mac_learning(engine, config)
    mac_learning_result_file = results_dir / "mac_learning.json"
    save_result(mac_learning_result, mac_learning_result_file)

    # ----- Jumbo Frames test -----
    print("Running Jumbo Frames test...")
    jumbo_frames_result = jumbo_frames(engine, config)
    jumbo_frames_result_file = results_dir / "jumbo_frames.json"
    save_result(jumbo_frames_result, jumbo_frames_result_file)

    # ----- 802.1Q Tagging test -----
    print("Running 802.1Q Tagging test...")
    dot1q_tagging_result = dot1q_tagging(engine, config)
    dot1q_tagging_result_file = results_dir / "dot1q_tagging.json"
    save_result(dot1q_tagging_result, dot1q_tagging_result_file)

    # ----- STP Convergence test -----
    print("Running STP Convergence test...")
    telemetry = TelemetryConfig(
        switch_ip="10.0.0.2", community="network-test", interface="GigabitEthernet1/0/5"
    )
    stp_convergence_result = stp_convergence(
        iperf3_engine,
        "172.16.0.2",
        on_link_failure=on_link_failure,
        config=config,
        telemetry=telemetry,
    )
    stp_convergence_result_file = results_dir / "stp_convergence.json"
    save_result(stp_convergence_result, stp_convergence_result_file)

    # ----- ACL Enforcement test -----
    print("Running ACL Enforcement test...")
    acl_enforcement_result = acl_enforcement(engine, config)
    acl_enforcement_result_file = results_dir / "acl_enforcement.json"
    save_result(acl_enforcement_result, acl_enforcement_result_file)


def generate_report(results_dir: Path) -> None:
    output_dir = Path("reports")
    gen = ReportGenerator(results_dir, output_dir)
    filename = f"{results_dir.name}_report.html"
    path = gen.generate(filename)
    print(f"Report written to {path}")


def latest_results_dir() -> Path:
    results_root = Path("results")
    dirs = sorted(
        (d for d in results_root.iterdir() if d.is_dir()),
        key=lambda d: d.name,
        reverse=True,
    )
    if not dirs:
        raise SystemExit("No results directories found under results/")
    return dirs[0]


def run_tests() -> None:
    ssh_options = ["-i", "/home/jimmy/.ssh/test-framework"]
    iperf3_engine = IPerf3Engine(ssh_options=ssh_options)
    scapy_engine = ScapyEngine(ssh_key_path="/home/jimmy/.ssh/test-framework")
    rfc2544_config = RFC2544Config(duration_sec=2)
    functional_test_config = FunctionalTestConfig(
        lab_secrets=load_lab_secrets(),
        src_ip="172.16.0.1",
        dst_ip="172.16.0.2",
        protocol="udp",
        frame_size=128,
        expect_tag_on_wire=False,
    )

    stamp = datetime.now().strftime("%Y-%m-%d-%H-%M")
    results_dir = Path("results") / stamp
    results_dir.mkdir(parents=True, exist_ok=True)

    run_rfc2544_tests(iperf3_engine, rfc2544_config, results_dir)
    run_functional_tests(
        scapy_engine, iperf3_engine, functional_test_config, results_dir
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Network Test Framework")
    parser.add_argument(
        "--report",
        nargs="?",
        const="latest",
        default=None,
        metavar="RESULTS_DIR",
        help="Generate HTML report from a results directory (default: latest run)",
    )
    args = parser.parse_args()

    if args.report is not None:
        if args.report == "latest":
            results_dir = latest_results_dir()
        else:
            results_dir = Path(args.report)
            if not results_dir.is_dir():
                raise SystemExit(f"Results directory not found: {results_dir}")
        generate_report(results_dir)
    else:
        run_tests()


if __name__ == "__main__":
    main()
