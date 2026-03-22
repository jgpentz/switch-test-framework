import json
from datetime import datetime
from pathlib import Path

from framework.tests.rfc2544 import throughput, latency, frame_loss, back_to_back
from framework.traffic.iperf3_engine import IPerf3Engine
from framework.traffic.scapy_engine import ScapyEngine
from framework.telemetry.cisco_snmp import poll_interface_counters


def main() -> None:
    ssh_options = ["-i", "/home/jimmy/.ssh/id_gen"]
    engine = IPerf3Engine(ssh_options=ssh_options)
    result = throughput(engine, "172.16.0.2")

    # Get time in format yyyy-mm-dd-hh-mm
    time = datetime.now().strftime("%Y-%m-%d-%H-%M")
    result_file = Path(f"results/{time}_throughput.json")
    with open(result_file, "w") as f:
        json.dump(result, f)

    print(result)

    # result = latency(engine, "172.16.0.2", throughput_bps=1_000_000_000)
    # print(result)

    # result = frame_loss(engine, "172.16.0.2")
    # print(result)

    # result = back_to_back(engine, "172.16.0.2")
    # print(result)

if __name__ == "__main__":
    main()  