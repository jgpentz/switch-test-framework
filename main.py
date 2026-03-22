import copy
import json
from datetime import datetime
from pathlib import Path

from framework.tests.rfc2544 import (
    back_to_back,
    frame_loss,
    latency,
    RFC2544Config,
    throughput,
)
from framework.traffic.iperf3_engine import IPerf3Engine


def save_result(result: dict, path: str):
    clean = copy.deepcopy(result)
    for item in clean.get("evidence", []):
        item.pop("raw_json", None)
    with open(path, "w") as f:
        json.dump(clean, f, indent=2)


def main() -> None:
    ssh_options = ["-i", "/home/jimmy/.ssh/id_gen"]
    engine = IPerf3Engine(ssh_options=ssh_options)
    config = RFC2544Config(frame_length=1472)

    # Get time in format yyyy-mm-dd-hh-mm
    time = datetime.now().strftime("%Y-%m-%d-%H-%M")

    # ----- Throughput test -----
    print("Running throughput test...")
    throughput_result = throughput(engine, "172.16.0.2", config=config)

    throughput_result_file = Path(f"results/{time}_throughput.json")
    save_result(throughput_result, throughput_result_file)

    # ----- Latency test -----
    print("Running latency test...")
    # throughput_result ={"details": {"zero_loss_bitrate_bps": 800_000_000}}
    latency_result = latency(
        engine,
        "172.16.0.2",
        throughput_bps=throughput_result["details"]["zero_loss_bitrate_bps"],
        config=config,
    )
    latency_result_file = Path(f"results/{time}_latency.json")
    save_result(latency_result, latency_result_file)

    # ----- Frame loss test -----
    print("Running frame loss test...")
    frame_loss_result = frame_loss(engine, "172.16.0.2", config=config)
    frame_loss_result_file = Path(f"results/{time}_frame_loss.json")
    save_result(frame_loss_result, frame_loss_result_file)

    # ----- Back-to-back test -----
    print("Running back-to-back test...")
    back_to_back_result = back_to_back(engine, "172.16.0.2", config=config)
    back_to_back_result_file = Path(f"results/{time}_back_to_back.json")
    save_result(back_to_back_result, back_to_back_result_file)


if __name__ == "__main__":
    main()
