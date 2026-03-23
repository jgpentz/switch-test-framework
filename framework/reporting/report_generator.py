from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import plotly.graph_objects as go
import plotly.offline as pyo
from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = Path(__file__).parent / "templates"

FUNCTIONAL_TESTS = {
    "vlan_isolation",
    "mac_learning",
    "jumbo_frames",
    "dot1q_tagging",
    "stp_convergence",
    "acl_enforcement",
}

RFC2544_TESTS = {"throughput", "frame_loss", "latency", "back_to_back"}

FRIENDLY_NAMES: dict[str, str] = {
    "throughput": "Throughput",
    "frame_loss": "Frame Loss Rate",
    "latency": "Latency",
    "back_to_back": "Back-to-Back",
    "vlan_isolation": "VLAN Isolation",
    "mac_learning": "MAC Learning",
    "jumbo_frames": "Jumbo Frames",
    "dot1q_tagging": "802.1Q Tagging",
    "stp_convergence": "STP Convergence",
    "acl_enforcement": "ACL Enforcement",
}


class ReportGenerator:
    def __init__(self, results_dir: Path, output_dir: Path) -> None:
        self.results_dir = results_dir
        self.output_dir = output_dir
        self._plotly_js_emitted = False

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def load_results(self) -> dict[str, dict]:
        results: dict[str, dict] = {}
        for path in sorted(self.results_dir.glob("*.json")):
            with path.open() as f:
                data = json.load(f)
            test_name = data.get("test", path.stem)
            results[test_name] = data
        return results

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------

    def build_executive_summary(self, results: dict[str, dict]) -> dict:
        total = len(results)
        passed = sum(1 for r in results.values() if r.get("passed"))
        failed = total - passed
        total_duration = sum(r.get("duration_sec", 0) for r in results.values())

        headline_throughput_mbps = None
        tp = results.get("throughput")
        if tp:
            bps = tp.get("details", {}).get("zero_loss_bitrate_bps")
            if bps is not None:
                headline_throughput_mbps = round(bps / 1_000_000, 2)

        switch_model = "Cisco Catalyst 3750"

        return {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "switch_model": switch_model,
            "total": total,
            "passed": passed,
            "failed": failed,
            "headline_throughput_mbps": headline_throughput_mbps,
            "total_duration_sec": round(total_duration, 1),
        }

    # ------------------------------------------------------------------
    # RFC 2544 charts and tables
    # ------------------------------------------------------------------

    def _plot(self, fig: go.Figure) -> str:
        """Render a Plotly figure to an HTML div.

        The first call embeds the full Plotly JS library inline so the
        report is self-contained.  Subsequent calls skip it.
        """
        include_js: bool | str = not self._plotly_js_emitted
        html = pyo.plot(fig, output_type="div", include_plotlyjs=include_js)
        self._plotly_js_emitted = True
        return html

    def build_throughput_chart(self, data: dict) -> str:
        details = data.get("details", {})
        per_frame = details.get("per_frame_size_results", [])
        if per_frame:
            labels = [str(item["frame_size"]) for item in per_frame]
            mbps = [
                round(item.get("zero_loss_bitrate_bps", 0) / 1_000_000, 2)
                for item in per_frame
            ]
            x_title = "Frame Size (bytes)"
            title = "Zero-Loss Throughput by Frame Size"
        else:
            trials = details.get("trials", [])
            if not trials:
                return "<p>No throughput trial data available.</p>"
            zero_loss = [t for t in trials if t.get("lost_percent", 1) == 0]
            if not zero_loss:
                zero_loss = trials
            labels = [f"{t['offered_bitrate_pct']}%" for t in zero_loss]
            mbps = [round(t["achieved_bitrate_bps"] / 1_000_000, 2) for t in zero_loss]
            x_title = "Offered Load (% of Line Rate)"
            title = "Zero-Loss Throughput by Offered Load"

        fig = go.Figure(
            data=[go.Bar(x=labels, y=mbps, marker_color="#2563eb")],
            layout=go.Layout(
                title=title,
                xaxis_title=x_title,
                yaxis_title="Achieved Throughput (Mbps)",
                template="plotly_white",
                height=400,
            ),
        )
        return self._plot(fig)

    _FRAME_LOSS_COLORS = [
        "#dc2626", "#2563eb", "#16a34a", "#d97706",
        "#7c3aed", "#db2777", "#0891b2", "#65a30d",
    ]

    def build_frame_loss_chart(self, data: dict) -> str:
        details = data.get("details", {})

        per_frame = details.get("per_frame_size_results", [])
        if per_frame:
            traces = []
            for i, entry in enumerate(per_frame):
                sweep = entry.get("results", [])
                if not sweep:
                    continue
                color = self._FRAME_LOSS_COLORS[i % len(self._FRAME_LOSS_COLORS)]
                traces.append(
                    go.Scatter(
                        x=[r["bitrate_pct"] for r in sweep],
                        y=[round(r["loss_pct"], 2) for r in sweep],
                        mode="lines+markers",
                        name=f"{entry['frame_size']} B",
                        line={"color": color},
                        marker={"size": 6},
                    )
                )
            if not traces:
                return "<p>No frame loss data available.</p>"
        else:
            flat = details.get("results", [])
            if not flat:
                return "<p>No frame loss data available.</p>"
            traces = [
                go.Scatter(
                    x=[r["bitrate_pct"] for r in flat],
                    y=[round(r["loss_pct"], 2) for r in flat],
                    mode="lines+markers",
                    name="default",
                    line={"color": "#dc2626"},
                    marker={"size": 8},
                )
            ]

        fig = go.Figure(
            data=traces,
            layout=go.Layout(
                title="Frame Loss Rate vs. Offered Load",
                xaxis_title="Offered Load (% of Line Rate)",
                yaxis_title="Loss (%)",
                template="plotly_white",
                height=450,
            ),
        )
        return self._plot(fig)

    def build_latency_table(self, data: dict) -> list[dict]:
        details = data.get("details", {})
        rows = []

        per_frame = details.get("per_frame_size_results", [])
        if per_frame:
            for frame_entry in per_frame:
                for entry in frame_entry.get("results", []):
                    rows.append(
                        {
                            "frame_size": frame_entry["frame_size"],
                            "load_pct": entry["load_pct"],
                            "jitter_ms_avg": round(entry["jitter_ms_avg"], 4),
                            "jitter_ms_std": round(entry["jitter_ms_std"], 4),
                            "samples": len(entry.get("jitter_ms_samples", [])),
                        }
                    )
        else:
            for entry in details.get("results", []):
                rows.append(
                    {
                        "frame_size": None,
                        "load_pct": entry["load_pct"],
                        "jitter_ms_avg": round(entry["jitter_ms_avg"], 4),
                        "jitter_ms_std": round(entry["jitter_ms_std"], 4),
                        "samples": len(entry.get("jitter_ms_samples", [])),
                    }
                )
        return rows

    def build_back_to_back_table(self, data: dict) -> list[dict]:
        details = data.get("details", {})

        per_frame = details.get("per_frame_size_results", [])
        if per_frame:
            return [
                {
                    "frame_size": entry["frame_size"],
                    "max_burst_frames": entry.get("max_burst_frames", 0),
                    "avg_burst_frames": entry.get("avg_burst_frames", 0),
                    "std_deviation": entry.get("std_deviation", 0),
                    "trials": entry.get("trials", 0),
                }
                for entry in per_frame
            ]

        return [
            {
                "frame_size": details.get("frame_size"),
                "max_burst_frames": details.get("max_burst_frames"),
                "avg_burst_frames": details.get("avg_burst_frames"),
                "std_deviation": details.get("std_deviation"),
                "trials": details.get("trials"),
            }
        ]

    # ------------------------------------------------------------------
    # Functional tests table
    # ------------------------------------------------------------------

    def build_functional_table(self, results: dict[str, dict]) -> list[dict]:
        rows = []
        for name in (
            "vlan_isolation",
            "mac_learning",
            "jumbo_frames",
            "dot1q_tagging",
            "stp_convergence",
            "acl_enforcement",
        ):
            r = results.get(name)
            if r is None:
                continue
            rows.append(
                {
                    "test": FRIENDLY_NAMES.get(name, name),
                    "passed": r.get("passed", False),
                    "duration_sec": round(r.get("duration_sec", 0), 1),
                    "timestamp": r.get("timestamp", ""),
                    "details": r.get("details", {}),
                }
            )
        return rows

    # ------------------------------------------------------------------
    # Telemetry
    # ------------------------------------------------------------------

    def build_telemetry_table(self, results: dict[str, dict]) -> list[dict]:
        rows = []
        for name, r in results.items():
            delta = r.get("switch_counter_delta", {})
            if not delta:
                continue
            rows.append({"test": FRIENDLY_NAMES.get(name, name), **delta})
        return rows

    # ------------------------------------------------------------------
    # Generate report
    # ------------------------------------------------------------------

    def generate(self, output_filename: str = "report.html") -> Path:
        self._plotly_js_emitted = False
        results = self.load_results()

        summary = self.build_executive_summary(results)

        throughput_chart = ""
        frame_loss_chart = ""
        latency_rows: list[dict] = []
        b2b_rows: list[dict] = []

        if "throughput" in results:
            throughput_chart = self.build_throughput_chart(results["throughput"])
        if "frame_loss" in results:
            frame_loss_chart = self.build_frame_loss_chart(results["frame_loss"])
        if "latency" in results:
            latency_rows = self.build_latency_table(results["latency"])
        if "back_to_back" in results:
            b2b_rows = self.build_back_to_back_table(results["back_to_back"])

        functional_rows = self.build_functional_table(results)
        telemetry_rows = self.build_telemetry_table(results)

        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=False,
        )
        template = env.get_template("report.html")

        html = template.render(
            summary=summary,
            throughput_chart=throughput_chart,
            frame_loss_chart=frame_loss_chart,
            latency_rows=latency_rows,
            back_to_back_rows=b2b_rows,
            functional_rows=functional_rows,
            telemetry_rows=telemetry_rows,
            results_dir_name=self.results_dir.name,
        )

        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_path = self.output_dir / output_filename
        output_path.write_text(html)
        return output_path
