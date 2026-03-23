# Phase 4 — Report Generator

## Status
- [ ] Jinja2 + Plotly installed
- [ ] `report_generator.py` implemented
- [ ] `report.html` Jinja2 template created
- [ ] Report generation wired into `main.py`

---

## Purpose

Transform raw JSON test results into a single self-contained HTML report
that can be opened in any browser, handed to a network engineering team,
or attached to an email. No server, no dependencies, no software required
to view it — everything is embedded inline.

---

## Tools

| Tool | Purpose | Install |
|------|---------|---------|
| Jinja2 | HTML templating — separates data from presentation | `uv add jinja2` |
| Plotly | Interactive embedded charts — zoom, hover, tooltips | `uv add plotly` |

Both run on the orchestrator only. Nothing new needed on the generator
or analyzer.

---

## File Structure

```
framework/
└── reporting/
    ├── __init__.py
    ├── report_generator.py    ← reads JSON, builds charts, renders template
    └── templates/
        └── report.html        ← Jinja2 template

results/
├── 2026-03-22/
    └── throughput.json
    └── frame_rate.json
    └── report.html
```

---

## Report Structure

### Section 1 — Executive Summary
The first thing anyone reads. Keep it to one screen.

| Field | Source |
|-------|--------|
| Report generated timestamp | system time |
| Switch hostname / IP | `config/lab_topology.yaml` |
| IOS version | Netmiko `show version` |
| Total tests run | count of result files |
| Tests passed | count where `passed: true` |
| Tests failed | count where `passed: false` |
| Zero-loss throughput (headline) | throughput result, best frame size |
| Test duration (total) | sum of `duration_sec` across all results |

---

### Section 2 — RFC 2544 Benchmarks

#### Throughput
- **Table** — frame size vs zero-loss bitrate (bps and % of link)
- **Bar chart** — frame size on X axis, zero-loss Mbps on Y axis
- Shows clearly how throughput degrades at smaller frame sizes

#### Frame Loss Rate
- **Multi-line chart** — one line per frame size
- X axis: offered bitrate as % of line rate (0–100%)
- Y axis: loss % (0–100%)
- This is the most impactful visual in the report

#### Latency
- **Table** — one row per trial, latency in ms, average highlighted
- Run at throughput rate per RFC 2544 spec
- 20 trials, report average

#### Back-to-Back
- **Table** — frame size vs max burst frames, std deviation
- Shows the switch's buffer depth at each frame size

---

### Section 3 — Functional Tests

- **Summary table** — one row per test

| Test | Result | Duration | Timestamp |
|------|--------|----------|-----------|
| VLAN Isolation | ✅ PASS | 2.3s | ... |
| MAC Learning | ✅ PASS | 4.1s | ... |
| Jumbo Frames | ✅ PASS | 1.8s | ... |
| 802.1Q Tagging | ✅ PASS | 2.0s | ... |
| STP Convergence | ✅ PASS | 35.2s | ... |
| ACL Enforcement | ✅ PASS | 3.4s | ... |

- **Evidence section** — for any failed test, show frames sent
  and received so the failure is clearly explained

---

### Section 4 — Switch Telemetry

- **Table** — interface counter deltas across the full test run
- TX/RX packets, errors, drops per port
- Correlates switch-side observations with test-side results
- Source: SNMP counter snapshots attached to each result

---

## Report Generator Implementation

### `report_generator.py`

```python
class ReportGenerator:
    def __init__(self, results_dir: str, output_dir: str):
        ...

    def load_results(self) -> dict:
        # Read all JSON files from results_dir
        # Organize by test type
        ...

    def build_throughput_chart(self, data: dict) -> str:
        # Plotly bar chart — frame size vs zero-loss Mbps
        # Returns HTML string to embed in template
        ...

    def build_frame_loss_chart(self, data: dict) -> str:
        # Plotly multi-line chart — loss % vs bitrate %
        # One line per frame size
        # Returns HTML string to embed in template
        ...

    def build_latency_table(self, data: dict) -> list:
        # Returns list of dicts for Jinja2 to render as table
        ...

    def generate(self, output_filename: str) -> str:
        # Load results
        # Build all charts
        # Render Jinja2 template
        # Write self-contained HTML file
        # Return output path
        ...
```

---

## Jinja2 Template Structure

```html
<!-- report.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Network Test Report — {{ timestamp }}</title>
    <!-- Plotly JS embedded inline — no CDN needed -->
    <!-- Minimal CSS embedded inline -->
</head>
<body>

  <!-- Section 1: Executive Summary -->
  <h1>Network Test Report</h1>
  <p>Generated: {{ timestamp }}</p>
  <p>Switch: {{ switch_ip }}</p>
  <p>Tests Passed: {{ passed }} / {{ total }}</p>
  <p>Zero-Loss Throughput: {{ headline_throughput_mbps }} Mbps</p>

  <!-- Section 2: RFC 2544 -->
  <h2>RFC 2544 Benchmarks</h2>

  <h3>Throughput</h3>
  {{ throughput_chart | safe }}       <!-- Plotly chart HTML -->
  {{ throughput_table | safe }}       <!-- HTML table -->

  <h3>Frame Loss Rate</h3>
  {{ frame_loss_chart | safe }}

  <h3>Latency</h3>
  {{ latency_table | safe }}

  <h3>Back-to-Back</h3>
  {{ back_to_back_table | safe }}

  <!-- Section 3: Functional Tests -->
  <h2>Functional Tests</h2>
  {{ functional_table | safe }}

  <!-- Section 4: Telemetry -->
  <h2>Switch Telemetry</h2>
  {{ telemetry_table | safe }}

</body>
</html>
```

---

## CLI Integration

Called from `main.py`:

```bash
# Generate report from all results in results/
uv run python main.py --report

# Generate report from a specific results file
uv run python main.py --report results/2026-03-22_full_suite.json
```

Produces:
```
reports/2026-03-22_report.html
```

---

## Self-Contained Output

The final HTML file must open with no internet connection and no
dependencies. To achieve this:

- Embed Plotly JS inline using `plotly.offline.plot()` with
  `include_plotlyjs='cdn'` switched to `include_plotlyjs=True`
- Embed all CSS inline in a `<style>` block
- No external fonts, no CDN links, no images from URLs

```python
import plotly.offline as pyo

chart_html = pyo.plot(
    fig,
    output_type='div',        # returns HTML string, not a file
    include_plotlyjs=True,    # embeds Plotly JS inline
)
```

---

## Key Charts

### Frame Loss Curve (most impactful)
Shows the performance fingerprint of the switch. Multi-line chart,
one line per frame size. Immediately communicates to any network
engineer how the switch behaves under load.

```
Loss %
100% |
     |                          ■ 64 bytes
     |                    ▲ 128 bytes
  50%|              ● 256 bytes
     |        ◆ 512 bytes
     |  ★ 1518 bytes
   0%|________________________
     0%   25%   50%   75%  100%
              Offered Load %
```

### Throughput vs Frame Size (second most impactful)
Bar chart showing zero-loss throughput at each RFC 2544 frame size.
Makes it immediately obvious where the 3750's packet-per-second
ceiling is.

---

## Build Order

1. Install dependencies — `uv add jinja2 plotly`
2. Build `report_generator.py` — load results, build charts
3. Build `report.html` Jinja2 template
4. Wire into `main.py` with `--report` flag
5. Verify output opens correctly in browser with no internet
