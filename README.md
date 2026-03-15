# AirSentry

> A passive Wi-Fi security monitoring and wireless research platform.

AirSentry observes nearby 802.11 wireless traffic, parses management frames, detects suspicious patterns, and generates structured research datasets — all from a clean, extensible CLI.

---

## Features

- **Live monitoring** from any monitor-mode Wi-Fi interface
- **PCAP replay** with original or configurable timing
- **Frame parsing** — beacon, probe request/response, deauthentication, disassociation
- **Threat detection** — deauth floods, evil-twin / rogue APs, beacon anomalies
- **Anomaly scoring** — heuristic warm-up → IsolationForest model
- **Research collection** — structured CSV / JSONL dataset export with MAC anonymization
- **Visualization** — matplotlib charts from collected datasets
- **Dataset toolkit** — merge, filter, clean, and summarize research datasets
- **Session dashboard** — rich summary at the end of every session

---

## Requirements

- Python 3.10+
- `scapy`, `typer`, `rich`, `scikit-learn`
- **Live capture requires root/sudo and a Wi-Fi adapter in monitor mode**
- Visualization requires `matplotlib` (optional)

## Installation

```bash
git clone https://github.com/yahiakortam/AirSentry.git
cd AirSentry

python3 -m venv .venv
source .venv/bin/activate

# Core install
pip install -e .

# With visualization support
pip install -e ".[viz]"
```

---

## Usage

### Live Monitor Mode

```bash
# Requires root and a monitor-mode interface
sudo airsentry monitor --interface wlan0mon

# Specific channel, verbose output
sudo airsentry monitor --interface wlan0mon --channel 6 --verbose

# Disable detection or analysis independently
sudo airsentry monitor --interface wlan0mon --no-detect
sudo airsentry monitor --interface wlan0mon --no-analyze

# Filter displayed frame types
sudo airsentry monitor --interface wlan0mon --filter deauth,beacon
```

### PCAP Replay

```bash
# Replay with original timing
airsentry replay --file capture.pcap

# Replay as fast as possible
airsentry replay --file capture.pcap --fast

# Cap replay rate
airsentry replay --file capture.pcap --rate 100
```

### Demo Mode

Demo mode replays a PCAP file with all detection and analysis features enabled,
and produces a detailed annotated session summary. Designed for first-time users
and presentations.

```bash
airsentry demo --file capture.pcap
airsentry demo --file examples/sample_dataset.csv --rate 500
```

### Research Data Collection

Collect a structured wireless environment dataset for a fixed duration.

```bash
# Requires root and monitor-mode interface
sudo airsentry collect --interface wlan0mon --location cafe_downtown --duration 1200

# Custom interval and window
sudo airsentry collect --interface wlan0mon --location office --duration 600 --interval 30 --window 60

# Export as CSV (default: JSONL)
sudo airsentry collect --interface wlan0mon --location home --duration 300 --format csv
```

### Visualization

Generate charts from a collected dataset (requires `matplotlib`):

```bash
airsentry visualize --file dataset.csv

# Specify output directory and format
airsentry visualize --file dataset.csv --output-dir ./charts --format svg
```

Generated charts:

| Chart | Description |
|-------|-------------|
| `anomaly_timeline` | Anomaly score over time with alert threshold |
| `frame_distribution` | Total frame counts by type |
| `device_activity` | Unique devices and SSIDs per window |
| `beacon_rate` | Beacon frames per second over time |

### Dataset Toolkit

```bash
# Merge multiple datasets into one sorted file
airsentry dataset merge --file session_a.csv --file session_b.csv --output merged.csv

# Print aggregate statistics
airsentry dataset summarize --file dataset.csv
airsentry dataset summarize --file dataset.csv --location cafe_downtown

# Filter by location label
airsentry dataset filter --file dataset.csv --location cafe_downtown --output cafe.csv

# Remove invalid or incomplete records
airsentry dataset clean --file dataset.csv --output clean.csv
```

---

## Session Summary

Every monitoring or replay session ends with a wireless environment summary:

```
──────────────────── Wireless Session Summary ────────────────────

  Devices detected      23    Beacon frames         5 400
  Unique SSIDs          11    Probe requests          128
  Unique BSSIDs         14    Deauth / Disassoc         7
                              Total frames parsed   5 535

  Alerts raised          2
  Analysis windows      12
  Last anomaly score   0.42  (IsolationForest)
  Session duration      8m 3s
```

---

## Project Structure

```
airsentry/
├── cli/              # CLI entrypoint and subcommands (Typer)
│   └── commands/     # monitor, replay, collect, demo, visualize, dataset
├── capture/          # Packet ingestion: live sniff + PCAP replay
├── parsing/          # Frame dispatcher and per-frame parsers
├── models/           # Normalized event/alert dataclasses and enums
├── detection/        # Detection engine, rolling window, rule-based detectors
├── analysis/         # Rolling event window, feature extraction, anomaly scoring, session stats
├── research/         # Research collector, dataset exporter, MAC anonymizer
├── visualization/    # Matplotlib chart generation
├── dataset/          # Dataset merge / filter / clean / summarize toolkit
├── output/           # Rich terminal output
├── logging/          # Structured JSONL session logger
├── config/           # Settings (TOML + env vars)
└── utils/            # Shared utilities

examples/
├── sample_dataset.csv    # 25-window synthetic dataset with simulated attack
└── README.md             # Example usage guide
```

---

## Configuration

AirSentry reads configuration from (in priority order):

1. `./airsentry.toml` in the working directory
2. `~/.config/airsentry/config.toml`
3. Environment variables (`AIRSENTRY_INTERFACE`, `NO_COLOR`, `AIRSENTRY_NO_LOG`)

Example `airsentry.toml`:

```toml
[capture]
bpf_filter = "type mgt"
snap_length = 65535

[detector]
deauth_window_seconds   = 10.0
deauth_burst_threshold  = 10
beacon_rate_threshold   = 50.0

[analysis]
window_seconds    = 60.0
interval_seconds  = 30.0
anomaly_threshold = 0.65

[logging]
enabled    = true
log_events = false
```

---

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| **1** | Core capture & parsing pipeline | ✅ |
| **2** | Rule-based threat detection | ✅ |
| **3** | Rolling windows + feature extraction + anomaly scoring | ✅ |
| **4** | Visualization, dataset toolkit, demo mode, session dashboard | ✅ |
| 5     | Dashboard / web interface | Planned |

---

## License

MIT
