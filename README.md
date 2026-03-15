# AirSentry

> A passive Wi-Fi security monitoring and research platform.

AirSentry observes nearby Wi-Fi traffic, parses 802.11 management frames, and surfaces them in a clean, readable format. It is designed as a research-grade tool that can be extended with detectors, anomaly scoring, and structured logging in future phases.

---

## Phase 1 — Core Capture & Parsing

**Phase 1** establishes the ingestion pipeline:

- Live monitoring from a Wi-Fi interface (monitor mode required)
- Offline replay from a PCAP file
- Parsing of 802.11 management frames: beacon, probe request/response, deauthentication, disassociation
- Normalized internal event objects
- Professional terminal output

---

## Requirements

- Python 3.10+
- `scapy`, `typer`, `rich`
- **Live capture requires root/sudo and a Wi-Fi adapter in monitor mode**

## Installation

```bash
# Clone the repository
git clone https://github.com/yahiakortam/AirSentry.git
cd AirSentry

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install -e .
```

---

## Usage

### Live Monitor Mode

```bash
# Requires root and a monitor-mode interface
sudo airsentry monitor --interface wlan0mon

# Specify a channel
sudo airsentry monitor --interface wlan0mon --channel 6

# Verbose output (show signal strength and more detail)
sudo airsentry monitor --interface wlan0mon --verbose
```

### PCAP Replay Mode

```bash
# Replay a captured PCAP file
airsentry replay --file capture.pcap

# Replay with simulated timing (inter-packet delay)
airsentry replay --file capture.pcap --rate 100

# Verbose output
airsentry replay --file capture.pcap --verbose
```

### Help

```bash
airsentry --help
airsentry monitor --help
airsentry replay --help
```

---

## Project Structure

```
airsentry/
├── cli/            # CLI entrypoint and subcommands (Typer)
├── capture/        # Packet ingestion: live sniff + PCAP replay
├── parsing/        # Frame dispatching and per-frame parsers
├── models/         # Normalized event dataclasses and enums
├── output/         # Terminal rendering (Rich)
├── config/         # Settings and configuration loading
└── utils/          # Shared utilities (MAC formatting, timestamps)
```

---

## Roadmap

| Phase | Description |
|-------|-------------|
| **1** ✅ | Core capture & parsing pipeline |
| 2 | Rule-based threat detection (deauth floods, rogue APs, etc.) |
| 3 | Rolling event windows + feature extraction |
| 4 | Anomaly scoring (ML/AI layer) |
| 5 | Structured logging + research collection workflows |
| 6 | Dashboard / web interface |

---

## License

MIT
