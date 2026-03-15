# AirSentry Examples

This directory contains example files for testing and demonstrating AirSentry features.

---

## sample_dataset.csv

A realistic synthetic research dataset representing a 25-minute monitoring session
at a coffee shop (`location: cafe_downtown`).

The session contains:

- **Windows 1–15**: normal, quiet wireless activity
- **Windows 16–19**: simulated attack — a deauthentication burst with SSID duplication (anomaly scores 0.28–0.87)
- **Windows 20–25**: environment returning to baseline

### Use with the dataset toolkit

```bash
# Summarize the dataset
airsentry dataset summarize --file examples/sample_dataset.csv

# Filter to a specific location
airsentry dataset filter --file examples/sample_dataset.csv --location cafe_downtown

# Clean the dataset (remove incomplete records)
airsentry dataset clean --file examples/sample_dataset.csv
```

### Generate charts

```bash
# Requires matplotlib: pip install matplotlib
airsentry visualize --file examples/sample_dataset.csv --output-dir examples/charts
```

This generates four charts in `examples/charts/`:

| File | Description |
|------|-------------|
| `anomaly_timeline.png` | Anomaly score over time (shows the attack spike at ~10:17) |
| `frame_distribution.png` | Total frame counts by type |
| `device_activity.png` | Unique devices and SSIDs per window |
| `beacon_rate.png` | Beacon rate (beacons/s) over time |

---

## Adding your own examples

To add a real PCAP capture for demo use:

1. Capture traffic in monitor mode: `sudo tcpdump -i wlan0mon -w capture.pcap type mgt`
2. Place the file here: `examples/my_capture.pcap`
3. Run the demo: `airsentry demo --file examples/my_capture.pcap`

Real PCAP files are excluded from this repository (`.gitignore`) to avoid
accidentally committing sensitive wireless environment data.
