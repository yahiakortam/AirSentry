"""AirSentry configuration: settings dataclass and loader."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]


# ---------------------------------------------------------------------------
# Settings dataclass
# ---------------------------------------------------------------------------

@dataclass
class CaptureSettings:
    """Settings that govern packet capture behavior."""
    default_interface: str = ""
    default_channel: Optional[int] = None
    bpf_filter: str = "type mgt"           # Capture management frames only
    snap_length: int = 65535               # Maximum bytes per packet


@dataclass
class OutputSettings:
    """Settings that govern terminal output behavior."""
    verbose: bool = False
    color: bool = True
    max_ssid_length: int = 32              # Truncate SSIDs longer than this


@dataclass
class DetectorSettings:
    """Settings that control detection engine behaviour and thresholds."""
    # Deauthentication burst detector
    deauth_window_seconds: float = 10.0    # Rolling window width in seconds
    deauth_burst_threshold: int = 10       # Frame count to trigger an alert

    # Beacon anomaly detector
    beacon_window_seconds: float = 30.0    # Rolling window width in seconds
    beacon_rate_threshold: float = 50.0    # Beacons/s per BSSID to trigger alert
    beacon_unique_ssid_threshold: int = 20 # Unique SSIDs in window to trigger alert


@dataclass
class LoggingSettings:
    """Settings that govern structured JSONL session logging."""
    enabled: bool = True        # Enable or disable session logging entirely
    log_events: bool = False    # Log raw events (alerts always logged when enabled)
    log_dir: str = ""           # Override directory; empty = platform default


@dataclass
class AnalysisSettings:
    """Settings that control the Phase 3 feature extraction and anomaly scoring layer."""
    enabled: bool = True               # Enable rolling-window analysis in monitor/replay
    window_seconds: float = 60.0       # Look-back window for feature extraction
    interval_seconds: float = 30.0     # How often to run an analysis cycle
    anomaly_threshold: float = 0.65    # Score above which ANOMALY_SCORE alert fires
    warmup_windows: int = 30           # Windows to collect before fitting IsolationForest


@dataclass
class ResearchSettings:
    """Settings for the 'collect' research data collection mode."""
    default_format: str = "jsonl"      # Output format: 'csv' or 'jsonl'
    default_output_dir: str = ""       # Override export directory; empty = platform default


@dataclass
class Settings:
    """
    Top-level AirSentry configuration object.

    Populated from (in ascending priority order):
      1. Built-in defaults
      2. TOML config file (~/.config/airsentry/config.toml or ./airsentry.toml)
      3. Environment variables (AIRSENTRY_*)
    """
    capture:  CaptureSettings  = field(default_factory=CaptureSettings)
    output:   OutputSettings   = field(default_factory=OutputSettings)
    detector: DetectorSettings = field(default_factory=DetectorSettings)
    logging:  LoggingSettings  = field(default_factory=LoggingSettings)
    analysis: AnalysisSettings = field(default_factory=AnalysisSettings)
    research: ResearchSettings = field(default_factory=ResearchSettings)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_PATHS: list[Path] = [
    Path("airsentry.toml"),
    Path.home() / ".config" / "airsentry" / "config.toml",
]


def load_settings(config_path: Optional[Path] = None) -> Settings:
    """
    Load and return a fully-resolved Settings object.

    Config search order:
      1. Explicit ``config_path`` argument (if provided)
      2. ``./airsentry.toml``
      3. ``~/.config/airsentry/config.toml``
    Environment variables override all file values.
    """
    settings = Settings()
    raw: dict = {}

    # Locate and parse TOML
    search_paths = [config_path] if config_path else _DEFAULT_CONFIG_PATHS
    for candidate in search_paths:
        if candidate and candidate.is_file():
            with open(candidate, "rb") as fh:
                raw = tomllib.load(fh)
            break

    # Apply capture settings from TOML
    if capture_raw := raw.get("capture", {}):
        settings.capture.default_interface = capture_raw.get(
            "default_interface", settings.capture.default_interface
        )
        settings.capture.default_channel = capture_raw.get(
            "default_channel", settings.capture.default_channel
        )
        settings.capture.bpf_filter = capture_raw.get(
            "bpf_filter", settings.capture.bpf_filter
        )
        settings.capture.snap_length = capture_raw.get(
            "snap_length", settings.capture.snap_length
        )

    # Apply output settings from TOML
    if output_raw := raw.get("output", {}):
        settings.output.verbose = output_raw.get("verbose", settings.output.verbose)
        settings.output.color = output_raw.get("color", settings.output.color)
        settings.output.max_ssid_length = output_raw.get(
            "max_ssid_length", settings.output.max_ssid_length
        )

    # Apply detector settings from TOML
    if det_raw := raw.get("detector", {}):
        settings.detector.deauth_window_seconds = det_raw.get(
            "deauth_window_seconds", settings.detector.deauth_window_seconds
        )
        settings.detector.deauth_burst_threshold = det_raw.get(
            "deauth_burst_threshold", settings.detector.deauth_burst_threshold
        )
        settings.detector.beacon_window_seconds = det_raw.get(
            "beacon_window_seconds", settings.detector.beacon_window_seconds
        )
        settings.detector.beacon_rate_threshold = det_raw.get(
            "beacon_rate_threshold", settings.detector.beacon_rate_threshold
        )
        settings.detector.beacon_unique_ssid_threshold = det_raw.get(
            "beacon_unique_ssid_threshold", settings.detector.beacon_unique_ssid_threshold
        )

    # Apply logging settings from TOML
    if log_raw := raw.get("logging", {}):
        settings.logging.enabled   = log_raw.get("enabled",    settings.logging.enabled)
        settings.logging.log_events = log_raw.get("log_events", settings.logging.log_events)
        settings.logging.log_dir   = log_raw.get("log_dir",    settings.logging.log_dir)

    # Apply analysis settings from TOML
    if analysis_raw := raw.get("analysis", {}):
        settings.analysis.enabled           = analysis_raw.get("enabled",           settings.analysis.enabled)
        settings.analysis.window_seconds    = analysis_raw.get("window_seconds",    settings.analysis.window_seconds)
        settings.analysis.interval_seconds  = analysis_raw.get("interval_seconds",  settings.analysis.interval_seconds)
        settings.analysis.anomaly_threshold = analysis_raw.get("anomaly_threshold", settings.analysis.anomaly_threshold)
        settings.analysis.warmup_windows    = analysis_raw.get("warmup_windows",    settings.analysis.warmup_windows)

    # Apply research settings from TOML
    if research_raw := raw.get("research", {}):
        settings.research.default_format     = research_raw.get("default_format",     settings.research.default_format)
        settings.research.default_output_dir = research_raw.get("default_output_dir", settings.research.default_output_dir)

    # Environment variable overrides
    if iface := os.environ.get("AIRSENTRY_INTERFACE"):
        settings.capture.default_interface = iface
    if os.environ.get("NO_COLOR"):
        settings.output.color = False
    if os.environ.get("AIRSENTRY_NO_LOG"):
        settings.logging.enabled = False

    return settings
