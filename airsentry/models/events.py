"""Normalized event models for 802.11 management frames.

All event objects are frozen dataclasses, meaning they are immutable once
created. This guarantees that parsers produce stable values and that
downstream consumers (detectors, loggers) cannot accidentally mutate events.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from airsentry.models.frame_types import DeauthReasonCode, ManagementSubtype


# ---------------------------------------------------------------------------
# Base event
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FrameEvent:
    """
    Base class for all parsed 802.11 management frame events.

    Every event in AirSentry carries these common fields.  Future phases
    (feature extraction, anomaly scoring) should extend this base rather than
    adding ad-hoc fields to the subclasses.
    """
    frame_type: ManagementSubtype
    timestamp: datetime
    src_mac: str                            # Normalized: "aa:bb:cc:dd:ee:ff"
    dst_mac: str
    bssid: str
    channel: Optional[int]                  # None if unavailable in packet
    signal_dbm: Optional[int]              # Received signal strength (dBm), if present


# ---------------------------------------------------------------------------
# Management frame events
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BeaconEvent(FrameEvent):
    """
    Parsed 802.11 Beacon frame.

    Beacons are broadcast by access points to advertise their presence.
    They carry the network name (SSID), supported rates, capabilities,
    and more.
    """
    ssid: str                               # May be empty string for hidden networks
    beacon_interval: Optional[int]          # Time units (TUs), 1 TU = 1024 µs
    capability_info: Optional[int]          # Raw capability flags word
    is_hidden: bool                         # True when SSID is empty or null-padded


@dataclass(frozen=True)
class ProbeRequestEvent(FrameEvent):
    """
    Parsed 802.11 Probe Request frame.

    Sent by stations scanning for networks.  An empty SSID means the
    station is doing a broadcast scan (looking for any AP).  A non-empty
    SSID means the station is looking for a specific network.
    """
    ssid: str                               # Empty string = wildcard / broadcast scan
    is_directed: bool                       # True when SSID is non-empty


@dataclass(frozen=True)
class ProbeResponseEvent(FrameEvent):
    """
    Parsed 802.11 Probe Response frame.

    Sent by an AP in reply to a directed Probe Request.  Contains the
    same network advertisement info as a Beacon.
    """
    ssid: str
    beacon_interval: Optional[int]
    capability_info: Optional[int]


@dataclass(frozen=True)
class DeauthEvent(FrameEvent):
    """
    Parsed 802.11 Deauthentication frame.

    Deauth frames terminate a station's authentication state.  They can
    be sent by an AP to kick a client, or by an attacker (deauth flood).
    The reason code indicates why the frame was sent.
    """
    reason_code: DeauthReasonCode
    reason_description: str                 # Human-readable reason code description


@dataclass(frozen=True)
class DisassocEvent(FrameEvent):
    """
    Parsed 802.11 Disassociation frame.

    Disassoc frames terminate an association (but not authentication).
    Similar to Deauth but leaves authentication state intact.
    """
    reason_code: DeauthReasonCode
    reason_description: str
