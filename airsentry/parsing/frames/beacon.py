"""Parser for 802.11 Beacon frames (subtype 8)."""

from __future__ import annotations

from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from scapy.packet import Packet

from airsentry.models.events import BeaconEvent
from airsentry.models.frame_types import ManagementSubtype
from airsentry.utils.mac import normalize_mac
from airsentry.utils.time import from_epoch


def parse(packet: Packet) -> Optional[BeaconEvent]:
    """
    Parse a Scapy packet containing a Dot11Beacon layer into a BeaconEvent.

    Returns None if the packet is missing required layers or is malformed.
    """
    if not (packet.haslayer(Dot11) and packet.haslayer(Dot11Beacon)):
        return None

    dot11 = packet.getlayer(Dot11)
    beacon = packet.getlayer(Dot11Beacon)

    ssid = _extract_ssid(packet)
    is_hidden = ssid == "" or ssid is None
    if ssid is None:
        ssid = ""

    signal_dbm = _extract_signal(packet)
    channel = _extract_channel(packet)

    cap_raw = getattr(beacon, "cap", None)
    cap_int: Optional[int] = int(cap_raw) if cap_raw is not None else None

    return BeaconEvent(
        frame_type=ManagementSubtype.BEACON,
        timestamp=from_epoch(float(packet.time)),
        src_mac=normalize_mac(dot11.addr2),
        dst_mac=normalize_mac(dot11.addr1),
        bssid=normalize_mac(dot11.addr3),
        channel=channel,
        signal_dbm=signal_dbm,
        ssid=ssid,
        beacon_interval=getattr(beacon, "beacon_interval", None),
        capability_info=cap_int,
        is_hidden=bool(is_hidden),
    )


def _extract_ssid(packet: Packet) -> Optional[str]:
    """Walk the information element chain and return the SSID string, or None."""
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 0:  # SSID element ID
            try:
                raw = bytes(elt.info)
                # A hidden SSID is either empty or all null bytes
                if not raw or all(b == 0 for b in raw):
                    return ""
                return raw.decode("utf-8", errors="replace")
            except Exception:
                return None
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return None


def _extract_signal(packet: Packet) -> Optional[int]:
    """Extract signal strength in dBm from RadioTap header, if present."""
    try:
        from scapy.layers.dot11 import RadioTap
        if packet.haslayer(RadioTap):
            rt = packet.getlayer(RadioTap)
            if hasattr(rt, "dBm_AntSignal"):
                return int(rt.dBm_AntSignal)
    except Exception:
        pass
    return None


def _extract_channel(packet: Packet) -> Optional[int]:
    """Extract channel number from the DS Parameter Set IE (ID 3), if present."""
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 3 and len(bytes(elt.info)) >= 1:  # DS Parameter Set
            return int(bytes(elt.info)[0])
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return None
