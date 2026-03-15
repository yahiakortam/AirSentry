"""Parser for 802.11 Probe Response frames (subtype 5)."""

from __future__ import annotations

from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeResp
from scapy.packet import Packet

from airsentry.models.events import ProbeResponseEvent
from airsentry.models.frame_types import ManagementSubtype
from airsentry.utils.mac import normalize_mac
from airsentry.utils.time import from_epoch


def parse(packet: Packet) -> Optional[ProbeResponseEvent]:
    """
    Parse a Scapy packet containing a Dot11ProbeResp layer into a ProbeResponseEvent.

    Probe responses are sent by an AP in reply to a directed probe request.
    They carry the same network advertisement info as beacons.
    """
    if not (packet.haslayer(Dot11) and packet.haslayer(Dot11ProbeResp)):
        return None

    dot11 = packet.getlayer(Dot11)
    probe_resp = packet.getlayer(Dot11ProbeResp)

    ssid = _extract_ssid(packet) or ""
    signal_dbm = _extract_signal(packet)
    channel = _extract_channel(packet)

    cap_raw = getattr(probe_resp, "cap", None)
    cap_int: Optional[int] = int(cap_raw) if cap_raw is not None else None

    return ProbeResponseEvent(
        frame_type=ManagementSubtype.PROBE_RESPONSE,
        timestamp=from_epoch(float(packet.time)),
        src_mac=normalize_mac(dot11.addr2),
        dst_mac=normalize_mac(dot11.addr1),
        bssid=normalize_mac(dot11.addr3),
        channel=channel,
        signal_dbm=signal_dbm,
        ssid=ssid,
        beacon_interval=getattr(probe_resp, "beacon_interval", None),
        capability_info=cap_int,
    )


def _extract_ssid(packet: Packet) -> Optional[str]:
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 0:
            try:
                raw = bytes(elt.info)
                if not raw or all(b == 0 for b in raw):
                    return ""
                return raw.decode("utf-8", errors="replace")
            except Exception:
                return None
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return None


def _extract_signal(packet: Packet) -> Optional[int]:
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
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 3 and len(bytes(elt.info)) >= 1:
            return int(bytes(elt.info)[0])
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return None
