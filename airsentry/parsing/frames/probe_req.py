"""Parser for 802.11 Probe Request frames (subtype 4)."""

from __future__ import annotations

from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeReq
from scapy.packet import Packet

from airsentry.models.events import ProbeRequestEvent
from airsentry.models.frame_types import ManagementSubtype
from airsentry.utils.mac import normalize_mac
from airsentry.utils.time import from_epoch


def parse(packet: Packet) -> Optional[ProbeRequestEvent]:
    """
    Parse a Scapy packet containing a Dot11ProbeReq layer into a ProbeRequestEvent.

    An empty SSID indicates a broadcast (wildcard) scan — the station is
    looking for any available network.  A non-empty SSID means the station
    is looking for a specific network (directed probe).
    """
    if not (packet.haslayer(Dot11) and packet.haslayer(Dot11ProbeReq)):
        return None

    dot11 = packet.getlayer(Dot11)
    ssid = _extract_ssid(packet) or ""
    is_directed = len(ssid) > 0

    signal_dbm = _extract_signal(packet)

    return ProbeRequestEvent(
        frame_type=ManagementSubtype.PROBE_REQUEST,
        timestamp=from_epoch(float(packet.time)),
        src_mac=normalize_mac(dot11.addr2),
        dst_mac=normalize_mac(dot11.addr1),
        bssid=normalize_mac(dot11.addr3),
        channel=None,                       # Probe requests don't include DS IE
        signal_dbm=signal_dbm,
        ssid=ssid,
        is_directed=is_directed,
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
