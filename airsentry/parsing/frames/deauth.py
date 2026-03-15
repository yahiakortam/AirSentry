"""Parser for 802.11 Deauthentication frames (subtype 12)."""

from __future__ import annotations

from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Deauth
from scapy.packet import Packet

from airsentry.models.events import DeauthEvent
from airsentry.models.frame_types import DeauthReasonCode, ManagementSubtype
from airsentry.utils.mac import normalize_mac
from airsentry.utils.time import from_epoch


def parse(packet: Packet) -> Optional[DeauthEvent]:
    """
    Parse a Scapy packet containing a Dot11Deauth layer into a DeauthEvent.

    Deauthentication frames are significant because floods of these frames
    (especially with reason code 7 or broadcast destinations) are a classic
    deauth attack indicator — a key future detection target.
    """
    if not (packet.haslayer(Dot11) and packet.haslayer(Dot11Deauth)):
        return None

    dot11 = packet.getlayer(Dot11)
    deauth = packet.getlayer(Dot11Deauth)

    raw_reason = getattr(deauth, "reason", 1)
    reason = DeauthReasonCode.from_code(int(raw_reason))
    signal_dbm = _extract_signal(packet)

    return DeauthEvent(
        frame_type=ManagementSubtype.DEAUTHENTICATION,
        timestamp=from_epoch(float(packet.time)),
        src_mac=normalize_mac(dot11.addr2),
        dst_mac=normalize_mac(dot11.addr1),
        bssid=normalize_mac(dot11.addr3),
        channel=None,                       # Deauth frames don't include DS IE
        signal_dbm=signal_dbm,
        reason_code=reason,
        reason_description=reason.description(),
    )


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
