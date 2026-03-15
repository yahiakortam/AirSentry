"""Parser for 802.11 Disassociation frames (subtype 10)."""

from __future__ import annotations

from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Disas
from scapy.packet import Packet

from airsentry.models.events import DisassocEvent
from airsentry.models.frame_types import DeauthReasonCode, ManagementSubtype
from airsentry.utils.mac import normalize_mac
from airsentry.utils.time import from_epoch


def parse(packet: Packet) -> Optional[DisassocEvent]:
    """
    Parse a Scapy packet containing a Dot11Disas layer into a DisassocEvent.

    Disassociation terminates the association but preserves authentication
    state. Like deauth, flood events are a useful detection signal.
    """
    if not (packet.haslayer(Dot11) and packet.haslayer(Dot11Disas)):
        return None

    dot11 = packet.getlayer(Dot11)
    disas = packet.getlayer(Dot11Disas)

    raw_reason = getattr(disas, "reason", 1)
    reason = DeauthReasonCode.from_code(int(raw_reason))
    signal_dbm = _extract_signal(packet)

    return DisassocEvent(
        frame_type=ManagementSubtype.DISASSOCIATION,
        timestamp=from_epoch(float(packet.time)),
        src_mac=normalize_mac(dot11.addr2),
        dst_mac=normalize_mac(dot11.addr1),
        bssid=normalize_mac(dot11.addr3),
        channel=None,
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
