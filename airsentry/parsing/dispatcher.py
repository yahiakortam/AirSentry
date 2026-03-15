"""
Frame dispatcher — routes raw Scapy packets to the correct frame parser.

Design:
- Each registered parser is a module with a ``parse(packet) -> Optional[FrameEvent]``
  function.  Adding a new frame type is one line: register a new module.
- The dispatcher silently drops unknown or unsupported subtypes (returns None),
  so callers iterate and filter without try/except noise.
"""

from __future__ import annotations

from typing import Callable, Optional

from scapy.layers.dot11 import Dot11
from scapy.packet import Packet

from airsentry.models.events import FrameEvent
from airsentry.models.frame_types import ManagementSubtype
from airsentry.parsing.frames import beacon, deauth, disassoc, probe_req, probe_resp

# ---------------------------------------------------------------------------
# Parser registry
#
# Maps ManagementSubtype → parser function.
# Each parser function signature: (Packet) -> Optional[FrameEvent]
# ---------------------------------------------------------------------------

_PARSERS: dict[int, Callable[[Packet], Optional[FrameEvent]]] = {
    ManagementSubtype.BEACON: beacon.parse,
    ManagementSubtype.PROBE_REQUEST: probe_req.parse,
    ManagementSubtype.PROBE_RESPONSE: probe_resp.parse,
    ManagementSubtype.DEAUTHENTICATION: deauth.parse,
    ManagementSubtype.DISASSOCIATION: disassoc.parse,
}


class FrameDispatcher:
    """
    Routes raw Scapy packets to the appropriate frame parser.

    Usage::

        dispatcher = FrameDispatcher()
        for packet in capture_source.packets():
            event = dispatcher.dispatch(packet)
            if event is not None:
                handle(event)
    """

    def __init__(self) -> None:
        self._stats: dict[str, int] = {}

    def dispatch(self, packet: Packet) -> Optional[FrameEvent]:
        """
        Route a raw packet to the appropriate parser.

        Returns a parsed FrameEvent, or None if the frame type is unsupported
        or the packet is malformed.
        """
        if not packet.haslayer(Dot11):
            return None

        dot11 = packet.getlayer(Dot11)

        # 802.11 type field: 0 = management, 1 = control, 2 = data
        if dot11.type != 0:
            return None

        subtype: int = dot11.subtype
        parser = _PARSERS.get(subtype)
        if parser is None:
            return None

        try:
            event = parser(packet)
        except Exception:
            # Swallow parse errors on malformed frames — never crash the pipeline
            return None

        if event is not None:
            # Update per-type counters for stats reporting
            key = event.frame_type.name
            self._stats[key] = self._stats.get(key, 0) + 1

        return event

    @property
    def stats(self) -> dict[str, int]:
        """Return a copy of per-frame-type parse counts."""
        return dict(self._stats)

    def reset_stats(self) -> None:
        """Reset all parse counters to zero."""
        self._stats.clear()
