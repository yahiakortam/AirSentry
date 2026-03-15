"""Shared EventFeedWidget — batched, color-coded event log used by Monitor and Replay views."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QTimer
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import QTextEdit, QWidget

from airsentry.models.events import (
    BeaconEvent, DeauthEvent, DisassocEvent,
    FrameEvent, ProbeRequestEvent, ProbeResponseEvent,
)
from airsentry.ui.style import (
    COLOR_BEACON, COLOR_DEAUTH, COLOR_DISASSOC,
    COLOR_PROBE_Q, COLOR_PROBE_R, TEXT_DIM,
)
from airsentry.utils.time import format_timestamp


_FRAME_COLORS = {
    "BEACON":           COLOR_BEACON,
    "PROBE_REQUEST":    COLOR_PROBE_Q,
    "PROBE_RESPONSE":   COLOR_PROBE_R,
    "DEAUTHENTICATION": COLOR_DEAUTH,
    "DISASSOCIATION":   COLOR_DISASSOC,
}

_MAX_LINES = 600


def _event_to_html(event: FrameEvent) -> str:
    """Convert a FrameEvent to a one-line colored HTML string."""
    color = _FRAME_COLORS.get(event.frame_type.name, "#a0a0b0")
    ts = format_timestamp(event.timestamp)
    label = event.frame_type.name.replace("_", " ")[:12].ljust(12)

    if isinstance(event, BeaconEvent):
        ssid = event.ssid or "<i>(hidden)</i>"
        detail = (
            f'SSID&nbsp;<b style="color:#dde3f0">{ssid}</b>'
            f'&nbsp;&nbsp;BSSID&nbsp;<span style="color:#5a6a8a">{event.bssid}</span>'
        )
        if event.channel:
            detail += f'&nbsp;<span style="color:#454e6a">ch{event.channel}</span>'
    elif isinstance(event, ProbeRequestEvent):
        if event.is_directed:
            target = f'→&nbsp;<b style="color:{color}">&quot;{event.ssid}&quot;</b>'
        else:
            target = f'<span style="color:#454e6a">→ [broadcast scan]</span>'
        detail = f'SRC&nbsp;<span style="color:#5a6a8a">{event.src_mac}</span>&nbsp;&nbsp;{target}'
    elif isinstance(event, ProbeResponseEvent):
        detail = (
            f'SSID&nbsp;<b style="color:#dde3f0">{event.ssid}</b>'
            f'&nbsp;→&nbsp;<span style="color:#5a6a8a">{event.dst_mac}</span>'
        )
    elif isinstance(event, (DeauthEvent, DisassocEvent)):
        is_bcast = event.dst_mac in ("ff:ff:ff:ff:ff:ff",)
        dst_str = f'<b style="color:{color}">BROADCAST</b>' if is_bcast else f'<b style="color:{color}">{event.dst_mac}</b>'
        detail = (
            f'SRC&nbsp;<span style="color:#5a6a8a">{event.src_mac}</span>'
            f'&nbsp;→&nbsp;{dst_str}'
            f'&nbsp;&nbsp;<span style="color:#454e6a">reason&nbsp;{event.reason_code.value}</span>'
        )
    else:
        detail = f'<span style="color:#5a6a8a">{event.src_mac}</span> → {event.dst_mac}'

    signal = ""
    if event.signal_dbm is not None:
        sig_color = "#4dffb4" if event.signal_dbm >= -60 else "#ffd93d" if event.signal_dbm >= -75 else "#ff5f57"
        signal = f'&nbsp;<span style="color:{sig_color}">{event.signal_dbm}&nbsp;dBm</span>'

    return (
        f'<span style="color:{TEXT_DIM}">{ts}</span>'
        f'&nbsp;&nbsp;<b style="color:{color}">[{label}]</b>'
        f'&nbsp;&nbsp;{detail}{signal}'
    )


class EventFeedWidget(QTextEdit):
    """
    Scrollable, color-coded event feed backed by a 150 ms flush timer.

    Calling ``add_event(event)`` queues an event; the QTimer batch-inserts
    the accumulated HTML into the QTextEdit to keep the UI responsive even
    at several hundred packets per second.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.NoWrap)
        self.document().setMaximumBlockCount(_MAX_LINES)

        self._pending: list[str] = []
        self._line_count = 0

        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(150)
        self._flush_timer.timeout.connect(self._flush)
        self._flush_timer.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_event(self, event: FrameEvent) -> None:
        """Queue an event for the next flush cycle."""
        self._pending.append(_event_to_html(event))

    def clear_feed(self) -> None:
        """Clear all content and reset the line counter."""
        self.clear()
        self._pending.clear()
        self._line_count = 0

    # ------------------------------------------------------------------
    # Internal flush
    # ------------------------------------------------------------------

    def _flush(self) -> None:
        if not self._pending:
            return

        batch = self._pending[:]
        self._pending.clear()

        cursor = QTextCursor(self.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)

        for html in batch:
            cursor.insertHtml(html)
            cursor.insertBlock()
            self._line_count += 1

        # Auto-scroll to bottom
        sb = self.verticalScrollBar()
        sb.setValue(sb.maximum())
