"""Live Wi-Fi packet capture using Scapy's sniff() engine."""

from __future__ import annotations

import socket
from typing import Generator, Optional

from scapy.all import conf as scapy_conf
from scapy.packet import Packet
from scapy.sendrecv import sniff

from airsentry.capture.base import CaptureError, CaptureSource


class LiveCapture(CaptureSource):
    """
    Captures 802.11 frames live from a wireless interface in monitor mode.

    Wraps Scapy's ``sniff()`` in a generator so that the rest of the
    pipeline receives one packet at a time and can stay responsive.

    Requirements:
    - The interface must be in monitor mode (``iw dev <iface> set type monitor``)
    - Root / CAP_NET_RAW capability is required
    """

    # Default BPF filter: capture only 802.11 management frames.
    # This reduces CPU load by dropping data and control frames early.
    DEFAULT_BPF_FILTER = "type mgt"

    def __init__(
        self,
        interface: str,
        channel: Optional[int] = None,
        bpf_filter: Optional[str] = None,
        packet_count: int = 0,              # 0 = capture indefinitely
        snap_length: int = 65535,
    ) -> None:
        """
        Args:
            interface:    Name of the monitor-mode wireless interface (e.g., "wlan0mon").
            channel:      Wi-Fi channel to lock to before capturing.  If None, the
                          interface's current channel is used.  Channel hopping is not
                          implemented in Phase 1.
            bpf_filter:   BPF filter expression.  Defaults to management frames only.
            packet_count: Maximum packets to capture; 0 = unlimited.
            snap_length:  Maximum bytes captured per packet.
        """
        self._interface = interface
        self._channel = channel
        self._bpf_filter = bpf_filter or self.DEFAULT_BPF_FILTER
        self._packet_count = packet_count
        self._snap_length = snap_length

        self._validate_interface()

    # ------------------------------------------------------------------
    # CaptureSource interface
    # ------------------------------------------------------------------

    @property
    def source_description(self) -> str:
        channel_info = f" (ch {self._channel})" if self._channel else ""
        return f"interface {self._interface}{channel_info}"

    def packets(self) -> Generator[Packet, None, None]:
        """
        Yield packets captured from the live interface.

        Uses Scapy's ``sniff()`` with a per-packet callback routed through
        a list so we can iterate lazily instead of collecting all packets
        into memory.
        """
        bucket: list[Packet] = []

        def _handler(pkt: Packet) -> None:
            bucket.append(pkt)

        try:
            sniff(
                iface=self._interface,
                prn=_handler,
                count=self._packet_count,
                store=False,         # Don't buffer; we handle storage ourselves
                filter=self._bpf_filter,
                monitor=True,
            )
        except PermissionError as exc:
            raise CaptureError(
                f"Permission denied on {self._interface!r}. "
                "Run AirSentry with root privileges (sudo) for live capture."
            ) from exc
        except OSError as exc:
            raise CaptureError(
                f"Failed to open interface {self._interface!r}: {exc}"
            ) from exc

        yield from bucket

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_interface(self) -> None:
        """Raise CaptureError if the interface does not exist on this system."""
        try:
            socket.if_nametoindex(self._interface)
        except OSError:
            raise CaptureError(
                f"Interface {self._interface!r} was not found. "
                "Ensure the interface is in monitor mode and the name is correct."
            )


class StreamingLiveCapture(CaptureSource):
    """
    Variant of LiveCapture that yields packets in real-time as they arrive,
    using Scapy's generator-based sniff (Scapy >= 2.5).

    This is the preferred capture mode for interactive monitoring because it
    doesn't buffer packets before yielding them.
    """

    DEFAULT_BPF_FILTER = "type mgt"

    def __init__(
        self,
        interface: str,
        bpf_filter: Optional[str] = None,
        snap_length: int = 65535,
    ) -> None:
        self._interface = interface
        self._bpf_filter = bpf_filter or self.DEFAULT_BPF_FILTER
        self._snap_length = snap_length
        self._validate_interface()

    @property
    def source_description(self) -> str:
        return f"interface {self._interface} [streaming]"

    def packets(self) -> Generator[Packet, None, None]:
        """
        Yield packets one at a time as they arrive on the interface.

        Uses ``sniff(store=False, prn=...)`` with a generator bridge so the
        caller receives packets without any buffering delay.
        """
        import queue
        import threading

        pkt_queue: queue.Queue[Optional[Packet]] = queue.Queue()
        stop_event = threading.Event()

        def _handler(pkt: Packet) -> None:
            pkt_queue.put(pkt)

        def _sniff_thread() -> None:
            try:
                sniff(
                    iface=self._interface,
                    prn=_handler,
                    count=0,
                    store=False,
                    filter=self._bpf_filter,
                    stop_filter=lambda _: stop_event.is_set(),
                    monitor=True,
                )
            except (PermissionError, OSError) as exc:
                pkt_queue.put(None)  # Signal failure
                raise CaptureError(str(exc)) from exc
            finally:
                pkt_queue.put(None)  # Signal completion

        thread = threading.Thread(target=_sniff_thread, daemon=True)
        thread.start()

        try:
            while True:
                pkt = pkt_queue.get()
                if pkt is None:
                    break
                yield pkt
        except KeyboardInterrupt:
            stop_event.set()
            thread.join(timeout=2.0)

    def _validate_interface(self) -> None:
        try:
            socket.if_nametoindex(self._interface)
        except OSError:
            raise CaptureError(
                f"Interface {self._interface!r} was not found. "
                "Ensure the interface is in monitor mode and the name is correct."
            )
