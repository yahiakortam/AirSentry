"""PCAP file replay capture source."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Generator, Optional

from scapy.packet import Packet
from scapy.utils import rdpcap

from airsentry.capture.base import CaptureError, CaptureSource


class PcapCapture(CaptureSource):
    """
    Replays packets from a PCAP or PCAPng file.

    Optionally simulates real-time pacing by sleeping between packets
    to approximate the original inter-packet timing.
    """

    def __init__(
        self,
        file_path: Path | str,
        rate_limit_pps: Optional[int] = None,
    ) -> None:
        """
        Args:
            file_path:      Path to the PCAP / PCAPng file.
            rate_limit_pps: If set, limit replay to this many packets per second.
                            If 0 or None, replay as fast as possible.
        """
        self._file_path = Path(file_path)
        self._rate_limit_pps = rate_limit_pps

        self._validate_file()

    # ------------------------------------------------------------------
    # CaptureSource interface
    # ------------------------------------------------------------------

    @property
    def source_description(self) -> str:
        return f"file {self._file_path.name}"

    def packets(self) -> Generator[Packet, None, None]:
        """
        Yield packets from the PCAP file in order.

        If ``rate_limit_pps`` is set, an inter-packet sleep is applied to
        throttle replay speed.
        """
        try:
            pcap_packets = rdpcap(str(self._file_path))
        except FileNotFoundError as exc:
            raise CaptureError(f"PCAP file not found: {self._file_path}") from exc
        except Exception as exc:
            raise CaptureError(
                f"Failed to read PCAP file {self._file_path!r}: {exc}"
            ) from exc

        if not pcap_packets:
            return

        sleep_interval: Optional[float] = None
        if self._rate_limit_pps and self._rate_limit_pps > 0:
            sleep_interval = 1.0 / self._rate_limit_pps

        prev_time: Optional[float] = None

        for pkt in pcap_packets:
            if sleep_interval is not None:
                time.sleep(sleep_interval)
            elif prev_time is not None:
                # Simulate original inter-packet timing
                pkt_time = float(pkt.time)
                gap = pkt_time - prev_time
                if 0 < gap < 5.0:  # Cap sleep at 5s to stay sane
                    time.sleep(gap)

            prev_time = float(pkt.time)
            yield pkt

    # ------------------------------------------------------------------
    # Stats helper (for summary after replay)
    # ------------------------------------------------------------------

    def packet_count(self) -> int:
        """Return the total number of packets in the PCAP without iterating."""
        try:
            return len(rdpcap(str(self._file_path)))
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_file(self) -> None:
        """Raise CaptureError if the PCAP file does not exist or is not readable."""
        if not self._file_path.exists():
            raise CaptureError(
                f"PCAP file not found: {self._file_path}\n"
                "Check the path and ensure the file exists."
            )
        if not self._file_path.is_file():
            raise CaptureError(
                f"{self._file_path!r} is not a file."
            )
        if self._file_path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
            # Warn but don't block — Scapy can handle many formats
            pass
