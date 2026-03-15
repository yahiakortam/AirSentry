"""Abstract base class for all AirSentry packet capture sources.

Adding a new capture source (e.g., remote socket, cloud buffer) requires only:
  1. Subclass CaptureSource
  2. Implement the packets() generator
  3. Register the source in the CLI command
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generator, Optional

# Scapy's Packet type (imported lazily in subclasses to avoid slow import at module load)
from scapy.packet import Packet


class CaptureSource(ABC):
    """
    Abstract base for packet capture sources.

    Subclasses yield raw Scapy ``Packet`` objects from their ``packets()``
    generator.  The rest of the pipeline (parsing, output) is agnostic to
    how packets are acquired.
    """

    @abstractmethod
    def packets(self) -> Generator[Packet, None, None]:
        """
        Yield raw packets one by one.

        Implementations should:
        - Yield ``scapy.packet.Packet`` objects
        - Raise ``CaptureError`` on unrecoverable failures
        - Handle their own cleanup in the generator's finally block
        """
        ...

    @property
    @abstractmethod
    def source_description(self) -> str:
        """A human-readable description of this capture source (e.g., interface name or file path)."""
        ...


class CaptureError(RuntimeError):
    """Raised when a capture source encounters an unrecoverable error."""
    pass
