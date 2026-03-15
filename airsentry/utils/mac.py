"""MAC address normalization and formatting utilities."""

from __future__ import annotations


def normalize_mac(raw: str | bytes | None) -> str:
    """
    Return a normalized, lowercase colon-delimited MAC address.

    Handles various input formats:
      - "AA:BB:CC:DD:EE:FF"  →  "aa:bb:cc:dd:ee:ff"
      - "aa-bb-cc-dd-ee-ff"  →  "aa:bb:cc:dd:ee:ff"
      - "aabbccddeeff"       →  "aa:bb:cc:dd:ee:ff"
      - bytes of length 6    →  "aa:bb:cc:dd:ee:ff"
      - None / empty         →  "00:00:00:00:00:00"
    """
    if not raw:
        return "00:00:00:00:00:00"

    if isinstance(raw, bytes):
        if len(raw) == 6:
            return ":".join(f"{b:02x}" for b in raw)
        return "00:00:00:00:00:00"

    cleaned = raw.strip().lower().replace("-", ":").replace(".", ":")

    # Remove all separators and re-format
    hex_only = cleaned.replace(":", "")
    if len(hex_only) != 12:
        return "00:00:00:00:00:00"

    try:
        int(hex_only, 16)
    except ValueError:
        return "00:00:00:00:00:00"

    return ":".join(hex_only[i:i+2] for i in range(0, 12, 2))


def is_broadcast(mac: str) -> bool:
    """Return True if the MAC address is the broadcast address (ff:ff:ff:ff:ff:ff)."""
    return mac == "ff:ff:ff:ff:ff:ff"


def is_multicast(mac: str) -> bool:
    """
    Return True if the MAC address is a multicast address.
    The least-significant bit of the first octet is 1 for multicast.
    """
    if len(mac) < 2:
        return False
    try:
        first_byte = int(mac[:2], 16)
        return bool(first_byte & 0x01)
    except ValueError:
        return False


def format_mac_short(mac: str) -> str:
    """
    Return the last three octets of a MAC address for compact display.
    Example: "aa:bb:cc:dd:ee:ff" → "dd:ee:ff"
    """
    parts = mac.split(":")
    if len(parts) == 6:
        return ":".join(parts[3:])
    return mac
