"""MAC address anonymization for AirSentry research datasets.

When exporting wireless data for research, raw MAC addresses must not be
stored because they are personally identifiable information (PII) that could
be used to track individuals over time.

Anonymization strategy
----------------------
Each MAC address is hashed with SHA-256.  The hash is seeded with a
per-session random salt so that MAC addresses from different collection
sessions cannot be linked, even if the same device was present in both.

The output format is ``anon:<first12hexchars>`` — 12 hex characters (6 bytes)
which is enough to distinguish devices within a session while being
irreversible without the session salt.

Usage
-----
::

    anonymizer = MACAnonymizer()
    anon = anonymizer.anonymize("aa:bb:cc:dd:ee:ff")
    # → "anon:3f7a2c1b9e04"

    # Or use the convenience function with a fixed global salt (testing only)
    anon = anonymize_mac("aa:bb:cc:dd:ee:ff")
"""

from __future__ import annotations

import hashlib
import os


class MACAnonymizer:
    """
    Session-scoped MAC address anonymizer.

    Each instance generates a unique random salt at construction time, so
    anonymized MACs from this session cannot be linked to those from other
    sessions.

    Parameters
    ----------
    salt:
        Optional fixed salt bytes (for reproducible tests).  If None, a
        random 32-byte salt is generated.
    """

    def __init__(self, salt: bytes | None = None) -> None:
        self._salt: bytes = salt if salt is not None else os.urandom(32)

    def anonymize(self, mac: str) -> str:
        """
        Return a privacy-safe identifier for *mac*.

        Parameters
        ----------
        mac:
            Normalized MAC address string (e.g. ``"aa:bb:cc:dd:ee:ff"``).

        Returns
        -------
        str
            ``"anon:<12 hex chars>"``, deterministic within this session.
        """
        normalized = mac.strip().lower()
        h = hashlib.sha256(self._salt + normalized.encode()).hexdigest()
        return f"anon:{h[:12]}"

    def anonymize_or_keep(self, mac: str) -> str:
        """
        Anonymize a real MAC address, but pass through already-anonymized values.

        Useful when processing events that may contain broadcast addresses or
        values already tagged as ``anon:``.
        """
        if mac.startswith("anon:") or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return mac
        return self.anonymize(mac)


# ---------------------------------------------------------------------------
# Module-level convenience (uses a random salt; non-reproducible)
# ---------------------------------------------------------------------------

_default_anonymizer: MACAnonymizer | None = None


def anonymize_mac(mac: str) -> str:
    """
    Anonymize a MAC address using a module-level session anonymizer.

    The salt is generated once per Python process.  Suitable for quick
    use in scripts; prefer ``MACAnonymizer`` for production code where you
    need to control the salt lifetime.
    """
    global _default_anonymizer
    if _default_anonymizer is None:
        _default_anonymizer = MACAnonymizer()
    return _default_anonymizer.anonymize(mac)
