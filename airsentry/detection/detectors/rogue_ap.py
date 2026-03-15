"""Rogue access point / evil-twin detector.

Detects when multiple distinct BSSIDs advertise the same SSID — a common
indicator of an "evil twin" or rogue access point attack, where an attacker
impersonates a legitimate network to lure clients.

Algorithm
---------
The detector maintains a persistent ``ssid → set[bssid]`` mapping built from
Beacon and Probe Response frames.  When a *new* BSSID is observed advertising
an *already-seen* SSID, an alert is raised.

Confidence increases with the number of extra BSSIDs:
  - 2 BSSIDs → 0.33
  - 3 BSSIDs → 0.67
  - 4+ BSSIDs → 1.0

Limitations / intentional simplifications
------------------------------------------
- Hidden networks (empty SSID) are ignored — they cannot be matched anyway.
- This detector does not time-limit entries: BSSIDs are remembered across the
  entire session.  This is correct for the passive monitoring use-case because
  a rogue AP may appear at any point.
- It does not verify RF fingerprints, vendor OUIs, or channel differences:
  those refinements belong in a future phase.
"""

from __future__ import annotations

from datetime import datetime
from collections import defaultdict

from airsentry.detection.base import Detector
from airsentry.models.alerts import Alert, AlertType, Severity, make_alert
from airsentry.models.events import BeaconEvent, FrameEvent, ProbeResponseEvent


class RogueAPDetector(Detector):
    """
    Detects multiple BSSIDs advertising the same SSID within a session.
    """

    _NAME = "rogue_ap"

    def __init__(self) -> None:
        # ssid → set of BSSIDs seen for that SSID
        self._ssid_bssids: dict[str, set[str]] = defaultdict(set)
        # Track pairs already alerted to avoid repeated alerts for the same combination
        self._alerted_pairs: set[tuple[str, str]] = set()

    @property
    def name(self) -> str:
        return self._NAME

    def feed(self, event: FrameEvent, now: datetime) -> list[Alert]:
        if not isinstance(event, (BeaconEvent, ProbeResponseEvent)):
            return []

        ssid: str = event.ssid.strip()
        bssid: str = event.bssid

        # Skip hidden or empty SSIDs — not actionable
        if not ssid:
            return []

        known_bssids = self._ssid_bssids[ssid]

        if bssid in known_bssids:
            # Already seen this exact (ssid, bssid) pair — nothing to do
            return []

        # New BSSID for this SSID
        alerts: list[Alert] = []

        if known_bssids:
            # At least one other BSSID was already advertising this SSID.
            # Alert for each new collision, but only once per (ssid, new_bssid) pair.
            pair_key = (ssid, bssid)
            if pair_key not in self._alerted_pairs:
                self._alerted_pairs.add(pair_key)
                all_bssids = known_bssids | {bssid}
                alerts.append(self._build_alert(ssid, all_bssids, bssid, now))

        known_bssids.add(bssid)
        return alerts

    def reset(self) -> None:
        self._ssid_bssids.clear()
        self._alerted_pairs.clear()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_alert(
        self,
        ssid: str,
        all_bssids: set[str],
        new_bssid: str,
        now: datetime,
    ) -> Alert:
        extra = len(all_bssids) - 1  # BSSIDs beyond the first
        confidence = min(1.0, extra / 3.0)
        bssid_list = sorted(all_bssids)

        description = (
            f"SSID \"{ssid}\" advertised by {len(all_bssids)} BSSIDs "
            f"— possible evil-twin/rogue AP "
            f"(new: {new_bssid}, known: {', '.join(sorted(all_bssids - {new_bssid}))})"
        )
        return make_alert(
            alert_type=AlertType.ROGUE_AP,
            severity=Severity.MEDIUM,
            confidence=confidence,
            description=description,
            timestamp=now,
            detector_name=self._NAME,
            src_macs=bssid_list,
            ssids=[ssid],
            bssid=new_bssid,
        )
