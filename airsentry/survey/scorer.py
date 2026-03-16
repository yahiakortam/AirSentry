"""Wi-Fi environment risk scorer.

Computes a 0-100 risk score from a list of ``NetworkInfo`` results.
Higher score = more risky environment.

Scoring factors:
- Open (unencrypted) networks         — high weight
- WEP networks                        — high weight (broken encryption)
- Absence of WPA3                     — moderate weight
- Duplicate SSIDs (possible evil twin) — moderate weight
- Hidden networks                     — low weight
- High network density                — low weight
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Optional

from airsentry.survey.scanner import NetworkInfo, SecurityType


@dataclass(frozen=True)
class SurveyResult:
    """Scored analysis of a Wi-Fi environment scan."""

    total_networks: int
    open_count: int
    wep_count: int
    wpa_count: int
    wpa2_count: int
    wpa3_count: int
    hidden_count: int
    duplicate_ssid_count: int
    risk_score: int  # 0-100

    @property
    def risk_label(self) -> str:
        if self.risk_score <= 30:
            return "Low"
        elif self.risk_score <= 60:
            return "Medium"
        else:
            return "High"


def score_environment(networks: list[NetworkInfo]) -> SurveyResult:
    """
    Analyze a list of scanned networks and return a scored result.
    """
    if not networks:
        return SurveyResult(
            total_networks=0, open_count=0, wep_count=0, wpa_count=0,
            wpa2_count=0, wpa3_count=0, hidden_count=0,
            duplicate_ssid_count=0, risk_score=0,
        )

    total = len(networks)

    sec_counts: dict[SecurityType, int] = Counter(n.security for n in networks)
    open_count = sec_counts.get(SecurityType.OPEN, 0)
    wep_count  = sec_counts.get(SecurityType.WEP, 0)
    wpa_count  = sec_counts.get(SecurityType.WPA, 0)
    wpa2_count = sec_counts.get(SecurityType.WPA2, 0)
    wpa3_count = sec_counts.get(SecurityType.WPA3, 0)
    hidden     = sum(1 for n in networks if n.is_hidden)

    # Duplicate SSIDs (same name, different BSSID — possible evil twin)
    ssid_bssids: dict[str, set[str]] = {}
    for n in networks:
        if not n.is_hidden:
            ssid_bssids.setdefault(n.ssid, set()).add(n.bssid)
    dup_ssids = sum(1 for bssids in ssid_bssids.values() if len(bssids) > 1)

    # --- Risk calculation ---
    score = 0.0

    # Open networks: 15 points per open network (capped at 45)
    score += min(open_count * 15, 45)

    # WEP networks: 12 points per WEP network (capped at 24)
    score += min(wep_count * 12, 24)

    # No WPA3 at all: +10
    if wpa3_count == 0 and total > 0:
        score += 10

    # Duplicate SSIDs: 8 points per duplicate group (capped at 24)
    score += min(dup_ssids * 8, 24)

    # Hidden networks: 3 points each (capped at 9)
    score += min(hidden * 3, 9)

    # High density (>15 networks): slight bump
    if total > 15:
        score += min((total - 15) * 0.5, 5)

    # Old WPA (not WPA2/3): 5 points each (capped at 10)
    score += min(wpa_count * 5, 10)

    risk_score = max(0, min(100, int(score)))

    return SurveyResult(
        total_networks=total,
        open_count=open_count,
        wep_count=wep_count,
        wpa_count=wpa_count,
        wpa2_count=wpa2_count,
        wpa3_count=wpa3_count,
        hidden_count=hidden,
        duplicate_ssid_count=dup_ssids,
        risk_score=risk_score,
    )
