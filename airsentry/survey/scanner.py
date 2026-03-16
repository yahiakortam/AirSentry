"""OS-level Wi-Fi network scanner — no monitor mode required.

Uses platform-native APIs to list visible Wi-Fi networks:
- macOS:  CoreWLAN framework (via pyobjc) → real SSIDs when Location Services
          is enabled; falls back to system_profiler otherwise.
- Linux:  nmcli -t -f SSID,BSSID,SIGNAL,CHAN,SECURITY dev wifi list

Returns a list of ``NetworkInfo`` dataclass instances.
"""

from __future__ import annotations

import platform
import plistlib
import re
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class SecurityType(Enum):
    OPEN = "Open"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    UNKNOWN = "Unknown"


@dataclass(frozen=True)
class NetworkInfo:
    ssid: str
    bssid: str
    signal_dbm: int
    channel: Optional[int]
    security: SecurityType

    @property
    def is_open(self) -> bool:
        return self.security == SecurityType.OPEN

    @property
    def is_hidden(self) -> bool:
        return self.ssid == "" or self.ssid == "(hidden)"


# Set to True after a scan if SSIDs were available (Location Services granted)
ssids_available: bool = False


def scan_networks() -> list[NetworkInfo]:
    """
    Scan visible Wi-Fi networks using OS-native tools.

    Raises ``RuntimeError`` if the scan command fails.
    """
    system = platform.system()
    if system == "Darwin":
        return _scan_macos()
    elif system == "Linux":
        return _scan_linux()
    else:
        raise RuntimeError(f"Wi-Fi scanning is not supported on {system}.")


# ---------------------------------------------------------------------------
# macOS — CoreWLAN (preferred) with system_profiler fallback
# ---------------------------------------------------------------------------

# CWSecurityType enum values → SecurityType mapping
_CW_SECURITY_MAP: dict[int, SecurityType] = {
    0: SecurityType.OPEN,        # kCWSecurityNone
    1: SecurityType.WEP,         # kCWSecurityWEP
    2: SecurityType.WPA,         # kCWSecurityWPAPersonal
    3: SecurityType.WPA,         # kCWSecurityWPAEnterprise
    4: SecurityType.WPA2,        # kCWSecurityWPA2Personal
    5: SecurityType.WPA2,        # kCWSecurityWPA2Enterprise
    6: SecurityType.WPA2,        # kCWSecurityWPA/WPA2 Personal (transition)
    7: SecurityType.WPA2,        # kCWSecurityWPA/WPA2 Enterprise (transition)
    # WPA3 values (128+)
    128: SecurityType.WPA2,      # Often reported for WPA2 on newer macOS
}


def _scan_macos() -> list[NetworkInfo]:
    global ssids_available

    # Try CoreWLAN first (gives real SSIDs if Location Services is granted)
    try:
        networks = _scan_corewlan()
        if networks:
            has_real = any(not n.is_hidden for n in networks)
            ssids_available = has_real
            return networks
    except Exception:
        pass

    # Fallback to system_profiler
    ssids_available = False
    return _scan_system_profiler()


def _scan_corewlan() -> list[NetworkInfo]:
    import CoreWLAN

    client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
    iface = client.interface()
    if iface is None:
        raise RuntimeError("No Wi-Fi interface found.")

    networks_set, err = iface.scanForNetworksWithName_error_(None, None)
    if err:
        raise RuntimeError(str(err))

    networks: list[NetworkInfo] = []
    for n in networks_set:
        ssid = n.ssid() or "(hidden)"
        bssid = (n.bssid() or "").lower()
        rssi = n.rssiValue()
        ch_obj = n.wlanChannel()
        channel = ch_obj.channelNumber() if ch_obj else None
        sec_val = n.securityType()
        security = _CW_SECURITY_MAP.get(sec_val, SecurityType.WPA2)

        networks.append(NetworkInfo(
            ssid=ssid,
            bssid=bssid,
            signal_dbm=rssi,
            channel=channel,
            security=security,
        ))

    return sorted(networks, key=lambda n: n.signal_dbm, reverse=True)


# ---------------------------------------------------------------------------
# macOS fallback — system_profiler
# ---------------------------------------------------------------------------

def _scan_system_profiler() -> list[NetworkInfo]:
    try:
        result = subprocess.run(
            ["system_profiler", "SPAirPortDataType", "-xml"],
            capture_output=True, timeout=20,
        )
    except FileNotFoundError:
        raise RuntimeError("system_profiler not found.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Wi-Fi scan timed out.")

    if result.returncode != 0:
        raise RuntimeError(f"system_profiler failed (exit {result.returncode}).")

    try:
        plist = plistlib.loads(result.stdout)
    except Exception:
        raise RuntimeError("Failed to parse system_profiler output.")

    return _parse_system_profiler(plist)


def _parse_system_profiler(plist: list) -> list[NetworkInfo]:
    networks: list[NetworkInfo] = []

    for top_item in plist:
        for item in top_item.get("_items", []):
            for iface in item.get("spairport_airport_interfaces", []):
                current = iface.get("spairport_current_network_information", {})
                if current:
                    net = _parse_profiler_network(current)
                    if net:
                        networks.append(net)

                others = iface.get("spairport_airport_other_local_wireless_networks", [])
                for entry in others:
                    net = _parse_profiler_network(entry)
                    if net:
                        networks.append(net)

    return networks


def _parse_profiler_network(entry: dict) -> Optional[NetworkInfo]:
    ssid = entry.get("_name", "").strip()
    if not ssid:
        ssid = "(hidden)"

    channel_str = entry.get("spairport_network_channel", "")
    channel: Optional[int] = None
    if channel_str:
        m = re.match(r"(\d+)", channel_str)
        if m:
            channel = int(m.group(1))

    sec_raw = entry.get("spairport_security_mode", "")
    security = _classify_profiler_security(sec_raw)

    signal = -70
    sig_str = entry.get("spairport_signal_noise", "")
    if sig_str:
        m = re.match(r"(-?\d+)\s*dBm", sig_str)
        if m:
            signal = int(m.group(1))

    return NetworkInfo(
        ssid=ssid,
        bssid="",
        signal_dbm=signal,
        channel=channel,
        security=security,
    )


def _classify_profiler_security(raw: str) -> SecurityType:
    lower = raw.lower()
    if "none" in lower or "open" in lower or not raw:
        return SecurityType.OPEN
    if "wpa3" in lower:
        return SecurityType.WPA3
    if "wpa2" in lower:
        return SecurityType.WPA2
    if "wpa" in lower:
        return SecurityType.WPA
    if "wep" in lower:
        return SecurityType.WEP
    return SecurityType.UNKNOWN


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

def _scan_linux() -> list[NetworkInfo]:
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "nmcli not found. Install NetworkManager for Wi-Fi scanning."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Wi-Fi scan timed out.")

    if result.returncode != 0:
        raise RuntimeError(f"nmcli scan failed: {result.stderr.strip()}")

    return _parse_nmcli_output(result.stdout)


def _parse_nmcli_output(output: str) -> list[NetworkInfo]:
    networks: list[NetworkInfo] = []
    for line in output.strip().splitlines():
        parts = line.split(":")
        if len(parts) < 5:
            continue

        ssid = parts[0].strip() or "(hidden)"
        bssid = parts[1].strip().lower().replace("\\:", ":")
        try:
            # nmcli reports signal as 0-100 percentage; convert to approximate dBm
            signal_pct = int(parts[2].strip())
            signal = int(-100 + signal_pct * 0.6)
        except ValueError:
            signal = -100
        try:
            channel = int(parts[3].strip())
        except ValueError:
            channel = None

        security_str = ":".join(parts[4:]).strip()
        security = _classify_security(security_str)

        networks.append(NetworkInfo(
            ssid=ssid,
            bssid=bssid,
            signal_dbm=signal,
            channel=channel,
            security=security,
        ))

    return networks


# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------

def _classify_security(raw: str) -> SecurityType:
    upper = raw.upper()
    if not raw or raw == "--" or "NONE" in upper:
        return SecurityType.OPEN
    if "WPA3" in upper or "SAE" in upper:
        return SecurityType.WPA3
    if "WPA2" in upper or "RSN" in upper:
        return SecurityType.WPA2
    if "WPA" in upper:
        return SecurityType.WPA
    if "WEP" in upper:
        return SecurityType.WEP
    return SecurityType.UNKNOWN
