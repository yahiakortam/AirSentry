"""Frame type enumerations for 802.11 management frames."""

from enum import IntEnum


class FrameType(IntEnum):
    """Top-level 802.11 frame type values (type field in the Frame Control word)."""
    MANAGEMENT = 0
    CONTROL = 1
    DATA = 2
    EXTENSION = 3


class ManagementSubtype(IntEnum):
    """
    802.11 management frame subtype values.
    Reference: IEEE 802.11-2020, Table 9-1.
    """
    ASSOCIATION_REQUEST = 0
    ASSOCIATION_RESPONSE = 1
    REASSOCIATION_REQUEST = 2
    REASSOCIATION_RESPONSE = 3
    PROBE_REQUEST = 4
    PROBE_RESPONSE = 5
    BEACON = 8
    DISASSOCIATION = 10
    AUTHENTICATION = 11
    DEAUTHENTICATION = 12
    ACTION = 13


class DeauthReasonCode(IntEnum):
    """
    IEEE 802.11-2020 deauthentication/disassociation reason codes.
    Only the most common codes are enumerated; unknown values fall back to UNSPECIFIED.
    Reference: IEEE 802.11-2020, Table 9-49.
    """
    UNSPECIFIED = 1
    PREV_AUTH_NOT_VALID = 2
    STA_LEAVING = 3
    DUE_TO_INACTIVITY = 4
    AP_UNABLE_TO_HANDLE = 5
    RECEIVED_WITH_CLASS2_FRAME = 6
    RECEIVED_WITH_CLASS3_FRAME = 7
    STA_LEFT_BSS = 8
    NOT_AUTHENTICATED = 9
    POWER_CAPABILITY_UNACCEPTABLE = 10
    SUPPORTED_CHANNEL_UNACCEPTABLE = 11
    INVALID_IE = 13
    MIC_FAILURE = 14
    FOUR_WAY_HANDSHAKE_TIMEOUT = 15
    GROUP_KEY_HANDSHAKE_TIMEOUT = 16
    IE_IN_4WAY_DIFFERS = 17
    GROUP_CIPHER_INVALID = 18
    PAIRWISE_CIPHER_INVALID = 19
    AKMP_INVALID = 20
    UNSUPPORTED_RSN_IE_VERSION = 21
    INVALID_RSN_IE_CAPABILITIES = 22
    IEEE_802_1X_AUTH_FAILED = 23
    CIPHER_SUITE_REJECTED = 24

    @classmethod
    def from_code(cls, code: int) -> "DeauthReasonCode":
        """Return the enum member for a given code, falling back to UNSPECIFIED."""
        try:
            return cls(code)
        except ValueError:
            return cls.UNSPECIFIED

    def description(self) -> str:
        """Return a human-readable description of this reason code."""
        _descriptions: dict[int, str] = {
            1: "Unspecified reason",
            2: "Previous authentication no longer valid",
            3: "Station is leaving (or has left) IBSS or ESS",
            4: "Disassociated due to inactivity",
            5: "Disassociated because AP is unable to handle all currently associated stations",
            6: "Class 2 frame received from non-authenticated station",
            7: "Class 3 frame received from non-associated station",
            8: "Station left BSS or reset",
            9: "Station requesting (re)association is not authenticated",
            15: "4-Way Handshake timeout",
            16: "Group Key Handshake timeout",
            23: "IEEE 802.1X authentication failed",
        }
        return _descriptions.get(self.value, self.name.replace("_", " ").title())
