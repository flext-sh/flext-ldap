from __future__ import annotations

# Constants for magic values
SECONDS_PER_DAY = 86400

# BER/ASN.1 encoding constants
BER_SEQUENCE_TAG = 0x30
BER_INTEGER_TAG = 0x02
BER_ENUMERATED_TAG = 0x0A
BER_CONTEXT_TAG_0 = 0xA0
BER_CONTEXT_TAG_1 = 0x81
BER_CONTEXT_TAG_0_SIMPLE = 0x80

"""LDAP Password Policy Control Implementation.

This module implements the Password Policy control as defined in the IETF draft
"Password Policy for LDAP Directories". This control provides critical security
functionality for password management in LDAP directories.

The password policy control allows clients to receive information about password
policies and password state, enabling better user experience and security enforcement.

Architecture:
    - PasswordPolicyControl: Request control for password policy information
    - PasswordPolicyResponse: Response control with policy warnings and errors
    - PasswordPolicyError: Enumeration of password policy error codes
    - PasswordPolicyWarning: Warning types for password expiration

Usage Example:
    >>> from ldap_core_shared.controls.password_policy import PasswordPolicyControl
    >>>
    >>> # Request password policy information during bind
    >>> control = PasswordPolicyControl()
    >>> result = connection.bind(
    ...     dn="uid=user,ou=people,dc=example,dc=com",
    ...     password="secret",
    ...     controls=[control]
    ... )
    >>>
    >>> # Check for password policy response
    >>> policy_response = result.get_response_control(
    ...     PasswordPolicyControl.control_type
    ... )
    >>> if policy_response and policy_response.warning:
    ...     print(
    ...         f"Password expires in {policy_response.time_before_expiration} seconds"
    ...     )

References:
    - perl-ldap: lib/Net/LDAP/Control/PasswordPolicy.pm
    - IETF Draft: Password Policy for LDAP Directories
    - OID: 1.3.6.1.4.1.42.2.27.8.5.1 (Sun/Oracle)
"""

from enum import IntEnum
from typing import Any

from pydantic import Field, validator

from ldap_core_shared.controls.base import (
    ControlDecodingError,
    ControlEncodingError,
    ControlOIDs,
    LDAPControl,
)


class PasswordPolicyError(IntEnum):
    """Password Policy Error Codes.

    These error codes indicate specific password policy violations
    that prevent the operation from succeeding.
    """

    PASSWORD_EXPIRED = 0
    ACCOUNT_LOCKED = 1
    CHANGE_AFTER_RESET = 2
    PASSWORD_MOD_NOT_ALLOWED = 3
    MUST_SUPPLY_OLD_PASSWORD = 4
    INSUFFICIENT_PASSWORD_QUALITY = 5
    PASSWORD_TOO_SHORT = 6
    PASSWORD_TOO_YOUNG = 7
    PASSWORD_IN_HISTORY = 8


class PasswordPolicyWarning(IntEnum):
    """Password Policy Warning Types.

    These warnings indicate policy conditions that don't prevent
    the operation but require user attention.
    """

    TIME_BEFORE_EXPIRATION = 0
    GRACE_LOGINS_REMAINING = 1


class PasswordPolicyControl(LDAPControl):
    """Password Policy Control.

    This control can be sent with bind operations to request password policy
    information from the server. The server responds with password policy
    warnings, errors, and state information.

    The control itself has no value when sent by the client - it's just a
    request for policy information. The server responds with a control
    containing policy state and warnings.

    Attributes:
        warning_type: Type of warning (expiration or grace logins)
        warning_value: Warning-specific value (time or count)
        error: Password policy error code
        grace_logins_remaining: Number of grace logins left
        time_before_expiration: Seconds until password expires

    Note:
        Client requests typically send this control with no value.
        Server responses contain the policy information in the control value.

    """

    control_type = ControlOIDs.PASSWORD_POLICY

    # Response fields (populated by server)
    warning_type: PasswordPolicyWarning | None = Field(
        default=None,
        description="Type of password policy warning",
    )

    warning_value: int | None = Field(
        default=None,
        description="Warning-specific value (time in seconds or count)",
        ge=0,
    )

    error: PasswordPolicyError | None = Field(
        default=None,
        description="Password policy error code",
    )

    # Convenience properties for common warning types
    @property
    def grace_logins_remaining(self) -> int | None:
        """Number of grace logins remaining."""
        if (
            self.warning_type == PasswordPolicyWarning.GRACE_LOGINS_REMAINING
            and self.warning_value is not None
        ):
            return self.warning_value
        return None

    @property
    def time_before_expiration(self) -> int | None:
        """Seconds until password expires."""
        if (
            self.warning_type == PasswordPolicyWarning.TIME_BEFORE_EXPIRATION
            and self.warning_value is not None
        ):
            return self.warning_value
        return None

    @validator("warning_value")
    def validate_warning_value(
        self,
        v: int | None,
        values: dict[str, Any],
    ) -> int | None:
        """Validate warning value is consistent with warning type."""
        if v is not None and v < 0:
            msg = "Warning value must be non-negative"
            raise ValueError(msg)
        return v

    def encode_value(self) -> bytes | None:
        """Encode password policy control value.

        For client requests, this is typically None (no value).
        For server responses, this encodes the policy state as ASN.1.

        The ASN.1 structure is:
        PasswordPolicyResponseValue ::= SEQUENCE {
            warning [0] CHOICE {
                timeBeforeExpiration [0] INTEGER,
                graceLoginsRemaining [1] INTEGER } OPTIONAL,
            error   [1] ENUMERATED {
                passwordExpired             (0),
                accountLocked               (1),
                changeAfterReset            (2),
                passwordModNotAllowed       (3),
                mustSupplyOldPassword       (4),
                insufficientPasswordQuality (5),
                passwordTooShort            (6),
                passwordTooYoung            (7),
                passwordInHistory           (8) } OPTIONAL }

        Returns:
            ASN.1 encoded control value or None for client requests

        Raises:
            ControlEncodingError: If encoding fails

        """
        # Client requests typically have no value
        if self.warning_type is None and self.error is None:
            return None

        try:
            content = b""

            # Encode warning if present
            if self.warning_type is not None and self.warning_value is not None:
                warning_content = self._encode_integer(self.warning_value)

                # Tag based on warning type
                if self.warning_type == PasswordPolicyWarning.TIME_BEFORE_EXPIRATION:
                    warning_tagged = self._encode_context_tag(0, warning_content)
                else:  # GRACE_LOGINS_REMAINING
                    warning_tagged = self._encode_context_tag(1, warning_content)

                # Wrap in warning choice context tag [0]
                warning_choice = self._encode_context_tag(0, warning_tagged)
                content += warning_choice

            # Encode error if present
            if self.error is not None:
                error_content = self._encode_enumerated(self.error.value)
                error_tagged = self._encode_context_tag(1, error_content)
                content += error_tagged

            # Wrap in SEQUENCE
            return self._encode_sequence(content) if content else None

        except Exception as e:
            msg = f"Failed to encode password policy control: {e}"
            raise ControlEncodingError(msg) from e

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> PasswordPolicyControl:
        """Decode password policy control value.

        Args:
            control_value: ASN.1 encoded control value (None for client requests)

        Returns:
            PasswordPolicyControl instance

        Raises:
            ControlDecodingError: If decoding fails

        """
        # Client requests have no value
        if not control_value:
            return cls()

        try:
            # Decode SEQUENCE
            content = cls._decode_sequence(control_value)

            warning_type = None
            warning_value = None
            error = None

            pos = 0
            while pos < len(content):
                tag = content[pos]

                if tag == BER_CONTEXT_TAG_0:  # Context tag [0] - warning
                    warning_content, pos = cls._decode_context_tag(content, pos)

                    # Decode warning choice
                    warning_tag = warning_content[0]
                    if (
                        warning_tag == BER_CONTEXT_TAG_0_SIMPLE
                    ):  # Context tag [0] - timeBeforeExpiration
                        warning_type = PasswordPolicyWarning.TIME_BEFORE_EXPIRATION
                        warning_value = cls._decode_integer(warning_content[2:])[0]
                    elif (
                        warning_tag == BER_CONTEXT_TAG_1
                    ):  # Context tag [1] - graceLoginsRemaining
                        warning_type = PasswordPolicyWarning.GRACE_LOGINS_REMAINING
                        warning_value = cls._decode_integer(warning_content[2:])[0]

                elif tag == BER_CONTEXT_TAG_1:  # Context tag [1] - error
                    error_content, pos = cls._decode_context_tag(content, pos)
                    error_value = cls._decode_enumerated(error_content)
                    error = PasswordPolicyError(error_value)

                else:
                    pos += 1  # Skip unknown tags

            return cls(
                warning_type=warning_type,
                warning_value=warning_value,
                error=error,
            )

        except Exception as e:
            msg = f"Failed to decode password policy control: {e}"
            raise ControlDecodingError(msg) from e

    @classmethod
    def request(cls) -> PasswordPolicyControl:
        """Create a password policy request control.

        This is the typical control sent by clients to request
        password policy information from the server.

        Returns:
            Control for requesting password policy information

        """
        return cls()

    def has_warning(self) -> bool:
        """Check if the response contains a warning."""
        return self.warning_type is not None

    def has_error(self) -> bool:
        """Check if the response contains an error."""
        return self.error is not None

    def is_password_expired(self) -> bool:
        """Check if password is expired."""
        return self.error == PasswordPolicyError.PASSWORD_EXPIRED

    def is_account_locked(self) -> bool:
        """Check if account is locked."""
        return self.error == PasswordPolicyError.ACCOUNT_LOCKED

    def is_password_expiring_soon(
        self,
        threshold_seconds: int = 86400,
    ) -> bool:  # 24 hours
        """Check if password is expiring soon.

        Args:
            threshold_seconds: Consider "soon" if expiring within this time

        Returns:
            True if password expires within threshold

        """
        if self.time_before_expiration is not None:
            return self.time_before_expiration <= threshold_seconds
        return False

    def get_error_message(self) -> str | None:
        """Get human-readable error message.

        Returns:
            Error description or None if no error

        """
        if not self.error:
            return None

        error_messages = {
            PasswordPolicyError.PASSWORD_EXPIRED: "Password has expired",
            PasswordPolicyError.ACCOUNT_LOCKED: "Account is locked",
            PasswordPolicyError.CHANGE_AFTER_RESET: (
                "Must change password after reset"
            ),
            PasswordPolicyError.PASSWORD_MOD_NOT_ALLOWED: (
                "Password modification not allowed"
            ),
            PasswordPolicyError.MUST_SUPPLY_OLD_PASSWORD: "Must supply old password",
            PasswordPolicyError.INSUFFICIENT_PASSWORD_QUALITY: "Password quality insufficient",
            PasswordPolicyError.PASSWORD_TOO_SHORT: "Password is too short",
            PasswordPolicyError.PASSWORD_TOO_YOUNG: "Password is too young to change",
            PasswordPolicyError.PASSWORD_IN_HISTORY: "Password is in history",
        }

        return error_messages.get(self.error, f"Unknown error: {self.error}")

    def get_warning_message(self) -> str | None:
        """Get human-readable warning message.

        Returns:
            Warning description or None if no warning

        """
        if not self.has_warning():
            return None

        if self.warning_type == PasswordPolicyWarning.TIME_BEFORE_EXPIRATION:
            days = (self.warning_value or 0) // SECONDS_PER_DAY
            if days > 0:
                return f"Password expires in {days} day(s)"
            return f"Password expires in {self.warning_value} second(s)"

        if self.warning_type == PasswordPolicyWarning.GRACE_LOGINS_REMAINING:
            return f"{self.warning_value} grace login(s) remaining"

        return "Unknown warning"

    # Simple ASN.1 encoding helpers
    @staticmethod
    def _encode_integer(value: int) -> bytes:
        """Encode integer as BER INTEGER."""
        if value == 0:
            content = b"\x00"
        else:
            content = value.to_bytes((value.bit_length() + 7) // 8, "big")
            if content[0] & 0x80:
                content = b"\x00" + content

        length = len(content)
        return b"\x02" + length.to_bytes(1, "big") + content

    @staticmethod
    def _encode_enumerated(value: int) -> bytes:
        """Encode integer as BER ENUMERATED."""
        if value == 0:
            content = b"\x00"
        else:
            content = value.to_bytes((value.bit_length() + 7) // 8, "big")
            if content[0] & 0x80:
                content = b"\x00" + content

        length = len(content)
        return b"\x0a" + length.to_bytes(1, "big") + content

    @staticmethod
    def _encode_sequence(content: bytes) -> bytes:
        """Encode content as BER SEQUENCE."""
        length = len(content)
        return b"\x30" + length.to_bytes(1, "big") + content

    @staticmethod
    def _encode_context_tag(tag_num: int, content: bytes) -> bytes:
        """Encode content with context-specific tag."""
        tag = 0x80 | tag_num  # Context-specific, primitive
        length = len(content)
        return bytes([tag]) + length.to_bytes(1, "big") + content

    @classmethod
    def _decode_sequence(cls, data: bytes) -> bytes:
        """Decode BER SEQUENCE and return content."""
        if not data or data[0] != BER_SEQUENCE_TAG:
            msg = "Not a SEQUENCE"
            raise ValueError(msg)
        length = data[1]
        return data[2 : 2 + length]

    @classmethod
    def _decode_integer(cls, data: bytes) -> tuple[int, bytes]:
        """Decode BER INTEGER and return value and remaining data."""
        if not data or data[0] != BER_INTEGER_TAG:
            msg = "Not an INTEGER"
            raise ValueError(msg)
        length = data[1]
        content = data[2 : 2 + length]
        value = int.from_bytes(content, "big")
        return value, data[2 + length :]

    @classmethod
    def _decode_enumerated(cls, data: bytes) -> int:
        """Decode BER ENUMERATED and return value."""
        if not data or data[0] != BER_ENUMERATED_TAG:
            msg = "Not an ENUMERATED"
            raise ValueError(msg)
        length = data[1]
        content = data[2 : 2 + length]
        return int.from_bytes(content, "big")

    @classmethod
    def _decode_context_tag(cls, data: bytes, pos: int) -> tuple[bytes, int]:
        """Decode context-specific tag and return content and new position."""
        data[pos]
        length = data[pos + 1]
        content = data[pos + 2 : pos + 2 + length]
        return content, pos + 2 + length


# TODO: Integration points for implementation:
#
# 1. Authentication Integration:
#    - Integrate with ldap_core_shared.core.security for password validation
#    - Add password policy checks to bind operations
#    - Implement password expiration warnings in authentication flow
#
# 2. Connection Manager Integration:
#    - Modify bind methods to support password policy control
#    - Handle password policy responses automatically
#    - Provide callbacks for password expiration warnings
#
# 3. User Experience Enhancements:
#    - Add password policy status to user session information
#    - Implement proactive password change notifications
#    - Provide password strength validation based on policy
#
# 4. Monitoring and Logging:
#    - Log password policy violations for security monitoring
#    - Track password expiration events
#    - Generate reports on password policy compliance
#
# 5. Configuration:
#    - Allow configuration of password policy warning thresholds
#    - Support custom error message templates
#    - Enable/disable automatic password policy checking
#
# 6. Testing Requirements:
#    - Unit tests for all error and warning scenarios
#    - Integration tests with different LDAP servers
#    - Security tests for password policy enforcement
#    - Performance tests for high-volume authentication
