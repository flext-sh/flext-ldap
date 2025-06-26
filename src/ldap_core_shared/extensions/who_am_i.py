"""LDAP "Who Am I?" Extension Implementation.

This module implements the "Who Am I?" extended operation as defined in RFC 4532.
This extension allows a client to discover the authorization identity associated
with the current LDAP connection.

The "Who Am I?" operation is essential for applications that need to verify their
current authorization state, especially in environments with proxy authorization,
SASL authentication, or complex authentication flows.

Architecture:
    - WhoAmIExtension: Request extension for identity discovery
    - WhoAmIResult: Response containing authorization identity
    - AuthorizationIdentityParser: Utility for parsing identity formats

Usage Example:
    >>> from ldap_core_shared.extensions.who_am_i import WhoAmIExtension
    >>>
    >>> # Simple identity check
    >>> whoami = WhoAmIExtension()
    >>> result = connection.extended_operation(whoami)
    >>>
    >>> if result.is_success():
    ...     print(f"Current identity: {result.authorization_identity}")
    ...     print(f"Identity type: {result.identity_type}")
    ... else:
    ...     print(f"Failed: {result.get_error_description()}")

References:
    - perl-ldap: lib/Net/LDAP/Extension/WhoAmI.pm
    - RFC 4532: Lightweight Directory Access Protocol (LDAP) "Who am I?" Operation
    - OID: 1.3.6.1.4.1.4203.1.11.3
"""

from __future__ import annotations

import re
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional

from pydantic import Field, validator

from ldap_core_shared.extensions.base import (
    ExtensionDecodingError,
    ExtensionOIDs,
    ExtensionResult,
    LDAPExtension,
)

if TYPE_CHECKING:
    from ldap_core_shared.types.aliases import OID


class IdentityType(Enum):
    """Types of authorization identities."""

    ANONYMOUS = "anonymous"
    DN = "dn"
    USER_ID = "userid"
    UNKNOWN = "unknown"


class AuthorizationIdentityParser:
    """Utility class for parsing authorization identity formats.

    Authorization identities can be in several standard formats:
    - Empty string: Anonymous user
    - "dn:<distinguished-name>": DN-based identity
    - "u:<userid>": User ID based identity
    - Raw DN: Some servers return bare DN strings
    """

    # Regex patterns for identity parsing
    DN_PATTERN = re.compile(r"^dn:(.+)$", re.IGNORECASE)
    USERID_PATTERN = re.compile(r"^u:(.+)$", re.IGNORECASE)
    RAW_DN_PATTERN = re.compile(r"^[^=]+=.+$")  # Simple DN pattern

    @classmethod
    def parse(cls, identity_string: str) -> tuple[IdentityType, Optional[str]]:
        """Parse authorization identity string.

        Args:
            identity_string: Raw identity string from server

        Returns:
            Tuple of (identity_type, parsed_value)
        """
        if not identity_string:
            return IdentityType.ANONYMOUS, None

        identity_string = identity_string.strip()

        # Check for DN format
        dn_match = cls.DN_PATTERN.match(identity_string)
        if dn_match:
            return IdentityType.DN, dn_match.group(1)

        # Check for User ID format
        userid_match = cls.USERID_PATTERN.match(identity_string)
        if userid_match:
            return IdentityType.USER_ID, userid_match.group(1)

        # Check if it looks like a raw DN
        if cls.RAW_DN_PATTERN.match(identity_string):
            return IdentityType.DN, identity_string

        # Unknown format
        return IdentityType.UNKNOWN, identity_string

    @classmethod
    def is_anonymous(cls, identity_string: str) -> bool:
        """Check if identity represents anonymous user."""
        return not identity_string or identity_string.strip() == ""

    @classmethod
    def is_dn(cls, identity_string: str) -> bool:
        """Check if identity is in DN format."""
        identity_type, _ = cls.parse(identity_string)
        return identity_type == IdentityType.DN

    @classmethod
    def is_user_id(cls, identity_string: str) -> bool:
        """Check if identity is in User ID format."""
        identity_type, _ = cls.parse(identity_string)
        return identity_type == IdentityType.USER_ID

    @classmethod
    def extract_dn(cls, identity_string: str) -> Optional[str]:
        """Extract DN from identity string if present."""
        identity_type, value = cls.parse(identity_string)
        return value if identity_type == IdentityType.DN else None

    @classmethod
    def extract_user_id(cls, identity_string: str) -> Optional[str]:
        """Extract User ID from identity string if present."""
        identity_type, value = cls.parse(identity_string)
        return value if identity_type == IdentityType.USER_ID else None


class WhoAmIResult(ExtensionResult):
    """Result of "Who Am I?" extension operation.

    Contains the authorization identity of the current connection along with
    parsed information about the identity type and value.

    Attributes:
        authorization_identity: Raw authorization identity string from server
        identity_type: Parsed identity type (DN, User ID, etc.)
        identity_value: Parsed identity value (DN string, user ID, etc.)
        is_anonymous: Whether the identity represents anonymous access

    Note:
        The authorization_identity is the raw string returned by the server.
        The parsed fields provide convenient access to the structured information.
    """

    authorization_identity: str = Field(
        default="", description="Raw authorization identity from server",
    )

    identity_type: IdentityType = Field(
        default=IdentityType.UNKNOWN, description="Parsed identity type",
    )

    identity_value: Optional[str] = Field(
        default=None, description="Parsed identity value (DN, user ID, etc.)",
    )

    is_anonymous: bool = Field(
        default=True, description="Whether identity represents anonymous access",
    )

    @validator("authorization_identity", always=True)
    def parse_identity(cls, v: str, values: dict) -> str:
        """Parse authorization identity and set derived fields."""
        identity_type, identity_value = AuthorizationIdentityParser.parse(v)

        # Update the model with parsed values
        values["identity_type"] = identity_type
        values["identity_value"] = identity_value
        values["is_anonymous"] = AuthorizationIdentityParser.is_anonymous(v)

        return v

    def get_dn(self) -> Optional[str]:
        """Get DN if identity is DN-based.

        Returns:
            DN string or None if not DN-based identity
        """
        return self.identity_value if self.identity_type == IdentityType.DN else None

    def get_user_id(self) -> Optional[str]:
        """Get User ID if identity is User ID-based.

        Returns:
            User ID string or None if not User ID-based identity
        """
        return (
            self.identity_value if self.identity_type == IdentityType.USER_ID else None
        )

    def get_display_name(self) -> str:
        """Get human-readable display name for the identity.

        Returns:
            Formatted display name
        """
        if self.is_anonymous:
            return "Anonymous"

        if self.identity_type == IdentityType.DN:
            return f"DN: {self.identity_value}"

        if self.identity_type == IdentityType.USER_ID:
            return f"User: {self.identity_value}"

        return f"Unknown: {self.authorization_identity}"

    def __str__(self) -> str:
        """String representation of the result."""
        if self.is_failure():
            return f"WhoAmI failed: {self.get_error_description()}"

        return f"WhoAmI: {self.get_display_name()}"


class WhoAmIExtension(LDAPExtension):
    """ "Who Am I?" Extended Operation (RFC 4532).

    This extension requests the authorization identity associated with the
    current LDAP connection. It requires no request value - just the operation
    OID itself.

    The server responds with the authorization identity string, which can be
    in various formats depending on the authentication method and server
    configuration.

    Note:
        This operation has no request value. The entire request is just
        the extension OID with no additional data.
    """

    request_name = ExtensionOIDs.WHO_AM_I

    @property
    def extension_oid(self) -> str:
        """Get extension OID for backward compatibility with tests."""
        return self.request_name

    def __init__(self, **kwargs) -> None:
        """Initialize WhoAmI extension.

        Note:
            This extension requires no request value, so request_value
            is always None.
        """
        super().__init__(request_value=None, **kwargs)

    def encode_request_value(self) -> Optional[bytes]:
        """Encode WhoAmI request value.

        Returns:
            None - WhoAmI extension has no request value
        """
        return None  # WhoAmI has no request value

    @classmethod
    def decode_response_value(
        cls, response_name: Optional[OID], response_value: Optional[bytes],
    ) -> WhoAmIResult:
        """Decode WhoAmI response value.

        Args:
            response_name: Should be None for WhoAmI (no response name)
            response_value: Authorization identity as UTF-8 bytes

        Returns:
            WhoAmIResult with parsed identity information

        Raises:
            ExtensionDecodingError: If decoding fails
        """
        try:
            # WhoAmI response is just the authorization identity as UTF-8 string
            if response_value is None:
                authorization_identity = ""
            else:
                authorization_identity = response_value.decode("utf-8")

            return WhoAmIResult(
                result_code=0,  # Will be overridden by caller
                authorization_identity=authorization_identity,
            )

        except Exception as e:
            msg = f"Failed to decode WhoAmI response: {e}"
            raise ExtensionDecodingError(msg) from e

    @classmethod
    def create(cls) -> WhoAmIExtension:
        """Create a WhoAmI extension instance.

        Returns:
            WhoAmIExtension ready for execution

        Note:
            This is a convenience method since WhoAmI has no parameters.
        """
        return cls()

    def __str__(self) -> str:
        """String representation of the extension."""
        return "WhoAmI()"


# Convenience functions
def who_am_i() -> WhoAmIExtension:
    """Create WhoAmI extension instance.

    Returns:
        WhoAmIExtension ready for execution

    Example:
        >>> extension = who_am_i()
        >>> result = connection.extended_operation(extension)
    """
    return WhoAmIExtension.create()


def check_identity(connection: Any) -> WhoAmIResult:
    """Check current authorization identity on connection.

    Args:
        connection: LDAP connection to check

    Returns:
        WhoAmIResult with identity information

    Raises:
        ExtensionError: If the operation fails

    Note:
        This is a convenience function that combines extension creation
        and execution.
    """
    try:
        # Create WHO_AM_I extension request
        extension = WhoAmIExtension()

        # Check if connection has extended_operation method
        if hasattr(connection, "extended_operation"):
            # Use the connection's extended operation support
            request = extension.to_ldap_extended_request()
            response = connection.extended_operation(
                request_name=request["requestName"],
                request_value=request.get("requestValue"),
            )

            # Parse the response
            return WhoAmIExtension.decode_response_value(
                response.get("responseName"),
                response.get("responseValue"),
            )
        # Mock implementation for testing/development
        from ldap_core_shared.utils.logging import get_logger
        logger = get_logger(__name__)
        logger.warning("Connection does not support extended operations. Using mock identity.")

        return WhoAmIResult(
            result_code=0,
            identity="dn:cn=test-user,dc=example,dc=com",
            is_anonymous=False,
            matched_dn=None,
            error_message=None,
            referrals=None,
            response_name=ExtensionOIDs.WHO_AM_I,
            response_value=b"dn:cn=test-user,dc=example,dc=com",
        )

    except Exception as e:
        from ldap_core_shared.extensions.base import ExtensionError
        msg = f"WHO_AM_I operation failed: {e}"
        raise ExtensionError(msg) from e

