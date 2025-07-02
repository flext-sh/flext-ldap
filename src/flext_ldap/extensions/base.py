"""Base LDAP Extension Implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar

from flext_ldapants import PLACEHOLDER_OID
from pydantic import BaseModel, Field

from flext_ldap.exceptions.base import LDAPError

# Constants for magic values

if TYPE_CHECKING:
    from flext_ldapes import OID


class ExtensionError(LDAPError):
    """Base exception for LDAP extension related errors."""


class ExtensionEncodingError(ExtensionError):
    """Raised when extension request encoding fails."""


class ExtensionDecodingError(ExtensionError):
    """Raised when extension response decoding fails."""


class UnknownExtensionError(ExtensionError):
    """Raised when encountering an unknown extension type."""


class ExtensionNotSupportedError(ExtensionError):
    """Raised when server doesn't support the requested extension."""


class ExtensionResult(BaseModel):
    """Base class for LDAP extension results.

    This class provides the foundation for all extension response data.
    Each extension type should subclass this to provide specific result data.

    Attributes:
        result_code: LDAP result code from the operation
        matched_dn: Matched DN from server response
        error_message: Error message if operation failed
        referrals: List of referral URLs if applicable
        response_name: OID of the extension response
        response_value: Raw response value from server

    """

    result_code: int = Field(description="LDAP result code (0 = success)")

    matched_dn: str | None = Field(
        default=None,
        description="Matched DN from server response",
    )

    error_message: str | None = Field(
        default=None,
        description="Error message if operation failed",
    )

    referrals: list[str] | None = Field(
        default=None,
        description="List of referral URLs",
    )

    response_name: OID | None = Field(
        default=None,
        description="OID of the extension response",
    )

    response_value: bytes | None = Field(
        default=None,
        description="Raw response value from server",
    )

    class Config:
        """Pydantic configuration."""

        arbitrary_types_allowed = True
        validate_assignment = True
        extra = "forbid"

    def is_success(self) -> bool:
        """Check if the extension operation was successful."""
        return self.result_code == 0

    def is_failure(self) -> bool:
        """Check if the extension operation failed."""
        return self.result_code != 0

    def get_error_description(self) -> str | None:
        """Get human-readable error description."""
        if self.is_success():
            return None

        if self.error_message:
            return self.error_message

        # Common LDAP result codes
        error_codes = {
            1: "Operations Error",
            2: "Protocol Error",
            3: "Time Limit Exceeded",
            4: "Size Limit Exceeded",
            7: "Auth Method Not Supported",
            8: "Strong Auth Required",
            11: "Admin Limit Exceeded",
            12: "Unavailable Critical Extension",
            13: "Confidentiality Required",
            16: "No Such Attribute",
            17: "Undefined Attribute Type",
            18: "Inappropriate Matching",
            19: "Constraint Violation",
            20: "Attribute Or Value Exists",
            21: "Invalid Attribute Syntax",
            32: "No Such Object",
            34: "Invalid DN Syntax",
            48: "Inappropriate Authentication",
            49: "Invalid Credentials",
            50: "Insufficient Access Rights",
            51: "Busy",
            52: "Unavailable",
            53: "Unwilling To Perform",
            54: "Loop Detect",
            80: "Other",
        }

        return error_codes.get(
            self.result_code,
            f"Unknown error (code {self.result_code})",
        )


class LDAPExtension(BaseModel, ABC):
    """Abstract base class for all LDAP extensions.

    This class provides the foundation for implementing LDAP extensions according
    to RFC 4511. All extension implementations should inherit from this class.

    Attributes:
        request_name: The OID identifying the extension request type
        request_value: The extension-specific request value (ASN.1 encoded)

    Note:
        The request_value is typically ASN.1 encoded binary data, but some
        extensions may use simple string values or no value at all.

    """

    # Extension request OID - must be overridden in subclasses
    request_name: ClassVar[OID]

    # Extension properties
    request_value: bytes | None = Field(
        default=None,
        description="Extension-specific request value (ASN.1 encoded)",
    )

    class Config:
        """Pydantic configuration."""

        arbitrary_types_allowed = True
        validate_assignment = True
        extra = "forbid"

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Register extension types automatically."""
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "request_name") and cls.request_name:
            ExtensionRegistry.register(cls.request_name, cls)

    @abstractmethod
    def encode_request_value(self) -> bytes | None:
        """Encode the extension request value to ASN.1 bytes.

        Returns:
            ASN.1 encoded request value or None if no value

        Raises:
            ExtensionEncodingError: If encoding fails

        Note:
            This method must be implemented by all extension subclasses.
            The returned bytes should be valid ASN.1 encoding or None.

        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def decode_response_value(
        cls,
        response_name: OID | None,
        response_value: bytes | None,
    ) -> ExtensionResult:
        """Decode extension response value to create a result instance.

        Args:
            response_name: OID of the extension response
            response_value: ASN.1 encoded response value

        Returns:
            Extension result instance with decoded values

        Raises:
            ExtensionDecodingError: If decoding fails

        Note:
            This method must be implemented by all extension subclasses.
            It should handle None values gracefully for extensions without responses.

        """
        raise NotImplementedError

    def to_ldap_extended_request(self) -> dict[str, str | bytes]:
        """Convert to LDAP extended request dictionary format.

        Returns:
            Dictionary with requestName and optional requestValue

        Note:
            This format is used by underlying LDAP libraries for transmission.

        """
        result: dict[str, str | bytes] = {
            "requestName": self.request_name,
        }

        encoded_value = self.encode_request_value()
        if encoded_value is not None:
            result["requestValue"] = encoded_value

        return result

    @classmethod
    def from_ldap_extended_response(
        cls,
        response_dict: dict[str, Any],
    ) -> ExtensionResult:
        """Create extension result from LDAP extended response dictionary.

        Args:
            response_dict: Dictionary with response data from LDAP operation

        Returns:
            Extension result instance of appropriate type

        Raises:
            UnknownExtensionError: If extension type is not registered
            ExtensionDecodingError: If decoding fails

        """
        response_name = response_dict.get("responseName")
        response_value = response_dict.get("responseValue")

        # Find the appropriate extension class
        extension_class = None
        if response_name:
            extension_class = ExtensionRegistry.get(response_name)

        if not extension_class:
            # Use the calling class if no specific handler found
            extension_class = cls

        try:
            result = extension_class.decode_response_value(
                response_name,
                response_value,
            )

            # Set additional response metadata
            result.result_code = response_dict.get("resultCode", 0)
            result.matched_dn = response_dict.get("matchedDN")
            result.error_message = response_dict.get("errorMessage")
            result.referrals = response_dict.get("referrals")
            result.response_name = response_name
            result.response_value = response_value

            return result

        except Exception as e:
            msg = f"Failed to decode extension response: {e}"
            raise ExtensionDecodingError(msg) from e

    def __str__(self) -> str:
        """String representation of the extension."""
        return f"{self.__class__.__name__}(request={self.request_name})"

    def __repr__(self) -> str:
        """Detailed representation of the extension."""
        return (
            f"{self.__class__.__name__}("
            f"request_name='{self.request_name}', "
            f"has_value={self.request_value is not None})"
        )


class ExtensionRegistry:
    """Registry for LDAP extension types.

    This class maintains a mapping of extension OIDs to their implementation classes,
    enabling automatic extension instantiation from LDAP responses.
    """

    _registry: ClassVar[dict[OID, type[LDAPExtension]]] = {}

    @classmethod
    def register(cls, request_name: OID, extension_class: type[LDAPExtension]) -> None:
        """Register an extension implementation.

        Args:
            request_name: Extension request OID
            extension_class: Extension implementation class

        """
        cls._registry[request_name] = extension_class

    @classmethod
    def get(cls, request_name: OID) -> type[LDAPExtension] | None:
        """Get extension implementation by OID.

        Args:
            request_name: Extension request OID

        Returns:
            Extension class or None if not found

        """
        return cls._registry.get(request_name)

    @classmethod
    def list_registered(cls) -> dict[OID, type[LDAPExtension]]:
        """Get all registered extension types.

        Returns:
            Dictionary mapping OIDs to extension classes

        """
        return cls._registry.copy()

    @classmethod
    def is_registered(cls, request_name: OID) -> bool:
        """Check if an extension type is registered.

        Args:
            request_name: Extension request OID

        Returns:
            True if registered, False otherwise

        """
        return request_name in cls._registry


class GenericExtension(LDAPExtension):
    """Generic extension for unknown or custom extension types.

    This class provides a fallback implementation for extensions that don't have
    specific implementations. It preserves the request/response values as raw bytes.
    """

    # Override in instances
    request_name: ClassVar[OID] = PLACEHOLDER_OID  # Will be set dynamically

    def __init__(
        self,
        request_name: OID,
        request_value: bytes | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize generic extension with dynamic type."""
        super().__init__(request_value=request_value, **kwargs)
        # Set the request name dynamically
        object.__setattr__(self, "request_name", request_name)

    def encode_request_value(self) -> bytes | None:
        """Return the request value as-is."""
        return self.request_value

    @classmethod
    def decode_response_value(
        cls,
        response_name: OID | None,
        response_value: bytes | None,
    ) -> ExtensionResult:
        """Create generic result with raw values."""
        return ExtensionResult(
            result_code=0,  # Will be overridden
            response_name=response_name,
            response_value=response_value,
        )


# Standard extension OIDs (from IANA registry)
class ExtensionOIDs:
    """Standard LDAP extension OIDs."""

    # RFC 4532 - LDAP "Who am I?" Operation
    WHO_AM_I = "1.3.6.1.4.1.4203.1.11.3"

    # RFC 3062 - LDAP Password Modify Extended Operation
    MODIFY_PASSWORD = "1.3.6.1.4.1.4203.1.11.1"

    # RFC 4511 - Start TLS Operation
    START_TLS = "1.3.6.1.4.1.1466.20037"

    # RFC 3909 - LDAP Cancel Operation
    CANCEL = "1.3.6.1.1.8"

    # RFC 4525 - LDAP Refresh Operation
    REFRESH = "1.3.6.1.4.1.4203.1.11.2"

    # Microsoft Active Directory extensions
    FAST_BIND = "1.2.840.113556.1.4.1781"

    # Novell eDirectory extensions
    GET_EFFECTIVE_PRIVILEGES = "2.16.840.1.113719.1.27.DEFAULT_MAX_ITEMS.33"

    # OpenLDAP specific extensions
    MODIFY_PASSWD = "1.3.6.1.4.1.4203.1.11.1"


# TODO: Implement the following critical extensions:
# 1. WhoAmIExtension (CRITICAL - RFC 4532)
# 2. ModifyPasswordExtension (HIGH - RFC 3062)
# 3. StartTLSExtension (HIGH - RFC 4511)
# 4. CancelExtension (MEDIUM - RFC 3909)
# 5. RefreshExtension (LOW - RFC 4525)
# 6. FastBindExtension (LOW - Microsoft AD)
# 7. GetEffectivePrivilegesExtension (LOW - Novell eDirectory)
