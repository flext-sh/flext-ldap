"""Base LDAP Control Implementation.

This module provides the foundation for all LDAP control implementations,
following the perl-ldap Net::LDAP::Control architecture with enterprise-grade
Python enhancements.

Controls are used to extend LDAP operations with additional functionality
such as paging, sorting, authorization, and security features.

Architecture:
    - LDAPControl: Abstract base class for all controls
    - ControlRegistry: Manages control type registration
    - ControlDecoder: Handles ASN.1 control decoding
    - ControlEncoder: Handles ASN.1 control encoding

References:
    - perl-ldap: lib/Net/LDAP/Control.pm
    - RFC 4511: Section 4.1.11 - Controls

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    try:
        import ldap3
    except ImportError:
        ldap3 = None  # type: ignore[assignment]

from ldap_core_shared.exceptions.base import LDAPError
from ldap_core_shared.utils.constants import PLACEHOLDER_OID

if TYPE_CHECKING:
    from ldap_core_shared.types.aliases import OID


class ControlError(LDAPError):
    """Base exception for LDAP control related errors."""


class ControlEncodingError(ControlError):
    """Raised when control encoding fails."""


class ControlDecodingError(ControlError):
    """Raised when control decoding fails."""


class UnknownControlError(ControlError):
    """Raised when encountering an unknown control type."""


class LDAPControl(BaseModel, ABC):
    """Abstract base class for all LDAP controls.

    This class provides the foundation for implementing LDAP controls according
    to RFC 4511. All control implementations should inherit from this class.

    Attributes:
        control_type: The OID identifying the control type
        criticality: Whether the control is critical (server must understand it)
        control_value: The control-specific value (ASN.1 encoded)

    Note:
        The control_value is typically ASN.1 encoded binary data, but some
        controls may use simple string or integer values.

    """

    # Control type OID - must be overridden in subclasses
    control_type: ClassVar[OID]

    # Control properties
    criticality: bool = Field(
        default=False,
        description="Whether this control is critical to the operation",
    )
    control_value: bytes | None = Field(
        default=None,
        description="Control-specific value (ASN.1 encoded)",
    )

    class Config:
        """Pydantic configuration."""

        arbitrary_types_allowed = True
        validate_assignment = True
        extra = "forbid"

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Register control types automatically."""
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "control_type") and cls.control_type:
            ControlRegistry.register(cls.control_type, cls)

    @abstractmethod
    def encode_value(self) -> bytes | None:
        """Encode the control value to ASN.1 bytes.

        Returns:
            ASN.1 encoded control value or None if no value

        Raises:
            ControlEncodingError: If encoding fails

        Note:
            This method must be implemented by all control subclasses.
            The returned bytes should be valid ASN.1 encoding.

        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def decode_value(cls, control_value: bytes | None) -> LDAPControl:
        """Decode ASN.1 bytes to create a control instance.

        Args:
            control_value: ASN.1 encoded control value

        Returns:
            Control instance with decoded values

        Raises:
            ControlDecodingError: If decoding fails

        Note:
            This method must be implemented by all control subclasses.
            It should handle None values gracefully for controls without values.

        """
        raise NotImplementedError

    def to_ldap_control(self) -> dict[str, Any]:
        """Convert to LDAP control dictionary format.

        Returns:
            Dictionary with controlType, criticality, and controlValue

        Note:
            This format is used by underlying LDAP libraries for transmission.

        """
        result = {
            "controlType": self.control_type,
            "criticality": self.criticality,
        }

        encoded_value = self.encode_value()
        if encoded_value is not None:
            result["controlValue"] = encoded_value

        return result

    def to_ldap3_control(self) -> Any:
        """Convert to ldap3 Control object format.

        Returns:
            ldap3 Control object compatible format

        Note:
            This method provides compatibility with ldap3 library control format.
            Returns the same dictionary as to_ldap_control for ldap3 compatibility.

        """
        try:
            import ldap3

            # Create ldap3.Control object if available
            encoded_value = self.encode_value()
            return ldap3.Control(  # type: ignore[attr-defined]
                oid=self.control_type,
                critical=self.criticality,
                value=encoded_value,
            )
        except ImportError:
            # Fallback to dictionary format if ldap3 not available
            return self.to_ldap_control()

    @classmethod
    def from_ldap_control(cls, control_dict: dict[str, Any]) -> LDAPControl:
        """Create control instance from LDAP control dictionary.

        Args:
            control_dict: Dictionary with controlType, criticality, controlValue

        Returns:
            Control instance of appropriate type

        Raises:
            UnknownControlError: If control type is not registered
            ControlDecodingError: If decoding fails

        """
        control_type = control_dict.get("controlType")
        if not control_type:
            msg = "Missing controlType in control dictionary"
            raise ControlDecodingError(msg)

        control_class = ControlRegistry.get(control_type)
        if not control_class:
            msg = f"Unknown control type: {control_type}"
            raise UnknownControlError(msg)

        control_value = control_dict.get("controlValue")
        instance = control_class.decode_value(control_value)
        instance.criticality = control_dict.get("criticality", False)

        return instance

    def __str__(self) -> str:
        """String representation of the control."""
        return f"{self.__class__.__name__}(type={self.control_type}, critical={self.criticality})"

    def __repr__(self) -> str:
        """Detailed representation of the control."""
        return (
            f"{self.__class__.__name__}("
            f"control_type='{self.control_type}', "
            f"criticality={self.criticality}, "
            f"has_value={self.control_value is not None})"
        )


class ControlRegistry:
    """Registry for LDAP control types.

    This class maintains a mapping of control OIDs to their implementation classes,
    enabling automatic control instantiation from LDAP responses.
    """

    _registry: ClassVar[dict[OID, type[LDAPControl]]] = {}

    @classmethod
    def register(cls, control_type: OID, control_class: type[LDAPControl]) -> None:
        """Register a control implementation.

        Args:
            control_type: Control OID
            control_class: Control implementation class

        """
        cls._registry[control_type] = control_class

    @classmethod
    def get(cls, control_type: OID) -> type[LDAPControl] | None:
        """Get control implementation by OID.

        Args:
            control_type: Control OID

        Returns:
            Control class or None if not found

        """
        return cls._registry.get(control_type)

    @classmethod
    def list_registered(cls) -> dict[OID, type[LDAPControl]]:
        """Get all registered control types.

        Returns:
            Dictionary mapping OIDs to control classes

        """
        return cls._registry.copy()

    @classmethod
    def is_registered(cls, control_type: OID) -> bool:
        """Check if a control type is registered.

        Args:
            control_type: Control OID

        Returns:
            True if registered, False otherwise

        """
        return control_type in cls._registry


class GenericControl(LDAPControl):
    """Generic control for unknown or custom control types.

    This class provides a fallback implementation for controls that don't have
    specific implementations. It preserves the control value as raw bytes.
    """

    # Dynamic control type handled in __init__

    def __init__(
        self,
        control_type: OID,
        control_value: bytes | None = None,
        criticality: bool = False,
        **kwargs: Any,
    ) -> None:
        """Initialize generic control with dynamic type."""
        super().__init__(criticality=criticality, control_value=control_value, **kwargs)
        # Set the control type dynamically
        object.__setattr__(self, "control_type", control_type)

    def encode_value(self) -> bytes | None:
        """Return the control value as-is."""
        return self.control_value

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> LDAPControl:
        """Create generic control with raw value."""
        return cls(
            control_type=PLACEHOLDER_OID,  # Will be overridden
            control_value=control_value,
        )


# Standard control type OIDs (from IANA registry)
class ControlOIDs:
    """Standard LDAP control OIDs."""

    # RFC 2696 - Simple Paged Results Manipulation
    PAGED_RESULTS = "1.2.840.113556.1.4.319"

    # RFC 2891 - Server Side Sorting of Search Results
    SERVER_SIDE_SORT = "1.2.840.113556.1.4.473"
    SERVER_SIDE_SORT_RESPONSE = "1.2.840.113556.1.4.474"

    # RFC 4370 - Proxied Authorization Control
    PROXY_AUTHORIZATION = "2.16.840.1.113730.3.4.18"

    # Password Policy Control (Draft)
    PASSWORD_POLICY = "1.3.6.1.4.1.42.2.27.8.5.1"

    # RFC 4533 - Content Synchronization Operation
    SYNC_REQUEST = "1.3.6.1.4.1.4203.1.9.1.1"
    SYNC_STATE = "1.3.6.1.4.1.4203.1.9.1.2"
    SYNC_DONE = "1.3.6.1.4.1.4203.1.9.1.3"

    # RFC 4528 - Assertion Control
    ASSERTION = "1.3.6.1.1.12"

    # RFC 4527 - Pre-read and Post-read Controls
    PRE_READ = "1.3.6.1.1.13.1"
    POST_READ = "1.3.6.1.1.13.2"

    # Virtual List View Control
    VLV_REQUEST = "2.16.840.1.113730.3.4.9"
    VLV_RESPONSE = "2.16.840.1.113730.3.4.10"

    # Tree Delete Control
    TREE_DELETE = "1.2.840.113556.1.4.805"

    # ManageDsaIT Control
    MANAGE_DSA_IT = "2.16.840.1.113730.3.4.2"

    # Subentries Control (RFC 3672)
    SUBENTRIES = "1.3.6.1.4.1.4203.1.10.1"

    # Matched Values Control (RFC 3876)
    MATCHED_VALUES = "1.2.826.0.1.3344810.2.3"


# TODO: Implement the following critical controls:
# 1. PagedResultsControl (CRITICAL - RFC 2696)
# 2. ServerSideSortControl (HIGH - RFC 2891)
# 3. PasswordPolicyControl (HIGH - Security)
# 4. ProxyAuthorizationControl (HIGH - RFC 4370)
# 5. SyncRequestControl (MEDIUM - RFC 4533)
# 6. AssertionControl (MEDIUM - RFC 4528)
# 7. PreReadControl/PostReadControl (MEDIUM - RFC 4527)
# 8. VLVControl (MEDIUM - Virtual List View)
# 9. TreeDeleteControl (LOW - Administrative)
# 10. SubentriesControl (LOW - RFC 3672)
