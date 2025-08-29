"""LDAP Utils - Facade redirecting to utilities.py and flext-core FlextUtilities.

DEPRECATED: This module is maintained for backward compatibility.
Use utilities.py (FlextLdapUtilities) for new code.

The FlextLdapUtils class now simply extends FlextUtilities from flext-core
with LDAP-specific functionality, eliminating duplication and leveraging
the comprehensive utility functions already available in flext-core.

Migration Guide:
    Old usage::
        from flext_ldap.utils import FlextLdapUtils

        result = FlextLdapUtils.Attributes.create_typed_ldap_attributes(attrs)

    New usage::
        from flext_ldap.utilities import FlextLdapUtilities
        from flext_core import FlextUtilities

        # Use flext-core for generic operations
        result = (
            FlextUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
                attrs
            )
        )

        # Use FlextLdapUtilities for LDAP-specific operations
        validated = FlextLdapUtilities.Validation.validate_attribute_name("cn")

"""

from __future__ import annotations

import warnings
from typing import cast

from flext_core import FlextLogger, FlextUtilities

from flext_ldap.typings import LdapAttributeDict
from flext_ldap.utilities import FlextLdapUtilities

logger = FlextLogger(__name__)

# Issue deprecation warning
warnings.warn(
    "flext_ldap.utils is deprecated. Use flext_ldap.utilities.FlextLdapUtilities "
    "for LDAP-specific functions and flext_core.FlextUtilities for generic functions.",
    DeprecationWarning,
    stacklevel=2,
)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _raise_malformed_property_error() -> None:
    """Helper function to raise malformed property error."""
    msg = "Malformed is_success property"
    raise RuntimeError(msg)


# =============================================================================
# BACKWARD COMPATIBILITY FACADE - Redirects to proper implementations
# =============================================================================


class FlextLdapUtils:
    """Backward compatibility facade redirecting to proper implementations.

    This class maintains backward compatibility while redirecting to the proper
    implementations in flext-core (generic utilities) and FlextLdapUtilities
    (LDAP-specific utilities).
    """

    # ==========================================================================
    # FACADE METHODS - Redirect to appropriate implementations
    # ==========================================================================

    # Generic utilities - redirect to flext-core
    Generators = FlextUtilities.Generators
    # LdapConverters = FlextUtilities.LdapConverters  # FIXME: Doesn't exist in flext-core
    TextProcessor = FlextUtilities.TextProcessor
    TimeUtils = FlextUtilities.TimeUtils
    Performance = FlextUtilities.Performance
    Conversions = FlextUtilities.Conversions
    TypeGuards = FlextUtilities.TypeGuards
    Formatters = FlextUtilities.Formatters
    ProcessingUtils = FlextUtilities.ProcessingUtils
    ResultUtils = FlextUtilities.ResultUtils

    # LDAP-specific utilities - redirect to FlextLdapUtilities
    Validation = FlextLdapUtilities.Validation
    DnParser = FlextLdapUtilities.DnParser
    LdapSpecific = FlextLdapUtilities.LdapSpecific

    # Forward declarations for mypy - actual assignment done after class definitions
    Ldap3: type[
        FlextLdapUtilsAttributes.Ldap3
    ]  # Will be assigned to FlextLdapUtilsAttributes.Ldap3
    Attributes: type[
        FlextLdapUtilsAttributes
    ]  # Will be assigned to FlextLdapUtilsAttributes

    # ==========================================================================
    # ADDITIONAL LEGACY METHODS
    # ==========================================================================

    @staticmethod
    def is_successful_result(result: object) -> bool:
        """Check if an object is a successful FlextResult.

        DEPRECATED: Use result.is_success directly instead.
        """
        try:
            # Check if object has is_success attribute
            if hasattr(result, "is_success"):
                success_value = result.is_success
                if success_value is True:
                    return True
                if success_value is False:
                    return False
                # Handle property that raises exception
                _raise_malformed_property_error()
            return False
        except Exception as e:
            if "Malformed is_success property" in str(e):
                raise  # Re-raise malformed property exceptions
            return False

    # ==========================================================================
    # LEGACY METHOD FACADES - For direct method calls
    # ==========================================================================

    @staticmethod
    def validate_attribute_name(name: str) -> str:
        """Legacy facade - redirect to FlextLdapUtilities."""
        result = FlextLdapUtilities.Validation.validate_attribute_name(name)
        return result.value if result.is_success else ""

    @staticmethod
    def safe_convert_external_dict_to_ldap_attributes(
        source_dict: object,
    ) -> dict[str, str | list[str]]:
        """Legacy facade - redirect to FlextLdapUtilities implementation."""
        return FlextLdapUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
            source_dict
        )

    @staticmethod
    def generate_id() -> str:
        """Legacy facade - redirect to flext-core."""
        return FlextUtilities.Generators.generate_id()

    @staticmethod
    def generate_uuid() -> str:
        """Legacy facade - redirect to flext-core."""
        return FlextUtilities.Generators.generate_uuid()

    @staticmethod
    def create_typed_ldap_attributes(
        attributes: dict[str, object],
    ) -> dict[str, object]:
        """Legacy facade - SIMPLIFIED to use FlextUtilities.

        DEPRECATED: Use FlextUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes() instead.
        """
        # Use FlextLdapUtilities implementation directly - it handles all the edge cases
        return FlextLdapUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
            attributes
        )  # type: ignore[return-value]  # Compatible conversion


# =============================================================================
# STANDALONE LEGACY FUNCTIONS - Required by __init__.py
# =============================================================================


def flext_ldap_validate_dn(dn: str) -> str:
    """Legacy function facade for DN validation.

    DEPRECATED: Use FlextLdapUtilities.DnParser.parse_distinguished_name() instead.
    """
    result = FlextLdapUtilities.DnParser.parse_distinguished_name(dn)
    if result.is_success:
        return dn  # Return original DN if valid
    msg = f"Invalid DN: {result.error}"
    raise ValueError(msg)


def flext_ldap_validate_attribute_name(name: str) -> str:
    """Legacy function facade for attribute name validation.

    DEPRECATED: Use FlextLdapUtilities.Validation.validate_attribute_name() instead.
    """
    result = FlextLdapUtilities.Validation.validate_attribute_name(name)
    if result.is_success:
        return result.value
    msg = f"Invalid attribute name: {result.error}"
    raise ValueError(msg)


def flext_ldap_validate_attribute_value(value: str) -> str:
    """Legacy function facade for attribute value validation.

    DEPRECATED: Use flext-core FlextUtilities.TextProcessor.clean_text() instead.
    """
    # Simple validation - clean text using flext-core
    normalized = FlextUtilities.TextProcessor.clean_text(str(value))
    if not normalized:
        msg = "Attribute value cannot be empty"
        raise ValueError(msg)
    return normalized


def flext_ldap_sanitize_attribute_name(name: str) -> str:
    """Legacy function facade for attribute name sanitization - USES FLEXT-CORE.

    DEPRECATED: Use FlextLdapUtilities.Validation.validate_attribute_name() instead.
    """
    result = FlextLdapUtilities.Validation.validate_attribute_name(name)
    if result.is_success:
        return result.value

    # Return sanitized version using FlextUtilities
    sanitized = FlextUtilities.TextProcessor.slugify(name)
    # Replace dashes with underscores for LDAP attribute naming
    sanitized = sanitized.replace("-", "_")
    if not sanitized or not sanitized[0].isalpha():
        sanitized = f"attr_{sanitized}"
    return sanitized


# =============================================================================
# NESTED CLASSES FOR LEGACY COMPATIBILITY
# =============================================================================


class FlextLdapUtilsAttributes:
    """Legacy compatibility class for attribute operations."""

    @staticmethod
    def create_typed_ldap_attributes(
        attributes: dict[str, object],
    ) -> LdapAttributeDict:
        """Legacy method redirecting to flext-core implementation."""
        # Cast to LdapAttributeDict type (compatible conversion)
        return FlextLdapUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
            attributes
        )  # type: ignore[return-value]

    @staticmethod
    def safe_convert_value_to_str(value: object) -> str:
        """Legacy method redirecting to flext-core implementation."""
        return FlextLdapUtilities.LdapConverters.safe_convert_value_to_str(value)

    @staticmethod
    def safe_convert_list_to_strings(values: list[object]) -> list[str]:
        """Legacy method redirecting to flext-core implementation."""
        return FlextLdapUtilities.LdapConverters.safe_convert_list_to_strings(values)

    @staticmethod
    def safe_str_attribute(
        attributes: dict[str, object]
        | dict[str, str | bytes | list[str] | list[bytes]],
        attr_name: str,
    ) -> str:
        """Safely extract string attribute from LDAP attributes dict - USES FLEXT-CORE."""
        if not FlextUtilities.TypeGuards.is_dict(
            attributes
        ) or not FlextUtilities.TypeGuards.is_string_non_empty(attr_name):
            return ""

        value = attributes.get(attr_name, "")
        if FlextUtilities.TypeGuards.is_list(value) and value:
            # If it's a list, take the first value using FlextUtilities
            list_value = cast("list[object]", value)
            return FlextUtilities.Conversions.safe_str(list_value[0])
        if value:
            return FlextUtilities.Conversions.safe_str(value)
        return ""

    class Ldap3:
        """Legacy compatibility class for LDAP3 operations."""

        @staticmethod
        def safe_ldap3_rebind_result(
            connection: object, dn: str, password: str
        ) -> bool:
            """Legacy compatibility method - simplified implementation."""
            try:
                return connection.rebind(dn, password) if connection else False  # type: ignore[attr-defined]
            except Exception:
                return False

        @staticmethod
        def safe_ldap3_search_result(search_result: object) -> bool:
            """Legacy compatibility method - check if search was successful."""
            if not search_result:
                return False
            # Check if search result has entries or result attribute indicating success
            if hasattr(search_result, "entries") and search_result.entries is not None:
                return True
            return bool(hasattr(search_result, "result") and search_result.result)

        @staticmethod
        def safe_ldap3_entries_list(connection: object) -> list[dict[str, object]]:
            """Legacy compatibility method - simplified implementation."""
            if not connection or not hasattr(connection, "entries"):
                return []
            return connection.entries  # type: ignore[no-any-return]

        @staticmethod
        def safe_ldap3_connection_result(connection: object) -> str:
            """Legacy compatibility method - get connection result/error message."""
            if not connection:
                return "No connection"
            if (
                hasattr(connection, "result")
                and connection.result
                and hasattr(connection.result, "get")
                and connection.result.get("description")
            ):
                return str(connection.result["description"])
            return "Connection error"

        @staticmethod
        def safe_ldap3_entry_dn(entry: object) -> str:
            """Legacy compatibility method - get entry DN."""
            if not entry:
                return ""
            if hasattr(entry, "entry_dn"):
                return str(entry.entry_dn)
            return ""

        @staticmethod
        def safe_ldap3_entry_attributes_list(entry: object) -> list[str]:
            """Legacy compatibility method - get entry attribute names."""
            if not entry or not hasattr(entry, "entry_attributes_as_dict"):
                return []
            try:
                attrs = entry.entry_attributes_as_dict
                return list(attrs.keys()) if attrs else []
            except Exception:
                return []

        @staticmethod
        def safe_ldap3_attribute_values(entry: object, attr_name: str) -> list[str]:
            """Legacy compatibility method - get attribute values."""
            if not entry or not attr_name:
                return []
            try:
                if hasattr(entry, "entry_attributes_as_dict"):
                    attrs = entry.entry_attributes_as_dict
                    if attrs and attr_name in attrs:
                        values = attrs[attr_name]
                        if isinstance(values, list):
                            return [str(v) for v in values]
                        return [str(values)]
            except Exception as e:
                # Log exception for debugging purposes
                logger.debug(f"Failed to get attribute values: {e}")
            return []


class FlextLdapValidationHelpers:
    """Legacy validation helpers redirecting to FlextLdapUtilities."""

    @staticmethod
    def validate_non_empty_string(value: str, field_name: str) -> str:
        """Validate and return non-empty string."""
        if not isinstance(value, str):
            msg = f"{field_name} must be a string"  # type: ignore[unreachable]
            raise TypeError(msg)

        cleaned = FlextUtilities.TextProcessor.clean_text(value)
        if not cleaned:
            msg = f"{field_name} cannot be empty"
            raise ValueError(msg)

        return cleaned

    @staticmethod
    def validate_dn_field(dn: str) -> str:
        """Validate DN field using FlextLdapUtilities."""
        result = FlextLdapUtilities.DnParser.parse_distinguished_name(dn)
        if result.is_success:
            return dn
        msg = f"Invalid DN: {result.error}"
        raise ValueError(msg)

    @staticmethod
    def validate_filter_field(filter_str: str) -> str:
        """Validate LDAP filter field."""
        if not isinstance(filter_str, str):
            msg = "Filter must be a string"  # type: ignore[unreachable]
            raise TypeError(msg)

        cleaned = FlextUtilities.TextProcessor.clean_text(filter_str)
        if not cleaned:
            msg = "Filter cannot be empty"
            raise ValueError(msg)

        # Basic filter validation - should contain equals sign or be wrapped in parentheses
        if not ("=" in cleaned or (cleaned.startswith("(") and cleaned.endswith(")"))):
            msg = "Invalid LDAP filter format"
            raise ValueError(msg)

        return cleaned

    @staticmethod
    def validate_uri_field(uri: str) -> str:
        """Validate URI field."""
        if not isinstance(uri, str):
            msg = "URI must be a string"  # type: ignore[unreachable]
            raise TypeError(msg)

        cleaned = FlextUtilities.TextProcessor.clean_text(uri)
        if not cleaned:
            msg = "URI cannot be empty"
            raise ValueError(msg)

        return cleaned

    @staticmethod
    def validate_base_dn_field(base_dn: str) -> str:
        """Validate base DN field."""
        return FlextLdapValidationHelpers.validate_dn_field(base_dn)

    @staticmethod
    def validate_cn_field(cn: str) -> str:
        """Validate CN field."""
        return FlextLdapValidationHelpers.validate_non_empty_string(cn, "CN")


# =============================================================================
# LEGACY ALIASES
# =============================================================================

# Maintain all legacy aliases for backward compatibility
# Note: FlextLdapUtilities is imported from utilities.py, this creates a legacy alias
# FlextLdapUtilities = FlextLdapUtils  # Legacy alias - causes type error, use import instead


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "FlextLdapUtils",
    "FlextLdapUtilsAttributes",
    "FlextLdapValidationHelpers",  # Legacy validation helpers
    "flext_ldap_sanitize_attribute_name",
    "flext_ldap_validate_attribute_name",
    "flext_ldap_validate_attribute_value",
    # Standalone legacy functions
    "flext_ldap_validate_dn",
]

# =============================================================================
# POST-DEFINITION REFERENCES - Fix forward reference issues
# =============================================================================

# Add references to FlextLdapUtils for backward compatibility
# Note: These assignments are done after class definition to avoid forward reference
FlextLdapUtils.Ldap3 = FlextLdapUtilsAttributes.Ldap3
FlextLdapUtils.Attributes = FlextLdapUtilsAttributes
