"""LDAP Utils - Single FlextLdapUtils class following FLEXT patterns.

Single class with all LDAP utility functionality organized as internal classes
and methods for complete backward compatibility and proper separation of concerns.

Examples:
    Basic usage with hierarchical utils::

        from utils import FlextLdapUtils

        # Type-safe attribute processing
        attrs = FlextLdapUtils.Attributes.create_typed_ldap_attributes(raw_attrs)
        dn_valid = FlextLdapUtils.Validation.validate_dn(dn)
        cached_config = FlextLdapUtils.Performance.get_cached_config("key")

    Legacy compatibility::

        # All previous classes still work as aliases
        from utils import FlextLdapUtilities, FlextLdapValidationHelpers
        result = FlextLdapUtilities.safe_convert_value_to_str(value)

"""

from __future__ import annotations

import re
from typing import ClassVar, TypeVar, cast
from urllib.parse import urlparse

from .constants import FlextLdapValidationMessages
from .typings import (
    LdapAttributeDict as UtilsLdapAttributeDict,
    LdapAttributeValue,
)

T = TypeVar("T")

# =============================================================================
# SINGLE FLEXT LDAP UTILS CLASS - Consolidated utility functionality
# =============================================================================


class FlextLdapUtils:
    """Single FlextLdapUtils class with all LDAP utility functionality.

    Consolidates ALL LDAP utilities into a single class following FLEXT patterns.
    Everything from the previous multiple utility classes is now available as
    internal methods and classes with full backward compatibility.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP utilities consolidated
        - Open/Closed: Extensible without modification
        - Liskov Substitution: Consistent interface across all utilities
        - Interface Segregation: Organized by domain for specific access
        - Dependency Inversion: Depends on abstractions not concrete implementations

    Examples:
        Type-safe operations::

            attrs = FlextLdapUtils.Attributes.create_typed_ldap_attributes(raw_attrs)
            dn_valid = FlextLdapUtils.Validation.validate_dn(dn)
            cached_config = FlextLdapUtils.Performance.get_cached_config("key")

        LDAP3 integration::

            result = FlextLdapUtils.Ldap3.safe_ldap3_search_result(search_result)
            entries = FlextLdapUtils.Ldap3.safe_ldap3_entries_list(connection)

    """

    # =========================================================================
    # ATTRIBUTES UTILITIES - Type-safe LDAP attribute processing
    # =========================================================================

    class Attributes:
        """LDAP attribute processing utilities."""

        @staticmethod
        def create_typed_ldap_attributes(
            attributes: dict[str, object | list[object]],
        ) -> UtilsLdapAttributeDict:
            """Create properly typed LDAP attributes dict.

            Converts generic attribute dict to LDAP-compatible format.
            """
            result: UtilsLdapAttributeDict = {}
            for key, value in attributes.items():
                if isinstance(value, list):
                    # Convert list of objects to list of strings/bytes
                    converted_list: list[str] = []
                    typed_list: list[object] = cast("list[object]", value)
                    for item in typed_list:
                        if isinstance(item, (str, bytes)):
                            converted_list.append(str(item))
                        else:
                            converted_list.append(str(item))
                    result[key] = converted_list
                elif isinstance(value, (str, bytes)):
                    result[key] = value
                else:
                    # Convert other types to string
                    result[key] = str(value)
            return result

        @staticmethod
        def safe_convert_external_dict_to_ldap_attributes(
            external_dict: object,
        ) -> UtilsLdapAttributeDict:
            """Safely convert external dictionary (Unknown type) to typed LDAP attributes.

            Handles Unknown types from external libraries like ldap3.
            """
            result: UtilsLdapAttributeDict = {}

            if not isinstance(external_dict, dict):
                return result

            # Type-safe iteration over Unknown dict
            typed_dict: dict[str, object] = cast("dict[str, object]", external_dict)
            for raw_key, raw_value in typed_dict.items():
                # Key from dict.items() is always string
                key = str(raw_key)
                if not key:
                    continue

                # Handle different value types safely
                if isinstance(raw_value, list):
                    # Convert list values to strings, handling bytes properly
                    str_list: list[str] = []
                    typed_list: list[object] = cast("list[object]", raw_value)
                    for item in typed_list:
                        if item is not None:
                            if isinstance(item, bytes):
                                # Decode bytes to string safely
                                str_list.append(item.decode("utf-8", errors="replace"))
                            else:
                                str_list.append(str(item))
                    if str_list:  # Only add non-empty lists
                        result[key] = str_list
                elif raw_value is not None:
                    # Convert single values to string, handling bytes properly
                    if isinstance(raw_value, bytes):
                        # Decode bytes to string safely
                        result[key] = raw_value.decode("utf-8", errors="replace")
                    else:
                        result[key] = str(raw_value)

            return result

        @staticmethod
        def safe_get_first_value(attributes: dict[str, object], key: str) -> str | None:
            """Safely get first value from LDAP attribute list."""
            value = attributes.get(key)
            if isinstance(value, list) and value:
                typed_list: list[object] = cast("list[object]", value)
                first_value: object = typed_list[0]
                return str(first_value)
            if isinstance(value, str):
                return value
            return None

        @staticmethod
        def safe_str_attribute(attributes: UtilsLdapAttributeDict, key: str) -> str | None:
            """Safely extract string attribute from LDAP attributes dict."""
            value = attributes.get(key)
            if value is None:
                return None

            # Handle direct string/bytes values
            result = FlextLdapUtils.Attributes._extract_string_from_value(value)
            if result is not None:
                return result

            # Handle lists - take first item
            if isinstance(value, list) and value:
                return FlextLdapUtils.Attributes._extract_string_from_value(value[0])

            return None

        @staticmethod
        def _extract_string_from_value(value: object) -> str | None:
            """Extract string from a single value (str or bytes).

            Refactored to use flext-core patterns for consistent error handling.
            """

            def _safe_extract() -> str | None:
                if isinstance(value, str):
                    return value if value.strip() else None
                if isinstance(value, bytes):
                    try:
                        decoded_str = value.decode("utf-8")
                        return decoded_str if decoded_str.strip() else None
                    except UnicodeDecodeError:
                        return None
                return None

            # Use flext-core safe pattern (modern approach)
            try:
                return _safe_extract()
            except Exception:
                # Flext-core pattern: fail gracefully instead of raising
                return None

        @staticmethod
        def create_ldap_attributes(attrs: dict[str, list[str]]) -> LdapAttributeDict:
            """Create LdapAttributeDict from dict with proper typing."""
            result: LdapAttributeDict = {}
            for key, value in attrs.items():
                # Since input is already typed as dict[str, list[str]], value is always list[str]
                attr_value: LdapAttributeValue = [str(item) for item in value]
                result[key] = attr_value
            return result

        @staticmethod
        def optimize_attribute_processing(
            attributes: dict[str, object],
        ) -> dict[str, object]:
            if not attributes:
                return {}

            # Inline attribute coercion for better performance (avoid import)
            def coerce_value(value: object) -> str | list[str]:
                if isinstance(value, list):
                    typed_list: list[object] = cast("list[object]", value)
                    return [str(item) for item in typed_list]
                return str(value)

            # Pre-allocate dictionary with known size for better performance
            result: dict[str, object] = {}
            result.update(
                {
                    key: coerce_value(value)
                    for key, value in attributes.items()
                    if value is not None  # Skip None values early
                },
            )
            return result

    # =========================================================================
    # VALIDATION UTILITIES - Input validation and sanitization
    # =========================================================================

    class Validation:
        """LDAP validation utilities."""

        @staticmethod
        def validate_dn(dn: str) -> bool:
            """Validate Distinguished Name format with caching."""
            if not dn or not isinstance(dn, str):
                return False

            # Check cache first for performance
            cached_result = FlextLdapUtils.Performance.get_cached_validation(dn, "dn")
            if cached_result is not None:
                return cached_result

            # Basic DN validation pattern
            dn_pattern = re.compile(
                r"^[a-zA-Z][\w-]*=.+(?:,[a-zA-Z][\w-]*=.+)*$",
            )

            result = bool(dn_pattern.match(dn.strip()))

            # Cache the result
            FlextLdapUtils.Performance.cache_validation_result(dn, "dn", result=result)
            return result

        @staticmethod
        def validate_attribute_name(name: str) -> bool:
            """Validate LDAP attribute name."""
            if not name or not isinstance(name, str):
                return False

            # LDAP attribute names per RFC 4512: base name + optional language tags/options
            # Supports: displayname;lang-es_es, orclinstancecount;oid-prd-app01.network.ctbc
            attr_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*(?:;[a-zA-Z0-9_.-]+)*$")
            return bool(attr_pattern.match(name))

        @staticmethod
        def validate_attribute_value(value: object) -> bool:
            """Validate LDAP attribute value."""
            if not isinstance(value, str):
                return False

            # Basic validation - no null characters
            return "\x00" not in value

        @staticmethod
        def sanitize_attribute_name(name: str) -> str:
            """Sanitize LDAP attribute name."""
            if not name:
                return ""

            # Remove invalid characters and normalize
            sanitized = re.sub(r"[^a-zA-Z0-9;-]", "", name)
            return sanitized.lower()

        @staticmethod
        def validate_non_empty_string(value: str, field_name: str) -> str:
            """Standard validation for non-empty string fields."""
            if not value or not value.strip():
                msg = FlextLdapValidationMessages.FIELD_CANNOT_BE_EMPTY.format(
                    field_name=field_name,
                )
                raise ValueError(msg)
            return value.strip()

        @staticmethod
        def validate_dn_field(value: str) -> str:
            """Standard DN validation for Pydantic models."""
            return FlextLdapUtils.Validation.validate_non_empty_string(
                value,
                FlextLdapValidationMessages.DN_FIELD_NAME,
            )

        @staticmethod
        def validate_filter_field(value: str) -> str:
            """Standard filter validation for Pydantic models."""
            return FlextLdapUtils.Validation.validate_non_empty_string(
                value,
                FlextLdapValidationMessages.SEARCH_FILTER_FIELD_NAME,
            )

        @staticmethod
        def validate_cn_field(value: str) -> str:
            """Standard common name validation for Pydantic models."""
            return FlextLdapUtils.Validation.validate_non_empty_string(
                value,
                FlextLdapValidationMessages.COMMON_NAME_FIELD_NAME,
            )

        @staticmethod
        def validate_file_path_field(value: str) -> str:
            """Standard file path validation for Pydantic models."""
            return FlextLdapUtils.Validation.validate_non_empty_string(
                value,
                FlextLdapValidationMessages.FILE_PATH_FIELD_NAME,
            )

        @staticmethod
        def validate_uri_field(value: str) -> str:
            """Standard URI validation for Pydantic models."""
            validated = FlextLdapUtils.Validation.validate_non_empty_string(
                value,
                FlextLdapValidationMessages.URI_FIELD_NAME,
            )
            parsed = urlparse(validated)
            if parsed.scheme not in {"ldap", "ldaps"}:
                msg = FlextLdapValidationMessages.INVALID_URI_SCHEME
                raise ValueError(msg)
            return validated

        @staticmethod
        def validate_base_dn_field(value: str) -> str:
            """Standard base DN validation for Pydantic models."""
            validated = FlextLdapUtils.Validation.validate_non_empty_string(
                value,
                FlextLdapValidationMessages.BASE_DN_FIELD_NAME,
            )
            if not FlextLdapUtils.Validation.validate_dn(validated):
                msg = FlextLdapValidationMessages.INVALID_DN_FORMAT
                raise ValueError(msg)
            return validated

    # =========================================================================
    # PERFORMANCE UTILITIES - Caching and optimization
    # =========================================================================

    class Performance:
        """Performance helpers for caching and micro-optimizations."""

        # Simple cache for frequently accessed configurations
        _config_cache: ClassVar[dict[str, object]] = {}
        _validation_cache: ClassVar[dict[str, bool]] = {}

        @classmethod
        def cache_config(cls, key: str, config: object) -> None:
            cls._config_cache[key] = config

        @classmethod
        def get_cached_config(cls, key: str) -> object | None:
            return cls._config_cache.get(key)

        @classmethod
        def cache_validation_result(
            cls,
            value: str,
            validation_type: str,
            *,
            result: bool,
        ) -> None:
            cache_key = f"{validation_type}:{value}"
            cls._validation_cache[cache_key] = result

        @classmethod
        def get_cached_validation(cls, value: str, validation_type: str) -> bool | None:
            cache_key = f"{validation_type}:{value}"
            return cls._validation_cache.get(cache_key)

        @classmethod
        def clear_cache(cls) -> None:
            cls._config_cache.clear()
            cls._validation_cache.clear()

    # =========================================================================
    # ERROR HANDLING UTILITIES - Centralized error patterns
    # =========================================================================

    class Errors:
        """Centralized error handling helpers to eliminate duplication."""

        @staticmethod
        def connection_failed_error(error: str | None = None, context: str = "") -> str:
            """Standard connection failure error message."""
            base_msg = FlextLdapValidationMessages.CONNECTION_FAILED
            if context:
                base_msg = (
                    FlextLdapValidationMessages.CONNECTION_FAILED_WITH_CONTEXT.format(
                        context=context,
                    )
                )
            if error:
                return f"{base_msg}: {error}"
            return base_msg

        @staticmethod
        def operation_failed_error(operation: str, error: str | None = None) -> str:
            """Standard operation failure error message."""
            base_msg = FlextLdapValidationMessages.OPERATION_FAILED.format(
                operation=operation.title(),
            )
            if error:
                return f"{base_msg}: {error}"
            return base_msg

        @staticmethod
        def validation_failed_error(field: str, reason: str | None = None) -> str:
            """Standard validation failure error message."""
            base_msg: str = FlextLdapValidationMessages.VALIDATION_FAILED.format(
                field=field,
            )
            if reason:
                return f"{base_msg}: {reason}"
            return base_msg

    # =========================================================================
    # CORE UTILITIES - General purpose utilities
    # =========================================================================

    class Core:
        """Core utility methods for common operations."""

        @staticmethod
        def is_successful_result(result: object) -> bool:
            """Check if FlextResult is successful."""
            return hasattr(result, "is_success") and bool(
                getattr(result, "is_success", False),
            )

        @staticmethod
        def extract_error_message(
            result: object,
            default_message: str = "Unknown error",
        ) -> str:
            """Extract error message from FlextResult or return default."""
            if hasattr(result, "error") and hasattr(result, "is_success"):
                is_success = getattr(result, "is_success", True)
                if not is_success:
                    error = getattr(result, "error", None)
                    return str(error) if error is not None else default_message
            return default_message

        @staticmethod
        def safe_dict_comprehension(source_dict: object) -> dict[str, object]:
            """Safely convert unknown dict to typed dict with string keys."""
            if not isinstance(source_dict, dict):
                return {}

            # Type-safe dict comprehension for LDAP data
            result: dict[str, object] = {}
            typed_dict: dict[str, object] = cast("dict[str, object]", source_dict)
            for key, value in typed_dict.items():
                # Key from dict.items() is always string
                str_key = str(key)
                if str_key:  # Skip empty keys
                    result[str_key] = value
            return result

        @staticmethod
        def safe_convert_value_to_str(value: object) -> str:
            """Safely convert any value to string, handling bytes properly."""
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return str(value) if value is not None else ""

        @staticmethod
        def safe_convert_list_to_strings(values: list[object]) -> list[str]:
            """Convert list of values to strings, handling bytes and filtering empty."""
            result: list[str] = []
            for item in values:
                if item is not None:
                    str_item = FlextLdapUtils.Core.safe_convert_value_to_str(item)
                    if str_item:  # Skip empty strings
                        result.append(str_item)
            return result

        @staticmethod
        def safe_list_conversion(source_value: object) -> list[str]:
            """Safely convert unknown value to list of strings for LDAP attributes."""
            if isinstance(source_value, list):
                typed_list: list[object] = cast("list[object]", source_value)
                return FlextLdapUtils.Core.safe_convert_list_to_strings(typed_list)
            if source_value is not None:
                str_value = FlextLdapUtils.Core.safe_convert_value_to_str(source_value)
                return [str_value] if str_value else []
            return []

        @staticmethod
        def safe_entry_attribute_access(entry: object, attribute: str) -> object | None:
            """Safely access entry attributes with proper typing."""
            if not hasattr(entry, attribute):
                return None

            # Type-safe attribute access
            attr_value = getattr(entry, attribute, None)
            return attr_value if attr_value is not None else None

        @staticmethod
        def safe_dict_comprehension_with_attribute_values(raw_dict: object) -> dict[str, LdapAttributeValue]:
            """Safely convert unknown dict to typed LDAP attributes.

            Handles unknown dictionary types from external libraries.
            """
            if not isinstance(raw_dict, dict):
                return {}

            result: dict[str, LdapAttributeValue] = {}
            typed_dict: dict[str, object] = cast("dict[str, object]", raw_dict)
            for key, value in typed_dict.items():
                str_key = str(key)
                if isinstance(value, list):
                    # Convert list to list of strings
                    typed_list: list[object] = cast("list[object]", value)
                    result[str_key] = [str(item) for item in typed_list]
                elif isinstance(value, (str, bytes)):
                    result[str_key] = str(value)
                else:
                    result[str_key] = str(value) if value is not None else ""
            return result

        @staticmethod
        def safe_list_access(data: object) -> list[object]:
            """Safely convert unknown data to list.

            Returns empty list if data is not a list.
            """
            if isinstance(data, list):
                return cast("list[object]", data)
            return []

        @staticmethod
        def safe_string_conversion(value: object) -> str:
            """Safely convert unknown value to string."""
            if value is None:
                return ""
            return str(value)

    # =========================================================================
    # LDAP3 UTILITIES - Handle External Library Types
    # =========================================================================

    class Ldap3:
        """LDAP3 integration utilities for handling external library types."""

        @staticmethod
        def safe_ldap3_search_result(ldap3_search_result: object) -> bool:
            """Safely extract boolean result from ldap3 search operation."""
            return bool(ldap3_search_result)

        @staticmethod
        def safe_ldap3_entries_list(connection: object) -> list[object]:
            """Safely extract entries list from ldap3 connection."""
            entries: object = getattr(connection, "entries", [])
            if isinstance(entries, list):
                return cast("list[object]", entries)
            return []

        @staticmethod
        def safe_ldap3_entry_dn(entry: object) -> str:
            """Safely extract DN from ldap3 entry object."""
            dn: object = getattr(entry, "entry_dn", None)
            return str(dn) if dn is not None else ""

        @staticmethod
        def safe_ldap3_entry_attributes_list(entry: object) -> list[str]:
            """Safely extract attribute names list from ldap3 entry."""
            if entry is None:
                return []

            attrs_dict: object = getattr(entry, "entry_attributes_as_dict", None)
            if attrs_dict is None:
                return []

            if isinstance(attrs_dict, dict):
                typed_dict: dict[str, object] = cast("dict[str, object]", attrs_dict)
                return list(typed_dict.keys())
            return []

        @staticmethod
        def safe_ldap3_attribute_values(entry: object, attr_name: str) -> list[str]:
            """Safely extract attribute values from ldap3 entry."""
            attr_obj: object = getattr(entry, attr_name, None)
            if attr_obj is None:
                return []

            values: object = getattr(attr_obj, "values", [])
            if isinstance(values, list):
                typed_values: list[object] = cast("list[object]", values)
                return [str(val) for val in typed_values if val is not None]
            return []

        @staticmethod
        def safe_ldap3_connection_result(connection: object) -> str:
            """Safely extract result message from ldap3 connection."""
            result: object = getattr(connection, "result", None)
            return str(result) if result is not None else "Unknown error"

        @staticmethod
        def safe_ldap3_rebind_result(connection: object, user: str, password: str) -> bool:
            """Safely execute and extract result from ldap3 rebind operation."""
            rebind_method: object = getattr(connection, "rebind", None)
            if rebind_method is None or not callable(rebind_method):
                return False

            try:
                rebind_result: object = rebind_method(user=user, password=password)
                return bool(rebind_result)
            except Exception:
                return False


# =============================================================================
# LEGACY COMPATIBILITY CLASSES - Backward Compatibility
# =============================================================================

# Legacy compatibility classes - mapped to consolidated FlextLdapUtils
FlextLdapUtilities = FlextLdapUtils.Core
FlextLdapPerformanceHelpers = FlextLdapUtils.Performance
FlextLdapValidationHelpers = FlextLdapUtils.Validation
FlextLdapErrorHelpers = FlextLdapUtils.Errors

# Additional legacy mapping for the old FlextLdapUtils validation methods
class _FlextLdapUtilsLegacy:
    """Legacy FlextLdapUtils class mapped to new consolidated structure."""

    validate_dn = FlextLdapUtils.Validation.validate_dn
    validate_attribute_name = FlextLdapUtils.Validation.validate_attribute_name
    validate_attribute_value = FlextLdapUtils.Validation.validate_attribute_value
    sanitize_attribute_name = FlextLdapUtils.Validation.sanitize_attribute_name


# =============================================================================
# FUNCTIONAL API - Convenience functions for testing/backwards compatibility
# =============================================================================


# Testing convenience functional API expected by imports/tests
def flext_ldap_validate_dn(dn: str) -> bool:
    """Validate Distinguished Name format."""
    return FlextLdapUtils.Validation.validate_dn(dn)


def flext_ldap_validate_attribute_name(name: str) -> bool:
    """Validate LDAP attribute name."""
    return FlextLdapUtils.Validation.validate_attribute_name(name)


def flext_ldap_validate_attribute_value(value: object) -> bool:
    """Validate LDAP attribute value."""
    return FlextLdapUtils.Validation.validate_attribute_value(value)


def flext_ldap_sanitize_attribute_name(name: str) -> str:
    """Sanitize LDAP attribute name."""
    return FlextLdapUtils.Validation.sanitize_attribute_name(name)


# Testing convenience alias with the exact expected export name
LdapAttributeDict = UtilsLdapAttributeDict

__all__ = [
    # Primary consolidated class
    "FlextLdapUtils",

    # Legacy compatibility classes
    "FlextLdapUtilities",
    "FlextLdapPerformanceHelpers",
    "FlextLdapValidationHelpers",
    "FlextLdapErrorHelpers",

    # Testing convenience type aliases
    "LdapAttributeDict",
    "UtilsLdapAttributeDict",

    # Functional API for backwards compatibility
    "flext_ldap_validate_dn",
    "flext_ldap_validate_attribute_name",
    "flext_ldap_validate_attribute_value",
    "flext_ldap_sanitize_attribute_name",
]
