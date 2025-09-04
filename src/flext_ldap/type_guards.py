"""FLEXT-LDAP Type Guards - Class-based runtime type checking for LDAP operations.

This module provides a class-based approach to type guards for runtime type checking
of LDAP-specific data structures. Eliminates all standalone functions and follows
the FlextLDAP[Module] naming convention.

All type guards return boolean values and narrow types for static analysis tools.
Uses isinstance() checks for runtime type validation and provides TypeGuard annotations
for MyPy type narrowing.

Architecture:
    - Eliminates standalone functions in favor of class-based structure
    - Provides TypeGuard annotations for MyPy type narrowing
    - Follows FlextLDAP[Module] naming convention
    - No legacy compatibility or fallback modes

Usage:
    >>> from flext_ldap.type_guards import FlextLDAPTypeGuards
    >>> result = some_ldap_operation()
    >>> if FlextLDAPTypeGuards.is_ldap_search_result(result.value):
    ...     # MyPy now knows result.value is TLdapSearchResult
    ...     for entry in result.value:
    ...         print(entry["dn"])
"""

from __future__ import annotations

from typing import TypeGuard, cast

from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.typings import (
    TLdapAttributes,
    TLdapAttributeValue,
    TLdapEntryData,
    TLdapSearchResult,
)


class FlextLDAPTypeGuards:
    """FlextLDAP Type Guards - Class-based runtime type checking for LDAP operations.

    Provides static methods for type checking LDAP-specific data structures.
    Eliminates all standalone functions and provides clean class-based API.
    """

    @staticmethod
    def is_ldap_dn(value: object) -> TypeGuard[str]:
        """Type guard for LDAP Distinguished Name.

        Args:
            value: Value to check

        Returns:
            True if value is a valid LDAP DN string

        """
        if not isinstance(value, str) or len(value) == 0:
            return False

        # Must contain '=' and have both attribute name and value
        if "=" not in value:
            return False

        # Check for basic DN format: attr=value
        parts = value.split("=")
        if len(parts) < FlextLDAPConstants.LdapValidation.MIN_DN_PARTS:
            return False

        # Must have non-empty attribute name and value
        attr_name = parts[0].strip()
        attr_value = "=".join(parts[1:]).strip()

        return len(attr_name) > 0 and len(attr_value) > 0

    @staticmethod
    def is_ldap_attribute_value(value: object) -> TypeGuard[TLdapAttributeValue]:
        """Type guard for LDAP attribute values.

        Args:
            value: Value to check

        Returns:
            True if value is a valid LDAP attribute value type

        """
        if isinstance(value, (str, bytes)):
            return True
        if isinstance(value, list):
            typed_list: list[object] = cast("list[object]", value)
            return all(isinstance(item, (str, bytes)) for item in typed_list)
        return False

    @staticmethod
    def is_ldap_attributes_dict(value: object) -> TypeGuard[TLdapAttributes]:
        """Type guard for LDAP attributes dictionary.

        Args:
            value: Value to check

        Returns:
            True if value is a valid LDAP attributes dict

        """
        if not isinstance(value, dict):
            return False

        typed_dict: dict[object, object] = cast("dict[object, object]", value)
        for key, val in typed_dict.items():
            if not isinstance(key, str):
                return False
            if not FlextLDAPTypeGuards.is_ldap_attribute_value(val):
                return False

        return True

    @staticmethod
    def is_ldap_search_result(value: object) -> TypeGuard[TLdapSearchResult]:
        """Type guard for LDAP search results.

        Args:
            value: Value to check

        Returns:
            True if value is a valid LDAP search result list

        """
        if not isinstance(value, list):
            return False

        typed_list: list[object] = cast("list[object]", value)
        for item in typed_list:
            if not isinstance(item, dict):
                return False
            if "dn" not in item:
                return False
            typed_item: dict[str, object] = cast("dict[str, object]", item)
            if not FlextLDAPTypeGuards.is_ldap_dn(typed_item["dn"]):
                return False

        return True

    @staticmethod
    def is_ldap_entry_data(value: object) -> TypeGuard[TLdapEntryData]:
        """Type guard for LDAP entry data.

        Args:
            value: Value to check

        Returns:
            True if value is a valid LDAP entry data dict

        """
        if not isinstance(value, dict):
            return False

        # Must have dn
        typed_dict: dict[str, object] = cast("dict[str, object]", value)
        if "dn" not in typed_dict or not FlextLDAPTypeGuards.is_ldap_dn(
            typed_dict["dn"]
        ):
            return False

        # Check other attributes
        for key, val in typed_dict.items():
            if key == "dn":
                continue
            # Entry data can contain various types including nested dicts (like "attributes")
            if key == "attributes":
                # Special handling for nested attributes dict
                if not FlextLDAPTypeGuards.is_ldap_attributes_dict(val):
                    return False
            elif not isinstance(val, (str, bytes, list, int, bool, dict)):
                return False

        return True

    @staticmethod
    def is_connection_result(value: object) -> TypeGuard[dict[str, object]]:
        """Type guard for LDAP connection results.

        Args:
            value: Value to check

        Returns:
            True if value is a valid connection result dict

        """
        return (
            isinstance(value, dict)
            and "status" in value
            and isinstance(value["status"], str)
        )

    @staticmethod
    def is_string_list(value: object) -> TypeGuard[list[str]]:
        """Type guard for list of strings.

        Args:
            value: Value to check

        Returns:
            True if value is a list of strings

        """
        if not isinstance(value, list):
            return False
        typed_list: list[object] = cast("list[object]", value)
        return all(isinstance(item, str) for item in typed_list)

    @staticmethod
    def is_bytes_list(value: object) -> TypeGuard[list[bytes]]:
        """Type guard for list of bytes.

        Args:
            value: Value to check

        Returns:
            True if value is a list of bytes

        """
        if not isinstance(value, list):
            return False
        typed_list: list[object] = cast("list[object]", value)
        return all(isinstance(item, bytes) for item in typed_list)

    @staticmethod
    def ensure_string_list(value: str | list[str]) -> list[str]:
        """Ensure value is a list of strings.

        Args:
            value: String or list of strings

        Returns:
            List of strings

        """
        if isinstance(value, str):
            return [value]
        if FlextLDAPTypeGuards.is_string_list(value):
            return value
        # Convert each item to string
        return (
            [str(item) for item in value] if isinstance(value, list) else [str(value)]
        )

    @staticmethod
    def ensure_ldap_dn(value: object) -> str:
        """Ensure value is a valid LDAP DN.

        Args:
            value: Value to convert to DN

        Returns:
            Valid LDAP DN string

        Raises:
            ValueError: If value cannot be converted to valid DN

        """
        if FlextLDAPTypeGuards.is_ldap_dn(value):
            return value

        str_value = str(value)
        if "=" in str_value:
            return str_value

        msg = f"Cannot convert {value!r} to valid LDAP DN"
        raise ValueError(msg)

    @staticmethod
    def has_error_attribute(obj: object) -> TypeGuard[object]:
        """Type guard for objects with error attribute.

        Args:
            obj: Object to check

        Returns:
            True if object has error attribute

        """
        return hasattr(obj, "error")

    @staticmethod
    def has_is_success_attribute(obj: object) -> TypeGuard[object]:
        """Type guard for objects with is_success attribute.

        Args:
            obj: Object to check

        Returns:
            True if object has is_success attribute

        """
        return hasattr(obj, "is_success")


# Constants and functions eliminated - use FlextLDAPTypeGuards directly following flext-core pattern

__all__ = [
    "FlextLDAPTypeGuards",
]
