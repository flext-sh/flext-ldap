"""FLEXT-LDAP Type Guards - Union Type Resolution Following Foundation Patterns.

This module provides type guard functions to resolve union type issues that are
common in LDAP operations. Following the proven patterns from flext-grpc domain
types architecture.

Type guards help MyPy understand which specific type is being used in union types,
eliminating attr-defined and union-attr errors.

Architecture:
    - Uses isinstance() checks for runtime type validation
    - Provides TypeGuard annotations for MyPy type narrowing
    - Follows foundation patterns from successful flext-grpc implementation
    - Eliminates the need for type: ignore comments

Usage:
    >>> result = some_ldap_operation()
    >>> if is_ldap_search_result(result.value):
    ...     # MyPy now knows result.value is TLdapSearchResult
    ...     for entry in result.value:
    ...         print(entry["dn"])

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypeGuard, cast

from flext_ldap.typings import (
    TLdapAttributes,
    TLdapAttributeValue,
    TLdapEntryData,
    TLdapSearchResult,
)

# =============================================================================
# LDAP DATA TYPE GUARDS - Union Type Resolution
# =============================================================================

# Constants for DN validation
MIN_DN_PARTS: int = 2

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
    if len(parts) < MIN_DN_PARTS:
        return False

    # Must have non-empty attribute name and value
    attr_name = parts[0].strip()
    attr_value = "=".join(parts[1:]).strip()

    return len(attr_name) > 0 and len(attr_value) > 0


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
        if not is_ldap_attribute_value(val):
            return False

    return True


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
        if not is_ldap_dn(typed_item["dn"]):
            return False

    return True


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
    if "dn" not in typed_dict or not is_ldap_dn(typed_dict["dn"]):
        return False

    # Check other attributes
    for key, val in typed_dict.items():
        if key == "dn":
            continue
        # key is already str from dict[str, object] annotation
        # Entry data can contain various types including nested dicts (like "attributes")
        if key == "attributes":
            # Special handling for nested attributes dict
            if not is_ldap_attributes_dict(val):
                return False
        elif not isinstance(val, (str, bytes, list, int, bool, dict)):
            return False

    return True


# =============================================================================
# CONNECTION TYPE GUARDS
# =============================================================================


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


# =============================================================================
# LIST TYPE GUARDS - For Union[List[X], X] patterns
# =============================================================================


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


# =============================================================================
# UTILITY FUNCTIONS - Type-safe conversions
# =============================================================================


def ensure_string_list(value: str | list[str]) -> list[str]:
    """Ensure value is a list of strings.

    Args:
      value: String or list of strings

    Returns:
      List of strings

    """
    if isinstance(value, str):
        return [value]
    if is_string_list(value):
        return value
    # Convert each item to string
    return [str(item) for item in value] if isinstance(value, list) else [str(value)]


def ensure_ldap_dn(value: object) -> str:
    """Ensure value is a valid LDAP DN.

    Args:
      value: Value to convert to DN

    Returns:
      Valid LDAP DN string

    Raises:
      ValueError: If value cannot be converted to valid DN

    """
    if is_ldap_dn(value):
        return value

    str_value = str(value)
    if "=" in str_value:
        return str_value

    msg = f"Cannot convert {value!r} to valid LDAP DN"
    raise ValueError(msg)


# =============================================================================
# ERROR HANDLING TYPE GUARDS
# =============================================================================


def has_error_attribute(obj: object) -> TypeGuard[object]:
    """Type guard for objects with error attribute.

    Args:
      obj: Object to check

    Returns:
      True if object has error attribute

    """
    return hasattr(obj, "error")


def has_is_success_attribute(obj: object) -> TypeGuard[object]:
    """Type guard for objects with is_success attribute.

    Args:
      obj: Object to check

    Returns:
      True if object has is_success attribute

    """
    return hasattr(obj, "is_success")


# Export all type guards
__all__ = [
    "ensure_ldap_dn",
    "ensure_string_list",
    "has_error_attribute",
    "has_is_success_attribute",
    "is_bytes_list",
    "is_connection_result",
    "is_ldap_attribute_value",
    "is_ldap_attributes_dict",
    "is_ldap_dn",
    "is_ldap_entry_data",
    "is_ldap_search_result",
    "is_string_list",
]
