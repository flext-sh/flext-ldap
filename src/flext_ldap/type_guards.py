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
    >>> if is_ldap_search_result(result.data):
    ...     # MyPy now knows result.data is TLdapSearchResult
    ...     for entry in result.data:
    ...         print(entry["dn"])

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeGuard

if TYPE_CHECKING:
    from flext_ldap.types import (
        TLdapAttributes,
        TLdapAttributeValue,
        TLdapDn,
        TLdapEntryData,
        TLdapSearchResult,
    )

# =============================================================================
# LDAP DATA TYPE GUARDS - Union Type Resolution
# =============================================================================


def is_ldap_dn(value: object) -> TypeGuard[TLdapDn]:
    """Type guard for LDAP Distinguished Name.

    Args:
        value: Value to check

    Returns:
        True if value is a valid LDAP DN string

    """
    return isinstance(value, str) and len(value) > 0 and "=" in value


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
        return all(isinstance(item, (str, bytes)) for item in value)
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

    for key, val in value.items():
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

    for item in value:
        if not isinstance(item, dict):
            return False
        if "dn" not in item:
            return False
        if not is_ldap_dn(item["dn"]):
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
    if "dn" not in value or not is_ldap_dn(value["dn"]):
        return False

    # Check other attributes
    for key, val in value.items():
        if key == "dn":
            continue
        if not isinstance(key, str):
            return False
        # Entry data can contain various types
        if not isinstance(val, (str, bytes, list, int, bool)):
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
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def is_bytes_list(value: object) -> TypeGuard[list[bytes]]:
    """Type guard for list of bytes.

    Args:
        value: Value to check

    Returns:
        True if value is a list of bytes

    """
    return isinstance(value, list) and all(isinstance(item, bytes) for item in value)


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
    # Fallback: convert each item to string
    return [str(item) for item in value] if isinstance(value, list) else [str(value)]


def ensure_ldap_dn(value: object) -> TLdapDn:
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
