"""LDAP type guards for flext-ldap.

This module provides type guard functions for LDAP operations,
following FLEXT architectural patterns and Python 3.13+ typing features.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldap.typings import FlextLdapTypes

if TYPE_CHECKING:
    from typing import TypeGuard


class FlextLdapTypeGuards:
    """LDAP type guard functions for runtime type checking."""

    @staticmethod
    def ensure_string_list(value: object) -> list[str]:
        """Ensure value is a list of strings, converting if necessary."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            # Check if all items are strings
            if all(isinstance(item, str) for item in value):
                return value
            # Convert non-string items to strings
            return [str(item) for item in value]
        # Convert other types to single-item list
        return [str(value)]

    @staticmethod
    def ensure_ldap_dn(value: object) -> str:
        """Ensure value is a valid LDAP DN string."""
        if not isinstance(value, str):
            msg = f"LDAP DN must be a string, got {type(value)}"
            raise TypeError(msg)

        if not value.strip():
            msg = "LDAP DN cannot be empty"
            raise ValueError(msg)

        # Check if DN has at least one '=' sign
        if "=" not in value:
            msg = "LDAP DN must contain at least one '=' sign"
            raise ValueError(msg)

        # Basic validation - check for proper format
        parts = value.split(",")
        for dn_part in parts:
            stripped_part = dn_part.strip()
            if not stripped_part:
                msg = "LDAP DN cannot have empty components"
                raise ValueError(msg)
            if "=" not in stripped_part:
                msg = "Each LDAP DN component must contain '='"
                raise ValueError(msg)
            attr, val = stripped_part.split("=", 1)
            if not attr.strip():
                msg = "LDAP DN attribute name cannot be empty"
                raise ValueError(msg)
            if not val.strip():
                msg = "LDAP DN attribute value cannot be empty"
                raise ValueError(msg)

        return value.strip()

    @staticmethod
    def has_error_attribute(obj: object) -> TypeGuard[object]:
        """Check if object has an 'error' attribute."""
        return hasattr(obj, "error")

    @staticmethod
    def has_is_success_attribute(obj: object) -> TypeGuard[object]:
        """Check if object has an 'is_success' attribute."""
        return hasattr(obj, "is_success")

    @staticmethod
    def is_connection_result(obj: object) -> TypeGuard[object]:
        """Check if object is a connection result type."""
        return (
            isinstance(obj, dict)
            and "server" in obj
            and "port" in obj
            and "use_ssl" in obj
        )

    @staticmethod
    def is_bytes_list(obj: object) -> TypeGuard[list[bytes]]:
        """Check if object is a list of bytes."""
        return isinstance(obj, list) and all(isinstance(item, bytes) for item in obj)

    @staticmethod
    def is_string_list(obj: object) -> TypeGuard[list[str]]:
        """Check if object is a list of strings."""
        return isinstance(obj, list) and all(isinstance(item, str) for item in obj)

    @staticmethod
    def is_ldap_entry_data(obj: object) -> TypeGuard[FlextLdapTypes.Entry.Data]:
        """Check if object is valid LDAP entry data."""
        if not isinstance(obj, dict):
            return False

        # Check if it has required LDAP entry structure
        if "dn" not in obj:
            return False

        # Check if attributes is a dict if present
        return not ("attributes" in obj and not isinstance(obj["attributes"], dict))

    @staticmethod
    def is_ldap_dn(obj: object) -> TypeGuard[str]:
        """Check if object is a valid LDAP DN string."""
        if not isinstance(obj, str):
            return False

        if not obj.strip():
            return False

        # Check if DN has at least one '=' sign
        if "=" not in obj:
            return False

        # Basic validation - check for proper format
        try:
            parts = obj.split(",")
            for dn_part in parts:
                stripped_part = dn_part.strip()
                if not stripped_part:
                    return False
                if "=" not in stripped_part:
                    return False
                attr, val = stripped_part.split("=", 1)
                if not attr.strip() or not val.strip():
                    return False
            return True
        except (ValueError, IndexError):
            return False

    @staticmethod
    def is_ldap_attribute_value(
        obj: object,
    ) -> TypeGuard[FlextLdapTypes.Entry.AttributeValue]:
        """Check if object is a valid LDAP attribute value."""
        return isinstance(obj, (str, bytes)) or (
            isinstance(obj, list)
            and all(isinstance(item, (str, bytes)) for item in obj)
        )

    @staticmethod
    def is_ldap_attributes_dict(
        obj: object,
    ) -> TypeGuard[FlextLdapTypes.Entry.AttributeDict]:
        """Check if object is a valid LDAP attributes dictionary."""
        if not isinstance(obj, dict):
            return False

        for key, value in obj.items():
            if not isinstance(key, str):
                return False
            if not FlextLdapTypeGuards.is_ldap_attribute_value(value):
                return False

        return True

    @staticmethod
    def is_ldap_search_result(obj: object) -> TypeGuard[FlextLdapTypes.Search.Result]:
        """Check if object is a valid LDAP search result."""
        if not isinstance(obj, list):
            return False

        for item in obj:
            if not isinstance(item, dict):
                return False
            if not FlextLdapTypeGuards.is_ldap_entry_data(item):
                return False

        return True
