"""LDAP utilities for flext-ldap domain.

This module provides LDAP-specific utility functions extending FlextUtilities
with domain-specific functionality. Following FLEXT standards, all utilities
are organized under a single FlextLdapUtilities class.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""
# type: ignore[attr-defined]

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextResult, FlextUtilities

if TYPE_CHECKING:
    from typing import TypeGuard

    from flext_ldap.typings import FlextLdapTypes


class FlextLdapUtilities(FlextUtilities):
    """Unified LDAP utilities class extending FlextUtilities with LDAP-specific functionality.

    This class extends the base FlextUtilities with LDAP-specific utility functions,
    type guards, and domain-specific processing following FLEXT domain separation patterns.
    """

    # =========================================================================
    # TYPE GUARDS - LDAP-specific type checking utilities
    # =========================================================================

    class TypeGuards:
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
            # Convert single value to list
            return [str(value)]

        @staticmethod
        def is_valid_dn(value: object) -> TypeGuard[str]:
            """Type guard to check if value is a valid LDAP DN."""
            if not isinstance(value, str):
                return False
            # Basic DN validation - must contain = and proper structure
            return "=" in value and len(value.strip()) > 0

        @staticmethod
        def is_valid_filter(value: object) -> TypeGuard[str]:
            """Type guard to check if value is a valid LDAP filter."""
            if not isinstance(value, str):
                return False
            # Basic filter validation
            return (
                len(value.strip()) > 0 and not value.strip().startswith("(")
            ) or value.strip().endswith(")")

        @staticmethod
        def is_attribute_dict(
            value: object,
        ) -> TypeGuard[FlextLdapTypes.EntryAttributeDict]:
            """Type guard to check if value is a valid LDAP attribute dictionary."""
            if not isinstance(value, dict):
                return False
            # Check if all keys are strings
            return all(isinstance(k, str) for k in value)

        @staticmethod
        def ensure_ldap_dn(value: object) -> str:
            """Ensure value is a valid LDAP DN, raising TypeError if not."""
            if not isinstance(value, str):
                error_msg = f"Expected string, got {type(value).__name__}"
                raise TypeError(error_msg)
            if not value.strip():
                error_msg = "DN cannot be empty"
                raise ValueError(error_msg)
            if "=" not in value:
                error_msg = "DN must contain at least one '='"
                raise ValueError(error_msg)
            if ",," in value:
                error_msg = "DN cannot contain empty components"
                raise ValueError(error_msg)
            if value.startswith("=") or value.endswith("="):
                error_msg = "DN component cannot start or end with '='"
                raise ValueError(error_msg)
            return value.strip()

        @staticmethod
        def has_error_attribute(value: object) -> bool:
            """Check if object has an error attribute."""
            return hasattr(value, "error")

        @staticmethod
        def has_is_success_attribute(value: object) -> bool:
            """Check if object has an is_success attribute."""
            return hasattr(value, "is_success")

        @staticmethod
        def is_connection_result(value: object) -> bool:
            """Type guard to check if value is a valid connection result dict."""
            if not isinstance(value, dict):
                return False
            required_keys = {"server", "port", "use_ssl"}
            return required_keys.issubset(value.keys())

        @staticmethod
        def is_bytes_list(value: object) -> bool:
            """Type guard to check if value is a list of bytes."""
            if not isinstance(value, list):
                return False
            return all(isinstance(item, bytes) for item in value)

        @staticmethod
        def is_string_list(value: object) -> bool:
            """Type guard to check if value is a list of strings."""
            if not isinstance(value, list):
                return False
            return all(isinstance(item, str) for item in value)

        @staticmethod
        def is_ldap_entry_data(value: object) -> bool:
            """Type guard to check if value is valid LDAP entry data."""
            if not isinstance(value, dict):
                return False
            # Must have dn
            if "dn" not in value:
                return False
            # dn must be string
            if not isinstance(value["dn"], str):
                return False
            # attributes is optional, but if present must be dict
            return not (
                "attributes" in value and not isinstance(value["attributes"], dict)
            )

        @staticmethod
        def is_ldap_dn(value: object) -> bool:
            """Type guard to check if value is a valid LDAP DN."""
            if not isinstance(value, str):
                return False
            if not value.strip():
                return False
            if "=" not in value:
                return False
            if ",," in value:
                return False
            return not (value.startswith("=") or value.endswith("="))

        @staticmethod
        def is_ldap_attribute_value(value: object) -> bool:
            """Type guard to check if value is a valid LDAP attribute value."""
            if isinstance(value, (str, bytes)):
                return True
            if isinstance(value, list):
                return all(isinstance(item, (str, bytes)) for item in value)
            return False

        @staticmethod
        def is_ldap_attributes_dict(value: object) -> bool:
            """Type guard to check if value is a valid LDAP attributes dict."""
            if not isinstance(value, dict):
                return False
            # All values must be valid attribute values
            return all(
                FlextLdapUtilities.TypeGuards.is_ldap_attribute_value(v)
                for v in value.values()
            )

        @staticmethod
        def is_ldap_search_result(value: object) -> bool:
            """Type guard to check if value is a valid LDAP search result."""
            if not isinstance(value, list):
                return False
            # All items must be valid LDAP entry data
            return all(
                FlextLdapUtilities.TypeGuards.is_ldap_entry_data(item) for item in value
            )

        @staticmethod
        def is_connection_config_data(
            value: object,
        ) -> TypeGuard[FlextLdapTypes.ConnectionConfigData]:
            """Type guard to check if value is valid ConnectionConfigData."""
            if not isinstance(value, dict):
                return False
            # Check required fields
            required_fields = {"server", "port"}
            if not required_fields.issubset(value.keys()):
                return False
            # Check field types
            return (
                isinstance(value.get("server"), str)
                and isinstance(value.get("port"), int)
                and isinstance(value.get("use_ssl", True), bool)
                and isinstance(value.get("bind_dn", ""), (str, type(None)))
                and isinstance(value.get("bind_password", ""), (str, type(None)))
                and isinstance(value.get("timeout", 30), int)
            )

        @staticmethod
        def is_search_request_data(
            value: object,
        ) -> TypeGuard[FlextLdapTypes.SearchRequestData]:
            """Type guard to check if value is valid SearchRequestData."""
            if not isinstance(value, dict):
                return False
            # Check required fields
            required_fields = {"base_dn", "filter_str"}
            if not required_fields.issubset(value.keys()):
                return False
            # Check field types
            return (
                isinstance(value.get("base_dn"), str)
                and isinstance(value.get("filter_str"), str)
                and isinstance(value.get("scope", "subtree"), str)
                and isinstance(value.get("attributes"), (list, type(None)))
                and isinstance(value.get("size_limit", 1000), int)
                and isinstance(value.get("time_limit", 60), int)
                and isinstance(value.get("page_size"), (int, type(None)))
                and isinstance(value.get("paged_cookie"), (bytes, type(None)))
                and isinstance(value.get("types_only", False), bool)
                and isinstance(value.get("deref_aliases", "never"), str)
            )

    # =========================================================================
    # LDAP-SPECIFIC PROCESSING UTILITIES
    # =========================================================================

    class Processing:
        """LDAP-specific data processing utilities."""

        @staticmethod
        def normalize_dn(dn: str) -> FlextResult[str]:
            """Normalize LDAP DN by removing extra whitespace and standardizing format."""
            try:
                if not dn or not isinstance(dn, str):
                    return FlextResult[str].fail("DN must be a non-empty string")

                # Remove extra whitespace and normalize
                normalized = dn.strip()
                if not normalized:
                    return FlextResult[str].fail(
                        "DN cannot be empty after normalization"
                    )

                return FlextResult[str].ok(normalized)
            except Exception as e:
                return FlextResult[str].fail(f"Failed to normalize DN: {e}")

        @staticmethod
        def normalize_filter(filter_str: str) -> FlextResult[str]:
            """Normalize LDAP filter by removing extra whitespace and standardizing format."""
            try:
                if not filter_str or not isinstance(filter_str, str):
                    return FlextResult[str].fail("Filter must be a non-empty string")

                # Remove extra whitespace and normalize
                normalized = filter_str.strip()
                if not normalized:
                    return FlextResult[str].fail(
                        "Filter cannot be empty after normalization"
                    )

                return FlextResult[str].ok(normalized)
            except Exception as e:
                return FlextResult[str].fail(f"Failed to normalize filter: {e}")

        @staticmethod
        def normalize_attributes(attributes: list[str]) -> FlextResult[list[str]]:
            """Normalize LDAP attribute names by removing extra whitespace."""
            try:
                if not attributes:
                    return FlextResult[list[str]].fail(
                        "Attributes list cannot be empty"
                    )

                normalized = []
                for attr in attributes:
                    normalized_attr = attr.strip()
                    if not normalized_attr:
                        return FlextResult[list[str]].fail(
                            f"Empty attribute name: {attr}"
                        )

                    normalized.append(normalized_attr)

                return FlextResult[list[str]].ok(normalized)
            except Exception as e:
                return FlextResult[list[str]].fail(
                    f"Failed to normalize attributes: {e}"
                )

    # =========================================================================
    # LDAP-SPECIFIC CONVERSION UTILITIES
    # =========================================================================

    class Conversion:
        """LDAP-specific data conversion utilities."""

        @staticmethod
        def attributes_to_dict(
            attributes: list[str], values: list[object]
        ) -> FlextResult[dict[str, object]]:
            """Convert parallel lists of attributes and values to a dictionary."""
            try:
                if len(attributes) != len(values):
                    return FlextResult[dict[str, object]].fail(
                        f"Attributes and values lists must have same length: {len(attributes)} vs {len(values)}"
                    )

                result = dict(zip(attributes, values, strict=False))

                return FlextResult[dict[str, object]].ok(result)
            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"Failed to convert attributes to dict: {e}"
                )

        @staticmethod
        def dict_to_attributes(
            attr_dict: dict[str, object],
        ) -> FlextResult[tuple[list[str], list[object]]]:
            """Convert attribute dictionary to parallel lists of attributes and values."""
            try:
                attributes = list(attr_dict.keys())
                values = list(attr_dict.values())

                return FlextResult[tuple[list[str], list[object]]].ok((
                    attributes,
                    values,
                ))
            except Exception as e:
                return FlextResult[tuple[list[str], list[object]]].fail(
                    f"Failed to convert dict to attributes: {e}"
                )


# Export the main utilities class
__all__ = [
    "FlextLdapUtilities",
]
