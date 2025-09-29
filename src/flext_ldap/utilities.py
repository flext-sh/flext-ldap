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

from __future__ import annotations

from typing import Sequence

from flext_core import FlextResult, FlextUtilities


class FlextLdapUtilities(FlextUtilities):
    """Unified LDAP utilities class extending FlextUtilities with LDAP-specific functionality.

    This class extends the base FlextUtilities with LDAP-specific utility functions,
    type guards, and domain-specific processing following FLEXT domain separation patterns.
    """

    # =========================================================================
    # CONVENIENCE METHODS - Direct access to nested class functionality
    # =========================================================================

    @staticmethod
    def normalize_dn(dn: str) -> FlextResult[str]:
        """Normalize LDAP DN by removing extra spaces."""
        return FlextLdapUtilities.Processing.normalize_dn(dn)

    @staticmethod
    def normalize_filter(filter_str: str) -> FlextResult[str]:
        """Normalize LDAP filter by removing extra spaces."""
        return FlextLdapUtilities.Processing.normalize_filter(filter_str)

    @staticmethod
    def normalize_attributes(attributes: list[str]) -> FlextResult[list[str]]:
        """Normalize LDAP attributes list by removing empty values."""
        return FlextLdapUtilities.Processing.normalize_attributes(attributes)

    @staticmethod
    def normalize_attribute_name(attribute_name: str) -> str:
        """Normalize LDAP attribute name by removing extra spaces."""
        return FlextLdapUtilities.Processing.normalize_attribute_name(attribute_name)

    @staticmethod
    def normalize_object_class(object_class: str) -> str:
        """Normalize LDAP object class name by removing extra spaces."""
        return FlextLdapUtilities.Processing.normalize_object_class(object_class)

    @staticmethod
    def is_ldap_dn(value: object) -> bool:
        """Check if value is a valid LDAP DN."""
        return FlextLdapUtilities.TypeGuards.is_ldap_dn(value)

    @staticmethod
    def is_ldap_filter(value: object) -> bool:
        """Check if value is a valid LDAP filter."""
        if not isinstance(value, str):
            return False
        # Basic filter validation
        return bool(value.strip() and ("=" in value or value.startswith("(")))

    @staticmethod
    def is_string_list(value: object) -> bool:
        """Check if value is a list of strings."""
        return FlextLdapUtilities.TypeGuards.is_string_list(value)

    @staticmethod
    def is_bytes_list(value: object) -> bool:
        """Check if value is a list of bytes."""
        return FlextLdapUtilities.TypeGuards.is_bytes_list(value)

    @staticmethod
    def is_ldap_attribute_value(value: object) -> bool:
        """Check if value is a valid LDAP attribute value."""
        return FlextLdapUtilities.TypeGuards.is_ldap_attribute_value(value)

    @staticmethod
    def is_ldap_attributes_dict(value: object) -> bool:
        """Check if value is a valid LDAP attributes dictionary."""
        return FlextLdapUtilities.TypeGuards.is_ldap_attributes_dict(value)

    @staticmethod
    def is_ldap_entry_data(value: object) -> bool:
        """Check if value is valid LDAP entry data."""
        return FlextLdapUtilities.TypeGuards.is_ldap_entry_data(value)

    @staticmethod
    def is_ldap_search_result(value: object) -> bool:
        """Check if value is a valid LDAP search result."""
        return FlextLdapUtilities.TypeGuards.is_ldap_search_result(value)

    @staticmethod
    def is_connection_result(value: object) -> bool:
        """Check if value is a valid connection result."""
        return FlextLdapUtilities.TypeGuards.is_connection_result(value)

    @staticmethod
    def dict_to_attributes(
        attributes_dict: dict[str, object],
    ) -> FlextResult[tuple[list[str], list[object]]]:
        """Convert dictionary to LDAP attributes format."""
        return FlextLdapUtilities.Conversion.dict_to_attributes(attributes_dict)

    @staticmethod
    def attributes_to_dict(
        attribute_names: Sequence[str], attribute_values: list[object]
    ) -> FlextResult[dict[str, str]]:
        """Convert LDAP attributes to dictionary format."""
        return FlextLdapUtilities.Conversion.attributes_to_dict(
            attribute_names, attribute_values
        )

    # =========================================================================
    # TYPE GUARDS - LDAP-specific type checking utilities
    # =========================================================================

    class TypeGuards(FlextUtilities.TypeGuards):
        """LDAP type guard functions for runtime type checking."""

        @staticmethod
        def ensure_string_list(value: object) -> list[str]:
            """Ensure value is a list of strings, converting as needed."""
            if isinstance(value, str):
                return [value]
            if isinstance(value, list):
                return [str(item) for item in value]
            return [str(value)]

        @staticmethod
        def is_string_list(value: object) -> bool:
            """Check if value is a list of strings."""
            if not isinstance(value, list):
                return False
            return all(isinstance(item, str) for item in value)

        @staticmethod
        def is_bytes_list(value: object) -> bool:
            """Check if value is a list of bytes."""
            if not isinstance(value, list):
                return False
            return all(isinstance(item, bytes) for item in value)

        @staticmethod
        def is_ldap_dn(value: object) -> bool:
            """Check if value is a valid LDAP DN."""
            if not isinstance(value, str):
                return False

            dn = value.strip()
            if not dn:
                return False

            # Must contain at least one '='
            if "=" not in dn:
                return False

            # Check for empty components
            parts = dn.split(",")
            for part in parts:
                stripped_part = part.strip()
                if not stripped_part:
                    return False
                if "=" not in part:
                    return False
                attr_name, _ = part.split("=", 1)
                if not attr_name.strip():
                    return False
                # Note: Empty attribute values are valid in LDAP DNs

            return True

        @staticmethod
        def is_ldap_attribute_value(value: object) -> bool:
            """Check if value is a valid LDAP attribute value."""
            if isinstance(value, (str, bytes)):
                return True
            if isinstance(value, list):
                # List must contain only strings or bytes
                return all(isinstance(item, (str, bytes)) for item in value)
            return False

        @staticmethod
        def is_ldap_attributes_dict(value: object) -> bool:
            """Check if value is a valid LDAP attributes dictionary."""
            if not isinstance(value, dict):
                return False
            # All keys should be strings, values should be strings, bytes, or lists
            for key, val in value.items():
                if not isinstance(key, str):
                    return False
                if isinstance(val, list):
                    # List values must contain only strings or bytes
                    if not all(isinstance(item, (str, bytes)) for item in val):
                        return False
                elif not isinstance(val, (str, bytes)):
                    return False
            return True

        @staticmethod
        def is_ldap_entry_data(value: object) -> bool:
            """Check if value is valid LDAP entry data."""
            if not isinstance(value, dict):
                return False
            # Must have dn key
            if "dn" not in value:
                return False
            # If attributes key exists, it must be a dict
            if "attributes" in value:
                return isinstance(value["attributes"], dict)
            return True

        @staticmethod
        def is_ldap_search_result(value: object) -> bool:
            """Check if value is a valid LDAP search result."""
            if not isinstance(value, list):
                return False
            # All items should be valid entry data
            return all(
                FlextLdapUtilities.TypeGuards.is_ldap_entry_data(item) for item in value
            )

        @staticmethod
        def ensure_ldap_dn(value: object) -> str:
            """Ensure value is a valid LDAP DN."""
            if not isinstance(value, str):
                error_msg = "DN must be a string"
                raise TypeError(error_msg)

            dn = value.strip()
            if not dn:
                error_msg = "DN cannot be empty"
                raise ValueError(error_msg)

            # Basic DN validation
            if "=" not in dn:
                error_msg = "DN must contain at least one '=' character"
                raise ValueError(error_msg)

            # Check for empty components
            parts = dn.split(",")
            for part in parts:
                stripped_part = part.strip()
                if not stripped_part:
                    error_msg = "DN cannot have empty components"
                    raise ValueError(error_msg)
                if "=" not in part:
                    error_msg = "DN component must contain '='"
                    raise ValueError(error_msg)
                attr_name, _attr_value = part.split("=", 1)
                if not attr_name.strip():
                    error_msg = "DN attribute name cannot be empty"
                    raise ValueError(error_msg)
                # Note: Empty attribute values are valid in LDAP DNs (e.g., cn=,dc=example)

            return dn

        @staticmethod
        def is_connection_result(value: object) -> bool:
            """Check if value is a connection result."""
            if not isinstance(value, dict):
                return False
            required_fields = ["server", "port", "use_ssl"]
            return all(field in value for field in required_fields)

        @staticmethod
        def has_error_attribute(value: object) -> bool:
            """Check if value has an error attribute."""
            return hasattr(value, "error")

        @staticmethod
        def has_is_success_attribute(value: object) -> bool:
            """Check if value has an is_success attribute."""
            return hasattr(value, "is_success")

    # =========================================================================
    # LDAP-SPECIFIC PROCESSING UTILITIES
    # =========================================================================

    class Processing(FlextUtilities.Processing):
        """LDAP data processing utilities."""

        @staticmethod
        def normalize_dn(dn: str) -> FlextResult[str]:
            """Normalize LDAP DN by removing extra spaces."""
            if not dn:
                return FlextResult[str].fail("DN must be a non-empty string")
            # Only remove leading/trailing spaces, preserve internal spacing
            normalized = dn.strip()
            return FlextResult[str].ok(normalized)

        @staticmethod
        def normalize_filter(filter_str: str) -> FlextResult[str]:
            """Normalize LDAP filter by removing extra spaces."""
            if not filter_str:
                return FlextResult[str].fail("Filter must be a non-empty string")
            # Remove leading/trailing spaces
            normalized = filter_str.strip()
            return FlextResult[str].ok(normalized)

        @staticmethod
        def normalize_attribute_name(attribute_name: str) -> str:
            """Normalize LDAP attribute name by removing extra spaces."""
            if not attribute_name:
                return attribute_name
            # Remove leading/trailing spaces
            return attribute_name.strip()

        @staticmethod
        def normalize_object_class(object_class: str) -> str:
            """Normalize LDAP object class name by removing extra spaces."""
            if not object_class:
                return object_class
            # Remove leading/trailing spaces
            return object_class.strip()

        @staticmethod
        def normalize_attributes(attributes: list[str]) -> FlextResult[list[str]]:
            """Normalize LDAP attributes list by removing empty values and stripping whitespace."""
            if not attributes:
                return FlextResult[list[str]].fail("Attributes list cannot be empty")
            # Strip whitespace and remove empty strings
            result = [attr.strip() for attr in attributes if attr.strip()]
            return FlextResult[list[str]].ok(result)

    # =========================================================================
    # LDAP-SPECIFIC CONVERSION UTILITIES
    # =========================================================================

    class Conversion(FlextUtilities.TypeConversions):
        """LDAP data conversion utilities."""

        @staticmethod
        def attributes_to_dict(
            attribute_names: Sequence[str], attribute_values: list[object]
        ) -> FlextResult[dict[str, str]]:
            """Convert LDAP attributes to dictionary format."""
            if len(attribute_names) != len(attribute_values):
                return FlextResult[dict[str, str]].fail(
                    f"Attribute names and values length mismatch: {len(attribute_names)} vs {len(attribute_values)}"
                )

            result: dict[str, str] = {}
            for i in range(len(attribute_names)):
                name = attribute_names[i]
                values = attribute_values[i]
                # Convert values to single string format (take first value if list)
                if isinstance(values, str):
                    result[name] = values
                elif isinstance(values, list):
                    if values:
                        result[name] = str(values[0])  # Take first value
                    else:
                        result[name] = ""  # Empty string for empty list
                else:
                    result[name] = str(values)

            return FlextResult[dict[str, str]].ok(result)

        @staticmethod
        def dict_to_attributes(
            attributes_dict: dict[str, object],
        ) -> FlextResult[tuple[list[str], list[object]]]:
            """Convert dictionary to LDAP attributes format."""
            attribute_names: list[str] = []
            attribute_values: list[object] = []

            for name, value in attributes_dict.items():
                attribute_names.append(name)
                # Keep the original value type for attributes_to_dict compatibility
                attribute_values.append(value)

            return FlextResult[tuple[list[str], list[object]]].ok(
                (
                    attribute_names,
                    attribute_values,
                )
            )

    @staticmethod
    def ensure_ldap_dn(dn: str) -> FlextResult[str]:
        """Ensure value is a valid LDAP DN."""
        try:
            validated_dn = FlextLdapUtilities.TypeGuards.ensure_ldap_dn(dn)
            return FlextResult[str].ok(validated_dn)
        except (TypeError, ValueError) as e:
            return FlextResult[str].fail(str(e))
        except Exception as e:
            return FlextResult[str].fail(f"DN validation failed: {e}")

    @staticmethod
    def ensure_string_list(value: object) -> FlextResult[list[str]]:
        """Ensure value is a list of strings."""
        try:
            result = FlextLdapUtilities.TypeGuards.ensure_string_list(value)
            return FlextResult[list[str]].ok(result)
        except Exception as e:
            return FlextResult[list[str]].fail(f"String list conversion failed: {e}")


# Export the main utilities class
__all__ = [
    "FlextLdapUtilities",
]
