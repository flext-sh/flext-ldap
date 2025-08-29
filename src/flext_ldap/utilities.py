"""FlextLdapUtilities - Extending flext-core FlextUtilities with LDAP-specific functionality.

This module extends the generic FlextUtilities from flext-core with LDAP-specific
utility functions, following FLEXT architectural patterns.

Examples:
    Using flext-core utilities directly::

        from flext_core import FlextUtilities

        # Generic utilities from flext-core
        id_val = FlextUtilities.Generators.generate_id()
        converted = (
            FlextUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
                data
            )
        )

    Using LDAP-specific extensions::

        from flext_ldap.utilities import FlextLdapUtilities

        # LDAP-specific validations
        valid_dn = FlextLdapUtilities.Validation.validate_attribute_name("cn")
        dn_parts = FlextLdapUtilities.DnParser.parse_distinguished_name(dn)

"""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextLogger, FlextResult, FlextUtilities

from flext_ldap.typings import LdapAttributeDict

logger = FlextLogger(__name__)


class FlextLdapUtilities:
    """FlextLdapUtilities using flext-core FlextUtilities with LDAP-specific functionality.

    Uses composition with flext-core FlextUtilities for generic utility functionality
    and adds LDAP-specific extensions, following modern FLEXT architectural patterns.

    LDAP-Specific Extensions:
        - Validation: LDAP attribute name validation, DN validation
        - DnParser: Distinguished Name parsing and manipulation
        - LdapSpecific: LDAP-only operations not in generic utilities
        - LdapConverters: LDAP-specific data conversion utilities

    Generic Functionality (via FlextUtilities):
        - FlextUtilities.Generators: ID, timestamp, correlation ID generation
        - FlextUtilities.TextProcessor: Text processing utilities
        - FlextUtilities.Performance: Performance tracking and caching
        - FlextUtilities.Conversions: Type conversions
        - FlextUtilities.Formatters: Data formatting
    """

    # ==========================================================================
    # LDAP-SPECIFIC NESTED CLASSES - Extensions beyond generic functionality
    # ==========================================================================

    class Validation:
        """LDAP-specific validation utilities extending generic validations."""

        # LDAP attribute name pattern (RFC 2252)
        ATTRIBUTE_NAME_PATTERN: ClassVar[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

        @classmethod
        def validate_attribute_name(cls, name: str) -> FlextResult[str]:
            """Validate LDAP attribute name according to RFC 2252.

            Args:
                name: Attribute name to validate

            Returns:
                FlextResult containing validated name or error

            """
            if not name or not isinstance(name, str):
                return FlextResult[str].fail("Attribute name cannot be empty")

            # Use flext-core text processing
            normalized = FlextUtilities.TextProcessor.clean_text(name.strip())

            if not re.match(cls.ATTRIBUTE_NAME_PATTERN, normalized):
                return FlextResult[str].fail(
                    f"Invalid LDAP attribute name: {name}. "
                    "Must start with letter and contain only letters, numbers, and hyphens."
                )

            return FlextResult[str].ok(normalized)

        @classmethod
        def validate_dn_component(cls, component: str) -> FlextResult[str]:
            """Validate DN component (e.g., 'cn=value').

            Args:
                component: DN component to validate

            Returns:
                FlextResult containing validated component or error

            """
            if not component or not isinstance(component, str):
                return FlextResult[str].fail("DN component cannot be empty")

            # Use flext-core text processing
            normalized = FlextUtilities.TextProcessor.clean_text(component.strip())

            if "=" not in normalized:
                return FlextResult[str].fail(
                    f"Invalid DN component: {component}. Must contain '='"
                )

            attr, value = normalized.split("=", 1)
            if not attr or not value:
                return FlextResult[str].fail(
                    f"Invalid DN component: {component}. Empty attribute or value"
                )

            return FlextResult[str].ok(normalized)

    class DnParser:
        """Distinguished Name parsing and manipulation utilities."""

        @staticmethod
        def parse_distinguished_name(dn: str) -> FlextResult[dict[str, str]]:
            """Parse DN into attribute-value pairs.

            Args:
                dn: Distinguished Name to parse

            Returns:
                FlextResult containing parsed DN components or error

            """
            if not dn or not isinstance(dn, str):
                return FlextResult[dict[str, str]].fail("DN cannot be empty")

            try:
                # Use flext-core text processing for normalization
                normalized_dn = FlextUtilities.TextProcessor.clean_text(dn.strip())

                components = normalized_dn.split(",")
                parsed: dict[str, str] = {}

                for component in components:
                    validation_result = (
                        FlextLdapUtilities.Validation.validate_dn_component(component)
                    )
                    if not validation_result.is_success:
                        return FlextResult[dict[str, str]].fail(
                            validation_result.error or "Invalid DN component"
                        )

                    attr, value = component.strip().split("=", 1)
                    parsed[attr.lower()] = value.strip()

                return FlextResult[dict[str, str]].ok(parsed)

            except Exception as e:
                return FlextResult[dict[str, str]].fail(f"Failed to parse DN: {e}")

        @staticmethod
        def get_parent_dn(dn: str) -> FlextResult[str]:
            """Get parent DN from child DN.

            Args:
                dn: Child DN

            Returns:
                FlextResult containing parent DN or error

            """
            if not dn or not isinstance(dn, str):
                return FlextResult[str].fail("DN cannot be empty")

            try:
                # Use flext-core text processing
                normalized_dn = FlextUtilities.TextProcessor.clean_text(dn.strip())
                components = normalized_dn.split(",", 1)

                min_dn_components = 2
                if len(components) < min_dn_components:
                    return FlextResult[str].fail("DN has no parent (already at root)")

                return FlextResult[str].ok(components[1].strip())

            except Exception as e:
                return FlextResult[str].fail(f"Failed to get parent DN: {e}")

        @staticmethod
        def get_rdn(dn: str) -> FlextResult[str]:
            """Get Relative Distinguished Name (first component).

            Args:
                dn: Full DN

            Returns:
                FlextResult containing RDN or error

            """
            if not dn or not isinstance(dn, str):
                return FlextResult[str].fail("DN cannot be empty")

            try:
                # Use flext-core text processing
                normalized_dn = FlextUtilities.TextProcessor.clean_text(dn.strip())
                rdn = normalized_dn.split(",", 1)[0].strip()

                return FlextResult[str].ok(rdn)

            except Exception as e:
                return FlextResult[str].fail(f"Failed to get RDN: {e}")

    class LdapSpecific:
        """LDAP-specific utilities not available in generic utilities."""

        @staticmethod
        def build_search_filter(
            base_class: str = "person", additional_filters: dict[str, str] | None = None
        ) -> str:
            """Build LDAP search filter from components.

            Args:
                base_class: Base object class
                additional_filters: Additional attribute filters

            Returns:
                Properly formatted LDAP search filter

            """
            filters = [f"(objectClass={base_class})"]

            if additional_filters:
                for attr, value in additional_filters.items():
                    # Use flext-core text processing for safe values
                    safe_value = FlextUtilities.TextProcessor.clean_text(str(value))
                    filters.append(f"({attr}={safe_value})")

            if len(filters) == 1:
                return filters[0]
            return f"(&{''.join(filters)})"

        @staticmethod
        def normalize_ldap_attributes(
            raw_attributes: dict[str, object],
        ) -> FlextResult[LdapAttributeDict]:
            """Normalize raw attributes to LDAP format using flext-core processing.

            Args:
                raw_attributes: Raw attribute dictionary

            Returns:
                FlextResult containing normalized LDAP attributes

            """
            try:
                if not isinstance(raw_attributes, dict):
                    return FlextResult[LdapAttributeDict].fail(
                        "raw_attributes must be a dictionary"
                    )

                # Convert each attribute using flext-core utilities
                normalized: LdapAttributeDict = {}

                for key, value in raw_attributes.items():
                    # Validate attribute name using our LDAP-specific validation
                    attr_validation = (
                        FlextLdapUtilities.Validation.validate_attribute_name(key)
                    )
                    if not attr_validation.is_success:
                        return FlextResult[LdapAttributeDict].fail(
                            f"Invalid attribute name '{key}': {attr_validation.error}"
                        )

                    attr_name = attr_validation.value

                    # Convert value to LDAP format
                    if value is None:
                        continue  # Skip None values
                    if isinstance(value, list):
                        # Convert list values to strings
                        str_values = []
                        for item in value:
                            str_val = FlextUtilities.TextProcessor.safe_string(item)
                            if str_val:  # Only add non-empty strings
                                str_values.append(str_val)
                        if str_values:  # Only add attribute if it has values
                            normalized[attr_name] = str_values
                    else:
                        # Convert single value to string
                        str_val = FlextUtilities.TextProcessor.safe_string(value)
                        if str_val:  # Only add non-empty strings
                            normalized[attr_name] = str_val

                return FlextResult[LdapAttributeDict].ok(normalized)

            except Exception as e:
                return FlextResult[LdapAttributeDict].fail(
                    f"Failed to normalize attributes: {e}"
                )

    class LdapConverters:
        """LDAP-specific data conversion utilities using flext-core."""

        @staticmethod
        def safe_convert_external_dict_to_ldap_attributes(
            source_dict: object,
        ) -> dict[str, str | list[str]]:
            """Convert external dictionary to LDAP attribute format.

            Args:
                source_dict: External dictionary or object to convert

            Returns:
                Dictionary with LDAP-compatible attribute values

            """
            if not isinstance(source_dict, dict):
                return {}

            result: dict[str, str | list[str]] = {}

            for key, value in source_dict.items():
                # Validate attribute name
                attr_validation = FlextLdapUtilities.Validation.validate_attribute_name(
                    str(key)
                )
                if not attr_validation.is_success:
                    continue  # Skip invalid attribute names

                attr_name = attr_validation.value

                # Convert value to LDAP format
                if value is None:
                    continue  # Skip None values
                if isinstance(value, list):
                    # Convert list values to strings
                    str_values = []
                    for item in value:
                        str_val = FlextUtilities.TextProcessor.safe_string(item)
                        if str_val:  # Only add non-empty strings
                            str_values.append(str_val)
                    if str_values:  # Only add attribute if it has values
                        result[attr_name] = str_values
                else:
                    # Convert single value to string
                    str_val = FlextUtilities.TextProcessor.safe_string(value)
                    if str_val:  # Only add non-empty strings
                        result[attr_name] = str_val

            return result

        @staticmethod
        def safe_convert_value_to_str(value: object) -> str:
            """Convert any value to safe string representation.

            Args:
                value: Value to convert

            Returns:
                String representation of the value

            """
            return FlextUtilities.TextProcessor.safe_string(value)

        @staticmethod
        def safe_convert_list_to_strings(values: list[object]) -> list[str]:
            """Convert list of objects to list of strings.

            Args:
                values: List of values to convert

            Returns:
                List of string representations

            """
            if not isinstance(values, list):
                return []

            result = []
            for value in values:
                str_val = FlextUtilities.TextProcessor.safe_string(value)
                if str_val:  # Only add non-empty strings
                    result.append(str_val)

            return result


# =============================================================================
# LEGACY COMPATIBILITY ALIASES
# =============================================================================

# Maintain backward compatibility with existing code
FlextLdapUtils = FlextLdapUtilities


# Legacy class aliases (if they existed in old code)
class FlextLdapUtilitiesLegacy:
    """Legacy compatibility class redirecting to new structure."""

    @staticmethod
    def validate_attribute_name(name: str) -> FlextResult[str]:
        """Legacy method redirecting to new structure."""
        return FlextLdapUtilities.Validation.validate_attribute_name(name)

    @staticmethod
    def safe_convert_external_dict_to_ldap_attributes(
        source_dict: object,
    ) -> dict[str, str | list[str]]:
        """Legacy method redirecting to flext-core implementation."""
        return FlextLdapUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
            source_dict
        )


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "FlextLdapUtilities",
    "FlextLdapUtilitiesLegacy",  # Legacy compatibility
    "FlextLdapUtils",  # Alias
]
