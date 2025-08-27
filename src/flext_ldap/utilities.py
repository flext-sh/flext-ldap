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

from flext_core import FlextResult, FlextUtilities, get_logger

from flext_ldap.typings import LdapAttributeDict

logger = get_logger(__name__)


class FlextLdapUtilities(FlextUtilities):
    """FlextLdapUtilities extending flext-core FlextUtilities with LDAP-specific functionality.

    Inherits all generic utility functionality from flext-core FlextUtilities and adds
    LDAP-specific extensions while avoiding duplication.

    LDAP-Specific Extensions:
        - Validation: LDAP attribute name validation, DN validation
        - DnParser: Distinguished Name parsing and manipulation
        - LdapSpecific: LDAP-only operations not in generic utilities

    Generic Functionality (from flext-core):
        - Generators: ID, timestamp, correlation ID generation
        - LdapConverters: Safe LDAP data conversion (already in flext-core)
        - TextProcessor: Text processing utilities
        - Performance: Performance tracking and caching
        - Conversions: Type conversions
        - Formatters: Data formatting
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
            """Normalize raw attributes to LDAP format using flext-core converters.

            Args:
                raw_attributes: Raw attribute dictionary

            Returns:
                FlextResult containing normalized LDAP attributes

            """
            try:
                # Use flext-core LDAP converters (already implemented!)
                normalized = FlextUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
                    raw_attributes
                )

                # Cast to correct type (flext-core returns dict[str, str | list[str]], we need LdapAttributeDict)
                normalized_typed: LdapAttributeDict = normalized  # type: ignore[assignment]
                return FlextResult[LdapAttributeDict].ok(normalized_typed)

            except Exception as e:
                return FlextResult[LdapAttributeDict].fail(
                    f"Failed to normalize attributes: {e}"
                )


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
        return (
            FlextUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
                source_dict
            )
        )


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "FlextLdapUtilities",
    "FlextLdapUtilitiesLegacy",  # Legacy compatibility
    "FlextLdapUtils",  # Alias
]
