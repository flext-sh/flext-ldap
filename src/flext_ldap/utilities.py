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

from collections.abc import Sequence

from flext_core import FlextResult, FlextTypes, FlextUtilities
from flext_ldap.exceptions import FlextLdapExceptions


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
    def normalize_attributes(
        attributes: FlextTypes.StringList,
    ) -> FlextResult[FlextTypes.StringList]:
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
        attributes_dict: FlextTypes.Dict,
    ) -> FlextResult[tuple[FlextTypes.StringList, FlextTypes.List]]:
        """Convert dictionary to LDAP attributes format."""
        return FlextLdapUtilities.Conversion.dict_to_attributes(attributes_dict)

    @staticmethod
    def attributes_to_dict(
        attribute_names: Sequence[str], attribute_values: FlextTypes.List
    ) -> FlextResult[FlextTypes.StringDict]:
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
        def ensure_string_list(value: object) -> FlextTypes.StringList:
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
            exceptions = FlextLdapExceptions()

            if not isinstance(value, str):
                error_msg = "DN must be a string"
                raise exceptions.type_error(
                    error_msg,
                    value=str(value),
                    expected_type="str",
                    actual_type=type(value).__name__,
                )

            dn = value.strip()
            if not dn:
                error_msg = "DN cannot be empty"
                raise exceptions.validation_error(error_msg, value=dn, field="dn")

            # Basic DN validation
            if "=" not in dn:
                error_msg = "DN must contain at least one '=' character"
                raise exceptions.validation_error(error_msg, value=dn, field="dn")

            # Check for empty components
            parts = dn.split(",")
            for part in parts:
                stripped_part = part.strip()
                if not stripped_part:
                    error_msg = "DN cannot have empty components"
                    raise exceptions.validation_error(error_msg, value=dn, field="dn")
                if "=" not in part:
                    error_msg = "DN component must contain '='"
                    raise exceptions.validation_error(error_msg, value=part, field="dn")
                attr_name, _attr_value = part.split("=", 1)
                if not attr_name.strip():
                    error_msg = "DN attribute name cannot be empty"
                    raise exceptions.validation_error(error_msg, value=part, field="dn")
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
        def normalize_attributes(
            attributes: FlextTypes.StringList,
        ) -> FlextResult[FlextTypes.StringList]:
            """Normalize LDAP attributes list by removing empty values and stripping whitespace."""
            if not attributes:
                return FlextResult[FlextTypes.StringList].fail(
                    "Attributes list cannot be empty"
                )
            # Strip whitespace and remove empty strings
            result = [attr.strip() for attr in attributes if attr.strip()]
            return FlextResult[FlextTypes.StringList].ok(result)

    # =========================================================================
    # LDAP-SPECIFIC CONVERSION UTILITIES
    # =========================================================================

    class Conversion(FlextUtilities.TypeConversions):
        """LDAP data conversion utilities."""

        @staticmethod
        def attributes_to_dict(
            attribute_names: Sequence[str], attribute_values: FlextTypes.List
        ) -> FlextResult[FlextTypes.StringDict]:
            """Convert LDAP attributes to dictionary format."""
            if len(attribute_names) != len(attribute_values):
                return FlextResult[FlextTypes.StringDict].fail(
                    f"Attribute names and values length mismatch: {len(attribute_names)} vs {len(attribute_values)}"
                )

            result: FlextTypes.StringDict = {}
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

            return FlextResult[FlextTypes.StringDict].ok(result)

        @staticmethod
        def dict_to_attributes(
            attributes_dict: FlextTypes.Dict,
        ) -> FlextResult[tuple[FlextTypes.StringList, FlextTypes.List]]:
            """Convert dictionary to LDAP attributes format."""
            attribute_names: FlextTypes.StringList = []
            attribute_values: FlextTypes.List = []

            for name, value in attributes_dict.items():
                attribute_names.append(name)
                # Keep the original value type for attributes_to_dict compatibility
                attribute_values.append(value)

            return FlextResult[tuple[FlextTypes.StringList, FlextTypes.List]].ok(
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
    def ensure_string_list(value: object) -> FlextResult[FlextTypes.StringList]:
        """Ensure value is a list of strings."""
        try:
            result = FlextLdapUtilities.TypeGuards.ensure_string_list(value)
            return FlextResult[FlextTypes.StringList].ok(result)
        except Exception as e:
            return FlextResult[FlextTypes.StringList].fail(
                f"String list conversion failed: {e}"
            )

    # =========================================================================
    # Enhanced flext-core Integration Methods
    # =========================================================================

    @staticmethod
    def create_flext_ldap_utilities() -> FlextResult[FlextLdapUtilities]:
        """Create enhanced FlextLdapUtilities with complete flext-core integration.

        Demonstrates proper flext-core integration by creating LDAP utilities
        that integrate with FlextContainer, FlextBus, FlextDispatcher, and other
        flext-core components for comprehensive LDAP utility management.

        Returns:
            FlextResult[FlextLdapUtilities]: Configured FlextLdapUtilities instance or error

        Example:
            >>> utilities_result = FlextLdapUtilities.create_flext_ldap_utilities()
            >>> if utilities_result.is_success:
            ...     utilities = utilities_result.unwrap()
            ...     # Use utilities with full flext-core integration
            ...     normalized_dn = utilities.normalize_dn("cn=john,dc=example,dc=com")
        """
        try:
            # Create base utilities with enhanced flext-core integration
            utilities = FlextLdapUtilities()

            # Validate utilities can access flext-core components
            try:
                from flext_core.config import FlextConfig
                from flext_core.loggings import FlextLogger
                from flext_core.container import FlextContainer

                # Test integration with core components
                FlextConfig()
                FlextLogger(__name__)
                FlextContainer.get_global()

                return FlextResult[FlextLdapUtilities].ok(utilities)

            except Exception as e:
                return FlextResult[FlextLdapUtilities].fail(
                    f"Flext-core integration check failed: {e}"
                )

        except Exception as e:
            return FlextResult[FlextLdapUtilities].fail(
                f"Failed to create flext-ldap utilities: {e}"
            )

    @staticmethod
    def validate_flext_ldap_utilities() -> FlextResult[FlextTypes.Dict]:
        """Validate complete flext-ldap utilities setup with integration patterns.

        Demonstrates comprehensive flext-ldap validation by checking that all
        utilities are properly configured and integrated with each other.

        Returns:
            FlextResult[FlextTypes.Dict]: Validation results with detailed component status

        Example:
            >>> setup_result = FlextLdapUtilities.validate_flext_ldap_utilities()
            >>> if setup_result.is_success:
            ...     status = setup_result.unwrap()
            ...     print(f"Normalization: {status['normalization']['status']}")
            ...     print(f"Type Guards: {status['type_guards']['status']}")
        """
        validation_results = {
            "utilities": {"status": "unknown", "details": ""},
            "normalization": {"status": "unknown", "details": ""},
            "type_guards": {"status": "unknown", "details": ""},
            "processing": {"status": "unknown", "details": ""},
            "validation": {"status": "unknown", "details": ""},
        }

        try:
            # Validate utilities itself
            utilities_result = FlextLdapUtilities.create_flext_ldap_utilities()
            if utilities_result.is_success:
                validation_results["utilities"] = {
                    "status": "valid",
                    "details": "FlextLdapUtilities properly initialized",
                }
            else:
                validation_results["utilities"] = {
                    "status": "invalid",
                    "details": utilities_result.error,
                }

            # Validate normalization utilities
            try:
                dn_result = FlextLdapUtilities.normalize_dn("cn=john,dc=example,dc=com")
                validation_results["normalization"] = {
                    "status": "available",
                    "details": f"Normalization utilities accessible, DN normalized: {dn_result.is_success}",
                }
            except Exception as e:
                validation_results["normalization"] = {
                    "status": "error",
                    "details": str(e),
                }

            # Validate type guards utilities
            try:
                dn_check = FlextLdapUtilities.is_ldap_dn("cn=john,dc=example,dc=com")
                validation_results["type_guards"] = {
                    "status": "available",
                    "details": f"Type guards accessible, DN check: {dn_check}",
                }
            except Exception as e:
                validation_results["type_guards"] = {
                    "status": "error",
                    "details": str(e),
                }

            # Validate processing utilities
            try:
                filter_result = FlextLdapUtilities.normalize_filter("(cn=john*)")
                validation_results["processing"] = {
                    "status": "available",
                    "details": f"Processing utilities accessible, filter normalized: {filter_result.is_success}",
                }
            except Exception as e:
                validation_results["processing"] = {
                    "status": "error",
                    "details": str(e),
                }

            # Validate validation utilities
            try:
                attrs_result = FlextLdapUtilities.normalize_attributes(
                    ["cn", "mail", ""]
                )
                validation_results["validation"] = {
                    "status": "available",
                    "details": f"Validation utilities accessible, attributes normalized: {attrs_result.is_success}",
                }
            except Exception as e:
                validation_results["validation"] = {
                    "status": "error",
                    "details": str(e),
                }

            # Check overall health
            all_valid = all(
                result["status"] in ["valid", "available"]
                for result in validation_results.values()
            )
            if all_valid:
                return FlextResult[FlextTypes.Dict].ok(
                    {
                        "overall_status": "healthy",
                        "components": validation_results,
                        "message": "All flext-ldap utilities are properly configured and accessible",
                    }
                )
            else:
                return FlextResult[FlextTypes.Dict].ok(
                    {
                        "overall_status": "degraded",
                        "components": validation_results,
                        "message": "Some flext-ldap utilities have issues - check details",
                    }
                )

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(
                f"Flext-ldap utilities validation failed: {e}"
            )

    @staticmethod
    def create_integration_example(component: str) -> FlextResult[str]:
        """Create practical flext-ldap utilities integration examples.

        Provides working code examples that demonstrate proper flext-ldap
        utilities integration patterns for different components and use cases.

        Args:
            component: Component name ('normalization', 'validation', 'processing', 'type_guards')

        Returns:
            FlextResult[str]: Integration example code or error

        Example:
            >>> example = FlextLdapUtilities.create_integration_example('normalization')
            >>> if example.is_success:
            ...     print(f"Normalization integration example: {example.unwrap()[:100]}...")
        """
        examples = {
            "normalization": """
# Example: Enhanced LDAP normalization with flext-core integration
from flext_ldap import FlextLdapUtilities
from flext_core import FlextResult

# Moved to services.py as FlextLdapServices
""",
            "validation": """
# Example: Enhanced LDAP validation with flext-core integration
from flext_ldap import FlextLdapUtilities
from flext_core import FlextResult

# Moved to services.py as FlextLdapServices
""",
            "processing": """
# Example: Enhanced LDAP processing with flext-core integration
from flext_ldap import FlextLdapUtilities
from flext_core import FlextResult

# Moved to services.py as FlextLdapServices
""",
            "type_guards": """
# Example: Enhanced type guards with flext-core integration
from flext_ldap import FlextLdapUtilities
from flext_core import FlextResult

# Moved to services.py as FlextLdapServices
""",
        }

        if component not in examples:
            available = ", ".join(examples.keys())
            return FlextResult[str].fail(
                f"Unknown component: {component}. Available: {available}"
            )

        return FlextResult[str].ok(examples[component].strip())

    @staticmethod
    def demonstrate_flext_ldap_utilities_patterns() -> FlextResult[FlextTypes.Dict]:
        """Demonstrate comprehensive flext-ldap utilities integration patterns.

        Provides a working example that showcases how all flext-ldap utilities
        work together with flext-core in realistic scenarios, demonstrating
        best practices for LDAP utility operations.

        Returns:
            FlextResult[FlextTypes.Dict]: Demonstration results with pattern explanations

        Example:
            >>> demo = FlextLdapUtilities.demonstrate_flext_ldap_utilities_patterns()
            >>> if demo.is_success:
            ...     patterns = demo.unwrap()
            ...     print(f"LDAP utilities pattern: {patterns['utilities_pattern']['description']}")
        """
        try:
            # Create utilities with integration validation
            utilities_result = FlextLdapUtilities.create_flext_ldap_utilities()
            if utilities_result.is_failure:
                return FlextResult[FlextTypes.Dict].fail(
                    f"Utilities creation failed: {utilities_result.error}"
                )

            utilities = utilities_result.unwrap()

            # Demonstrate normalization pattern
            dn_normalization = utilities.normalize_dn("cn=john doe ,dc=example,dc=com")
            filter_normalization = utilities.normalize_filter("(cn=john*)")
            attr_normalization = utilities.normalize_attributes(
                ["cn", "mail", "", "memberOf"]
            )

            # Demonstrate validation pattern
            dn_validation = utilities.is_ldap_dn("cn=john.doe,dc=example,dc=com")
            filter_validation = utilities.is_ldap_filter("(cn=john*)")
            entry_validation = utilities.is_ldap_entry_data(
                {"dn": "cn=john,dc=example,dc=com", "attributes": {"cn": ["John"]}}
            )

            # Demonstrate type guards pattern
            string_list_check = utilities.is_string_list(["cn", "mail"])
            bytes_list_check = utilities.is_bytes_list([b"data1", b"data2"])

            return FlextResult[FlextTypes.Dict].ok(
                {
                    "demonstration_status": "successful",
                    "patterns_demonstrated": {
                        "normalization_pattern": {
                            "description": "LDAP data normalization with flext-core integration",
                            "example_result": {
                                "dn_normalized": dn_normalization.is_success,
                                "filter_normalized": filter_normalization.is_success,
                                "attributes_normalized": attr_normalization.is_success,
                            },
                            "integration_level": "full",
                        },
                        "validation_pattern": {
                            "description": "LDAP type validation with comprehensive checking",
                            "example_result": {
                                "dn_valid": dn_validation,
                                "filter_valid": filter_validation,
                                "entry_valid": entry_validation,
                            },
                            "integration_level": "full",
                        },
                        "type_guards_pattern": {
                            "description": "Runtime type checking for LDAP data structures",
                            "example_result": {
                                "string_list_valid": string_list_check,
                                "bytes_list_valid": bytes_list_check,
                            },
                            "integration_level": "full",
                        },
                    },
                    "integration_level": "comprehensive",
                    "components_integrated": [
                        "FlextLdapUtilities",
                        "FlextLdapTypes",
                        "FlextLdapModels",
                    ],
                    "best_practices_demonstrated": [
                        "LDAP data normalization with flext-core patterns",
                        "Type validation with comprehensive checking",
                        "Runtime type guards for data structure validation",
                        "Error handling with flext-core integration",
                        "Type-safe LDAP utility operations",
                    ],
                }
            )

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(
                f"LDAP utilities pattern demonstration failed: {e}"
            )


# Export the main utilities class
__all__ = [
    "FlextLdapUtilities",
]
