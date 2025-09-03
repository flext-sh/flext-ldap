"""FlextLDAPUtilities - Extending flext-core FlextUtilities with LDAP-specific functionality.

This module extends the generic FlextUtilities from flext-core with LDAP-specific
utility functions, following FLEXT architectural patterns with proper naming.

Examples:
    Using flext-core utilities directly::

        from flext_core import FlextUtilities

        # Generic utilities from flext-core
        id_val = FlextUtilities.Generators.generate_id()
        converted = FlextUtilities.TextProcessor.clean_text(data)

    Using LDAP-specific extensions::

        from flext_ldap.utilities import FlextLDAPUtilities

        # LDAP-specific validations
        valid_dn = FlextLDAPUtilities.Validation.validate_attribute_name("cn")
        dn_parts = FlextLDAPUtilities.DnParser.parse_distinguished_name(dn)

"""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextLogger, FlextResult, FlextUtilities
from ldap3 import Connection

from flext_ldap.typings import LdapAttributeDict

logger = FlextLogger(__name__)


class FlextLDAPUtilities:
    """FlextLDAPUtilities using flext-core FlextUtilities with LDAP-specific functionality.

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

        @staticmethod
        def validate_non_empty_string(value: object, field_name: str = "value") -> str:
            """Validate that string is not empty after stripping whitespace.

            Args:
                value: String to validate
                field_name: Name of the field (for error messages)

            Returns:
                Stripped string

            Raises:
                ValueError: If string is empty after stripping

            """
            if not isinstance(value, str):
                msg = f"Expected string for {field_name}, got {type(value).__name__}"
                raise TypeError(msg)

            stripped = value.strip()
            if not stripped:
                msg = f"{field_name} cannot be empty"
                raise ValueError(msg)

            return stripped

        @staticmethod
        def validate_filter_field(filter_str: str) -> str:
            """Validate LDAP filter field.

            Args:
                filter_str: Filter string to validate

            Returns:
                Validated filter string

            Raises:
                ValueError: If filter is invalid

            """
            return FlextLDAPUtilities.Validation.validate_non_empty_string(
                filter_str, "filter"
            )

        @staticmethod
        def validate_uri_field(uri: str) -> str:
            """Validate URI field.

            Args:
                uri: URI to validate

            Returns:
                Validated URI

            Raises:
                ValueError: If URI is invalid

            """
            return FlextLDAPUtilities.Validation.validate_non_empty_string(uri, "uri")

        @staticmethod
        def validate_base_dn_field(base_dn: str) -> str:
            """Validate base DN field.

            Args:
                base_dn: Base DN to validate

            Returns:
                Validated base DN

            Raises:
                ValueError: If base DN is invalid

            """
            return FlextLDAPUtilities.Validation.validate_non_empty_string(
                base_dn, "base_dn"
            )

        @staticmethod
        def validate_cn_field(cn: str) -> str:
            """Validate CN field.

            Args:
                cn: CN to validate

            Returns:
                Validated CN

            Raises:
                ValueError: If CN is invalid

            """
            return FlextLDAPUtilities.Validation.validate_non_empty_string(cn, "cn")

        @staticmethod
        def validate_attribute_value(value: object) -> bool:
            """Validate LDAP attribute value.

            Args:
                value: Attribute value to validate

            Returns:
                True if valid, False otherwise

            """
            if not isinstance(value, str):
                return False

            # Basic validation - non-empty strings are generally valid
            return len(value.strip()) > 0

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
        def validate_dn(dn: str) -> bool:
            """Validate DN format according to RFC 2253.

            Args:
                dn: Distinguished name to validate

            Returns:
                bool: True if valid, False otherwise

            """
            if not dn or not isinstance(dn, str):
                return False

            try:
                # Basic DN format validation
                normalized_dn = dn.strip()
                if not normalized_dn or "=" not in normalized_dn:
                    return False

                # Check each component
                components = normalized_dn.split(",")
                expected_parts_count = 2
                for raw_component in components:
                    component = raw_component.strip()
                    if not component or "=" not in component:
                        return False

                    parts = component.split("=", 1)
                    if (
                        len(parts) != expected_parts_count
                        or not parts[0].strip()
                        or not parts[1].strip()
                    ):
                        return False

                return True

            except Exception:
                return False

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
                        FlextLDAPUtilities.Validation.validate_dn_component(component)
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

        @staticmethod
        def validate_dn_field(dn: str) -> str:
            """Validate DN field for Pydantic field validation.

            Args:
                dn: Distinguished Name to validate

            Returns:
                Validated DN string

            Raises:
                ValueError: If DN is invalid

            """
            if not dn or not isinstance(dn, str):
                empty_dn_msg = "DN cannot be empty"
                raise ValueError(empty_dn_msg)

            normalized_dn = FlextUtilities.TextProcessor.clean_text(dn.strip())

            # Basic DN format validation - must contain at least one '=' and one ','
            if "=" not in normalized_dn:
                invalid_format_msg = f"Invalid DN format: {dn}. Must contain '='"
                raise ValueError(invalid_format_msg)

            # Validate each component
            components = normalized_dn.split(",")
            for raw_component in components:
                component = raw_component.strip()
                if not component or "=" not in component:
                    invalid_component_msg = f"Invalid DN component in: {dn}"
                    raise ValueError(invalid_component_msg)

                attr, value = component.split("=", 1)
                if not attr.strip() or not value.strip():
                    empty_attr_msg = (
                        f"Invalid DN component (empty attribute or value) in: {dn}"
                    )
                    raise ValueError(empty_attr_msg)

            return normalized_dn

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
                # Convert each attribute using flext-core utilities
                normalized: LdapAttributeDict = {}

                for key, value in raw_attributes.items():
                    # Validate attribute name using our LDAP-specific validation
                    attr_validation = (
                        FlextLDAPUtilities.Validation.validate_attribute_name(key)
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

        # LDAP3 Utility Methods for safe ldap3 library interactions
        class Ldap3:
            """Safe wrappers for ldap3 library operations."""

            @staticmethod
            def safe_ldap3_rebind_result(
                connection: Connection, dn: str, password: str
            ) -> bool:
                """Safely handle ldap3 rebind result.

                Args:
                    connection: LDAP3 connection object
                    dn: Distinguished name for rebind
                    password: Password for rebind

                Returns:
                    bool: True if rebind successful, False otherwise

                """
                try:
                    # Use hasattr to safely check if connection has rebind method
                    if not hasattr(connection, "rebind"):
                        return False

                    # Safe method call using getattr for untyped ldap3
                    rebind_method = connection.rebind
                    result = rebind_method(user=dn, password=password)
                    return bool(result)
                except Exception:
                    return False

            @staticmethod
            def safe_ldap3_connection_result(connection: Connection) -> str:
                """Safely get connection result message.

                Args:
                    connection: LDAP3 connection object

                Returns:
                    str: Connection result message

                """
                try:
                    if hasattr(connection, "result"):
                        result_obj = connection.result
                        if hasattr(result_obj, "get"):
                            get_method = result_obj.get
                            return str(get_method("description", "Unknown error"))
                    return "Connection result unavailable"
                except Exception:
                    return "Failed to get connection result"

            @staticmethod
            def safe_ldap3_search_result(search_result: object) -> bool:
                """Safely handle ldap3 search result.

                Args:
                    search_result: LDAP3 search result

                Returns:
                    bool: True if search successful, False otherwise

                """
                try:
                    return bool(search_result)
                except Exception:
                    return False

            @staticmethod
            def safe_ldap3_entries_list(connection: Connection) -> list[dict[str, object]]:
                """Safely get entries from ldap3 connection.

                Args:
                    connection: LDAP3 connection object

                Returns:
                    list[dict[str, object]]: List of entry dictionaries

                """
                try:
                    if hasattr(connection, "entries"):
                        entries = getattr(connection, "entries", [])
                        return [
                            dict(entry) if hasattr(entry, "__dict__") else {}
                            for entry in entries
                        ]
                    return []
                except Exception:
                    return []

            @staticmethod
            def safe_ldap3_entry_dn(entry: dict[str, object]) -> str:
                """Safely get DN from ldap3 entry.

                Args:
                    entry: LDAP3 entry dictionary

                Returns:
                    str: Entry DN or empty string

                """
                try:
                    return str(entry.get("dn", ""))
                except Exception:
                    return ""

            @staticmethod
            def safe_ldap3_entry_attributes_list(entry: dict[str, object]) -> list[str]:
                """Safely get attribute names from ldap3 entry.

                Args:
                    entry: LDAP3 entry dictionary

                Returns:
                    list[str]: List of attribute names

                """
                try:
                    return [key for key in entry if key != "dn"]
                except Exception:
                    return []

            @staticmethod
            def safe_ldap3_attribute_values(
                entry: dict[str, object], attr_name: str
            ) -> list[str]:
                """Safely get attribute values from ldap3 entry.

                Args:
                    entry: LDAP3 entry dictionary
                    attr_name: Attribute name

                Returns:
                    list[str]: List of attribute values

                """
                try:
                    value = entry.get(attr_name, [])
                    if isinstance(value, list):
                        return [str(v) for v in value]
                    return [str(value)] if value else []
                except Exception:
                    return []

    class LdapConverters:
        """LDAP-specific data conversion utilities using flext-core."""

        @staticmethod
        def safe_convert_external_dict_to_ldap_attributes(
            source_dict: object,
        ) -> LdapAttributeDict:
            """Convert external dictionary to LDAP attribute format.

            Args:
                source_dict: External dictionary or object to convert

            Returns:
                Dictionary with LDAP-compatible attribute values

            """
            if not isinstance(source_dict, dict):
                return {}

            result: LdapAttributeDict = {}

            for key, value in source_dict.items():
                # Validate attribute name
                attr_validation = FlextLDAPUtilities.Validation.validate_attribute_name(
                    str(key)
                )
                if not attr_validation.is_success:
                    continue  # Skip invalid attribute names

                attr_name = attr_validation.value

                # Convert value to LDAP format
                if value is None:
                    continue  # Skip None values
                if isinstance(value, list):
                    # Convert list values, preserving bytes
                    converted_values = []
                    for item in value:
                        if isinstance(item, bytes):
                            converted_values.append(item)  # Preserve bytes
                        else:
                            str_val = FlextUtilities.TextProcessor.safe_string(item)
                            if str_val:  # Only add non-empty strings
                                converted_values.append(str_val)
                    if converted_values:  # Only add attribute if it has values
                        result[attr_name] = converted_values
                # Convert single value, preserving bytes
                elif isinstance(value, bytes):
                    result[attr_name] = value  # Preserve bytes
                else:
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
            result = []
            for value in values:
                str_val = FlextUtilities.TextProcessor.safe_string(value)
                if str_val:  # Only add non-empty strings
                    result.append(str_val)

            return result

        @staticmethod
        def safe_get_first_value(attributes: dict[str, object], key: str) -> str | None:
            """Safely get first value from attribute dictionary.

            Args:
                attributes: Dictionary of attributes
                key: Attribute key to get

            Returns:
                First value as string or None if not found

            """
            value = attributes.get(key)
            if value is None:
                return None

            if isinstance(value, list):
                return str(value[0]) if value else None

            return str(value)

        @staticmethod
        def sanitize_attribute_name(name: object) -> str:
            """Sanitize LDAP attribute name by removing dangerous characters.

            Args:
                name: Attribute name to sanitize

            Returns:
                Sanitized attribute name

            """
            if not isinstance(name, str):
                return ""

            # Remove dangerous LDAP characters
            dangerous_chars = ["*", "(", ")", "\\", "&", "|", "="]
            sanitized = name
            for char in dangerous_chars:
                sanitized = sanitized.replace(char, "")

            return sanitized.strip()

        @staticmethod
        def extract_error_message(result: FlextResult[object]) -> str:
            """Extract error message from result object.

            Args:
                result: Result object to extract error from

            Returns:
                Error message string

            """
            try:
                if hasattr(result, "error") and result.error:
                    return str(result.error)
                if hasattr(result, "is_success") and not result.is_success:
                    return "Operation failed"
            except AttributeError:
                pass
            return "Unknown error"

        @staticmethod
        def is_successful_result(result: object) -> bool:
            """Check if result object indicates success.

            Args:
                result: Result object to check

            Returns:
                True if successful, False otherwise

            """
            if hasattr(result, "is_success"):
                return bool(getattr(result, "is_success", False))
            return False

        @staticmethod
        def safe_list_conversion(value: object) -> list[str]:
            """Safely convert any value to list of strings.

            Args:
                value: Value to convert to list

            Returns:
                List of strings

            """
            if value is None:
                return []

            if isinstance(value, list):
                return [str(item) for item in value]

            return [str(value)]

        @staticmethod
        def create_ldap_attributes(attributes: dict[str, object]) -> LdapAttributeDict:
            """Create LDAP attributes dictionary from input.

            Args:
                attributes: Input attributes dictionary

            Returns:
                LDAP-compatible attributes dictionary

            """
            return FlextLDAPUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
                attributes
            )

        @staticmethod
        def safe_ldap3_rebind_result(
            connection: Connection, user: str, password: str
        ) -> bool:
            """Safely get rebind result from ldap3 connection.

            Args:
                connection: LDAP3 connection object
                user: User DN for rebind
                password: Password for rebind

            Returns:
                True if rebind successful, False otherwise

            """
            try:
                if connection is None:
                    return False
                if hasattr(connection, "rebind"):
                    connection.rebind(user, password)
                if hasattr(connection, "result"):
                    result = connection.result
                    if isinstance(result, dict):
                        return result.get("description") == "success"
                return False
            except AttributeError:
                return False
            except Exception:
                return False

        @staticmethod
        def safe_ldap3_search_result(result: object) -> bool:
            """Safely convert ldap3 search result to boolean.

            Args:
                result: LDAP3 search result object

            Returns:
                Boolean representation of result

            """
            return bool(result)

        @staticmethod
        def safe_ldap3_connection_result(connection: Connection) -> str:
            """Safely get connection result description.

            Args:
                connection: LDAP3 connection object

            Returns:
                Error description string

            """
            try:
                if connection is None:
                    return "Unknown error"
                if hasattr(connection, "result") and isinstance(
                    connection.result, dict
                ):
                    description = connection.result.get("description", "Unknown error")
                    return str(description)
                return "Unknown error"
            except AttributeError:
                return "Unknown error"

        @staticmethod
        def safe_ldap3_entries_list(response: Connection) -> list[object]:
            """Safely extract entries list from ldap3 response.

            Args:
                response: LDAP3 response object

            Returns:
                List of entries or empty list

            """
            try:
                if response is None:
                    return []
                if hasattr(response, "entries") and isinstance(response.entries, list):
                    return list(response.entries)
                return []
            except AttributeError:
                return []

        @staticmethod
        def safe_ldap3_entry_dn(entry: dict[str, object]) -> str:
            """Safely extract DN from ldap3 entry.

            Args:
                entry: LDAP3 entry object

            Returns:
                Entry DN or empty string

            """
            try:
                if entry is None:
                    return ""
                if hasattr(entry, "entry_dn"):
                    return str(entry.entry_dn)
                return ""
            except AttributeError:
                return ""

        @staticmethod
        def safe_ldap3_entry_attributes_list(entry: dict[str, object]) -> list[str]:
            """Safely extract attribute names from ldap3 entry.

            Args:
                entry: LDAP3 entry object

            Returns:
                List of attribute names

            """
            try:
                if entry is None:
                    return []
                if hasattr(entry, "entry_attributes_as_dict"):
                    attrs_dict = entry.entry_attributes_as_dict
                    if isinstance(attrs_dict, dict):
                        return list(attrs_dict.keys())
                return []
            except AttributeError:
                return []

        @staticmethod
        def safe_ldap3_attribute_values(entry: dict[str, object], attribute: str) -> list[str]:
            """Safely extract attribute values from ldap3 entry.

            Args:
                entry: LDAP3 entry object
                attribute: Attribute name to extract

            Returns:
                List of attribute values

            """
            try:
                if entry is None:
                    return []
                if hasattr(entry, "entry_attributes_as_dict"):
                    attrs_dict = entry.entry_attributes_as_dict
                    if isinstance(attrs_dict, dict) and attribute in attrs_dict:
                        values = attrs_dict[attribute]
                        if isinstance(values, list):
                            return [str(v) for v in values]
                        return [str(values)]
                return []
            except AttributeError:
                return []


# =============================================================================
# LEGACY COMPATIBILITY ALIASES
# =============================================================================

# Backward compatibility alias - Remove legacy code entirely per requirements
# No legacy compatibility, no fallback modes


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "FlextLDAPUtilities",
]
