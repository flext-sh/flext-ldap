"""LDAP Entry Processing and Manipulation Utilities.

This module provides comprehensive LDAP entry processing following LDAP standards
with perl-ldap compatibility patterns for entry manipulation, attribute processing,
and data transformation essential for directory operations.

LDAP entries provide structured data containers for directory information,
enabling attribute management, value processing, and entry manipulation
critical for enterprise directory applications and data management.

Architecture:
    - LDAPEntry: Main entry representation and manipulation class
    - AttributeValue: Individual attribute value processing
    - EntryProcessor: Advanced entry processing utilities
    - EntryValidator: Entry validation and compliance checking

Usage Example:
    >>> from flext_ldap.utilities.entry import LDAPEntry
    >>>
    >>> # Create entry from dictionary
    >>> entry_data = {
    ...     "cn": ["John Doe"],
    ...     "mail": ["john.doe@example.com", "jdoe@example.com"],
    ...     "objectClass": ["person", "inetOrgPerson"]
    ... }
    >>> entry = LDAPEntry("cn=John Doe,ou=users,dc=example,dc=com", entry_data)
    >>>
    >>> # Manipulate attributes
    >>> entry.add_attribute("telephoneNumber", "+1-555-123-4567")
    >>> entry.remove_attribute_value("mail", "jdoe@example.com")
    >>> entry.replace_attribute("displayName", "John Q. Doe")

References:
    - perl-ldap: lib/Net/LDAP/Entry.pm
    - RFC 4511: LDAP Protocol Specification
    - RFC 4517: LDAP Syntaxes and Matching Rules
    - LDAP data processing and manipulation patterns
"""

from __future__ import annotations

import base64
from enum import Enum
from typing import Any, cast

from flext_ldapn import DistinguishedName
from pydantic import BaseModel, Field


class AttributeValueType(Enum):
    """LDAP attribute value types."""

    STRING = "string"  # UTF-8 string value
    BINARY = "binary"  # Binary data value
    INTEGER = "integer"  # Integer value
    BOOLEAN = "boolean"  # Boolean value
    TIME = "time"  # Generalized time value
    DN = "dn"  # Distinguished name value


class ModificationType(Enum):
    """LDAP modification operation types."""

    ADD = "add"  # Add attribute values
    DELETE = "delete"  # Delete attribute values
    REPLACE = "replace"  # Replace all attribute values
    INCREMENT = "increment"  # Increment integer value


class AttributeValue(BaseModel):
    """Individual LDAP attribute value representation."""

    value: str | bytes | int | bool = Field(description="Attribute value")

    value_type: AttributeValueType = Field(
        default=AttributeValueType.STRING,
        description="Type of attribute value",
    )

    is_binary: bool = Field(default=False, description="Whether value is binary")

    encoding: str = Field(
        default="utf-8",
        description="Text encoding for string values",
    )

    def get_string_value(self) -> str:
        """Get value as string.

        Returns:
            String representation of value
        """
        if isinstance(self.value, str):
            return self.value
        if isinstance(self.value, bytes):
            if self.is_binary:
                return base64.b64encode(self.value).decode("ascii")
            return self.value.decode(self.encoding, errors="replace")
        if isinstance(self.value, int | bool):
            return str(self.value)
        # Handle any other types (defensive programming)
        msg = f"Unsupported value type: {type(self.value)}"  # type: ignore[unreachable]
        raise TypeError(msg)

    def get_binary_value(self) -> bytes:
        """Get value as bytes.

        Returns:
            Binary representation of value
        """
        if isinstance(self.value, bytes):
            return self.value
        if isinstance(self.value, str):
            if self.is_binary:
                # Decode base64
                try:
                    return base64.b64decode(self.value)
                except Exception:
                    # Fallback to UTF-8 encoding
                    return self.value.encode(self.encoding)
            else:
                return self.value.encode(self.encoding)
        else:
            return str(self.value).encode(self.encoding)

    def get_typed_value(self) -> str | bytes | int | bool:
        """Get value in its appropriate type.

        Returns:
            Value in appropriate Python type
        """
        if self.value_type == AttributeValueType.STRING:
            return self.get_string_value()
        if self.value_type == AttributeValueType.BINARY:
            return self.get_binary_value()
        if self.value_type == AttributeValueType.INTEGER:
            if isinstance(self.value, int):
                return self.value
            try:
                return int(self.get_string_value())
            except ValueError:
                return 0
        elif self.value_type == AttributeValueType.BOOLEAN:
            if isinstance(self.value, bool):
                return self.value
            str_val = self.get_string_value().lower()
            return str_val in {"true", "1", "yes", "on"}
        else:
            return self.get_string_value()

    def is_equal_to(self, other_value: str | bytes | AttributeValue) -> bool:
        """Check if value is equal to another value.

        Args:
            other_value: Value to compare against

        Returns:
            True if values are equal
        """
        if isinstance(other_value, AttributeValue):
            return self.get_typed_value() == other_value.get_typed_value()
        # Must be str or bytes based on type annotation
        return self.get_string_value() == str(other_value)

    def __str__(self) -> str:
        """String representation."""
        return self.get_string_value()

    def __eq__(self, other: object) -> bool:
        """Check value equality."""
        if isinstance(other, str | bytes | AttributeValue):
            return self.is_equal_to(other)
        return False

    def __hash__(self) -> int:
        """Hash for AttributeValue."""
        return hash((self.get_string_value(), self.value_type, self.is_binary))


class LDAPEntry:
    """LDAP entry representation and manipulation.

    This class provides comprehensive LDAP entry processing capabilities
    with support for attribute manipulation, value processing, and entry
    validation following LDAP standards.

    Example:
        >>> # Create entry
        >>> entry = LDAPEntry(
        ...     "cn=John Doe,ou=users,dc=example,dc=com",
        ...     {
        ...         "cn": ["John Doe"],
        ...         "sn": ["Doe"],
        ...         "givenName": ["John"],
        ...         "objectClass": ["person", "inetOrgPerson"],
        ...         "mail": ["john.doe@example.com"]
        ...     }
        ... )
        >>>
        >>> # Access attributes
        >>> print(f"CN: {entry.get_attribute('cn')}")
        >>> print(f"Mail: {entry.get_attribute_values('mail')}")
        >>>
        >>> # Modify attributes
        >>> entry.add_attribute("telephoneNumber", "+1-555-123-4567")
        >>> entry.remove_attribute_value("mail", "john.doe@example.com")
        >>> entry.replace_attribute("displayName", "John Q. Doe")
        >>>
        >>> # Entry operations
        >>> print(f"Object classes: {entry.get_object_classes()}")
        >>> print(f"Has attribute: {entry.has_attribute('mail')}")
    """

    def __init__(
        self,
        dn: str | None = None,
        attributes: dict[str, list[str] | list[bytes] | list[Any]] | None = None,
    ) -> None:
        """Initialize LDAP entry.

        Args:
            dn: Distinguished name of entry
            attributes: Dictionary of attribute name to values
        """
        self._dn = DistinguishedName(dn) if dn else None
        self._attributes: dict[str, list[AttributeValue]] = {}

        if attributes:
            for attr_name, values in attributes.items():
                self.set_attribute(attr_name, values)

    @property
    def dn(self) -> DistinguishedName | None:
        """Get entry DN.

        Returns:
            Entry distinguished name
        """
        return self._dn

    def set_dn(self, dn: str | DistinguishedName) -> None:
        """Set entry DN.

        Args:
            dn: Distinguished name to set
        """
        if isinstance(dn, str):
            self._dn = DistinguishedName(dn)
        else:
            self._dn = dn

    def get_attribute_names(self) -> set[str]:
        """Get all attribute names in entry.

        Returns:
            Set of attribute names
        """
        return set(self._attributes.keys())

    def has_attribute(self, attribute_name: str) -> bool:
        """Check if entry has attribute.

        Args:
            attribute_name: Attribute name to check

        Returns:
            True if entry has attribute
        """
        return attribute_name.lower() in {name.lower() for name in self._attributes}

    def get_attribute(self, attribute_name: str) -> str | None:
        """Get first value of attribute.

        Args:
            attribute_name: Attribute name

        Returns:
            First attribute value or None
        """
        values = self.get_attribute_values(attribute_name)
        return values[0] if values else None

    def get_attribute_values(self, attribute_name: str) -> list[str]:
        """Get all values of attribute.

        Args:
            attribute_name: Attribute name

        Returns:
            List of attribute values
        """
        # Case-insensitive attribute lookup
        for attr_name, values in self._attributes.items():
            if attr_name.lower() == attribute_name.lower():
                return [value.get_string_value() for value in values]

        return []

    def get_attribute_objects(self, attribute_name: str) -> list[AttributeValue]:
        """Get attribute value objects.

        Args:
            attribute_name: Attribute name

        Returns:
            List of AttributeValue objects
        """
        # Case-insensitive attribute lookup
        for attr_name, values in self._attributes.items():
            if attr_name.lower() == attribute_name.lower():
                return values.copy()

        return []

    def set_attribute(
        self,
        attribute_name: str,
        values: str | list[str] | list[bytes] | list[Any],
    ) -> None:
        """Set attribute values (replace existing).

        Args:
            attribute_name: Attribute name
            values: Attribute values
        """
        if isinstance(values, str):
            values = [values]

        attribute_values = []
        for value in values:
            if isinstance(value, AttributeValue):
                attribute_values.append(value)
            else:
                # Determine value type
                is_binary = isinstance(value, bytes)
                value_type = (
                    AttributeValueType.BINARY
                    if is_binary
                    else AttributeValueType.STRING
                )

                attribute_values.append(
                    AttributeValue(
                        value=value,
                        value_type=value_type,
                        is_binary=is_binary,
                    ),
                )

        self._attributes[attribute_name] = attribute_values

    def add_attribute(
        self,
        attribute_name: str,
        values: str | list[str] | list[bytes] | list[Any],
    ) -> None:
        """Add values to attribute (append to existing).

        Args:
            attribute_name: Attribute name
            values: Attribute values to add
        """
        if isinstance(values, str):
            values = [values]

        existing_values = self.get_attribute_objects(attribute_name)

        for value in values:
            if isinstance(value, AttributeValue):
                existing_values.append(value)
            else:
                # Determine value type
                is_binary = isinstance(value, bytes)
                value_type = (
                    AttributeValueType.BINARY
                    if is_binary
                    else AttributeValueType.STRING
                )

                existing_values.append(
                    AttributeValue(
                        value=value,
                        value_type=value_type,
                        is_binary=is_binary,
                    ),
                )

        self._attributes[attribute_name] = existing_values

    def remove_attribute(self, attribute_name: str) -> bool:
        """Remove entire attribute.

        Args:
            attribute_name: Attribute name to remove

        Returns:
            True if attribute was removed
        """
        # Case-insensitive removal
        for attr_name in list(self._attributes.keys()):
            if attr_name.lower() == attribute_name.lower():
                del self._attributes[attr_name]
                return True

        return False

    def remove_attribute_value(
        self,
        attribute_name: str,
        value: str | bytes,
    ) -> bool:
        """Remove specific value from attribute.

        Args:
            attribute_name: Attribute name
            value: Value to remove

        Returns:
            True if value was removed
        """
        # Case-insensitive attribute lookup
        for attr_name, values in self._attributes.items():
            if attr_name.lower() == attribute_name.lower():
                original_count = len(values)

                # Remove matching values
                remaining_values = [val for val in values if not val.is_equal_to(value)]

                if len(remaining_values) < original_count:
                    if remaining_values:
                        self._attributes[attr_name] = remaining_values
                    else:
                        del self._attributes[attr_name]
                    return True

                break

        return False

    def replace_attribute(
        self,
        attribute_name: str,
        values: str | list[str] | list[bytes] | list[Any],
    ) -> None:
        """Replace attribute values (alias for set_attribute).

        Args:
            attribute_name: Attribute name
            values: New attribute values
        """
        self.set_attribute(attribute_name, values)

    def get_object_classes(self) -> list[str]:
        """Get object class values.

        Returns:
            List of object classes
        """
        return self.get_attribute_values("objectClass")

    def has_object_class(self, object_class: str) -> bool:
        """Check if entry has specific object class.

        Args:
            object_class: Object class to check

        Returns:
            True if entry has object class
        """
        object_classes = self.get_object_classes()
        return object_class.lower() in {oc.lower() for oc in object_classes}

    def add_object_class(self, object_class: str) -> None:
        """Add object class to entry.

        Args:
            object_class: Object class to add
        """
        if not self.has_object_class(object_class):
            self.add_attribute("objectClass", object_class)

    def remove_object_class(self, object_class: str) -> bool:
        """Remove object class from entry.

        Args:
            object_class: Object class to remove

        Returns:
            True if object class was removed
        """
        return self.remove_attribute_value("objectClass", object_class)

    def get_size(self) -> int:
        """Get approximate size of entry in bytes.

        Returns:
            Approximate entry size
        """
        size = 0

        # Add DN size
        if self._dn:
            size += len(str(self._dn))

        # Add attribute sizes
        for attr_name, values in self._attributes.items():
            size += len(attr_name)
            for value in values:
                if isinstance(value.value, bytes):
                    size += len(value.value)
                else:
                    size += len(str(value.value))

        return size

    def to_dict(self, include_dn: bool = True) -> dict[str, Any]:
        """Convert entry to dictionary representation.

        Args:
            include_dn: Whether to include DN in result

        Returns:
            Dictionary representation of entry
        """
        result: dict[str, Any] = {}

        if include_dn and self._dn:
            result["dn"] = str(self._dn)

        for attr_name, values in self._attributes.items():
            result[attr_name] = [value.get_string_value() for value in values]

        return result

    def to_ldif(self) -> str:
        """Convert entry to LDIF format.

        Returns:
            LDIF representation of entry
        """
        lines = []

        # Add DN
        if self._dn:
            lines.append(f"dn: {self._dn}")

        # Add attributes
        for attr_name, values in sorted(self._attributes.items()):
            for value in values:
                if value.is_binary:
                    # Binary values are base64 encoded
                    encoded_value = base64.b64encode(value.get_binary_value()).decode(
                        "ascii",
                    )
                    lines.append(f"{attr_name}:: {encoded_value}")
                else:
                    lines.append(f"{attr_name}: {value.get_string_value()}")

        return "\n".join(lines)

    def copy(self) -> LDAPEntry:
        """Create copy of entry.

        Returns:
            Copy of entry
        """
        new_entry = LDAPEntry()

        if self._dn:
            new_entry._dn = self._dn.copy()

        new_entry._attributes = {}
        for attr_name, values in self._attributes.items():
            new_entry._attributes[attr_name] = [
                AttributeValue(**value.dict()) for value in values
            ]

        return new_entry

    def validate(self) -> list[str]:
        """Validate entry consistency.

        Returns:
            List of validation errors
        """
        errors = []

        # Check required attributes
        if not self.has_attribute("objectClass"):
            errors.append("Entry must have objectClass attribute")

        # Check DN validity
        if self._dn and not self._dn.is_valid():
            errors.extend(
                [f"DN error: {error}" for error in self._dn.get_validation_errors()],
            )

        # Check for empty attributes
        for attr_name, values in self._attributes.items():
            if not values:
                errors.append(f"Attribute {attr_name} has no values")

        return errors

    def is_valid(self) -> bool:
        """Check if entry is valid.

        Returns:
            True if entry is valid
        """
        return len(self.validate()) == 0

    def __str__(self) -> str:
        """String representation."""
        if self._dn:
            return str(self._dn)
        return "Anonymous Entry"

    def __repr__(self) -> str:
        """Detailed string representation."""
        return f"LDAPEntry(dn='{self._dn}', attributes={len(self._attributes)})"

    def __eq__(self, other: object) -> bool:
        """Check entry equality."""
        if not isinstance(other, LDAPEntry):
            return False

        return self._dn == other._dn and self._attributes == other._attributes

    def __hash__(self) -> int:
        """Hash for LDAPEntry."""
        return hash(
            (
                self._dn,
                tuple(
                    sorted(
                        (
                            attr_name,
                            tuple(values) if isinstance(values, list) else values,
                        )
                        for attr_name, values in self._attributes.items()
                    ),
                ),
            ),
        )


class EntryProcessor:
    """Advanced entry processing utilities."""

    @staticmethod
    def merge_entries(base_entry: LDAPEntry, update_entry: LDAPEntry) -> LDAPEntry:
        """Merge two entries.

        Args:
            base_entry: Base entry
            update_entry: Entry with updates

        Returns:
            Merged entry
        """
        merged = base_entry.copy()

        for attr_name in update_entry.get_attribute_names():
            values = update_entry.get_attribute_values(attr_name)
            merged.set_attribute(attr_name, values)

        return merged

    @staticmethod
    def diff_entries(entry1: LDAPEntry, entry2: LDAPEntry) -> list[dict[str, Any]]:
        """Generate differences between two entries.

        Args:
            entry1: First entry
            entry2: Second entry

        Returns:
            List of modification operations
        """
        modifications = []

        all_attrs = entry1.get_attribute_names() | entry2.get_attribute_names()

        for attr_name in all_attrs:
            values1 = set(entry1.get_attribute_values(attr_name))
            values2 = set(entry2.get_attribute_values(attr_name))

            if values1 != values2:
                if not values1:
                    # Attribute added
                    modifications.append(
                        {
                            "operation": ModificationType.ADD.value,
                            "attribute": attr_name,
                            "values": list(values2),
                        },
                    )
                elif not values2:
                    # Attribute removed
                    modifications.append(
                        {
                            "operation": ModificationType.DELETE.value,
                            "attribute": attr_name,
                            "values": list(values1),
                        },
                    )
                else:
                    # Attribute modified
                    modifications.append(
                        {
                            "operation": ModificationType.REPLACE.value,
                            "attribute": attr_name,
                            "values": list(values2),
                        },
                    )

        return modifications

    @staticmethod
    def filter_entry_attributes(
        entry: LDAPEntry,
        allowed_attributes: set[str],
    ) -> LDAPEntry:
        """Filter entry to include only allowed attributes.

        Args:
            entry: Entry to filter
            allowed_attributes: Set of allowed attribute names

        Returns:
            Filtered entry
        """
        filtered = LDAPEntry()

        if entry.dn:
            filtered.set_dn(entry.dn)

        for attr_name in entry.get_attribute_names():
            if attr_name.lower() in {name.lower() for name in allowed_attributes}:
                values = entry.get_attribute_values(attr_name)
                filtered.set_attribute(attr_name, values)

        return filtered

    @staticmethod
    def normalize_entry(entry: LDAPEntry) -> LDAPEntry:
        """Normalize entry format.

        Args:
            entry: Entry to normalize

        Returns:
            Normalized entry
        """
        normalized = LDAPEntry()

        # Normalize DN
        if entry.dn:
            normalized_dn = entry.dn.normalize()
            normalized.set_dn(normalized_dn)

        # Normalize attributes (lowercase names, sorted values)
        for attr_name in sorted(entry.get_attribute_names()):
            values = sorted(entry.get_attribute_values(attr_name))
            normalized.set_attribute(attr_name.lower(), values)

        return normalized


# Convenience functions
def create_entry(dn: str, attributes: dict[str, str | list[str]]) -> LDAPEntry:
    """Create LDAP entry from dictionary.

    Args:
        dn: Distinguished name
        attributes: Attribute dictionary

    Returns:
        LDAP entry object
    """
    # Convert single strings to lists for LDAPEntry constructor
    normalized_attrs: dict[str, list[str]] = {}
    for name, value in attributes.items():
        if isinstance(value, str):
            normalized_attrs[name] = [value]
        else:
            normalized_attrs[name] = value

    return LDAPEntry(
        dn,
        cast(
            "dict[str, list[str] | list[bytes] | list[Any]] | None",
            normalized_attrs,
        ),
    )


def parse_ldif_entry(ldif_text: str) -> LDAPEntry | None:
    """Parse LDIF text into entry.

    Args:
        ldif_text: LDIF text to parse

    Returns:
        Parsed entry or None if invalid

    Raises:
        NotImplementedError: LDIF parsing not yet implemented
    """
    # TODO: Implement LDIF parsing
    # This would parse LDIF format into LDAPEntry objects
    msg = (
        "LDIF parsing not yet implemented. "
        "Implement LDIF text parsing with proper attribute handling, "
        "base64 decoding, and multi-line value support."
    )
    raise NotImplementedError(msg)


def entry_to_json(entry: LDAPEntry) -> str:
    """Convert entry to JSON string.

    Args:
        entry: Entry to convert

    Returns:
        JSON representation of entry
    """
    import json

    return json.dumps(entry.to_dict(), indent=2, sort_keys=True)


def validate_entry_schema(entry: LDAPEntry, schema: dict[str, Any]) -> list[str]:
    """Validate entry against schema.

    Args:
        entry: Entry to validate
        schema: Schema definition

    Returns:
        List of validation errors

    Raises:
        NotImplementedError: Schema validation not yet implemented
    """
    # TODO: Implement schema validation
    # This would validate entry against LDAP schema definitions
    msg = (
        "Entry schema validation not yet implemented. "
        "Implement validation against LDAP schema with object class "
        "requirements, attribute syntax checking, and constraint validation."
    )
    raise NotImplementedError(msg)


# TODO: Integration points for implementation:
#
# 1. Schema Integration:
#    - Complete LDAP schema validation
#    - Object class and attribute constraints
#    - Syntax validation for different attribute types
#
# 2. LDIF Processing:
#    - Complete LDIF import/export functionality
#    - Multi-line value handling
#    - Change record processing
#
# 3. Advanced Entry Operations:
#    - Entry comparison and merging algorithms
#    - Efficient entry modification tracking
#    - Bulk entry processing operations
#
# 4. Performance Optimization:
#    - Memory-efficient entry storage
#    - Optimized attribute access patterns
#    - Bulk operation optimizations
#
# 5. Data Type Support:
#    - Extended attribute value type support
#    - Custom data type handlers
#    - Binary data processing improvements
#
# 6. Integration with Directory Operations:
#    - Direct integration with search results
#    - Entry modification operation builders
#    - Result set processing utilities
#
# 7. Testing Requirements:
#    - Unit tests for all entry functionality
#    - Performance tests for large entries
#    - Schema validation tests
#    - LDIF processing tests
