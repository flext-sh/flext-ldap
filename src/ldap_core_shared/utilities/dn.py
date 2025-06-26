"""LDAP Distinguished Name (DN) Parsing and Manipulation Utilities.

This module provides comprehensive DN processing following RFC 4514 with
perl-ldap compatibility patterns for DN parsing, validation, normalization,
and manipulation of LDAP distinguished names.

Distinguished Names provide hierarchical naming for directory entries,
enabling unique identification and structured organization essential for
enterprise directory operations and identity management.

Architecture:
    - DistinguishedName: Main DN representation and manipulation class
    - DNComponent: Individual RDN (Relative Distinguished Name) component
    - DNParser: Parser for DN syntax and structure
    - DNValidator: DN validation and compliance checking

Usage Example:
    >>> from ldap_core_shared.utilities.dn import DistinguishedName
    >>>
    >>> # Parse DN string
    >>> dn = DistinguishedName("cn=John Doe,ou=Users,dc=example,dc=com")
    >>>
    >>> # Access DN components
    >>> print(f"RDN: {dn.rdn}")  # cn=John Doe
    >>> print(f"Parent: {dn.parent}")  # ou=Users,dc=example,dc=com
    >>> print(f"Components: {list(dn.components)}")
    >>>
    >>> # Manipulate DN
    >>> child_dn = dn.add_child("uid=johndoe")
    >>> normalized = dn.normalize()

References:
    - perl-ldap: lib/Net/LDAP/Util.pm (escape_dn_value, unescape_dn_value)
    - RFC 4514: LDAP String Representation of Distinguished Names
    - RFC 4511: LDAP Protocol Specification
    - X.500 Distinguished Name standards
"""

from __future__ import annotations

import re
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional, Union

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from collections.abc import Iterator


class DNEscapeMode(Enum):
    """DN escaping modes."""

    RFC4514 = "rfc4514"        # Standard RFC 4514 escaping
    MINIMAL = "minimal"        # Minimal escaping (only required chars)
    FULL = "full"             # Full escaping (all special chars)


class AttributeType(Enum):
    """Common LDAP attribute types."""

    CN = "cn"                 # Common Name
    OU = "ou"                # Organizational Unit
    O = "o"                  # Organization
    C = "c"                  # Country
    L = "l"                  # Locality
    ST = "st"                # State/Province
    STREET = "street"        # Street Address
    DC = "dc"                # Domain Component
    UID = "uid"              # User ID
    MAIL = "mail"            # Email Address
    SN = "sn"                # Surname
    GIVEN_NAME = "givenName"  # Given Name


class DNComponent(BaseModel):
    """Individual DN component (RDN) representation."""

    attribute_type: str = Field(description="Attribute type name")
    attribute_value: str = Field(description="Attribute value")

    # Escaping and formatting
    escape_mode: DNEscapeMode = Field(
        default=DNEscapeMode.RFC4514, description="Escaping mode to use",
    )

    def get_escaped_value(self) -> str:
        """Get escaped attribute value.

        Returns:
            Escaped attribute value
        """
        return escape_dn_value(self.attribute_value, self.escape_mode)

    def get_normalized_type(self) -> str:
        """Get normalized attribute type.

        Returns:
            Normalized attribute type (lowercase)
        """
        return self.attribute_type.lower().strip()

    def to_string(self, escape_value: bool = True) -> str:
        """Convert component to string representation.

        Args:
            escape_value: Whether to escape the attribute value

        Returns:
            String representation of component
        """
        attr_type = self.get_normalized_type()
        attr_value = self.get_escaped_value() if escape_value else self.attribute_value
        return f"{attr_type}={attr_value}"

    def matches_type(self, attribute_type: Union[str, AttributeType]) -> bool:
        """Check if component matches attribute type.

        Args:
            attribute_type: Attribute type to match

        Returns:
            True if component matches type
        """
        if isinstance(attribute_type, AttributeType):
            target_type = attribute_type.value
        else:
            target_type = attribute_type

        return self.get_normalized_type() == target_type.lower().strip()

    def __str__(self) -> str:
        """String representation."""
        return self.to_string()

    def __eq__(self, other: object) -> bool:
        """Check component equality."""
        if not isinstance(other, DNComponent):
            return False

        return (
            self.get_normalized_type() == other.get_normalized_type() and
            self.attribute_value == other.attribute_value
        )


class DistinguishedName:
    """LDAP Distinguished Name representation and manipulation.

    This class provides comprehensive DN processing capabilities following
    RFC 4514 standards with perl-ldap compatibility patterns for parsing,
    validation, and manipulation.

    Example:
        >>> # Parse DN
        >>> dn = DistinguishedName("cn=John Doe,ou=Users,dc=example,dc=com")
        >>>
        >>> # Access components
        >>> print(f"RDN: {dn.rdn}")
        >>> print(f"Parent: {dn.parent}")
        >>> print(f"Depth: {dn.depth}")
        >>>
        >>> # Manipulation
        >>> child = dn.add_child("uid=johndoe")
        >>> normalized = dn.normalize()
        >>> is_child = dn.is_child_of("dc=example,dc=com")
        >>>
        >>> # Component access
        >>> for component in dn.components:
        ...     print(f"{component.attribute_type}={component.attribute_value}")
    """

    # Regex patterns for DN parsing
    DN_COMPONENT_PATTERN = re.compile(
        r'([a-zA-Z][a-zA-Z0-9-]*|\d+(?:\.\d+)*)\s*=\s*'  # Attribute type
        r'((?:[^,=+"<>#;\\]|\\[,=+"<>#;\\]|\\[0-9a-fA-F]{2})*)',  # Attribute value
    )

    ESCAPE_PATTERN = re.compile(r"\\(.)")
    HEX_ESCAPE_PATTERN = re.compile(r"\\([0-9a-fA-F]{2})")

    def __init__(self, dn_string: Optional[str] = None) -> None:
        """Initialize Distinguished Name.

        Args:
            dn_string: DN string to parse (optional)
        """
        self._components: list[DNComponent] = []
        self._original_string = dn_string
        self._validation_errors: list[str] = []

        if dn_string:
            try:
                self._parse_dn(dn_string.strip())
            except Exception as e:
                self._validation_errors.append(f"DN parsing error: {e}")

    def _parse_dn(self, dn_string: str) -> None:
        """Parse DN string into components.

        Args:
            dn_string: DN string to parse
        """
        if not dn_string:
            return  # Empty DN is valid

        # Split by commas, being careful about escaped commas
        component_strings = self._split_dn_components(dn_string)

        for component_str in component_strings:
            component_str = component_str.strip()
            if not component_str:
                continue

            # Parse individual component
            match = self.DN_COMPONENT_PATTERN.match(component_str)
            if not match:
                msg = f"Invalid DN component format: {component_str}"
                raise ValueError(msg)

            attr_type, attr_value = match.groups()

            # Unescape attribute value
            unescaped_value = self._unescape_dn_value(attr_value)

            component = DNComponent(
                attribute_type=attr_type.strip(),
                attribute_value=unescaped_value,
            )

            self._components.append(component)

    def _split_dn_components(self, dn_string: str) -> list[str]:
        """Split DN string into individual component strings.

        Args:
            dn_string: DN string to split

        Returns:
            List of component strings
        """
        components = []
        current_component = ""
        i = 0

        while i < len(dn_string):
            char = dn_string[i]

            if char == "\\":
                # Escaped character - include both backslash and next char
                if i + 1 < len(dn_string):
                    current_component += char + dn_string[i + 1]
                    i += 2
                else:
                    current_component += char
                    i += 1
            elif char == ",":
                # Component separator
                components.append(current_component)
                current_component = ""
                i += 1
            else:
                current_component += char
                i += 1

        # Add final component
        if current_component:
            components.append(current_component)

        return components

    def _unescape_dn_value(self, value: str) -> str:
        """Unescape DN attribute value.

        Args:
            value: Escaped attribute value

        Returns:
            Unescaped attribute value
        """
        # Handle hex escapes first
        def hex_replacer(match: Any) -> str:
            hex_code = match.group(1)
            return chr(int(hex_code, 16))

        value = self.HEX_ESCAPE_PATTERN.sub(hex_replacer, value)

        # Handle standard escapes
        def escape_replacer(match: Any) -> str:
            return str(match.group(1))

        value = self.ESCAPE_PATTERN.sub(escape_replacer, value)

        # Trim leading and trailing spaces
        return value.strip()

    def to_string(self, escape_mode: DNEscapeMode = DNEscapeMode.RFC4514) -> str:
        """Convert DN to string representation.

        Args:
            escape_mode: Escaping mode to use

        Returns:
            DN string representation
        """
        if not self._components:
            return ""

        component_strings = []
        for component in self._components:
            component.escape_mode = escape_mode
            component_strings.append(component.to_string())

        return ",".join(component_strings)

    def normalize(self) -> DistinguishedName:
        """Normalize DN format.

        Returns:
            Normalized DN
        """
        normalized_components = []

        for component in self._components:
            normalized_component = DNComponent(
                attribute_type=component.get_normalized_type(),
                attribute_value=component.attribute_value.strip(),
            )
            normalized_components.append(normalized_component)

        normalized_dn = DistinguishedName()
        normalized_dn._components = normalized_components
        return normalized_dn

    def is_valid(self) -> bool:
        """Check if DN is valid.

        Returns:
            True if DN is valid
        """
        return len(self._validation_errors) == 0

    def get_validation_errors(self) -> list[str]:
        """Get validation errors.

        Returns:
            List of validation error messages
        """
        return self._validation_errors.copy()

    @property
    def rdn(self) -> Optional[DNComponent]:
        """Get Relative Distinguished Name (first component).

        Returns:
            First DN component or None if empty
        """
        return self._components[0] if self._components else None

    @property
    def parent(self) -> Optional[DistinguishedName]:
        """Get parent DN (all components except first).

        Returns:
            Parent DN or None if no parent
        """
        if len(self._components) <= 1:
            return None

        parent_dn = DistinguishedName()
        parent_dn._components = self._components[1:]
        return parent_dn

    @property
    def components(self) -> Iterator[DNComponent]:
        """Iterate over DN components.

        Yields:
            DN components from left to right
        """
        yield from self._components

    @property
    def depth(self) -> int:
        """Get DN depth (number of components).

        Returns:
            Number of DN components
        """
        return len(self._components)

    def get_component_by_type(self, attribute_type: Union[str, AttributeType]) -> Optional[DNComponent]:
        """Get first component with specified attribute type.

        Args:
            attribute_type: Attribute type to search for

        Returns:
            First matching component or None
        """
        for component in self._components:
            if component.matches_type(attribute_type):
                return component
        return None

    def get_components_by_type(self, attribute_type: Union[str, AttributeType]) -> list[DNComponent]:
        """Get all components with specified attribute type.

        Args:
            attribute_type: Attribute type to search for

        Returns:
            List of matching components
        """
        return [component for component in self._components if component.matches_type(attribute_type)]

    def add_child(self, child_rdn: str) -> DistinguishedName:
        """Add child RDN to create new DN.

        Args:
            child_rdn: Child RDN string (e.g., "uid=johndoe")

        Returns:
            New DN with child added
        """
        # Parse child RDN
        child_dn = DistinguishedName(child_rdn)
        if not child_dn._components:
            msg = f"Invalid child RDN: {child_rdn}"
            raise ValueError(msg)

        if len(child_dn._components) > 1:
            msg = "Child RDN must be a single component"
            raise ValueError(msg)

        # Create new DN with child as first component
        new_dn = DistinguishedName()
        new_dn._components = [child_dn._components[0], *self._components]
        return new_dn

    def is_child_of(self, parent_dn: Union[str, DistinguishedName]) -> bool:
        """Check if this DN is a child of specified parent DN.

        Args:
            parent_dn: Parent DN to check against

        Returns:
            True if this DN is a child of parent DN
        """
        if isinstance(parent_dn, str):
            parent_dn = DistinguishedName(parent_dn)

        if not parent_dn or parent_dn.depth >= self.depth:
            return False

        # Check if parent components match the suffix of this DN
        parent_components = list(parent_dn.components)
        our_suffix = self._components[-len(parent_components):]

        for i, parent_component in enumerate(parent_components):
            if our_suffix[i] != parent_component:
                return False

        return True

    def is_ancestor_of(self, child_dn: Union[str, DistinguishedName]) -> bool:
        """Check if this DN is an ancestor of specified child DN.

        Args:
            child_dn: Child DN to check against

        Returns:
            True if this DN is an ancestor of child DN
        """
        if isinstance(child_dn, str):
            child_dn = DistinguishedName(child_dn)

        return child_dn.is_child_of(self)

    def get_common_ancestor(self, other_dn: Union[str, DistinguishedName]) -> Optional[DistinguishedName]:
        """Get common ancestor DN with another DN.

        Args:
            other_dn: Other DN to compare with

        Returns:
            Common ancestor DN or None if no common ancestor
        """
        if isinstance(other_dn, str):
            other_dn = DistinguishedName(other_dn)

        our_components = list(reversed(self._components))
        other_components = list(reversed(other_dn._components))

        common_components = []

        # Find common suffix components
        min_length = min(len(our_components), len(other_components))
        for i in range(min_length):
            if our_components[i] == other_components[i]:
                common_components.append(our_components[i])
            else:
                break

        if not common_components:
            return None

        # Create common ancestor DN
        ancestor_dn = DistinguishedName()
        ancestor_dn._components = list(reversed(common_components))
        return ancestor_dn

    def get_relative_name(self, base_dn: Union[str, DistinguishedName]) -> Optional[DistinguishedName]:
        """Get relative name from base DN.

        Args:
            base_dn: Base DN to calculate relative name from

        Returns:
            Relative DN or None if not a child of base DN
        """
        if isinstance(base_dn, str):
            base_dn = DistinguishedName(base_dn)

        if not self.is_child_of(base_dn):
            return None

        # Return components not in base DN
        relative_depth = self.depth - base_dn.depth
        relative_dn = DistinguishedName()
        relative_dn._components = self._components[:relative_depth]
        return relative_dn

    def get_attribute_types(self) -> set[str]:
        """Get all attribute types used in DN.

        Returns:
            Set of attribute type names
        """
        return {component.get_normalized_type() for component in self._components}

    def copy(self) -> DistinguishedName:
        """Create copy of DN.

        Returns:
            Copy of DN
        """
        new_dn = DistinguishedName()
        new_dn._components = [
            DNComponent(**component.dict()) for component in self._components
        ]
        return new_dn

    def __str__(self) -> str:
        """String representation."""
        return self.to_string()

    def __repr__(self) -> str:
        """Detailed string representation."""
        return f"DistinguishedName('{self.to_string()}')"

    def __eq__(self, other: object) -> bool:
        """Check DN equality."""
        if not isinstance(other, DistinguishedName):
            return False

        # Compare normalized DNs
        self_normalized = self.normalize()
        other_normalized = other.normalize()

        return self_normalized._components == other_normalized._components

    def __len__(self) -> int:
        """Get DN depth."""
        return self.depth

    def __bool__(self) -> bool:
        """Check if DN is non-empty."""
        return len(self._components) > 0


class DNParser:
    """Advanced DN parsing utilities."""

    @staticmethod
    def parse_dn_string(dn_string: str) -> DistinguishedName:
        """Parse DN string with enhanced error handling."""
        return DistinguishedName(dn_string)

    @staticmethod
    def parse(dn_string: str) -> DistinguishedName:
        """Parse DN string and return DistinguishedName object.

        Args:
            dn_string: DN string to parse

        Returns:
            DistinguishedName object
        """
        return DistinguishedName(dn_string)

    @staticmethod
    def validate_dn_syntax(dn_string: str) -> list[str]:
        """Validate DN syntax and return errors."""
        try:
            dn = DistinguishedName(dn_string)
            return dn.get_validation_errors()
        except Exception as e:
            return [str(e)]

    @staticmethod
    def parse_rdn(rdn_string: str) -> DNComponent:
        """Parse a single RDN string into a DNComponent.

        Args:
            rdn_string: RDN string to parse

        Returns:
            DNComponent representing the parsed RDN
        """
        # Parse as minimal DN with one component
        dn = DistinguishedName(rdn_string.strip())
        if dn.components:
            return next(iter(dn.components))
        msg = f"Invalid RDN string: {rdn_string}"
        raise ValueError(msg)

    @staticmethod
    def escape_attribute_value(value: str) -> str:
        """Escape special characters in attribute value for DN representation.

        Args:
            value: Attribute value to escape

        Returns:
            Escaped value suitable for DN string
        """
        # Escape special DN characters according to RFC 4514
        escaped = value
        # Escape leading and trailing spaces
        if escaped.startswith(" "):
            escaped = "\\" + escaped
        if escaped.endswith(" ") and not escaped.endswith("\\ "):
            escaped = escaped[:-1] + "\\ "

        # Escape special characters
        for char in ['"', "+", ",", ";", "<", ">", "\\", "\x00"]:
            escaped = escaped.replace(char, "\\" + char)

        return escaped

    @staticmethod
    def unescape_attribute_value(value: str) -> str:
        """Unescape special characters in DN attribute value.

        Args:
            value: Escaped attribute value

        Returns:
            Unescaped attribute value
        """
        unescaped = value
        # Unescape special characters
        for char in ['"', "+", ",", ";", "<", ">", "\\", "\x00", " "]:
            unescaped = unescaped.replace("\\" + char, char)
        return unescaped

    @staticmethod
    def needs_escaping(value: str) -> bool:
        """Check if attribute value needs escaping for DN representation.

        Args:
            value: Attribute value to check

        Returns:
            True if value needs escaping
        """
        if not value:
            return False

        # Check for leading/trailing spaces
        if value.startswith(" ") or value.endswith(" "):
            return True

        # Check for special characters
        special_chars = ['"', "+", ",", ";", "<", ">", "\\", "\x00"]
        return any(char in value for char in special_chars)

    @staticmethod
    def hex_escape_attribute_value(value: str) -> str:
        """Hex escape attribute value for DN representation.

        Args:
            value: Attribute value to hex escape

        Returns:
            Hex escaped value
        """
        result = ""
        for char in value:
            if ord(char) < 32 or ord(char) > 126:
                result += f"\\{ord(char):02X}"
            else:
                result += char
        return result

    @staticmethod
    def hex_unescape_attribute_value(value: str) -> str:
        """Hex unescape attribute value from DN representation.

        Args:
            value: Hex escaped attribute value

        Returns:
            Unescaped attribute value
        """
        result = ""
        i = 0
        while i < len(value):
            if value[i] == "\\" and i + 2 < len(value):
                try:
                    # Try to parse hex escape sequence
                    hex_code = value[i + 1:i + 3]
                    char_code = int(hex_code, 16)
                    result += chr(char_code)
                    i += 3
                except ValueError:
                    # Not a valid hex escape, keep as is
                    result += value[i]
                    i += 1
            else:
                result += value[i]
                i += 1
        return result

    @staticmethod
    def split_dn_hierarchy(dn_string: str) -> list[str]:
        """Split DN into hierarchy levels.

        Args:
            dn_string: DN string to split

        Returns:
            List of DN strings from most specific to least specific
        """
        try:
            dn = DistinguishedName(dn_string)
            hierarchy = []

            current_dn: Optional[DistinguishedName] = dn
            while current_dn and current_dn.depth > 0:
                hierarchy.append(str(current_dn))
                current_dn = current_dn.parent

            return hierarchy
        except Exception:
            return []


class DNValidator:
    """DN validation and compliance checking utilities."""

    @staticmethod
    def is_valid_attribute_type(attr_type: str) -> bool:
        """Check if attribute type is valid according to LDAP standards.

        Args:
            attr_type: Attribute type to validate

        Returns:
            True if attribute type is valid
        """
        if not attr_type:
            return False

        # Basic attribute type validation - starts with letter, contains letters/digits/hyphens
        import string

        if not attr_type[0].isalpha():
            return False

        allowed_chars = string.ascii_letters + string.digits + "-"
        return all(c in allowed_chars for c in attr_type)

    @staticmethod
    def get_attribute_type_format(attr_type: str) -> str:
        """Get the format specification for an attribute type.

        Args:
            attr_type: Attribute type to get format for

        Returns:
            Format specification string
        """
        # Return basic format info - in real implementation this would
        # consult LDAP schema
        common_formats = {
            "cn": "DirectoryString",
            "sn": "DirectoryString",
            "givenName": "DirectoryString",
            "mail": "IA5String",
            "uid": "DirectoryString",
            "dc": "IA5String",
            "ou": "DirectoryString",
            "o": "DirectoryString",
            "c": "CountryString",
        }

        return common_formats.get(attr_type.lower(), "DirectoryString")


# Utility functions
def escape_dn_value(value: str, escape_mode: DNEscapeMode = DNEscapeMode.RFC4514) -> str:
    """Escape DN attribute value.

    Args:
        value: Attribute value to escape
        escape_mode: Escaping mode to use

    Returns:
        Escaped attribute value
    """
    if not value:
        return value

    # Characters that must be escaped according to RFC 4514
    special_chars = {",", "=", "+", "<", ">", "#", ";", "\\", '"'}

    # Leading and trailing spaces must be escaped
    escaped = ""

    # Escape leading spaces
    i = 0
    while i < len(value) and value[i] == " ":
        escaped += "\\ "
        i += 1

    # Escape middle characters
    while i < len(value):
        char = value[i]

        # Check for trailing spaces
        if char == " ":
            # Count trailing spaces
            j = i
            while j < len(value) and value[j] == " ":
                j += 1

            if j == len(value):
                # These are trailing spaces - escape them
                while i < j:
                    escaped += "\\ "
                    i += 1
            else:
                # Not trailing spaces - don't escape
                escaped += char
                i += 1
        elif char in special_chars:
            # Escape special characters
            escaped += "\\" + char
            i += 1
        elif ord(char) < 32 or ord(char) > 126:
            # Escape non-printable characters as hex
            escaped += f"\\{ord(char):02X}"
            i += 1
        else:
            # Regular character
            escaped += char
            i += 1

    return escaped


def unescape_dn_value(escaped_value: str) -> str:
    """Unescape DN attribute value.

    Args:
        escaped_value: Escaped attribute value

    Returns:
        Unescaped attribute value
    """
    dn = DistinguishedName(f"dummy={escaped_value}")
    if dn._components:
        return dn._components[0].attribute_value
    return escaped_value


def normalize_dn(dn_string: str) -> str:
    """Normalize DN string format.

    Args:
        dn_string: DN string to normalize

    Returns:
        Normalized DN string
    """
    try:
        dn = DistinguishedName(dn_string)
        normalized = dn.normalize()
        return str(normalized)
    except Exception:
        return dn_string


def is_valid_dn(dn_string: str) -> bool:
    """Validate DN string format.

    Args:
        dn_string: DN string to validate

    Returns:
        True if DN is valid
    """
    try:
        dn = DistinguishedName(dn_string)
        return dn.is_valid()
    except Exception:
        return False


def get_dn_parent(dn_string: str) -> Optional[str]:
    """Get parent DN string.

    Args:
        dn_string: DN string

    Returns:
        Parent DN string or None
    """
    try:
        dn = DistinguishedName(dn_string)
        parent = dn.parent
        return str(parent) if parent else None
    except Exception:
        return None


def get_dn_rdn(dn_string: str) -> Optional[str]:
    """Get RDN (first component) from DN string.

    Args:
        dn_string: DN string

    Returns:
        RDN string or None
    """
    try:
        dn = DistinguishedName(dn_string)
        rdn = dn.rdn
        return str(rdn) if rdn else None
    except Exception:
        return None


def compare_dns(dn1: str, dn2: str) -> bool:
    """Compare two DN strings for equality.

    Args:
        dn1: First DN string
        dn2: Second DN string

    Returns:
        True if DNs are equal
    """
    try:
        dn_obj1 = DistinguishedName(dn1)
        dn_obj2 = DistinguishedName(dn2)
        return dn_obj1 == dn_obj2
    except Exception:
        return False


# TODO: Integration points for implementation:
#
# 1. Schema Integration:
#    - Schema-aware attribute type validation
#    - Object class and attribute validation
#    - Syntax checking for attribute values
#
# 2. Advanced DN Operations:
#    - DN-based access control evaluation
#    - DN pattern matching and wildcards
#    - DN transformation and mapping rules
#
# 3. Performance Optimization:
#    - Efficient DN parsing algorithms
#    - DN caching and normalization
#    - Optimized string operations
#
# 4. International Support:
#    - Unicode handling in DN values
#    - Internationalized domain names
#    - Locale-specific sorting and comparison
#
# 5. Security and Validation:
#    - DN injection prevention
#    - Input sanitization and validation
#    - Security policy enforcement
#
# 6. Integration with Directory Operations:
#    - Direct integration with search operations
#    - DN-based result filtering
#    - Dynamic DN construction
#
# 7. Testing Requirements:
#    - Unit tests for all DN functionality
#    - Edge case and boundary tests
#    - Performance tests for DN operations
#    - Compliance tests with RFC 4514
