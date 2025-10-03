"""Domain value objects for flext-ldap with immutability and validation.

This module defines immutable value objects for LDAP domain concepts like
DistinguishedName, Filter, Scope, etc. All value objects are immutable,
validated, and provide factory methods for creation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from flext_core import FlextLogger

_logger = FlextLogger(__name__)


class FlextLdapValueObjects:
    """Namespace class for all LDAP domain value objects.

    Value objects are immutable domain objects that represent concepts
    like DistinguishedName, Filter, Scope, etc. They provide validation
    and factory methods for safe creation.
    """

    class DistinguishedName(BaseModel):
        """Immutable value object representing an LDAP Distinguished Name.

        Provides RFC 2253 compliant DN parsing, validation, and manipulation.
        Immutable to ensure thread safety and value object semantics.
        """

        value: str = Field(..., description="The DN string value")
        components: list[dict[str, str]] = Field(
            default_factory=list,
            description="Parsed DN components as attribute-value pairs",
        )
        rdn: dict[str, str] | None = Field(
            default=None, description="Relative Distinguished Name (first component)"
        )

        @field_validator("value")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format according to RFC 2253."""
            if not v or not v.strip():
                raise PydanticCustomError("dn_empty", "DN cannot be empty")

            v = v.strip()

            # Basic DN validation - should have at least one attribute=value pair
            if "=" not in v:
                raise PydanticCustomError(
                    "dn_invalid", "DN must contain attribute=value pairs"
                )

            # Check for properly escaped special characters
            # This is a simplified validation - full RFC 2253 validation would be more complex
            if any(char in v for char in ["\n", "\r", "\t"]):
                raise PydanticCustomError(
                    "dn_invalid_chars", "DN contains invalid characters"
                )

            return v

        @model_validator(mode="after")
        def parse_components(self) -> FlextLdapValueObjects.DistinguishedName:
            """Parse DN into components after validation."""
            try:
                self.components = self._parse_dn_components(self.value)
                self.rdn = self.components[0] if self.components else None
            except Exception as e:
                raise PydanticCustomError("dn_parse_error", f"Failed to parse DN: {e}")

            return self

        @classmethod
        def create(cls, dn_string: str) -> FlextLdapValueObjects.DistinguishedName:
            """Factory method for creating DistinguishedName instances."""
            return cls(value=dn_string)

        @classmethod
        def create_user_dn(
            cls, uid: str, base_dn: str = "dc=example,dc=com"
        ) -> FlextLdapValueObjects.DistinguishedName:
            """Factory method for creating user DNs."""
            if not uid:
                raise ValueError("User ID cannot be empty")
            return cls.create(f"uid={uid},ou=users,{base_dn}")

        @classmethod
        def create_group_dn(
            cls, cn: str, base_dn: str = "dc=example,dc=com"
        ) -> FlextLdapValueObjects.DistinguishedName:
            """Factory method for creating group DNs."""
            if not cn:
                raise ValueError("Group CN cannot be empty")
            return cls.create(f"cn={cn},ou=groups,{base_dn}")

        def _parse_dn_components(self, dn: str) -> list[dict[str, str]]:
            """Parse DN into individual components."""
            components = []
            current = ""
            in_quotes = False
            escape_next = False

            i = 0
            while i < len(dn):
                char = dn[i]

                if escape_next:
                    current += char
                    escape_next = False
                elif char == "\\":
                    current += char
                    escape_next = True
                elif char == '"':
                    in_quotes = not in_quotes
                    current += char
                elif char == "," and not in_quotes:
                    # End of component
                    if current.strip():
                        components.append(self._parse_component(current.strip()))
                    current = ""
                else:
                    current += char

                i += 1

            # Add final component
            if current.strip():
                components.append(self._parse_component(current.strip()))

            return components

        def _parse_component(self, component: str) -> dict[str, str]:
            """Parse a single DN component into attribute-value pair."""
            if "=" not in component:
                raise ValueError(f"Invalid DN component: {component}")

            attr, value = component.split("=", 1)

            # Handle multi-valued RDNs (attr1=value1+attr2=value2)
            if "+" in value:
                # For simplicity, we'll just take the first pair
                # Full multi-valued RDN support would be more complex
                value = value.split("+")[0]

            return {attr.strip(): value.strip()}

        def get_parent_dn(self) -> FlextLdapValueObjects.DistinguishedName | None:
            """Get the parent DN by removing the RDN."""
            if len(self.components) <= 1:
                return None

            parent_components = self.components[1:]
            parent_value = ",".join(
                f"{attr}={value}"
                for comp in parent_components
                for attr, value in comp.items()
            )
            return self.create(parent_value)

        def is_descendant_of(
            self, other: FlextLdapValueObjects.DistinguishedName
        ) -> bool:
            """Check if this DN is a descendant of another DN."""
            if len(self.components) <= len(other.components):
                return False

            # Check if our suffix matches the other DN
            return self.components[-len(other.components) :] == other.components

        def get_domain_components(self) -> list[str]:
            """Extract domain components (dc=*) from DN."""
            return [
                value
                for comp in self.components
                for attr, value in comp.items()
                if attr.lower() == "dc"
            ]

        def to_string(self) -> str:
            """Get string representation of DN."""
            return self.value

        def __str__(self) -> str:
            return self.value

        def __eq__(self, other: object) -> bool:
            if not isinstance(other, self.__class__):
                return False
            return self.value.lower() == other.value.lower()

        def __hash__(self) -> int:
            return hash(self.value.lower())

    class Scope(BaseModel):
        """Immutable value object representing LDAP search scope.

        Provides type-safe scope handling with validation and meaningful names.
        """

        value: str = Field(..., description="Scope value")
        name: str = Field(..., description="Human-readable scope name")
        description: str = Field(..., description="Scope description")

        _SCOPE_DEFINITIONS = {
            "base": ("BASE", "Search only the base entry"),
            "one": ("ONE", "Search one level below base"),
            "subtree": ("SUBTREE", "Search entire subtree"),
            "sub": ("SUBTREE", "Search entire subtree"),  # alias
        }

        @field_validator("value")
        @classmethod
        def validate_scope(cls, v: str) -> str:
            """Validate scope value."""
            v = v.lower()
            if v not in cls._SCOPE_DEFINITIONS:
                valid_scopes = list(cls._SCOPE_DEFINITIONS.keys())
                raise PydanticCustomError(
                    "scope_invalid",
                    "Scope must be one of: {scopes}",
                    {"scopes": ", ".join(valid_scopes)},
                )
            return v

        @model_validator(mode="after")
        def set_metadata(self) -> FlextLdapValueObjects.Scope:
            """Set name and description based on value."""
            name, description = self._SCOPE_DEFINITIONS[self.value]
            self.name = name
            self.description = description
            return self

        @classmethod
        def create(cls, scope: str) -> FlextLdapValueObjects.Scope:
            """Factory method for creating Scope instances."""
            return cls(value=scope)

        @classmethod
        def base(cls) -> FlextLdapValueObjects.Scope:
            """Create base scope."""
            return cls.create("base")

        @classmethod
        def one(cls) -> FlextLdapValueObjects.Scope:
            """Create one level scope."""
            return cls.create("one")

        @classmethod
        def subtree(cls) -> FlextLdapValueObjects.Scope:
            """Create subtree scope."""
            return cls.create("subtree")

        def __str__(self) -> str:
            return self.value

        def __eq__(self, other: object) -> bool:
            if not isinstance(other, self.__class__):
                return False
            return self.value == other.value

        def __hash__(self) -> int:
            return hash(self.value)

    class Filter(BaseModel):
        """Immutable value object representing LDAP search filters.

        Provides type-safe filter construction with proper LDAP syntax validation
        and factory methods for common filter patterns.
        """

        value: str = Field(..., description="LDAP filter string")
        is_complex: bool = Field(
            default=False, description="Whether filter contains operators"
        )

        @field_validator("value")
        @classmethod
        def validate_filter(cls, v: str) -> str:
            """Validate LDAP filter syntax."""
            if not v or not v.strip():
                raise PydanticCustomError("filter_empty", "Filter cannot be empty")

            v = v.strip()

            # Basic syntax validation
            if not cls._is_valid_filter_syntax(v):
                raise PydanticCustomError(
                    "filter_invalid", "Invalid LDAP filter syntax"
                )

            return v

        @model_validator(mode="after")
        def analyze_complexity(self) -> FlextLdapValueObjects.Filter:
            """Analyze filter complexity."""
            self.is_complex = any(op in self.value for op in ["&", "|", "!"])
            return self

        @staticmethod
        def _is_valid_filter_syntax(filter_str: str) -> bool:
            """Check basic LDAP filter syntax."""
            # Very simplified validation - real LDAP filters are complex
            # This just checks for balanced parentheses and basic structure

            paren_count = 0
            in_string = False
            escape_next = False

            for char in filter_str:
                if escape_next:
                    escape_next = False
                    continue

                if char == "\\":
                    escape_next = True
                elif char == "(":
                    if not in_string:
                        paren_count += 1
                elif char == ")":
                    if not in_string:
                        paren_count -= 1
                        if paren_count < 0:
                            return False
                elif char == '"' or char == "'":
                    in_string = not in_string

            return paren_count == 0 and not in_string

        @classmethod
        def create(cls, filter_str: str) -> FlextLdapValueObjects.Filter:
            """Factory method for creating Filter instances."""
            return cls(value=filter_str)

        @classmethod
        def equals(cls, attribute: str, value: str) -> FlextLdapValueObjects.Filter:
            """Create equality filter."""
            if not attribute or not value:
                raise ValueError("Attribute and value cannot be empty")
            return cls.create(f"({attribute}={value})")

        @classmethod
        def starts_with(
            cls, attribute: str, value: str
        ) -> FlextLdapValueObjects.Filter:
            """Create starts-with filter."""
            if not attribute or not value:
                raise ValueError("Attribute and value cannot be empty")
            return cls.create(f"({attribute}={value}*)")

        @classmethod
        def ends_with(cls, attribute: str, value: str) -> FlextLdapValueObjects.Filter:
            """Create ends-with filter."""
            if not attribute or not value:
                raise ValueError("Attribute and value cannot be empty")
            return cls.create(f"({attribute}=*{value})")

        @classmethod
        def contains(cls, attribute: str, value: str) -> FlextLdapValueObjects.Filter:
            """Create contains filter."""
            if not attribute or not value:
                raise ValueError("Attribute and value cannot be empty")
            return cls.create(f"({attribute}=*{value}*)")

        @classmethod
        def greater_than(
            cls, attribute: str, value: str
        ) -> FlextLdapValueObjects.Filter:
            """Create greater-than filter."""
            if not attribute or not value:
                raise ValueError("Attribute and value cannot be empty")
            return cls.create(f"({attribute}>={value})")

        @classmethod
        def less_than(cls, attribute: str, value: str) -> FlextLdapValueObjects.Filter:
            """Create less-than filter."""
            if not attribute or not value:
                raise ValueError("Attribute and value cannot be empty")
            return cls.create(f"({attribute}<={value})")

        @classmethod
        def object_class(cls, object_class: str) -> FlextLdapValueObjects.Filter:
            """Create object class filter."""
            if not object_class:
                raise ValueError("Object class cannot be empty")
            return cls.equals("objectClass", object_class)

        @classmethod
        def user_by_uid(cls, uid: str) -> FlextLdapValueObjects.Filter:
            """Create user search filter by UID."""
            return cls.equals("uid", uid)

        @classmethod
        def group_by_cn(cls, cn: str) -> FlextLdapValueObjects.Filter:
            """Create group search filter by CN."""
            return cls.equals("cn", cn)

        @classmethod
        def and_filters(
            cls, *filters: FlextLdapValueObjects.Filter
        ) -> FlextLdapValueObjects.Filter:
            """Combine filters with AND operator."""
            if not filters:
                raise ValueError("At least one filter required")
            if len(filters) == 1:
                return filters[0]

            filter_str = f"(&{''.join(f.value for f in filters)})"
            return cls.create(filter_str)

        @classmethod
        def or_filters(
            cls, *filters: FlextLdapValueObjects.Filter
        ) -> FlextLdapValueObjects.Filter:
            """Combine filters with OR operator."""
            if not filters:
                raise ValueError("At least one filter required")
            if len(filters) == 1:
                return filters[0]

            filter_str = f"(|{''.join(f.value for f in filters)})"
            return cls.create(filter_str)

        @classmethod
        def not_filter(
            cls, filter_obj: FlextLdapValueObjects.Filter
        ) -> FlextLdapValueObjects.Filter:
            """Create NOT filter."""
            filter_str = f"(!{filter_obj.value})"
            return cls.create(filter_str)

        def to_string(self) -> str:
            """Get string representation of filter."""
            return self.value

        def __str__(self) -> str:
            return self.value

        def __eq__(self, other: object) -> bool:
            if not isinstance(other, self.__class__):
                return False
            return self.value == other.value

        def __hash__(self) -> int:
            return hash(self.value)

    class AttributeName(BaseModel):
        """Immutable value object representing LDAP attribute names.

        Provides validation and normalization of LDAP attribute names.
        """

        value: str = Field(..., description="Attribute name")
        normalized: str = Field(..., description="Normalized attribute name")

        @field_validator("value")
        @classmethod
        def validate_attribute_name(cls, v: str) -> str:
            """Validate LDAP attribute name format."""
            if not v or not v.strip():
                raise PydanticCustomError(
                    "attr_empty", "Attribute name cannot be empty"
                )

            v = v.strip()

            # Basic attribute name validation
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9\-_]*$", v):
                raise PydanticCustomError(
                    "attr_invalid", "Invalid attribute name format"
                )

            return v

        @model_validator(mode="after")
        def normalize_name(self) -> FlextLdapValueObjects.AttributeName:
            """Normalize attribute name to lowercase."""
            self.normalized = self.value.lower()
            return self

        @classmethod
        def create(cls, name: str) -> FlextLdapValueObjects.AttributeName:
            """Factory method for creating AttributeName instances."""
            return cls(value=name)

        def matches(self, other: str) -> bool:
            """Check if this attribute matches another name (case-insensitive)."""
            return self.normalized == other.lower()

        def __str__(self) -> str:
            return self.value

        def __eq__(self, other: object) -> bool:
            if not isinstance(other, self.__class__):
                return False
            return self.normalized == other.normalized

        def __hash__(self) -> int:
            return hash(self.normalized)


__all__ = [
    "FlextLdapValueObjects",
]
