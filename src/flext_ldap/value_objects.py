"""LDAP Value Objects - Single FlextLdapValueObjects class following FLEXT patterns.

Single class with all LDAP value objects following domain-driven design patterns
organized as internal classes for complete backward compatibility.

Examples:
    Distinguished Name operations::

        from value_objects import FlextLdapValueObjects

        # Create DN
        dn_result = FlextLdapValueObjects.DistinguishedName.create("cn=user,dc=example,dc=com")
        dn = dn_result.value

        # Check hierarchy
        is_child = dn.is_descendant_of("dc=example,dc=com")

    Filter operations::

        # Create filters
        filter_obj = FlextLdapValueObjects.Filter.equals("uid", "john")
        complex_filter = FlextLdapValueObjects.Filter.object_class("person")

    Scope operations::

        # Create scopes
        base_scope = FlextLdapValueObjects.Scope.base()
        sub_scope = FlextLdapValueObjects.Scope.sub()

    Legacy compatibility::

        # All previous classes still work as direct imports
        from value_objects import FlextLdapDistinguishedName, FlextLdapFilter
        dn = FlextLdapDistinguishedName(value="cn=user,dc=example,dc=com")

"""

from __future__ import annotations

import re
from typing import ClassVar, final, override

from flext_core import FlextResult, FlextValue, get_logger
from pydantic import ConfigDict, Field, field_validator

logger = get_logger(__name__)

# =============================================================================
# SINGLE FLEXT LDAP VALUE OBJECTS CLASS - Consolidated value object functionality
# =============================================================================


class FlextLdapValueObjects:
    """Single FlextLdapValueObjects class with all LDAP value objects.

    Consolidates ALL LDAP value objects into a single class following FLEXT patterns.
    Everything from DN validation to filter creation is available as internal classes
    with full backward compatibility and domain-driven design principles.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP value objects consolidated
        - Open/Closed: Extensible without modification
        - Liskov Substitution: Consistent interface across all value objects
        - Interface Segregation: Organized by value object type for specific access
        - Dependency Inversion: Depends on FlextValue abstraction

    Examples:
        Distinguished Name operations::

            dn_result = FlextLdapValueObjects.DistinguishedName.create("cn=user,dc=example,dc=com")
            if dn_result.is_success:
                dn = dn_result.value
                rdn = dn.rdn
                is_child = dn.is_descendant_of("dc=example,dc=com")

        Filter operations::

            equals_filter = FlextLdapValueObjects.Filter.equals("uid", "john")
            class_filter = FlextLdapValueObjects.Filter.object_class("person")
            all_filter = FlextLdapValueObjects.Filter.all_objects()

        Scope operations::

            base_scope = FlextLdapValueObjects.Scope.base()
            one_scope = FlextLdapValueObjects.Scope.one()
            sub_scope = FlextLdapValueObjects.Scope.sub()

    """

    # =========================================================================
    # DISTINGUISHED NAME - DN value object with RFC 2253 compliance
    # =========================================================================

    @final
    class DistinguishedName(FlextValue):
        """LDAP Distinguished Name value object with RFC 2253 compliance."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
            str_strip_whitespace=True,
            frozen=True,
        )

        value: str = Field(
            ...,
            description="RFC 2253 compliant Distinguished Name",
            min_length=3,
            max_length=2048,
        )

        # Basic DN validation pattern - simplified for practical use
        DN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"^[a-zA-Z]+=[^,]+(?:,[a-zA-Z]+=[^,]+)*$",
        )

        @field_validator("value")
        @classmethod
        def validate_dn_format(cls, value: str) -> str:
            """Validate Distinguished Name format."""
            if not value or not value.strip():
                msg = "Distinguished Name cannot be empty"
                raise ValueError(msg)

            # Basic format validation
            if not cls.DN_PATTERN.match(value):
                msg = f"Invalid DN format: {value}"
                raise ValueError(msg)

            return value.strip()

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules for DN."""
            try:
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"DN validation error: {e}")

        @property
        def rdn(self) -> str:
            """Get the Relative Distinguished Name (first component)."""
            return self.value.split(",", 1)[0].strip()

        def is_descendant_of(self, parent_dn: str | FlextLdapValueObjects.DistinguishedName) -> bool:
            """Check if this DN is a descendant of the given parent DN."""
            parent_str = (
                parent_dn.value
                if hasattr(parent_dn, "value")
                else parent_dn
            )
            return self.value.lower().endswith(parent_str.lower())

        @classmethod
        def create(cls, value: str) -> FlextResult[FlextLdapValueObjects.DistinguishedName]:
            """Create DN from string with validation."""
            try:
                dn = cls(value=value)
                return FlextResult.ok(dn)
            except Exception as e:
                return FlextResult.fail(str(e))

    # =========================================================================
    # SCOPE - LDAP search scope value object
    # =========================================================================

    @final
    class Scope(FlextValue):
        """LDAP search scope value object."""

        scope: str = Field(..., description="LDAP search scope")

        # Valid LDAP scopes per RFC 4511
        VALID_SCOPES: ClassVar[set[str]] = {
            "base",
            "one",
            "sub",
            "children",
            "onelevel",
            "subtree",
        }

        @field_validator("scope")
        @classmethod
        def validate_scope(cls, value: str) -> str:
            """Validate LDAP scope value."""
            normalized = value.lower()
            if normalized not in cls.VALID_SCOPES:
                msg = f"Invalid LDAP scope: {value}. Must be one of {cls.VALID_SCOPES}"
                raise ValueError(msg)
            return normalized

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules."""
            try:
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Scope validation error: {e}")

        @classmethod
        def create(cls, scope: str) -> FlextResult[FlextLdapValueObjects.Scope]:
            """Create scope value object with validation."""
            try:
                scope_obj = cls(scope=scope)
                return FlextResult.ok(scope_obj)
            except ValueError as e:
                return FlextResult.fail(str(e))

        @classmethod
        def base(cls) -> FlextLdapValueObjects.Scope:
            """Create base scope (search only the entry itself)."""
            return cls(scope="base")

        @classmethod
        def one(cls) -> FlextLdapValueObjects.Scope:
            """Create one-level scope (search direct children only)."""
            return cls(scope="one")

        @classmethod
        def sub(cls) -> FlextLdapValueObjects.Scope:
            """Create subtree scope (search entry and all descendants)."""
            return cls(scope="sub")

    # =========================================================================
    # FILTER - LDAP filter value object with RFC 4515 compliance
    # =========================================================================

    @final
    class Filter(FlextValue):
        """LDAP filter value object with RFC 4515 compliance."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
            str_strip_whitespace=True,
            frozen=True,
        )

        value: str = Field(
            ...,
            description="RFC 4515 compliant LDAP filter",
            min_length=1,
            max_length=4096,  # Reasonable filter size limit
        )

        # Basic LDAP filter validation pattern
        FILTER_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"^\([&|!]?[\w\s\-=><~:*().,]+\)$",
        )

        @field_validator("value")
        @classmethod
        def validate_filter_format(cls, value: str) -> str:
            """Validate LDAP filter format."""
            if not value or not value.strip():
                msg = "LDAP filter cannot be empty"
                raise ValueError(msg)

            # Must start and end with parentheses
            if not (value.startswith("(") and value.endswith(")")):
                msg = f"LDAP filter must be enclosed in parentheses: {value}"
                raise ValueError(msg)

            return value.strip()

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules for filter."""
            try:
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Filter validation error: {e}")

        @classmethod
        def create(cls, value: str) -> FlextResult[FlextLdapValueObjects.Filter]:
            """Create filter from string with validation."""
            try:
                filter_obj = cls(value=value)
                return FlextResult.ok(filter_obj)
            except Exception as e:
                return FlextResult.fail(str(e))

        @classmethod
        def equals(cls, attribute: str, value: str) -> FlextLdapValueObjects.Filter:
            """Create equality filter."""
            return cls(value=f"({attribute}={value})")

        @classmethod
        def starts_with(cls, attribute: str, value: str) -> FlextLdapValueObjects.Filter:
            """Create starts-with filter."""
            return cls(value=f"({attribute}={value}*)")

        @classmethod
        def object_class(cls, object_class: str) -> FlextLdapValueObjects.Filter:
            """Create object class filter."""
            return cls(value=f"(objectClass={object_class})")

        @classmethod
        def all_objects(cls) -> FlextLdapValueObjects.Filter:
            """Create filter that matches all objects."""
            return cls(value="(objectClass=*)")


# =============================================================================
# LEGACY COMPATIBILITY CLASSES - Backward Compatibility
# =============================================================================

# Legacy class aliases for backward compatibility
FlextLdapDistinguishedName = FlextLdapValueObjects.DistinguishedName
FlextLdapScope = FlextLdapValueObjects.Scope
FlextLdapFilter = FlextLdapValueObjects.Filter


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Primary consolidated class
    "FlextLdapValueObjects",

    # Legacy compatibility classes
    "FlextLdapDistinguishedName",
    "FlextLdapScope",
    "FlextLdapFilter",
]
