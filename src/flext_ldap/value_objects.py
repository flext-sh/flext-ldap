"""LDAP value objects following domain-driven design patterns."""

from __future__ import annotations

import re
from typing import ClassVar, final, override

from flext_core import FlextResult, FlextValue, get_logger
from pydantic import ConfigDict, Field, field_validator

logger = get_logger(__name__)


@final
class FlextLdapDistinguishedName(FlextValue):
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

    def is_descendant_of(self, parent_dn: str | FlextLdapDistinguishedName) -> bool:
        """Check if this DN is a descendant of the given parent DN."""
        parent_str = (
            parent_dn.value
            if isinstance(parent_dn, FlextLdapDistinguishedName)
            else parent_dn
        )
        return self.value.lower().endswith(parent_str.lower())

    @classmethod
    def create(cls, value: str) -> FlextResult[FlextLdapDistinguishedName]:
        """Create DN from string with validation."""
        try:
            dn = cls(value=value)
            return FlextResult[FlextLdapDistinguishedName].ok(dn)
        except Exception as e:
            return FlextResult[FlextLdapDistinguishedName].fail(str(e))


@final
class FlextLdapScope(FlextValue):
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
    def create(cls, scope: str) -> FlextResult[FlextLdapScope]:
        """Create scope value object with validation."""
        try:
            scope_obj = cls(scope=scope)
            return FlextResult[FlextLdapScope].ok(scope_obj)
        except ValueError as e:
            return FlextResult[FlextLdapScope].fail(str(e))

    @classmethod
    def base(cls) -> FlextLdapScope:
        """Create base scope (search only the entry itself)."""
        return cls(scope="base")

    @classmethod
    def one(cls) -> FlextLdapScope:
        """Create one-level scope (search direct children only)."""
        return cls(scope="one")

    @classmethod
    def sub(cls) -> FlextLdapScope:
        """Create subtree scope (search entry and all descendants)."""
        return cls(scope="sub")


@final
class FlextLdapFilter(FlextValue):
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
    def create(cls, value: str) -> FlextResult[FlextLdapFilter]:
        """Create filter from string with validation."""
        try:
            filter_obj = cls(value=value)
            return FlextResult[FlextLdapFilter].ok(filter_obj)
        except Exception as e:
            return FlextResult[FlextLdapFilter].fail(str(e))

    @classmethod
    def equals(cls, attribute: str, value: str) -> FlextLdapFilter:
        """Create equality filter."""
        return cls(value=f"({attribute}={value})")

    @classmethod
    def starts_with(cls, attribute: str, value: str) -> FlextLdapFilter:
        """Create starts-with filter."""
        return cls(value=f"({attribute}={value}*)")

    @classmethod
    def object_class(cls, object_class: str) -> FlextLdapFilter:
        """Create object class filter."""
        return cls(value=f"(objectClass={object_class})")

    @classmethod
    def all_objects(cls) -> FlextLdapFilter:
        """Create filter that matches all objects."""
        return cls(value="(objectClass=*)")
