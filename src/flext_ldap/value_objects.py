"""LDAP Value Objects - Immutable Domain Values.

🏗️ CLEAN ARCHITECTURE: Domain Value Objects (SOLID-compliant)
Extends flext-core FlextValueObject pattern for consistency across FLEXT ecosystem.

Value Objects follow DDD principles:
    - Immutable: Cannot be changed after creation
    - Equality by value: Two objects with same values are equal
    - No identity: Unlike entities, value objects don't have unique identifiers
    - Self-validating: Validate their own invariants

SOLID Principles Applied:
    - SRP: Each value object has single responsibility
    - OCP: Extensible through composition, not modification
    - LSP: All value objects are perfectly substitutable
    - ISP: Focused interfaces, no unused methods
    - DIP: Depend on FlextValueObject abstraction

Built on flext-core foundation:
    - Extends FlextValueObject for consistency
    - Uses FlextResult[T] for creation validation
    - Integrates with FlextValidation system
    - Follows immutable patterns

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, ClassVar, final

from flext_core import FlextResult, FlextValue
from pydantic import Field, field_validator

# ===== LDAP SCOPE VALUE OBJECT =====


@final
class FlextLdapScope(FlextValue):
    """LDAP search scope value object.

    Immutable value object representing LDAP search scope levels.
    Self-validates scope values against LDAP standard.
    """

    scope: str = Field(..., description="LDAP search scope")

    # Valid LDAP scopes per RFC 4511
    VALID_SCOPES: ClassVar[set[str]] = {"base", "one", "sub", "children"}

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, value: str) -> str:
        """Validate LDAP scope value."""
        if value not in cls.VALID_SCOPES:
            msg = f"Invalid LDAP scope: {value}. Must be one of {cls.VALID_SCOPES}"
            raise ValueError(msg)
        return value.lower()

    @classmethod
    def create(cls, scope: str) -> FlextResult[FlextLdapScope]:
        """Create scope value object with validation.

        Args:
            scope: LDAP search scope string

        Returns:
            FlextResult[FlextLdapScope]: Validated scope object

        """
        try:
            scope_obj = cls(scope=scope)
            return FlextResult.ok(scope_obj)
        except ValueError as e:
            return FlextResult.fail(str(e))

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

    @classmethod
    def children(cls) -> FlextLdapScope:
        """Create children scope (search all descendants, not entry itself)."""
        return cls(scope="children")

    def is_base(self) -> bool:
        """Check if this is base scope."""
        return self.scope == "base"

    def is_one_level(self) -> bool:
        """Check if this is one-level scope."""
        return self.scope == "one"

    def is_subtree(self) -> bool:
        """Check if this is subtree scope."""
        return self.scope == "sub"

    def is_children(self) -> bool:
        """Check if this is children scope."""
        return self.scope == "children"

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for LDAP scope."""
        # All validation is done in field validators
        return FlextResult.ok(None)


# ===== LDAP DISTINGUISHED NAME VALUE OBJECT =====


@final
class FlextLdapDistinguishedName(FlextValue):
    """LDAP Distinguished Name (DN) value object.

    Immutable value object representing a validated LDAP DN.
    Enforces RFC 4514 DN format and provides parsing utilities.
    """

    dn: str = Field(..., description="Distinguished Name string")

    # RFC 4514 DN component pattern
    DN_COMPONENT_PATTERN: ClassVar[str] = r"^[a-zA-Z][a-zA-Z0-9-]*=.+$"
    DN_PATTERN: ClassVar[str] = (
        r"^[a-zA-Z][a-zA-Z0-9-]*=.+(?:,[a-zA-Z][a-zA-Z0-9-]*=.+)*$"
    )
    MIN_COMPONENTS_FOR_PARENT: ClassVar[int] = 2

    @field_validator("dn")
    @classmethod
    def validate_dn(cls, value: str) -> str:
        """Validate DN format per RFC 4514."""
        if not value.strip():
            msg = "Distinguished Name cannot be empty"
            raise ValueError(msg)

        # Normalize whitespace
        normalized = re.sub(r"\s*,\s*", ",", value.strip())

        # Validate overall format
        if not re.match(cls.DN_PATTERN, normalized):
            msg = f"Invalid DN format: {value}. Must follow RFC 4514 format"
            raise ValueError(msg)

        return normalized

    @classmethod
    def create(cls, dn: str) -> FlextResult[FlextLdapDistinguishedName]:
        """Create DN value object with validation.

        Args:
            dn: Distinguished name string

        Returns:
            FlextResult[FlextLdapDistinguishedName]: Validated DN object

        """
        try:
            dn_obj = cls(dn=dn)
            return FlextResult.ok(dn_obj)
        except ValueError as e:
            return FlextResult.fail(str(e))

    def get_components(self) -> list[tuple[str, str]]:
        """Parse DN into (attribute, value) components.

        Returns:
            List of (attribute_type, attribute_value) tuples

        """
        components = []
        for component in self.dn.split(","):
            if "=" in component:
                attr_type, attr_value = component.split("=", 1)
                components.append((attr_type.strip(), attr_value.strip()))
        return components

    def get_rdn(self) -> str:
        """Get Relative Distinguished Name (first component).

        Returns:
            String representation of the RDN

        """
        return self.dn.split(",")[0]

    def get_parent_dn(self) -> FlextLdapDistinguishedName | None:
        """Get parent DN by removing the RDN.

        Returns:
            Parent DN object, or None if this is a root DN

        """
        components = self.dn.split(",", 1)
        if len(components) < self.MIN_COMPONENTS_FOR_PARENT:
            return None
        parent_result = FlextLdapDistinguishedName.create(components[1])
        return parent_result.data if parent_result.is_success else None

    def is_parent_of(self, child_dn: FlextLdapDistinguishedName) -> bool:
        """Check if this DN is parent of another DN.

        Args:
            child_dn: Potential child DN

        Returns:
            True if this DN is parent of child_dn

        """
        return child_dn.dn.endswith(f",{self.dn}")

    def is_child_of(self, parent_dn: FlextLdapDistinguishedName) -> bool:
        """Check if this DN is child of another DN.

        Args:
            parent_dn: Potential parent DN

        Returns:
            True if this DN is child of parent_dn

        """
        return self.dn.endswith(f",{parent_dn.dn}")

    def get_attribute_value(self, attribute_type: str) -> str | None:
        """Get value for specific attribute type.

        Args:
            attribute_type: Attribute type to find (e.g., 'cn', 'ou', 'dc')

        Returns:
            Attribute value if found, None otherwise

        """
        for attr_type, attr_value in self.get_components():
            if attr_type.lower() == attribute_type.lower():
                return attr_value
        return None

    @property
    def value(self) -> str:
        """Compatibility property - alias for dn attribute."""
        return self.dn

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for LDAP DN."""
        # All validation is done in field validators
        return FlextResult.ok(None)


# ===== LDAP FILTER VALUE OBJECT =====


@final
class FlextLdapFilter(FlextValue):
    """LDAP search filter value object.

    Immutable value object representing a validated LDAP search filter.
    Enforces RFC 4515 filter syntax and provides query building utilities.
    """

    filter_string: str = Field(..., description="LDAP filter string")

    # Basic RFC 4515 filter validation pattern
    FILTER_PATTERN: ClassVar[str] = r"^\(.+\)$"

    @field_validator("filter_string")
    @classmethod
    def validate_filter(cls, value: str) -> str:
        """Validate LDAP filter syntax."""
        if not value.strip():
            msg = "LDAP filter cannot be empty"
            raise ValueError(msg)

        normalized = value.strip()

        # Must be enclosed in parentheses
        if not re.match(cls.FILTER_PATTERN, normalized):
            msg = f"Invalid LDAP filter: {value}. Must be enclosed in parentheses"
            raise ValueError(msg)

        # Basic balance check for parentheses
        if normalized.count("(") != normalized.count(")"):
            msg = f"Unbalanced parentheses in LDAP filter: {value}"
            raise ValueError(msg)

        return normalized

    @classmethod
    def create(cls, filter_string: str) -> FlextResult[FlextLdapFilter]:
        """Create filter value object with validation.

        Args:
            filter_string: LDAP filter string

        Returns:
            FlextResult[FlextLdapFilter]: Validated filter object

        """
        try:
            filter_obj = cls(filter_string=filter_string)
            return FlextResult.ok(filter_obj)
        except ValueError as e:
            return FlextResult.fail(str(e))

    @classmethod
    def equals(cls, attribute: str, value: str) -> FlextLdapFilter:
        """Create equality filter (attr=value).

        Args:
            attribute: Attribute name
            value: Attribute value

        Returns:
            FlextLdapFilter for equality comparison

        """
        # Escape special characters in value
        escaped_value = cls._escape_filter_value(value)
        return cls(filter_string=f"({attribute}={escaped_value})")

    @classmethod
    def present(cls, attribute: str) -> FlextLdapFilter:
        """Create presence filter (attr=*).

        Args:
            attribute: Attribute name

        Returns:
            FlextLdapFilter for presence check

        """
        return cls(filter_string=f"({attribute}=*)")

    @classmethod
    def substring(cls, attribute: str, substring: str) -> FlextLdapFilter:
        """Create substring filter (attr=*value*).

        Args:
            attribute: Attribute name
            substring: Substring to search for

        Returns:
            FlextLdapFilter for substring search

        """
        escaped_substring = cls._escape_filter_value(substring)
        return cls(filter_string=f"({attribute}=*{escaped_substring}*)")

    @classmethod
    def and_filters(cls, *filters: FlextLdapFilter) -> FlextLdapFilter:
        """Create AND filter combining multiple filters.

        Args:
            filters: Filters to combine with AND logic

        Returns:
            FlextLdapFilter representing AND combination

        """
        if not filters:
            msg = "Cannot create AND filter with no sub-filters"
            raise ValueError(msg)

        if len(filters) == 1:
            return filters[0]

        combined = "(&" + "".join(f.filter_string for f in filters) + ")"
        return cls(filter_string=combined)

    @classmethod
    def or_filters(cls, *filters: FlextLdapFilter) -> FlextLdapFilter:
        """Create OR filter combining multiple filters.

        Args:
            filters: Filters to combine with OR logic

        Returns:
            FlextLdapFilter representing OR combination

        """
        if not filters:
            msg = "Cannot create OR filter with no sub-filters"
            raise ValueError(msg)

        if len(filters) == 1:
            return filters[0]

        combined = "(|" + "".join(f.filter_string for f in filters) + ")"
        return cls(filter_string=combined)

    @classmethod
    def not_filter(cls, filter_obj: FlextLdapFilter) -> FlextLdapFilter:
        """Create NOT filter negating another filter.

        Args:
            filter_obj: Filter to negate

        Returns:
            FlextLdapFilter representing NOT operation

        """
        return cls(filter_string=f"(!{filter_obj.filter_string})")

    @staticmethod
    def _escape_filter_value(value: str) -> str:
        """Escape special characters in filter values per RFC 4515.

        Args:
            value: Value to escape

        Returns:
            Escaped value safe for use in LDAP filters

        """
        # RFC 4515 special characters that need escaping
        escapes = {
            "*": r"\2a",
            "(": r"\28",
            ")": r"\29",
            "\\": r"\5c",
            "\x00": r"\00",
        }

        escaped = value
        for char, escape_seq in escapes.items():
            escaped = escaped.replace(char, escape_seq)

        return escaped

    def is_equality_filter(self) -> bool:
        """Check if this is a simple equality filter."""
        # Simple heuristic: contains = but not *, (, ), &, |, !
        inner = self.filter_string[1:-1]  # Remove outer parentheses
        return "=" in inner and not any(char in inner for char in "*()&|!")

    def get_attribute_name(self) -> str | None:
        """Extract attribute name from simple equality filter."""
        if not self.is_equality_filter():
            return None

        inner = self.filter_string[1:-1]
        if "=" in inner:
            return inner.split("=")[0].strip()
        return None

    @property
    def filter_str(self) -> str:
        """Compatibility property - alias for filter_string attribute."""
        return self.filter_string

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for LDAP filter."""
        # All validation is done in field validators
        return FlextResult.ok(None)


# ===== USER CREATION CONFIGURATION =====


@dataclass
class UserCreationConfig:
    """Configuration for user creation requests."""

    given_name: str | None = None
    mail: str | None = None
    user_password: str | None = None
    object_classes: list[str] | None = None
    additional_attributes: dict[str, Any] | None = None


# ===== LDAP USER REQUEST VALUE OBJECT =====


@final
class FlextLdapCreateUserRequest(FlextValue):
    """Value object for user creation requests.

    Immutable value object encapsulating all data needed to create a user.
    Self-validates business rules and required attributes.
    """

    dn: str = Field(..., description="User distinguished name")
    uid: str = Field(..., description="User unique identifier")
    cn: str = Field(..., description="Common name")
    sn: str = Field(..., description="Surname")
    given_name: str | None = Field(None, description="Given name")
    mail: str | None = Field(None, description="Email address")
    user_password: str | None = Field(None, description="User password")
    phone: str | None = Field(None, description="Phone number")
    department: str | None = Field(None, description="Department")
    title: str | None = Field(None, description="Job title")
    object_classes: list[str] = Field(
        default_factory=lambda: ["inetOrgPerson", "organizationalPerson", "person"],
        description="LDAP object classes",
    )
    additional_attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional LDAP attributes",
    )

    @field_validator("dn")
    @classmethod
    def validate_dn(cls, value: str) -> str:
        """Validate DN format."""
        dn_result = FlextLdapDistinguishedName.create(value)
        if not dn_result.is_success:
            raise ValueError(dn_result.error)
        return value

    @field_validator("uid", "cn", "sn")
    @classmethod
    def validate_required_string(cls, value: str) -> str:
        """Validate required string fields."""
        if not value or not value.strip():
            msg = "Required field cannot be empty"
            raise ValueError(msg)
        return value.strip()

    @field_validator("mail")
    @classmethod
    def validate_email(cls, value: str | None) -> str | None:
        """Validate email format if provided."""
        if value is None:
            return None

        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, value):
            msg = f"Invalid email format: {value}"
            raise ValueError(msg)
        return value.lower()

    @field_validator("object_classes")
    @classmethod
    def validate_object_classes(cls, value: list[str]) -> list[str]:
        """Validate object classes."""
        if not value:
            msg = "At least one object class is required"
            raise ValueError(msg)

        # Ensure person is included for user objects
        required_classes = {"person", "organizationalPerson"}
        provided_classes = set(value)

        if not required_classes.intersection(provided_classes):
            msg = "User must include person or organizationalPerson object class"
            raise ValueError(msg)

        return list(dict.fromkeys(value))  # Remove duplicates while preserving order

    @classmethod
    def create(
        cls,
        dn: str,
        uid: str,
        cn: str,
        sn: str,
        config: UserCreationConfig | None = None,
    ) -> FlextResult[FlextLdapCreateUserRequest]:
        """Create user request with validation.

        Args:
            dn: User distinguished name
            uid: User unique identifier
            cn: Common name
            sn: Surname
            config: Optional configuration for additional user attributes

        Returns:
            FlextResult[FlextLdapCreateUserRequest]: Validated user request

        """
        try:
            config = config or UserCreationConfig()
            request = cls(
                dn=dn,
                uid=uid,
                cn=cn,
                sn=sn,
                given_name=config.given_name,
                mail=config.mail,
                user_password=config.user_password,
                object_classes=config.object_classes
                or ["inetOrgPerson", "organizationalPerson", "person"],
                additional_attributes=config.additional_attributes or {},
            )
            return FlextResult.ok(request)
        except ValueError as e:
            return FlextResult.fail(str(e))

    def to_ldap_attributes(self) -> dict[str, Any]:
        """Convert to LDAP attribute dictionary for creation.

        Returns:
            Dictionary suitable for LDAP entry creation

        """
        attributes = {
            "objectClass": self.object_classes,
            "uid": self.uid,
            "cn": self.cn,
            "sn": self.sn,
        }

        # Add optional attributes if provided
        if self.given_name:
            attributes["givenName"] = self.given_name

        if self.mail:
            attributes["mail"] = self.mail

        if self.user_password:
            attributes["userPassword"] = self.user_password

        if self.phone:
            attributes["telephoneNumber"] = self.phone

        if self.department:
            attributes["departmentNumber"] = self.department

        if self.title:
            attributes["title"] = self.title

        # Add any additional attributes
        attributes.update(self.additional_attributes)

        return attributes

    def get_dn_object(self) -> FlextResult[FlextLdapDistinguishedName]:
        """Get validated DN object.

        Returns:
            FlextResult[FlextLdapDistinguishedName]: DN value object

        """
        return FlextLdapDistinguishedName.create(self.dn)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for user creation request."""
        # All validation is done in field validators
        return FlextResult.ok(None)
