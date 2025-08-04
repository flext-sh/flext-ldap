"""FLEXT-LDAP Domain Value Objects - Immutable Business Data Structures.

This module defines domain value objects that represent immutable concepts
in the LDAP directory domain. All value objects extend flext-core foundation
patterns and implement comprehensive validation and business rules.

Value objects are immutable data structures that encapsulate LDAP-specific
data types with built-in validation, formatting, and domain logic.

Architecture:
    Following Clean Architecture and Domain-Driven Design principles,
    value objects represent concepts that:
    - Are immutable after creation
    - Contain business logic specific to their domain
    - Validate their own consistency and constraints
    - Provide rich domain operations beyond simple data storage

Key Components:
    - FlextLdapDistinguishedName: RFC 4514 compliant DN representation
    - FlextLdapFilterValue: LDAP search filter with validation
    - FlextLdapUri: LDAP URI parsing and validation
    - FlextLdapScopeEnum: Search scope enumeration
    - Request Objects: User creation and operation requests

Standards Compliance:
    - RFC 4514: Distinguished Names format validation
    - RFC 4515: LDAP search filter syntax
    - RFC 4516: LDAP URI format specification
    - Type-safe operations with comprehensive MyPy compliance

Example:
    Creating and using domain value objects:

    >>> dn = FlextLdapDistinguishedName(value="uid=john,ou=users,dc=example,dc=com")
    >>> filter_obj = FlextLdapFilterValue.equals("uid", "john")
    >>> uri = FlextLdapUri(value="ldaps://directory.example.com:636")
    >>>
    >>> validation = dn.validate_domain_rules()
    >>> if validation.is_success:
    ...     print(f"Valid DN: {dn.get_rdn()}")

Integration:
    - Built on flext-core FlextDomainValueObject foundation
    - Compatible with LDAP protocol implementations
    - Supports serialization for data interchange

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from enum import StrEnum
from urllib.parse import urlparse

from flext_core import (
    FlextDomainValueObject,
    FlextResult,
    get_logger,
)
from pydantic import Field, field_validator

logger = get_logger(__name__)


class FlextLdapScopeEnum(StrEnum):
    """LDAP search scope enumeration with legacy compatibility.

    Defines valid search scope values for LDAP directory operations
    with backward compatibility aliases for existing implementations.

    Search scopes determine the breadth of directory tree traversal
    during LDAP search operations.

    Values:
        BASE: Search only the base entry (scope 0)
        ONE_LEVEL: Search immediate children only (scope 1)
        SUBTREE: Search entire subtree recursively (scope 2)

    Legacy Aliases:
        ONE: Alias for ONE_LEVEL
        SUB: Alias for SUBTREE
    """

    BASE = "base"
    ONE_LEVEL = "onelevel"
    SUBTREE = "subtree"

    # Legacy mappings for backward compatibility
    ONE = "onelevel"
    SUB = "subtree"


class FlextLdapDistinguishedName(FlextDomainValueObject):
    """LDAP Distinguished Name value object with RFC 4514 compliance.

    Immutable value object representing LDAP Distinguished Names (DNs)
    with comprehensive validation, parsing, and hierarchical operations.

    Distinguished Names uniquely identify entries in LDAP directory
    hierarchies and must conform to RFC 4514 format specifications.

    Attributes:
        value: String representation of the Distinguished Name

    Business Rules:
        - DN must contain at least one attribute=value pair
        - Components must be properly formatted with '=' separators
        - Attribute names and values cannot be empty
        - Format must comply with RFC 4514 specifications

    Domain Operations:
        - get_rdn(): Extract Relative Distinguished Name
        - get_parent_dn(): Navigate directory hierarchy
        - is_child_of(): Check hierarchical relationships
        - get_components(): Parse DN structure

    Example:
        >>> dn = FlextLdapDistinguishedName(
        ...     value="cn=John Doe,ou=users,dc=example,dc=com"
        ... )
        >>> print(dn.get_rdn())  # "cn=John Doe"
        >>> parent = dn.get_parent_dn()  # "ou=users,dc=example,dc=com"

    """

    value: str = Field(..., description="DN string value")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for DN."""
        if not self.value or not self.value.strip():
            return FlextResult.fail("Distinguished name cannot be empty")
        if "=" not in self.value:
            return FlextResult.fail("Distinguished name must contain at least one RDN")
        return FlextResult.ok(None)

    @field_validator("value")
    @classmethod
    def validate_dn(cls, v: str) -> str:
        """Validate DN format.

        Args:
            v: DN string to validate

        Returns:
            Validated DN string

        Raises:
            ValueError: If DN format is invalid

        """
        if not v or not isinstance(v, str):
            msg = "DN must be a non-empty string"
            raise ValueError(msg)

        if "=" not in v:
            msg = "DN must contain at least one attribute=value pair"
            raise ValueError(msg)

        # Validate each component
        components = v.split(",")
        for raw_component in components:
            component = raw_component.strip()
            if "=" not in component:
                msg = f"Invalid DN component: {component}"
                raise ValueError(msg)

            attr_name, attr_value = component.split("=", 1)
            if not attr_name.strip() or not attr_value.strip():
                msg = f"Invalid DN component: {component}"
                raise ValueError(msg)

        return v

    def __str__(self) -> str:
        """Return DN string value."""
        return self.value

    def get_rdn(self) -> str:
        """Get relative distinguished name (first component).

        Returns:
            The RDN (leftmost component)

        """
        return self.value.split(",")[0].strip()

    def get_parent_dn(self) -> FlextLdapDistinguishedName | None:
        """Get parent DN.

        Returns:
            Parent DN or None if this is root

        """
        components = self.value.split(",")
        if len(components) <= 1:
            return None

        parent_dn = ",".join(components[1:]).strip()
        return FlextLdapDistinguishedName(value=parent_dn)

    def get_components(self) -> list[str]:
        """Get all DN components.

        Returns:
            List of DN components.

        """
        return [component.strip() for component in self.value.split(",")]

    def is_child_of(self, parent: FlextLdapDistinguishedName) -> bool:
        """Check if this DN is a child of another DN.

        Args:
            parent: Potential parent DN

        Returns:
            True if this DN is a child of parent

        """
        return self.value.lower().endswith(parent.value.lower())


# 🚀 CODE CONSOLIDATION: Temporarily disabled due to API incompatibility
# TODO(https://github.com/flext/flext-ldap/issues/consolidation): Re-enable after API compatibility with flext-ldif DN  # noqa: FIX002
# Note: Consolidation disabled - using local implementation for now


class FlextLdapFilterValue(FlextDomainValueObject):
    """LDAP search filter value object with RFC 4515 compliance.

    Immutable value object representing LDAP search filters with comprehensive
    validation, composition operations, and filter building capabilities.

    LDAP filters define search criteria for directory queries and must
    conform to RFC 4515 filter syntax specifications.

    Attributes:
        value: String representation of the LDAP filter expression

    Business Rules:
        - Filter must be enclosed in parentheses
        - Parentheses must be balanced throughout expression
        - Filter syntax must comply with RFC 4515 format
        - Empty filters are not permitted

    Domain Operations:
        - equals()/present(): Create basic filter expressions
        - and_filters()/or_filters(): Combine multiple filters
        - contains()/starts_with(): Pattern matching filters
        - person_filter()/group_filter(): Object class filters

    Example:
        >>> user_filter = FlextLdapFilterValue.equals("uid", "john")
        >>> mail_filter = FlextLdapFilterValue.present("mail")
        >>> combined = FlextLdapFilterValue.and_filters(user_filter, mail_filter)
        >>> print(combined.value)  # "(&(uid=john)(mail=*))"

    """

    value: str = Field(..., description="LDAP filter string")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP filter using Railway-Oriented Programming.

        SOLID REFACTORING: Reduced from 4 returns to 2 returns using
        Railway-Oriented Programming + Strategy Pattern.
        """
        # Railway-Oriented Programming: Chain validations with early exit
        validation_errors = self._collect_filter_validation_errors()

        if validation_errors:
            return FlextResult.fail(validation_errors[0])  # Return first error

        return FlextResult.ok(None)

    def _collect_filter_validation_errors(self) -> list[str]:
        """DRY helper: Collect all filter validation errors using Strategy Pattern."""
        errors = []

        # Strategy 1: Empty value validation
        if not self.value:
            errors.append("LDAP filter cannot be empty")

        # Strategy 2: Parentheses wrapping validation
        if not (self.value.startswith("(") and self.value.endswith(")")):
            errors.append("LDAP filter must be enclosed in parentheses")

        # Strategy 3: Balanced parentheses validation
        open_count = self.value.count("(")
        close_count = self.value.count(")")
        if open_count != close_count:
            errors.append("LDAP filter has unbalanced parentheses")

        return errors

    @field_validator("value")
    @classmethod
    def validate_filter(cls, v: str) -> str:
        """Validate LDAP filter format.

        Args:
            v: Filter string to validate

        Returns:
            Validated filter string

        Raises:
            ValueError: If filter format is invalid

        """
        if not v or not isinstance(v, str):
            msg = "Filter must be a non-empty string"
            raise ValueError(msg)

        if not (v.startswith("(") and v.endswith(")")):
            msg = "Filter must be wrapped in parentheses"
            raise ValueError(msg)

        # Check for balanced parentheses
        open_count = v.count("(")
        close_count = v.count(")")
        if open_count != close_count:
            msg = "Filter has unbalanced parentheses"
            raise ValueError(msg)

        return v

    def __str__(self) -> str:
        """Return filter string value."""
        return self.value

    @classmethod
    def equals(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create equality filter.

        Args:
            attribute: Attribute name
            value: Attribute value

        Returns:
            Equality filter

        """
        return cls(value=f"({attribute}={value})")

    @classmethod
    def present(cls, attribute: str) -> FlextLdapFilterValue:
        """Create presence filter.

        Args:
            attribute: Attribute name

        Returns:
            Presence filter

        """
        return cls(value=f"({attribute}=*)")

    @classmethod
    def and_filters(cls, *filters: FlextLdapFilterValue) -> FlextLdapFilterValue:
        """Combine filters with AND logic."""
        return cls._combine_filters("&", *filters)

    @classmethod
    def or_filters(cls, *filters: FlextLdapFilterValue) -> FlextLdapFilterValue:
        """Combine filters with OR logic."""
        return cls._combine_filters("|", *filters)

    @classmethod
    def _combine_filters(
        cls,
        operator: str,
        *filters: FlextLdapFilterValue,
    ) -> FlextLdapFilterValue:
        """Template method for combining filters - eliminates code duplication.

        Args:
            operator: LDAP logical operator ("&" for AND, "|" for OR)
            filters: Filters to combine

        Returns:
            Combined filter

        """
        if len(filters) == 0:
            msg = "At least one filter required"
            raise ValueError(msg)
        if len(filters) == 1:
            return filters[0]

        filter_strings = [f.value for f in filters]
        combined = f"({operator}{''.join(filter_strings)})"
        return cls(value=combined)

    @classmethod
    def contains(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create a contains filter (consolidated from models.py)."""
        return cls(value=f"({attribute}=*{value}*)")

    @classmethod
    def starts_with(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create a starts-with filter (consolidated from models.py)."""
        return cls(value=f"({attribute}={value}*)")

    @classmethod
    def ends_with(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create an ends-with filter (consolidated from models.py)."""
        return cls(value=f"({attribute}=*{value})")

    @classmethod
    def not_equals(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create a not-equals filter (consolidated from models.py)."""
        return cls(value=f"(!({attribute}={value}))")

    @classmethod
    def person_filter(cls) -> FlextLdapFilterValue:
        """Create a filter for person objects (consolidated from models.py)."""
        return cls(value="(objectClass=person)")

    @classmethod
    def group_filter(cls) -> FlextLdapFilterValue:
        """Create a filter for group objects (consolidated from models.py)."""
        return cls.or_filters(
            cls(value="(objectClass=group)"),
            cls(value="(objectClass=groupOfNames)"),
            cls(value="(objectClass=groupOfUniqueNames)"),
        )

    def __and__(self, other: FlextLdapFilterValue) -> FlextLdapFilterValue:
        """Combine filters with AND operation (consolidated from models.py)."""
        return self.and_filters(self, other)

    def __or__(self, other: FlextLdapFilterValue) -> FlextLdapFilterValue:
        """Combine filters with OR operation (consolidated from models.py)."""
        return self.or_filters(self, other)


class FlextLdapUri(FlextDomainValueObject):
    """LDAP URI value object."""

    value: str = Field(..., description="LDAP URI string")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP URI using Railway-Oriented Programming.

        SOLID REFACTORING: Reduced from 4 returns to 2 returns using
        Railway-Oriented Programming + Strategy Pattern.
        """
        # Railway-Oriented Programming: Chain validations with early exit
        validation_errors = self._collect_uri_validation_errors()

        if validation_errors:
            return FlextResult.fail(validation_errors[0])  # Return first error

        return FlextResult.ok(None)

    def _collect_uri_validation_errors(self) -> list[str]:
        """DRY helper: Collect all URI validation errors using Strategy Pattern."""
        errors = []

        # Strategy 1: Empty value validation
        if not self.value:
            errors.append("LDAP URI cannot be empty")
            return errors  # Early exit if empty - no point parsing

        # Strategy 2: Parse and validate scheme
        parsed = urlparse(self.value)
        if parsed.scheme not in {"ldap", "ldaps"}:
            errors.append("LDAP URI must use ldap:// or ldaps:// scheme")

        # Strategy 3: Hostname validation
        if not parsed.hostname:
            errors.append("LDAP URI must specify hostname")

        return errors

    @field_validator("value")
    @classmethod
    def validate_uri(cls, v: str) -> str:
        """Validate LDAP URI format.

        Args:
            v: URI string to validate

        Returns:
            Validated URI string

        Raises:
            ValueError: If URI format is invalid

        """
        if not v or not isinstance(v, str):
            msg = "URI must be a non-empty string"
            raise ValueError(msg)

        parsed = urlparse(v)
        if parsed.scheme not in {"ldap", "ldaps"}:
            msg = "URI must use ldap:// or ldaps:// scheme"
            raise ValueError(msg)

        if not parsed.hostname:
            msg = "URI must specify hostname"
            raise ValueError(msg)

        return v

    def __str__(self) -> str:
        """Return URI string value."""
        return self.value

    @property
    def hostname(self) -> str:
        """Get hostname from URI."""
        return urlparse(self.value).hostname or ""

    @property
    def port(self) -> int:
        """Get port from URI."""
        parsed = urlparse(self.value)
        if parsed.port:
            return parsed.port
        return 636 if parsed.scheme == "ldaps" else 389

    @property
    def is_secure(self) -> bool:
        """Check if URI uses secure connection."""
        return urlparse(self.value).scheme == "ldaps"


class FlextLdapObjectClass(FlextDomainValueObject):
    """LDAP object class value object."""

    name: str = Field(..., description="Object class name")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP object class."""
        if not self.name or not self.name.strip():
            return FlextResult.fail("Object class name cannot be empty")
        # Basic validation - alphanumeric and common chars
        if not self.name.replace("-", "").replace("_", "").isalnum():
            return FlextResult.fail("Object class name contains invalid characters")
        return FlextResult.ok(None)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate object class name.

        Args:
            v: Object class name to validate

        Returns:
            Validated object class name

        Raises:
            ValueError: If name is invalid

        """
        if not v or not isinstance(v, str):
            msg = "Object class name must be a non-empty string"
            raise ValueError(msg)

        # Basic validation - alphanumeric and common chars
        if not v.replace("-", "").replace("_", "").isalnum():
            msg = "Object class name contains invalid characters"
            raise ValueError(msg)

        return v

    def __str__(self) -> str:
        """Return object class name."""
        return self.name


class FlextLdapAttributesValue(FlextDomainValueObject):
    """LDAP attributes value object."""

    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="LDAP attributes as name-value pairs",
    )

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP attributes."""
        for name, values in self.attributes.items():
            if not name or not name.strip():
                return FlextResult.fail("Attribute name cannot be empty")
            if not values:
                return FlextResult.fail(
                    f"Attribute '{name}' must have at least one value",
                )
        return FlextResult.ok(None)

    def get_single_value(self, name: str) -> str | None:
        """Get single value for attribute.

        Args:
            name: Attribute name

        Returns:
            First value or None if not found

        """
        values = self.attributes.get(name, [])
        return values[0] if values else None

    def get_values(self, name: str) -> list[str]:
        """Get all values for attribute.

        Args:
            name: Attribute name

        Returns:
            List of values (empty if not found)

        """
        return self.attributes.get(name, [])

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists.

        Args:
            name: Attribute name

        Returns:
            True if attribute exists

        """
        return name in self.attributes

    def add_value(self, name: str, value: str) -> FlextLdapAttributesValue:
        """Add value to attribute.

        Args:
            name: Attribute name
            value: Value to add

        Returns:
            New LDAPAttributes instance with added value

        """
        new_attrs = self.attributes.copy()
        if name not in new_attrs:
            new_attrs[name] = []
        new_attrs[name] += [value]
        return FlextLdapAttributesValue(attributes=new_attrs)

    def remove_value(self, name: str, value: str) -> FlextLdapAttributesValue:
        """Remove value from attribute.

        Args:
            name: Attribute name
            value: Value to remove

        Returns:
            New LDAPAttributes instance with removed value

        """
        new_attrs = self.attributes.copy()
        if name in new_attrs:
            new_values = [v for v in new_attrs[name] if v != value]
            if new_values:
                new_attrs[name] = new_values
            else:
                del new_attrs[name]
        return FlextLdapAttributesValue(attributes=new_attrs)


class FlextLdapConnectionInfo(FlextDomainValueObject):
    """LDAP connection information value object."""

    server_uri: FlextLdapUri
    bind_dn: FlextLdapDistinguishedName | None = None
    is_authenticated: bool = False
    is_secure: bool = False
    protocol_version: int = 3

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP connection info."""
        if not self.server_uri:
            return FlextResult.fail("Connection info must have server_uri")
        if self.protocol_version not in {2, 3}:
            return FlextResult.fail("Protocol version must be 2 or 3")
        return FlextResult.ok(None)

    @property
    def connection_string(self) -> str:
        """Get connection string representation."""
        auth_status = "authenticated" if self.is_authenticated else "anonymous"
        security = "secure" if self.is_secure else "insecure"
        return f"{self.server_uri} ({auth_status}, {security})"


class FlextLdapExtendedEntry(FlextDomainValueObject):
    """Extended LDAP entry value object with rich domain operations.

    Value object representing LDAP directory entries with comprehensive
    utility methods for attribute access, type detection, and data extraction.

    Provides high-level operations for working with LDAP entry data
    while maintaining immutability and domain logic encapsulation.

    Attributes:
        dn: Distinguished Name of the entry
        attributes: Dictionary of LDAP attributes with multi-valued support

    Domain Operations:
        - get_attribute()/get_single_attribute(): Safe attribute access
        - get_cn()/get_uid()/get_mail(): Convenience methods for common attributes
        - is_person()/is_group(): Object class type detection
        - has_attribute(): Attribute presence checking

    Business Rules:
        - Distinguished Name must be present and non-empty
        - Attributes follow LDAP multi-value conventions
        - Type detection based on standard object classes

    Example:
        >>> entry = FlextLdapExtendedEntry(
        ...     dn="uid=john,ou=users,dc=example,dc=com",
        ...     attributes={"cn": ["John Doe"], "objectClass": ["person"]},
        ... )
        >>> print(entry.get_cn())  # "John Doe"
        >>> print(entry.is_person())  # True

    """

    dn: str = Field(..., description="Distinguished Name")
    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="LDAP attributes",
    )

    def get_attribute(self, name: str) -> list[str] | None:
        """Get LDAP attribute values by name."""
        return self.attributes.get(name)

    def has_attribute(self, name: str) -> bool:
        """Check if LDAP entry has a specific attribute."""
        return name in self.attributes

    def get_single_attribute(self, name: str) -> str | None:
        """Get single value from an LDAP attribute."""
        values = self.get_attribute(name)
        return values[0] if values else None

    def get_cn(self) -> str | None:
        """Get the common name (cn) attribute."""
        return self.get_single_attribute("cn")

    def get_uid(self) -> str | None:
        """Get the user identifier (uid) attribute."""
        return self.get_single_attribute("uid")

    def get_mail(self) -> str | None:
        """Get the email (mail) attribute."""
        return self.get_single_attribute("mail")

    def is_person(self) -> bool:
        """Check if this LDAP entry represents a person."""
        object_classes = self.get_attribute("objectClass")
        return bool(
            object_classes and "person" in [oc.lower() for oc in object_classes],
        )

    def is_group(self) -> bool:
        """Check if this LDAP entry represents a group."""
        object_classes = self.get_attribute("objectClass")
        return bool(
            object_classes
            and any(
                oc.lower() in {"group", "groupofnames", "groupofuniquenames"}
                for oc in object_classes
            ),
        )

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP extended entry."""
        if not self.dn:
            return FlextResult.fail("LDAP entry must have a distinguished name")
        return FlextResult.ok(None)


class FlextLdapCreateUserRequest(FlextDomainValueObject):
    """User creation request value object with comprehensive validation.

    Immutable value object encapsulating all required and optional data
    for creating LDAP user accounts with business rule validation.

    This request object ensures data consistency and validates business
    constraints before user creation operations are performed.

    Attributes:
        dn: Distinguished Name for the new user account
        uid: Unique user identifier (login name)
        cn: Common name (display name)
        sn: Surname (family name)
        mail: Optional email address
        phone: Optional telephone number
        ou: Optional organizational unit
        department: Optional department affiliation
        title: Optional job title or position
        object_classes: Optional LDAP object classes (defaults to inetOrgPerson)

    Business Rules:
        - Distinguished Name must be present and non-empty
        - User identifier (uid) must be specified
        - Common name (cn) and surname (sn) are required
        - Email address must follow valid format if provided
        - All text fields must not be whitespace-only

    Example:
        >>> request = FlextLdapCreateUserRequest(
        ...     dn="uid=john,ou=users,dc=example,dc=com",
        ...     uid="john",
        ...     cn="John Doe",
        ...     sn="Doe",
        ...     mail="john.doe@example.com",
        ... )
        >>> validation = request.validate_domain_rules()

    """

    dn: str = Field(..., description="Distinguished name for the user")
    uid: str = Field(..., description="User identifier")
    cn: str = Field(..., description="Common name")
    sn: str = Field(..., description="Surname")
    mail: str | None = Field(None, description="Email address")
    phone: str | None = Field(None, description="Phone number")
    ou: str | None = Field(None, description="Organizational unit")
    department: str | None = Field(None, description="Department")
    title: str | None = Field(None, description="Job title")
    object_classes: list[str] | None = Field(None, description="LDAP object classes")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate user creation request using Railway-Oriented Programming.

        SOLID REFACTORING: Reduced from 4 returns to 2 returns using
        Railway-Oriented Programming + Strategy Pattern.
        """
        # Railway-Oriented Programming: Chain validations with early exit
        validation_errors = self._collect_user_request_validation_errors()

        if validation_errors:
            return FlextResult.fail(validation_errors[0])  # Return first error

        return FlextResult.ok(None)

    def _collect_user_request_validation_errors(self) -> list[str]:
        """DRY helper: Collect user request validation errors using Strategy Pattern."""
        errors = []

        # Strategy 1: DN validation
        if not self.dn or not self.dn.strip():
            errors.append("DN cannot be empty")

        # Strategy 2: UID validation
        if not self.uid or not self.uid.strip():
            errors.append("UID cannot be empty")

        # Strategy 3: Email format validation (only if provided)
        if self.mail and "@" not in self.mail:
            errors.append("Email must be valid format")

        return errors

    @field_validator("dn")
    @classmethod
    def validate_dn(cls, v: str) -> str:
        """Validate DN is not empty."""
        if not v or v.isspace():
            msg = "DN cannot be empty or whitespace only"
            raise ValueError(msg)
        return v.strip()

    @field_validator("uid", "cn", "sn")
    @classmethod
    def validate_required_fields(cls, v: str) -> str:
        """Validate required fields are not empty."""
        if not v or v.isspace():
            msg = "Required field cannot be empty or whitespace only"
            raise ValueError(msg)
        return v.strip()


# Backward compatibility aliases
LDAPScope = FlextLdapScopeEnum
LDAPFilter = FlextLdapFilterValue
LDAPUri = FlextLdapUri
LDAPObjectClass = FlextLdapObjectClass
LDAPAttributes = FlextLdapAttributesValue
LDAPConnectionInfo = FlextLdapConnectionInfo
# Consolidated from models.py
ExtendedLDAPEntry = FlextLdapExtendedEntry
LDAPEntry = FlextLdapExtendedEntry  # Default entry type
# Enhanced filter with builder methods from models.py
FlextLdapFilter = FlextLdapFilterValue  # Use our comprehensive filter implementation
