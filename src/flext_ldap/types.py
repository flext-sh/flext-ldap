"""FLEXT-LDAP Types - Centralized Type Definitions Following Foundation Patterns.

This module centralizes ALL type definitions for FLEXT-LDAP following docs/patterns/
foundation.md patterns. Eliminates duplications and provides single source of truth
for type definitions across the entire library.

All types follow flext-core foundation patterns:
- FlextModel: Base with validation
- FlextEntity: Identity-based domain objects
- FlextValue: Immutable value objects
- FlextResult: Railway-oriented programming

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from enum import Enum, StrEnum
from urllib.parse import urlparse

from flext_core import (
    FlextDomainValueObject,
    FlextResult,
    get_logger,
)
from pydantic import Field, field_validator

logger = get_logger(__name__)

# CENTRALIZED ENUMS - Single source of truth


class FlextLdapDataType(Enum):
    """LDAP data types with intelligent detection - CENTRALIZED from duplicates."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    BINARY = "binary"
    DATETIME = "datetime"
    DN = "dn"
    EMAIL = "email"
    PHONE = "phone"
    UUID = "uuid"
    URL = "url"
    IP_ADDRESS = "ip_address"
    MAC_ADDRESS = "mac_address"
    CERTIFICATE = "certificate"
    PASSWORD_DATA_TYPE = "password_field"  # noqa: S105  # nosec B105 - data type identifier
    UNKNOWN = "unknown"


class FlextLdapScopeEnum(StrEnum):
    """LDAP search scope enumeration with legacy compatibility."""

    BASE = "base"
    ONE_LEVEL = "onelevel"
    SUBTREE = "subtree"

    # Legacy mappings for backward compatibility
    ONE = "onelevel"
    SUB = "subtree"

# CENTRALIZED VALUE OBJECTS - Following foundation patterns


class FlextLdapDistinguishedName(FlextDomainValueObject):
    """LDAP Distinguished Name value object with RFC 4514 compliance."""

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
        """Validate DN format."""
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
        """Get relative distinguished name (first component)."""
        return self.value.split(",")[0].strip()

    def get_parent_dn(self) -> FlextLdapDistinguishedName | None:
        """Get parent DN."""
        components = self.value.split(",")
        if len(components) <= 1:
            return None

        parent_dn = ",".join(components[1:]).strip()
        return FlextLdapDistinguishedName(value=parent_dn)

    def get_components(self) -> list[str]:
        """Get all DN components."""
        return [component.strip() for component in self.value.split(",")]

    def is_child_of(self, parent: FlextLdapDistinguishedName) -> bool:
        """Check if this DN is a child of another DN."""
        return self.value.lower().endswith(parent.value.lower())


class FlextLdapFilterValue(FlextDomainValueObject):
    """LDAP search filter value object with RFC 4515 compliance."""

    value: str = Field(..., description="LDAP filter string")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP filter."""
        validation_errors = self._collect_filter_validation_errors()

        if validation_errors:
            return FlextResult.fail(validation_errors[0])

        return FlextResult.ok(None)

    def _collect_filter_validation_errors(self) -> list[str]:
        """Collect all filter validation errors."""
        errors = []

        if not self.value:
            errors.append("LDAP filter cannot be empty")

        if not (self.value.startswith("(") and self.value.endswith(")")):
            errors.append("LDAP filter must be enclosed in parentheses")

        open_count = self.value.count("(")
        close_count = self.value.count(")")
        if open_count != close_count:
            errors.append("LDAP filter has unbalanced parentheses")

        return errors

    @field_validator("value")
    @classmethod
    def validate_filter(cls, v: str) -> str:
        """Validate LDAP filter format."""
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
        """Create equality filter."""
        return cls(value=f"({attribute}={value})")

    @classmethod
    def present(cls, attribute: str) -> FlextLdapFilterValue:
        """Create presence filter."""
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
        """Template method for combining filters."""
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
        """Create a contains filter."""
        return cls(value=f"({attribute}=*{value}*)")

    @classmethod
    def starts_with(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create a starts-with filter."""
        return cls(value=f"({attribute}={value}*)")

    @classmethod
    def ends_with(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create an ends-with filter."""
        return cls(value=f"({attribute}=*{value})")

    @classmethod
    def not_equals(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create a not-equals filter."""
        return cls(value=f"(!({attribute}={value}))")

    @classmethod
    def person_filter(cls) -> FlextLdapFilterValue:
        """Create a filter for person objects."""
        return cls(value="(objectClass=person)")

    @classmethod
    def group_filter(cls) -> FlextLdapFilterValue:
        """Create a filter for group objects."""
        return cls.or_filters(
            cls(value="(objectClass=group)"),
            cls(value="(objectClass=groupOfNames)"),
            cls(value="(objectClass=groupOfUniqueNames)"),
        )

    def __and__(self, other: FlextLdapFilterValue) -> FlextLdapFilterValue:
        """Combine filters with AND operation."""
        return self.and_filters(self, other)

    def __or__(self, other: FlextLdapFilterValue) -> FlextLdapFilterValue:
        """Combine filters with OR operation."""
        return self.or_filters(self, other)


class FlextLdapUri(FlextDomainValueObject):
    """LDAP URI value object with RFC 4516 compliance."""

    value: str = Field(..., description="LDAP URI string")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP URI."""
        validation_errors = self._collect_uri_validation_errors()

        if validation_errors:
            return FlextResult.fail(validation_errors[0])

        return FlextResult.ok(None)

    def _collect_uri_validation_errors(self) -> list[str]:
        """Collect all URI validation errors."""
        errors = []

        if not self.value:
            errors.append("LDAP URI cannot be empty")
            return errors

        parsed = urlparse(self.value)
        if parsed.scheme not in {"ldap", "ldaps"}:
            errors.append("LDAP URI must use ldap:// or ldaps:// scheme")

        if not parsed.hostname:
            errors.append("LDAP URI must specify hostname")

        return errors

    @field_validator("value")
    @classmethod
    def validate_uri(cls, v: str) -> str:
        """Validate LDAP URI format."""
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


class FlextLdapCreateUserRequest(FlextDomainValueObject):
    """User creation request value object with comprehensive validation."""

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
        """Validate user creation request."""
        validation_errors = self._collect_user_request_validation_errors()

        if validation_errors:
            return FlextResult.fail(validation_errors[0])

        return FlextResult.ok(None)

    def _collect_user_request_validation_errors(self) -> list[str]:
        """Collect user request validation errors."""
        errors = []

        if not self.dn or not self.dn.strip():
            errors.append("DN cannot be empty")

        if not self.uid or not self.uid.strip():
            errors.append("UID cannot be empty")

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


# BACKWARD COMPATIBILITY ALIASES - Centralized
LDAPScope = FlextLdapScopeEnum
LDAPFilter = FlextLdapFilterValue
LDAPUri = FlextLdapUri
CreateUserRequest = FlextLdapCreateUserRequest
DistinguishedName = FlextLdapDistinguishedName

# Export legacy name used in old converters.py
FlextSimpleConverter = None  # Will be imported from infrastructure
