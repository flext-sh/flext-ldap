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
    FlextResult,
    FlextValue,
    get_logger,
)
from pydantic import Field, field_validator

from flext_ldap.value_objects import (
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName,
    FlextLdapFilter,
)

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
    PASSWORD_DATA_TYPE = "password_field"  # noqa: S105 - symbolic enum label, not credential
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


# FlextLdapDistinguishedName: CONSOLIDATED to value_objects.py (RFC 4514 compliant)
# Import from: from flext_ldap.value_objects import FlextLdapDistinguishedName


# FlextLdapFilterValue: CONSOLIDATED to value_objects.py (RFC 4515 compliant)
# Import from: from flext_ldap.value_objects import FlextLdapFilter


class FlextLdapUri(FlextValue):
    """LDAP URI value object with RFC 4516 compliance."""

    value: str = Field(..., description="LDAP URI string")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP URI."""
        validation_errors = self._collect_uri_validation_errors()

        if validation_errors:
            return FlextResult.fail(validation_errors[0])

        return FlextResult.ok(None)

    def validate_business_rules(self) -> FlextResult[None]:
        """Required by FlextValue: delegate to domain rules."""
        return self.validate_domain_rules()

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


# FlextLdapCreateUserRequest: CONSOLIDATED to value_objects.py (comprehensive validation)
# Import from: from flext_ldap.value_objects import FlextLdapCreateUserRequest


# Consolidated classes available for backward compatibility aliases

# BACKWARD COMPATIBILITY ALIASES - Centralized
LDAPScope = FlextLdapScopeEnum
LDAPFilter = FlextLdapFilter  # Now from value_objects.py
LDAPUri = FlextLdapUri
CreateUserRequest = FlextLdapCreateUserRequest  # Now from value_objects.py
DistinguishedName = FlextLdapDistinguishedName  # Now from value_objects.py
FlextLdapFilterValue = FlextLdapFilter  # Legacy alias

# Export legacy name used in old converters.py
FlextSimpleConverter: object | None = None  # Will be imported from infrastructure
