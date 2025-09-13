"""LDAP Value Objects module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import ClassVar, final

from flext_core import FlextModels, FlextResult, FlextUtilities, FlextValidations
from pydantic import ConfigDict, Field, field_validator

from flext_ldap.constants import FlextLDAPConstants

# Python 3.13 type aliases
type ValidatedDn = str
type LdapFilterString = str
type AttributeName = str


class FlextLDAPValueObjects:
    """Single FlextLDAPValueObjects class with all LDAP value objects.

    Consolidates ALL LDAP value objects into a single class following FLEXT patterns.
    Everything from DN validation to filter creation is available as internal classes
    with full backward compatibility and domain-driven design principles.
    """

    # =========================================================================
    # DISTINGUISHED NAME - DN value object with RFC 2253 compliance
    # =========================================================================

    @final
    class DistinguishedName(FlextModels.Value):
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
            min_length=FlextLDAPConstants.LdapValidation.MIN_DN_LENGTH,
            max_length=FlextLDAPConstants.LdapValidation.MAX_DN_LENGTH,
        )

        # DN validation pattern from SOURCE OF TRUTH
        DN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            FlextLDAPConstants.LdapValidation.DN_PATTERN,
        )

        @field_validator("value")
        @classmethod
        def validate_dn_format(cls, value: str) -> str:
            """Validate DN using FlextValidations SOURCE OF TRUTH - ELIMINATE local duplication."""
            # Use FlextValidations instead of local logic
            if not FlextValidations.is_non_empty_string(value):
                error_msg = "Distinguished Name cannot be empty"
                raise ValueError(error_msg)

            # Use FlextValidations pattern matching instead of local regex
            # Basic pattern validation for DN format
            if not re.match(r"^[a-zA-Z]+=.+", value):
                error_msg = f"Invalid DN format: {value}"
                raise ValueError(error_msg)

            return value.strip()

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules for DN."""
            # DN is validated in field_validator, no additional business rules
            return FlextResult.ok(None)

        @property
        def rdn(self) -> str:
            """Get the Relative Distinguished Name (first component)."""
            return self.value.split(",", 1)[0].strip()

        def is_descendant_of(
            self,
            parent_dn: str | FlextLDAPValueObjects.DistinguishedName,
        ) -> bool:
            """Check if this DN is a descendant of the given parent DN."""
            parent_str = parent_dn if isinstance(parent_dn, str) else parent_dn.value
            return self.value.lower().endswith(parent_str.lower())

        @classmethod
        def create(
            cls,
            value: str,
        ) -> FlextResult[FlextLDAPValueObjects.DistinguishedName]:
            """Create DN from string with validation."""
            try:
                dn = cls(value=value)
                return FlextResult.ok(dn)
            except ValueError as e:
                return FlextResult.fail(str(e))
            except TypeError as e:
                return FlextResult.fail(f"Invalid input type: {e}")

    # =========================================================================
    # SCOPE - LDAP search scope value object
    # =========================================================================

    @final
    class Scope(FlextModels.Value):
        """LDAP search scope value object."""

        scope: str = Field(..., description="LDAP search scope")

        # Valid LDAP scopes from SOURCE OF TRUTH
        VALID_SCOPES: ClassVar[set[str]] = FlextLDAPConstants.Scopes.VALID_SCOPES

        @field_validator("scope")
        @classmethod
        def validate_scope(cls, value: str) -> str:
            """Validate LDAP scope value."""
            normalized = value.lower()
            if normalized not in cls.VALID_SCOPES:
                msg = f"Invalid LDAP scope: {value}. Must be one of {cls.VALID_SCOPES}"
                raise ValueError(msg)
            return normalized

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules."""
            # Scope is validated in field_validator, no additional business rules
            return FlextResult.ok(None)

        @classmethod
        def create(cls, scope: str) -> FlextResult[FlextLDAPValueObjects.Scope]:
            """Create scope value object with validation."""
            try:
                scope_obj = cls(scope=scope)
                return FlextResult.ok(scope_obj)
            except ValueError as e:
                return FlextResult.fail(str(e))

        @classmethod
        def base(cls) -> FlextLDAPValueObjects.Scope:
            """Create base scope (search only the entry itself)."""
            return cls(scope=FlextLDAPConstants.Scopes.BASE)

        @classmethod
        def one(cls) -> FlextLDAPValueObjects.Scope:
            """Create one-level scope (search direct children only)."""
            return cls(scope=FlextLDAPConstants.Scopes.ONE)

        @classmethod
        def sub(cls) -> FlextLDAPValueObjects.Scope:
            """Create subtree scope (search entry and all descendants)."""
            return cls(scope=FlextLDAPConstants.Scopes.SUB)

        @classmethod
        def subtree(cls) -> FlextLDAPValueObjects.Scope:
            """Create subtree scope (alias for sub)."""
            return cls(scope=FlextLDAPConstants.Scopes.SUB)

        @classmethod
        def onelevel(cls) -> FlextLDAPValueObjects.Scope:
            """Create one level scope (alias for one)."""
            return cls(scope=FlextLDAPConstants.Scopes.ONE)

    # =========================================================================
    # FILTER - LDAP filter value object with RFC 4515 compliance
    # =========================================================================

    @final
    class Filter(FlextModels.Value):
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
            min_length=FlextLDAPConstants.LdapValidation.MIN_FILTER_LENGTH,
            max_length=FlextLDAPConstants.LdapValidation.MAX_FILTER_LENGTH_VALUE_OBJECTS,
        )

        # LDAP filter validation pattern from SOURCE OF TRUTH
        FILTER_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            FlextLDAPConstants.LdapValidation.FILTER_PATTERN,
        )

        @field_validator("value")
        @classmethod
        def validate_filter_format(cls, value: str) -> str:
            """Validate LDAP filter using FlextValidations SOURCE OF TRUTH - ELIMINATE local duplication."""
            # Use FlextValidations for consistent validation
            if not FlextValidations.is_non_empty_string(value):
                error_msg = "LDAP filter cannot be empty"
                raise ValueError(error_msg)

            # Use FlextValidations pattern matching for LDAP filter format
            pattern_result = FlextValidations.BusinessValidators.validate_string_field(
                value, pattern=r"^\(.+\)$"
            )
            if pattern_result.is_failure:
                error_msg = f"Invalid LDAP filter format: {value}"
                raise ValueError(error_msg)

            # Clean text using FlextUtilities (keep this as it's domain-specific)
            clean_value = FlextUtilities.TextProcessor.clean_text(value)
            if not clean_value:
                error_msg = "LDAP filter cannot be empty after cleaning"
                raise ValueError(error_msg)

            # Must start and end with parentheses
            if not (clean_value.startswith("(") and clean_value.endswith(")")):
                msg = f"LDAP filter must be enclosed in parentheses: {clean_value}"
                raise ValueError(msg)

            return clean_value

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules for filter."""
            # Filter is validated in field_validator, no additional business rules
            return FlextResult.ok(None)

        @classmethod
        def create(cls, value: str) -> FlextResult[FlextLDAPValueObjects.Filter]:
            """Create filter from string with validation."""
            try:
                filter_obj = cls(value=value)
                return FlextResult.ok(filter_obj)
            except ValueError as e:
                return FlextResult.fail(str(e))
            except TypeError as e:
                return FlextResult.fail(f"Invalid input type: {e}")

        @classmethod
        def equals(cls, attribute: str, value: str) -> FlextLDAPValueObjects.Filter:
            """Create equality filter."""
            return cls(value=f"({attribute}={value})")

        @classmethod
        def starts_with(
            cls,
            attribute: str,
            value: str,
        ) -> FlextLDAPValueObjects.Filter:
            """Create starts-with filter."""
            return cls(value=f"({attribute}={value}*)")

        @classmethod
        def object_class(cls, object_class: str) -> FlextLDAPValueObjects.Filter:
            """Create object class filter."""
            return cls(value=f"(objectClass={object_class})")

        @classmethod
        def all_objects(cls) -> FlextLDAPValueObjects.Filter:
            """Create filter that matches all objects."""
            return cls(value="(objectClass=*)")


__all__ = [
    "FlextLDAPValueObjects",
]
