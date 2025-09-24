"""FLEXT-LDAP Centralized Validations - Break circular dependency.

Extracted from domain.py to eliminate circular import between models.py and domain.py.
This module provides centralized validation logic used by Pydantic validators.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_core import FlextHandlers, FlextModels, FlextResult
from flext_ldap.constants import FlextLdapConstants


class FlextLdapValidations(FlextHandlers[object, FlextResult[object]]):
    """Centralized validation - SOURCE OF TRUTH for all LDAP validations."""

    @staticmethod
    def validate_dn(dn: str, context: str = "DN") -> FlextResult[None]:
        """Centralized DN validation - ELIMINATE ALL DUPLICATION."""
        if not dn or not dn.strip():
            return FlextResult[None].fail(f"{context} cannot be empty")

        # Basic DN format validation (RFC 2253) - must contain = and proper structure
        if (
            not re.match(r"^[a-zA-Z0-9=,\s\-\._]+$", dn.strip())
            or "=" not in dn.strip()
        ):
            return FlextResult[None].fail(f"{context} contains invalid characters")

        return FlextResult[None].ok(None)

    @staticmethod
    def validate_filter(filter_str: str) -> FlextResult[None]:
        """Centralized LDAP filter validation - ELIMINATE ALL DUPLICATION."""
        if not filter_str or not filter_str.strip():
            return FlextResult[None].fail("Filter cannot be empty")

        # Basic filter format validation
        if not re.match(r"^[\(\)=&!|a-zA-Z0-9\s\-\.\*]+$", filter_str.strip()):
            return FlextResult[None].fail("Filter contains invalid characters")

        # Require parentheses like Filter class
        if not (
            filter_str.strip().startswith("(") and filter_str.strip().endswith(")")
        ):
            return FlextResult[None].fail("LDAP filter must be enclosed in parentheses")

        return FlextResult[None].ok(None)

    @staticmethod
    def validate_email(email: str | None) -> FlextResult[None]:
        """Centralized email validation using FlextModels.EmailAddress - ELIMINATE ALL DUPLICATION."""
        if email is None:
            return FlextResult[None].ok(None)

        # Use FlextModels.create_validated_email for validation
        email_result: FlextResult[FlextModels.EmailAddress] = (
            FlextModels.create_validated_email(email)
        )
        if email_result.is_failure:
            return FlextResult[None].fail(
                f"Email validation failed: {email_result.error or 'invalid format'}",
            )

        return FlextResult[None].ok(None)

    @staticmethod
    def validate_password(password: str | None) -> FlextResult[None]:
        """Centralized password validation - ELIMINATE ALL DUPLICATION."""
        if password is None:
            return FlextResult[None].ok(None)

        if len(password) < FlextLdapConstants.Validation.MIN_PASSWORD_LENGTH:
            return FlextResult[None].fail(
                f"Password must be at least {FlextLdapConstants.Validation.MIN_PASSWORD_LENGTH} characters",
            )

        if len(password) > FlextLdapConstants.Validation.MAX_PASSWORD_LENGTH:
            return FlextResult[None].fail(
                f"Password must be no more than {FlextLdapConstants.Validation.MAX_PASSWORD_LENGTH} characters",
            )

        return FlextResult[None].ok(None)

    @staticmethod
    def validate_uri(uri: str) -> FlextResult[None]:
        """Centralized URI validation - ELIMINATE ALL DUPLICATION."""
        if not uri or not uri.strip():
            return FlextResult[None].fail("URI cannot be empty")

        # Validate LDAP URI format specifically
        if not uri.strip().startswith(
            (
                FlextLdapConstants.Protocol.PROTOCOL_PREFIX_LDAP,
                FlextLdapConstants.Protocol.PROTOCOL_PREFIX_LDAPS,
            ),
        ):
            return FlextResult[None].fail(
                f"URI must start with {FlextLdapConstants.Protocol.PROTOCOL_PREFIX_LDAP} or {FlextLdapConstants.Protocol.PROTOCOL_PREFIX_LDAPS}",
            )

        return FlextResult[None].ok(None)

    @staticmethod
    def validate_attributes(attributes: list[str]) -> FlextResult[None]:
        """Centralized LDAP attribute names validation - ELIMINATE ALL DUPLICATION."""
        if not attributes:
            return FlextResult[None].fail("Attributes list cannot be empty")

        for attr in attributes:
            if not isinstance(attr, str) or not attr.strip():
                return FlextResult[None].fail(f"Invalid attribute name: {attr}")

        return FlextResult[None].ok(None)

    @staticmethod
    def validate_object_classes(object_classes: list[str]) -> FlextResult[None]:
        """Centralized LDAP object class names validation - ELIMINATE ALL DUPLICATION."""
        if not object_classes:
            return FlextResult[None].fail("Object classes list cannot be empty")

        for oc in object_classes:
            if not isinstance(oc, str) or not oc.strip():
                return FlextResult[None].fail(f"Invalid object class name: {oc}")

        return FlextResult[None].ok(None)


__all__ = ["FlextLdapValidations"]
