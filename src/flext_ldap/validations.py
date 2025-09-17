"""FLEXT-LDAP Centralized Validations - Break circular dependency.

Extracted from domain.py to eliminate circular import between models.py and domain.py.
This module provides centralized validation logic used by Pydantic validators.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_core import FlextModels, FlextResult
from flext_ldap.constants import FlextLdapConstants


class FlextLdapValidations:
    """Centralized validation using direct validation - SOURCE OF TRUTH for all LDAP validations."""

    @staticmethod
    def validate_dn(dn: str, context: str = "DN") -> FlextResult[None]:
        """Centralized DN validation using direct validation - ELIMINATE ALL DUPLICATION."""
        if not dn or not dn.strip():
            return FlextResult[None].fail(f"{context} cannot be empty")

        # Use simple validation for string
        if not isinstance(dn, str) or len(dn.strip()) == 0:
            return FlextResult[None].fail(f"{context} must be a non-empty string")

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

        return FlextResult[None].ok(None)

    @staticmethod
    def validate_email(email: str | None) -> FlextResult[None]:
        """Centralized email validation using FlextModels.EmailAddress - ELIMINATE ALL DUPLICATION."""
        if email is None:
            return FlextResult[None].ok(None)

        # Use FlextModels.EmailAddress for validation
        email_result = FlextModels.EmailAddress.create(email)
        if email_result.is_failure:
            return FlextResult[None].fail(
                f"Email validation failed: {email_result.error or 'invalid format'}"
            )

        return FlextResult[None].ok(None)

    @staticmethod
    def validate_password(password: str | None) -> FlextResult[None]:
        """Centralized password validation - ELIMINATE ALL DUPLICATION."""
        if password is None:
            return FlextResult[None].ok(None)

        if len(password) < FlextLdapConstants.LdapValidation.MIN_PASSWORD_LENGTH:
            return FlextResult[None].fail(
                f"Password must be at least {FlextLdapConstants.LdapValidation.MIN_PASSWORD_LENGTH} characters"
            )

        if len(password) > FlextLdapConstants.LdapValidation.MAX_PASSWORD_LENGTH:
            return FlextResult[None].fail(
                f"Password must be no more than {FlextLdapConstants.LdapValidation.MAX_PASSWORD_LENGTH} characters"
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
                FlextLdapConstants.LDAP.PROTOCOL_PREFIX_LDAP,
                FlextLdapConstants.LDAP.PROTOCOL_PREFIX_LDAPS,
            ),
        ):
            return FlextResult[None].fail(
                f"URI must start with {FlextLdapConstants.LDAP.PROTOCOL_PREFIX_LDAP} or {FlextLdapConstants.LDAP.PROTOCOL_PREFIX_LDAPS}",
            )

        return FlextResult[None].ok(None)


__all__ = ["FlextLdapValidations"]
