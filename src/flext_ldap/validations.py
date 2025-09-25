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

    def handle(self, message: object) -> FlextResult[FlextResult[object]]:
        """Handle validation request."""
        return FlextResult[FlextResult[object]].ok(FlextResult[object].ok(message))

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

        # Allow both simple filters (objectClass=person) and complex filters ((objectClass=person))
        # Simple filters are valid LDAP filters
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

        if len(password) < FlextLdapConstants.LdapValidation.MIN_PASSWORD_LENGTH:
            return FlextResult[None].fail(
                f"Password must be at least {FlextLdapConstants.LdapValidation.MIN_PASSWORD_LENGTH} characters",
            )

        if len(password) > FlextLdapConstants.LdapValidation.MAX_PASSWORD_LENGTH:
            return FlextResult[None].fail(
                f"Password must be no more than {FlextLdapConstants.LdapValidation.MAX_PASSWORD_LENGTH} characters",
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

    @staticmethod
    def validate_server_uri(server_uri: str) -> FlextResult[None]:
        """Validate LDAP server URI."""
        return FlextLdapValidations.validate_uri(server_uri)

    @staticmethod
    def validate_port(port: int) -> FlextResult[None]:
        """Validate LDAP port number."""
        max_port = 65535
        if port <= 0 or port > max_port:
            return FlextResult[None].fail(f"Port must be between 1 and {max_port}")
        return FlextResult[None].ok(None)

    @staticmethod
    def validate_timeout(timeout: int) -> FlextResult[None]:
        """Validate LDAP timeout."""
        if timeout < 0:
            return FlextResult[None].fail("Timeout must be non-negative")
        return FlextResult[None].ok(None)

    @staticmethod
    def validate_size_limit(size_limit: int) -> FlextResult[None]:
        """Validate LDAP size limit."""
        if size_limit < 0:
            return FlextResult[None].fail("Size limit must be non-negative")
        return FlextResult[None].ok(None)

    @staticmethod
    def validate_scope(scope: str) -> FlextResult[None]:
        """Validate LDAP search scope."""
        valid_scopes = {"base", "onelevel", "subtree"}
        if scope.lower() not in valid_scopes:
            return FlextResult[None].fail(f"Invalid scope: {scope}. Must be one of {valid_scopes}")
        return FlextResult[None].ok(None)

    @staticmethod
    def validate_modify_operation(operation: str) -> FlextResult[None]:
        """Validate LDAP modify operation."""
        valid_operations = {"MODIFY_REPLACE", "MODIFY_ADD", "MODIFY_DELETE"}
        if operation not in valid_operations:
            return FlextResult[None].fail(f"Invalid modify operation: {operation}. Must be one of {valid_operations}")
        return FlextResult[None].ok(None)

    @staticmethod
    def validate_object_class(object_class: str) -> FlextResult[None]:
        """Validate LDAP object class."""
        valid_classes = {"inetOrgPerson", "organizationalPerson", "groupOfNames", "person", "top"}
        if object_class not in valid_classes:
            return FlextResult[None].fail(f"Invalid object class: {object_class}")
        return FlextResult[None].ok(None)

    @staticmethod
    def validate_connection_config(config: dict[str, object]) -> FlextResult[None]:
        """Validate LDAP connection configuration."""
        try:
            # Check required fields
            required_fields = ["server_uri", "bind_dn", "bind_password"]
            for field in required_fields:
                if field not in config:
                    return FlextResult[None].fail(f"Missing required field: {field}")

            # Validate server URI
            server_uri = str(config["server_uri"])
            uri_result = FlextLdapValidations.validate_server_uri(server_uri)
            if uri_result.is_failure:
                return uri_result

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Connection config validation failed: {e}")


__all__ = ["FlextLdapValidations"]
