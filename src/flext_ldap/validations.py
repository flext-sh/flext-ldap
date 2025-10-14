"""FLEXT-LDAP Centralized Validations - Break circular dependency.

Extracted from domain.py to eliminate circular import between models.py and domain.py.
This module provides centralized validation logic used by Pydantic validators.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_core import FlextCore

from flext_ldap.constants import FlextLdapConstants


class FlextLdapValidations:
    """Centralized LDAP validations to eliminate circular dependencies."""

    @staticmethod
    def validate_dn(dn: str | None, context: str = "DN") -> FlextCore.Result[bool]:
        """Centralized DN validation - ELIMINATE ALL DUPLICATION."""
        if dn is None:
            return FlextCore.Result[bool].fail(f"{context} cannot be None")
        if not dn or not dn.strip():
            return FlextCore.Result[bool].fail(f"{context} cannot be empty")

        # Basic DN format validation (RFC 2253) - must contain = and proper structure
        if (
            not re.match(r"^[a-zA-Z0-9=,\s\-\._]+$", dn.strip())
            or "=" not in dn.strip()
        ):
            return FlextCore.Result[bool].fail(f"{context} contains invalid characters")

        return FlextCore.Result[bool].ok(True)

    @staticmethod
    def validate_filter(filter_str: str | None) -> FlextCore.Result[bool]:
        """Centralized LDAP filter validation - ELIMINATE ALL DUPLICATION."""
        if filter_str is None:
            return FlextCore.Result[bool].fail("Filter cannot be None")
        if not filter_str or not filter_str.strip():
            return FlextCore.Result[bool].fail("Filter cannot be empty")

        # Basic filter format validation
        filter_str = filter_str.strip()
        if not filter_str.startswith("(") or not filter_str.endswith(")"):
            return FlextCore.Result[bool].fail("Filter must be enclosed in parentheses")

        return FlextCore.Result[bool].ok(True)

    @staticmethod
    def validate_attributes(
        attributes: FlextCore.Types.StringList | None,
    ) -> FlextCore.Result[bool]:
        """Centralized LDAP attributes validation - ELIMINATE ALL DUPLICATION."""
        if attributes is None or not attributes:
            return FlextCore.Result[bool].fail("Attributes list cannot be empty")

        for attr in attributes:
            if not attr or not attr.strip():
                return FlextCore.Result[bool].fail(f"Invalid attribute name: {attr}")
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9\-]*$", attr.strip()):
                return FlextCore.Result[bool].fail(f"Invalid attribute name: {attr}")

        return FlextCore.Result[bool].ok(True)

    @staticmethod
    def validate_server_uri(server_uri: str | None) -> FlextCore.Result[bool]:
        """Centralized server URI validation - ELIMINATE ALL DUPLICATION."""
        if server_uri is None:
            return FlextCore.Result[bool].fail("URI cannot be None")
        if not server_uri or not server_uri.strip():
            return FlextCore.Result[bool].fail("URI cannot be empty")

        server_uri = server_uri.strip()
        if not server_uri.startswith(("ldap://", "ldaps://")):
            return FlextCore.Result[bool].fail(
                "URI must start with ldap:// or ldaps://"
            )

        return FlextCore.Result[bool].ok(True)

    @staticmethod
    def validate_timeout(timeout: int | None) -> FlextCore.Result[bool]:
        """Centralized timeout validation - LDAP-specific non-negative integer."""
        if timeout is None:
            return FlextCore.Result[bool].fail("Timeout cannot be None")

        if timeout < 0:
            return FlextCore.Result[bool].fail("Timeout must be non-negative")

        return FlextCore.Result[bool].ok(True)

    @staticmethod
    def validate_size_limit(size_limit: int | None) -> FlextCore.Result[bool]:
        """Centralized size limit validation - LDAP-specific non-negative integer."""
        if size_limit is None:
            return FlextCore.Result[bool].fail("Size limit cannot be None")

        if size_limit < 0:
            return FlextCore.Result[bool].fail("Size limit must be non-negative")

        return FlextCore.Result[bool].ok(True)

    @staticmethod
    def validate_scope(scope: str | None) -> FlextCore.Result[bool]:
        """Centralized LDAP scope validation - LDAP-specific."""
        if scope is None:
            return FlextCore.Result[bool].fail("Scope cannot be None")

        valid_scopes = {"base", "onelevel", "subtree"}
        if scope.lower() not in valid_scopes:
            error_msg = f"Invalid scope: {scope}. Must be one of {', '.join(sorted(valid_scopes))}"
            return FlextCore.Result[bool].fail(error_msg)

        return FlextCore.Result[bool].ok(True)

    @staticmethod
    def validate_modify_operation(operation: str | None) -> FlextCore.Result[bool]:
        """Centralized LDAP modify operation validation - LDAP-specific."""
        if operation is None:
            return FlextCore.Result[bool].fail("Operation cannot be None")

        valid_operations = {"add", "delete", "replace"}
        if operation.lower() not in valid_operations:
            error_msg = f"Invalid operation: {operation}. Must be one of {', '.join(sorted(valid_operations))}"
            return FlextCore.Result[bool].fail(error_msg)

        return FlextCore.Result[bool].ok(True)

    @staticmethod
    def validate_object_class(object_class: str | None) -> FlextCore.Result[bool]:
        """Centralized LDAP object class validation - LDAP-specific."""
        if object_class is None:
            return FlextCore.Result[bool].fail("Object class cannot be None")

        if not object_class or not object_class.strip():
            return FlextCore.Result[bool].fail("Object class cannot be empty")

        return FlextCore.Result[bool].ok(True)

    @staticmethod
    def validate_password(password: str | None) -> FlextCore.Result[bool]:
        """Centralized password validation - ELIMINATE ALL DUPLICATION."""
        if password is None:
            return FlextCore.Result[bool].fail("Password cannot be None")

        min_length = FlextLdapConstants.Validation.MIN_PASSWORD_LENGTH
        max_length = FlextLdapConstants.Validation.MAX_PASSWORD_LENGTH

        if len(password) < min_length:
            return FlextCore.Result[bool].fail(
                f"Password must be at least {min_length} characters",
            )

        if len(password) > max_length:
            return FlextCore.Result[bool].fail(
                f"Password must be no more than {max_length} characters",
            )

        return FlextCore.Result[bool].ok(True)

    @staticmethod
    def validate_connection_config(
        config: FlextCore.Types.Dict | None,
    ) -> FlextCore.Result[bool]:
        """Centralized connection config validation - ELIMINATE ALL DUPLICATION."""
        if config is None:
            return FlextCore.Result[bool].fail("Config cannot be None")

        required_fields = ["server", "port", "bind_dn", "bind_password"]
        for field in required_fields:
            if field not in config or config[field] is None:
                return FlextCore.Result[bool].fail(f"Missing required field: {field}")

        return FlextCore.Result[bool].ok(True)


__all__ = ["FlextLdapValidations"]
