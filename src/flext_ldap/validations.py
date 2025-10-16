"""FLEXT-LDAP Centralized Validations - Break circular dependency.

Extracted from domain.py to eliminate circular import between models.py and domain.py.
This module provides centralized validation logic used by Pydantic validators.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re

from flext_core import FlextResult, FlextTypes, FlextUtilities

from flext_ldap.constants import FlextLdapConstants


class FlextLdapValidations:
    """Centralized LDAP validations to eliminate circular dependencies."""

    @staticmethod
    def validate_dn(dn: str | None, context: str = "DN") -> FlextResult[bool]:
        """Centralized DN validation - ELIMINATE ALL DUPLICATION."""
        if dn is None:
            return FlextResult[bool].fail(f"{context} cannot be None")
        if not dn or not dn.strip():
            return FlextResult[bool].fail(f"{context} cannot be empty")

        # Basic DN format validation (RFC 2253) - must contain = and proper structure
        if (
            not re.match(r"^[a-zA-Z0-9=,\s\-\._]+$", dn.strip())
            or "=" not in dn.strip()
        ):
            return FlextResult[bool].fail(f"{context} contains invalid characters")

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_filter(filter_str: str | None) -> FlextResult[bool]:
        """Centralized LDAP filter validation - ELIMINATE ALL DUPLICATION."""
        if filter_str is None:
            return FlextResult[bool].fail("Filter cannot be None")
        if not filter_str or not filter_str.strip():
            return FlextResult[bool].fail("Filter cannot be empty")

        # Basic filter format validation
        filter_str = filter_str.strip()
        if not filter_str.startswith("(") or not filter_str.endswith(")"):
            return FlextResult[bool].fail("Filter must be enclosed in parentheses")

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_attributes(
        attributes: FlextTypes.StringList | None,
    ) -> FlextResult[bool]:
        """Centralized LDAP attributes validation - ELIMINATE ALL DUPLICATION."""
        if attributes is None or not attributes:
            return FlextResult[bool].fail("Attributes list cannot be empty")

        for attr in attributes:
            if not attr or not attr.strip():
                return FlextResult[bool].fail(f"Invalid attribute name: {attr}")
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9\-]*$", attr.strip()):
                return FlextResult[bool].fail(f"Invalid attribute name: {attr}")

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_server_uri(server_uri: str | None) -> FlextResult[bool]:
        """Centralized server URI validation - ELIMINATE ALL DUPLICATION."""
        if server_uri is None:
            return FlextResult[bool].fail("URI cannot be None")
        if not server_uri or not server_uri.strip():
            return FlextResult[bool].fail("URI cannot be empty")

        server_uri = server_uri.strip()
        if not server_uri.startswith(("ldap://", "ldaps://")):
            return FlextResult[bool].fail("URI must start with ldap:// or ldaps://")

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_timeout(timeout: int | None) -> FlextResult[bool]:
        """Centralized timeout validation - LDAP-specific non-negative integer."""
        if timeout is None:
            return FlextResult[bool].fail("Timeout cannot be None")

        if timeout < 0:
            return FlextResult[bool].fail("Timeout must be non-negative")

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_size_limit(size_limit: int | None) -> FlextResult[bool]:
        """Centralized size limit validation - LDAP-specific non-negative integer."""
        if size_limit is None:
            return FlextResult[bool].fail("Size limit cannot be None")

        if size_limit < 0:
            return FlextResult[bool].fail("Size limit must be non-negative")

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_scope(scope: str | None) -> FlextResult[bool]:
        """Centralized LDAP scope validation - LDAP-specific."""
        if scope is None:
            return FlextResult[bool].fail("Scope cannot be None")

        valid_scopes = {"base", "onelevel", "subtree"}
        if scope.lower() not in valid_scopes:
            error_msg = f"Invalid scope: {scope}. Must be one of {', '.join(sorted(valid_scopes))}"
            return FlextResult[bool].fail(error_msg)

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_modify_operation(operation: str | None) -> FlextResult[bool]:
        """Centralized LDAP modify operation validation - LDAP-specific."""
        if operation is None:
            return FlextResult[bool].fail("Operation cannot be None")

        valid_operations = {"add", "delete", "replace"}
        if operation.lower() not in valid_operations:
            error_msg = f"Invalid operation: {operation}. Must be one of {', '.join(sorted(valid_operations))}"
            return FlextResult[bool].fail(error_msg)

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_object_class(object_class: str | None) -> FlextResult[bool]:
        """Centralized LDAP object class validation - LDAP-specific."""
        if object_class is None:
            return FlextResult[bool].fail("Object class cannot be None")

        if not object_class or not object_class.strip():
            return FlextResult[bool].fail("Object class cannot be empty")

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_password(password: str | None) -> FlextResult[bool]:
        """Centralized password validation - ELIMINATE ALL DUPLICATION."""
        if password is None:
            return FlextResult[bool].fail("Password cannot be None")

        min_length = FlextLdapConstants.Validation.MIN_PASSWORD_LENGTH
        max_length = FlextLdapConstants.Validation.MAX_PASSWORD_LENGTH

        if len(password) < min_length:
            return FlextResult[bool].fail(
                f"Password must be at least {min_length} characters",
            )

        if len(password) > max_length:
            return FlextResult[bool].fail(
                f"Password must be no more than {max_length} characters",
            )

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_connection_config(
        config: FlextTypes.Dict | None,
    ) -> FlextResult[bool]:
        """Centralized connection config validation - ELIMINATE ALL DUPLICATION."""
        if config is None:
            return FlextResult[bool].fail("Config cannot be None")

        required_fields = ["server", "port", "bind_dn", "bind_password"]
        for field in required_fields:
            if field not in config or config[field] is None:
                return FlextResult[bool].fail(f"Missing required field: {field}")

        return FlextResult[bool].ok(True)

    # Field validator helpers for Pydantic (raise exceptions instead of returning Result)

    @staticmethod
    def validate_dn_for_field(dn: str) -> str:
        """DN validation for Pydantic field validators - raises exception on failure."""
        # Import here to avoid circular dependency
        from flext_core import FlextExceptions  # noqa: PLC0415
        from flext_ldif import DnService  # noqa: PLC0415

        # Clean DN first to handle OID export quirks
        cleaned_dn = DnService.clean_dn(dn)

        validation_result = FlextLdapValidations.validate_dn(cleaned_dn).map(
            lambda _: None
        )
        if validation_result.is_failure:
            error_msg = validation_result.error or "DN validation failed"
            raise FlextExceptions.ValidationError(error_msg, field="dn", value=dn)
        return cleaned_dn.strip()

    @staticmethod
    def validate_email_for_field(email: str | None) -> str | None:
        """Email validation for Pydantic field validators - raises exception on failure."""
        if email is None:
            return None

        # Import here to avoid circular dependency
        from flext_core import FlextExceptions  # noqa: PLC0415

        validation_result = FlextUtilities.Validation.validate_email(email)
        if validation_result.is_failure:
            error_msg = validation_result.error or "Email validation failed"
            raise FlextExceptions.ValidationError(error_msg, field="email", value=email)
        return email

    @staticmethod
    def validate_password_for_field(password: str | None) -> str | None:
        """Password validation for Pydantic field validators - raises exception on failure."""
        # Import here to avoid circular dependency
        from flext_core import FlextExceptions  # noqa: PLC0415

        validation_result = FlextLdapValidations.validate_password(
            str(password) if password is not None else ""
        ).map(lambda _: None)
        if validation_result.is_failure:
            error_msg = validation_result.error or "Password validation failed"
            raise FlextExceptions.ValidationError(
                error_msg, field="password", value="***"
            )
        return password

    @staticmethod
    def validate_required_string_for_field(value: str) -> str:
        """Required string validation for Pydantic field validators - raises exception on failure."""
        # Import here to avoid circular dependency
        from flext_core import FlextExceptions  # noqa: PLC0415

        if not value or not value.strip():
            error_msg = "Required field cannot be empty"
            raise FlextExceptions.ValidationError(
                error_msg,
                field="required_string",
                value=value,
            )
        return value.strip()


__all__ = ["FlextLdapValidations"]
