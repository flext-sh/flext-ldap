"""Centralized LDAP validations breaking circular dependencies.

Extracted from domain.py to eliminate circular imports. Provides
centralized validation logic for Pydantic validators with DN format,
filter syntax, and attribute validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_core import FlextExceptions, FlextResult
from flext_ldif.services import FlextLdifDn, FlextLdifValidation

from flext_ldap.constants import FlextLdapConstants


class FlextLdapValidations:
    """Centralized LDAP validations delegating to flext-ldif services.

    Delegates shared validation logic to flext-ldif services to eliminate
    duplication and follow SRP. LDAP-specific validations remain here.
    """

    _dn_service = FlextLdifDn()
    _validation_service = FlextLdifValidation()

    @classmethod
    def validate_dn(cls, dn: str | None, context: str = "DN") -> FlextResult[bool]:
        """Centralized DN validation - delegates to FlextLdifDn."""
        if dn is None:
            return FlextResult[bool].fail(f"{context} cannot be None")
        if not dn or not dn.strip():
            return FlextResult[bool].fail(f"{context} cannot be empty")

        # Clean DN first to handle formatting issues
        cleaned_dn = cls._dn_service.clean_dn(dn.strip())

        # Validate format using FlextLdifDn
        format_result = cls._dn_service.validate_format(cleaned_dn)
        if format_result.is_failure:
            return format_result.map(lambda _: False)

        is_valid = format_result.unwrap()
        if not is_valid:
            return FlextResult[bool].fail(f"{context} has invalid format")

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_filter(filter_str: str | None) -> FlextResult[bool]:
        """Centralized LDAP filter validation - ELIMINATE ALL DUPLICATION."""
        if filter_str is None:
            return FlextResult[bool].fail("Filter cannot be None")
        if not filter_str or not filter_str.strip():
            return FlextResult[bool].fail("Filter cannot be empty")

        # Use regex for pattern validation
        # LDAP filters must be enclosed in parentheses: (filter)
        if not re.match(
            FlextLdapConstants.RegexPatterns.FILTER_PATTERN,
            filter_str.strip(),
        ):
            return FlextResult[bool].fail("Filter must be enclosed in parentheses")

        return FlextResult[bool].ok(True)

    @classmethod
    def validate_attributes(
        cls,
        attributes: list[str] | None,
    ) -> FlextResult[bool]:
        """Centralized LDAP attributes validation - delegates to FlextLdifValidation."""
        if attributes is None or not attributes:
            return FlextResult[bool].fail("Attributes list cannot be empty")

        for attr in attributes:
            if not attr or not attr.strip():
                return FlextResult[bool].fail(f"Invalid attribute name: {attr}")

            # Use FlextLdifValidation for RFC 4512 compliant validation
            attr_result = cls._validation_service.validate_attribute_name(attr.strip())
            if attr_result.is_failure or not attr_result.unwrap():
                return FlextResult[bool].fail(f"Invalid attribute name: {attr}")

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_server_uri(server_uri: str | None) -> FlextResult[bool]:
        """Centralized server URI validation - ELIMINATE ALL DUPLICATION."""
        if server_uri is None:
            return FlextResult[bool].fail("URI cannot be None")
        if not server_uri or not server_uri.strip():
            return FlextResult[bool].fail("URI cannot be empty")

        server_uri_stripped = server_uri.strip()

        # Use regex for pattern validation
        # LDAP URIs must start with ldap:// or ldaps://
        if not re.match(
            FlextLdapConstants.RegexPatterns.SERVER_URI_PATTERN,
            server_uri_stripped,
        ):
            return FlextResult[bool].fail("URI must start with ldap:// or ldaps://")

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_timeout(timeout: int | None) -> FlextResult[bool]:
        """Centralized timeout validation - LDAP-specific non-negative integer."""
        if timeout is None:
            return FlextResult[bool].fail("Timeout cannot be None")

        # Validate non-negative using Pydantic v2 Field constraint pattern
        if timeout < 0:
            return FlextResult[bool].fail("Timeout must be non-negative")

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_size_limit(size_limit: int | None) -> FlextResult[bool]:
        """Centralized size limit validation - LDAP-specific non-negative integer."""
        if size_limit is None:
            return FlextResult[bool].fail("Size limit cannot be None")

        # Validate non-negative using Pydantic v2 Field constraint pattern
        if size_limit < 0:
            return FlextResult[bool].fail("Size limit must be non-negative")

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_scope(scope: str | None) -> FlextResult[bool]:
        """Centralized LDAP scope validation - LDAP-specific."""
        if scope is None:
            return FlextResult[bool].fail("Scope cannot be None")

        valid_scopes = FlextLdapConstants.ValidationSets.VALID_SCOPES
        if scope.lower() not in valid_scopes:
            scopes_str = ", ".join(sorted(valid_scopes))
            error_msg = f"Invalid scope: {scope}. Must be one of {scopes_str}"
            return FlextResult[bool].fail(error_msg)

        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_modify_operation(operation: str | None) -> FlextResult[bool]:
        """Centralized LDAP modify operation validation - LDAP-specific."""
        if operation is None:
            return FlextResult[bool].fail("Operation cannot be None")

        valid_operations = {
            "add",
            "delete",
            "replace",
        }
        if operation.lower() not in valid_operations:
            ops_str = ", ".join(sorted(valid_operations))
            error_msg = f"Invalid operation: {operation}. Must be one of {ops_str}"
            return FlextResult[bool].fail(error_msg)

        return FlextResult[bool].ok(True)

    @classmethod
    def validate_object_class(cls, object_class: str | None) -> FlextResult[bool]:
        """Centralized LDAP object class validation - delegates to FlextLdifValidation."""
        if object_class is None:
            return FlextResult[bool].fail("Object class cannot be None")

        if not object_class or not object_class.strip():
            return FlextResult[bool].fail("Object class cannot be empty")

        # Use FlextLdifValidation for RFC 4512 compliant validation
        oc_result = cls._validation_service.validate_objectclass_name(
            object_class.strip(),
        )
        if oc_result.is_failure:
            return oc_result.map(lambda _: False)

        is_valid = oc_result.unwrap()
        if not is_valid:
            return FlextResult[bool].fail("Object class has invalid format")

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
        config: dict[str, object] | None,
    ) -> FlextResult[bool]:
        """Centralized connection config validation - ELIMINATE ALL DUPLICATION."""
        if config is None:
            return FlextResult[bool].fail("Config cannot be None")

        required_fields = FlextLdapConstants.ValidationSets.REQUIRED_CONNECTION_FIELDS
        for field in required_fields:
            if field not in config or config[field] is None:
                return FlextResult[bool].fail(f"Missing required field: {field}")

        return FlextResult[bool].ok(True)

    # Field validators for Pydantic (raise exceptions)

    @classmethod
    def validate_dn_for_field(cls, dn: str) -> str:
        """DN validation for Pydantic field validators - raises exception on failure."""
        # Clean DN first to handle OID export quirks
        cleaned_dn = cls._dn_service.clean_dn(dn)

        validation_result = cls.validate_dn(cleaned_dn).map(lambda _: None)
        if validation_result.is_failure:
            error_msg = validation_result.error or "DN validation failed"
            raise FlextExceptions.ValidationError(error_msg, field="dn", value=dn)
        return cleaned_dn.strip()

    @staticmethod
    def validate_password_for_field(password: str | None) -> str | None:
        """Password field validator - raises on failure."""
        # Import here to avoid circular dependency
        validation_result = FlextLdapValidations.validate_password(
            str(password) if password is not None else "",
        ).map(lambda _: None)
        if validation_result.is_failure:
            error_msg = validation_result.error or "Password validation failed"
            raise FlextExceptions.ValidationError(
                error_msg,
                field="password",
                value="***",
            )
        return password

    @staticmethod
    def validate_required_string_for_field(value: str) -> str:
        """Required string field validator - raises on failure."""
        # Import here to avoid circular dependency

        if not value or not value.strip():
            error_msg = "Required field cannot be empty"
            raise FlextExceptions.ValidationError(
                error_msg,
                field="required_string",
                value=value,
            )
        return value.strip()


__all__ = ["FlextLdapValidations"]
