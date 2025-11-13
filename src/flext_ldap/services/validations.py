"""Centralized LDAP validations breaking circular dependencies.

Extracted from domain.py to eliminate circular imports. Provides
centralized validation logic for Pydantic validators with DN format,
filter syntax, and attribute validation.

Most validations delegate to FlextLdapUtilities.Validation and FlextLdifUtilities
following Single Responsibility Principle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextExceptions, FlextResult, FlextRuntime

from flext_ldif import FlextLdifUtilities
from flext_ldif.services.validation import FlextLdifValidation

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.utilities import FlextLdapUtilities


class FlextLdapValidations:
    """Centralized LDAP validations delegating to utilities and flext-ldif services.

    Delegates shared validation logic to utilities and flext-ldif services to eliminate
    duplication and follow SRP. Provides convenience methods for common validations.
    """

    _dn_service = FlextLdifUtilities.DN()
    _validation_service = FlextLdifValidation()

    @classmethod
    def validate_dn(cls, dn: str | None, context: str = "DN") -> FlextResult[bool]:
        """Centralized DN validation - delegates to FlextLdifUtilities.DN.

        Args:
            dn: DN string to validate
            context: Context string for error messages

        Returns:
            FlextResult[bool] indicating validation success or failure

        """
        if dn is None:
            return FlextResult[bool].fail(f"{context} cannot be None")
        if not dn or not dn.strip():
            return FlextResult[bool].fail(f"{context} cannot be empty")

        # Clean DN first to handle formatting issues
        cleaned_dn = cls._dn_service.clean_dn(dn.strip())

        # Validate format using FlextLdifDn
        is_valid = cls._dn_service.validate(cleaned_dn)
        if not is_valid:
            return FlextResult[bool].fail(f"{context} has invalid format")

        return FlextResult[bool].ok(True)

    @classmethod
    def validate_attributes(
        cls,
        attributes: list[str] | None,
    ) -> FlextResult[bool]:
        """Centralized LDAP attributes validation - delegates to FlextLdifValidation.

        Args:
            attributes: List of attribute names to validate

        Returns:
            FlextResult[bool] indicating validation success or failure

        """
        if attributes is None or not attributes:
            return FlextResult[bool].fail("Attributes list cannot be empty")

        for attr in attributes:
            if not attr or not attr.strip():
                return FlextResult[bool].fail(f"Invalid attribute name: {attr}")

            # Use FlextLdifValidation for RFC 4512 compliant validation
            attr_result = cls._validation_service.validate_attribute_name(attr.strip())
            if attr_result.is_failure or not attr_result.unwrap():
                return FlextResult[bool].fail(f"Invalid attribute name: {attr}")

            # Additional validation: check if attribute name is a valid Python identifier
            # This helps catch common mistakes while allowing valid LDAP attribute names
            if not FlextRuntime.is_valid_identifier(attr.strip()):
                # Log warning but don't fail - LDAP allows attribute names that aren't Python identifiers
                cls._validation_service.logger.warning(
                    f"Attribute name '{attr}' is not a valid Python identifier, "
                    "but may still be valid for LDAP"
                )

        return FlextResult[bool].ok(True)

    @classmethod
    def validate_object_class(cls, object_class: str | None) -> FlextResult[bool]:
        """Centralized LDAP object class validation - delegates to FlextLdifValidation.

        Args:
            object_class: Object class name to validate

        Returns:
            FlextResult[bool] indicating validation success or failure

        """
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
    def validate_connection_config(
        config: dict[str, object] | None,
    ) -> FlextResult[bool]:
        """Centralized connection config validation.

        Args:
            config: Connection configuration dictionary

        Returns:
            FlextResult[bool] indicating validation success or failure

        """
        if config is None:
            return FlextResult[bool].fail("Config cannot be None")
        if not config:
            return FlextResult[bool].fail("Config cannot be empty")

        # Config is guaranteed to be a non-empty dict at this point
        required_fields = FlextLdapConstants.ValidationSets.REQUIRED_CONNECTION_FIELDS
        for field in required_fields:
            if field not in config or config[field] is None:
                return FlextResult[bool].fail(f"Missing required field: {field}")
        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_filter(filter_str: str | None) -> FlextResult[bool]:
        """Centralized LDAP filter validation - delegates to FlextLdapUtilities.

        Args:
            filter_str: LDAP filter string to validate

        Returns:
            FlextResult[bool] indicating validation success or failure

        """
        return FlextLdapUtilities.Validation.validate_ldap_filter("filter", filter_str)

    @staticmethod
    def validate_password(password: str | None) -> FlextResult[bool]:
        """Centralized password validation - delegates to FlextLdapUtilities.

        Args:
            password: Password string to validate

        Returns:
            FlextResult[bool] indicating validation success or failure

        """
        return FlextLdapUtilities.Validation.validate_password("password", password)

    @staticmethod
    def validate_server_uri(uri: str | None) -> FlextResult[bool]:
        """Centralized LDAP server URI validation - delegates to FlextLdapUtilities.

        Args:
            uri: LDAP server URI to validate

        Returns:
            FlextResult[bool] indicating validation success or failure

        """
        return FlextLdapUtilities.Validation.validate_ldap_uri("server_uri", uri)

    @staticmethod
    def validate_scope(scope: object) -> FlextResult[bool]:
        """Centralized LDAP scope validation - delegates to FlextLdapUtilities.

        Args:
            scope: LDAP scope to validate

        Returns:
            FlextResult[bool] indicating validation success or failure

        """
        return FlextLdapUtilities.Validation.validate_scope(scope)

    @staticmethod
    def validate_modify_operation(operation: object) -> FlextResult[bool]:
        """Centralized LDAP modify operation validation - delegates to FlextLdapUtilities.

        Args:
            operation: LDAP modify operation to validate

        Returns:
            FlextResult[bool] indicating validation success or failure

        """
        return FlextLdapUtilities.Validation.validate_modify_operation(operation)

    @staticmethod
    def validate_timeout(timeout: object) -> FlextResult[bool]:
        """Centralized timeout validation - delegates to FlextLdapUtilities.

        Args:
            timeout: Timeout value to validate

        Returns:
            FlextResult[bool] indicating validation success or failure

        """
        return FlextLdapUtilities.Validation.validate_non_negative_int("timeout", timeout)

    # Field validators for Pydantic (raise exceptions)

    @classmethod
    def validate_dn_for_field(cls, dn: str) -> str:
        """DN validation for Pydantic field validators - raises exception on failure.

        Args:
            dn: DN string to validate

        Returns:
            Cleaned DN string

        Raises:
            FlextExceptions.ValidationError: If validation fails

        """
        # Clean DN first to handle OID export quirks
        cleaned_dn = cls._dn_service.clean_dn(dn)

        validation_result = cls.validate_dn(cleaned_dn).map(lambda _: None)
        if validation_result.is_failure:
            error_msg = validation_result.error or "DN validation failed"
            raise FlextExceptions.ValidationError(error_msg, field="dn", value=dn)
        return cleaned_dn.strip()

    @staticmethod
    def validate_password_for_field(password: str | None) -> str | None:
        """Password field validator - raises on failure.

        Args:
            password: Password string to validate

        Returns:
            Original password if valid

        Raises:
            FlextExceptions.ValidationError: If validation fails

        """
        validation_result = FlextLdapUtilities.Validation.validate_password(
            "password",
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
        """Required string field validator - raises on failure.

        Args:
            value: String value to validate

        Returns:
            Stripped string value

        Raises:
            FlextExceptions.ValidationError: If validation fails

        """
        if not value or not value.strip():
            error_msg = "Required field cannot be empty"
            raise FlextExceptions.ValidationError(
                error_msg,
                field="required_string",
                value=value,
            )
        return value.strip()


__all__ = ["FlextLdapValidations"]
