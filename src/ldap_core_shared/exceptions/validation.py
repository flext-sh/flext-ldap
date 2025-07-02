"""✅ Validation-related LDAP Exceptions.

Exception classes for data validation and schema compliance errors.
"""

from __future__ import annotations

from typing import Any

from ldap_core_shared.exceptions.base import LDAPError


class ValidationError(LDAPError):
    """✅ Exception for data validation failures.

    Raised when LDAP data doesn't conform to expected format or schema.
    """

    def __init__(
        self,
        message: str,
        *,
        field_name: str | None = None,
        field_value: Any | None = None,
        validation_rule: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize validation error.

        Args:
            message: Error description
            field_name: Name of field that failed validation
            field_value: Value that failed validation
            validation_rule: Rule that was violated
            **kwargs: Additional arguments for LDAPError

        """
        context = kwargs.get("context", {})
        if field_name:
            context["field_name"] = field_name
        if field_value is not None:
            context["field_value"] = str(field_value)  # Convert to string for safety
        if validation_rule:
            context["validation_rule"] = validation_rule

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class SchemaValidationError(ValidationError):
    """📋 Exception for LDAP schema validation failures."""

    def __init__(
        self,
        message: str,
        *,
        object_class: str | None = None,
        attribute_name: str | None = None,
        schema_rule: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize schema validation error.

        Args:
            message: Error description
            object_class: Object class involved in error
            attribute_name: Attribute that failed validation
            schema_rule: Schema rule that was violated
            **kwargs: Additional arguments for ValidationError

        """
        context = kwargs.get("context", {})
        if object_class:
            context["object_class"] = object_class
        if attribute_name:
            context["attribute_name"] = attribute_name
        if schema_rule:
            context["schema_rule"] = schema_rule

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class DNValidationError(ValidationError):
    """🏷️ Exception for Distinguished Name validation failures."""

    def __init__(
        self,
        message: str,
        *,
        dn: str | None = None,
        component: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize DN validation error.

        Args:
            message: Error description
            dn: DN that failed validation
            component: Specific DN component that failed
            **kwargs: Additional arguments for ValidationError

        """
        context = kwargs.get("context", {})
        if dn:
            context["dn"] = dn
        if component:
            context["component"] = component

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class FilterValidationError(ValidationError):
    """🔍 Exception for LDAP filter validation failures."""

    def __init__(
        self,
        message: str,
        *,
        filter_string: str | None = None,
        filter_component: str | None = None,
        syntax_error: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize filter validation error.

        Args:
            message: Error description
            filter_string: LDAP filter that failed validation
            filter_component: Specific filter component that failed
            syntax_error: Syntax error details
            **kwargs: Additional arguments for ValidationError

        """
        context = kwargs.get("context", {})
        if filter_string:
            context["filter_string"] = filter_string
        if filter_component:
            context["filter_component"] = filter_component
        if syntax_error:
            context["syntax_error"] = syntax_error

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class AttributeValidationError(ValidationError):
    """🏷️ Exception for LDAP attribute validation failures."""

    def __init__(
        self,
        message: str,
        *,
        attribute_name: str | None = None,
        attribute_value: Any | None = None,
        attribute_syntax: str | None = None,
        validation_type: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize attribute validation error.

        Args:
            message: Error description
            attribute_name: Name of attribute that failed validation
            attribute_value: Value that failed validation
            attribute_syntax: Expected attribute syntax
            validation_type: Type of validation that failed
            **kwargs: Additional arguments for ValidationError

        """
        context = kwargs.get("context", {})
        if attribute_name:
            context["attribute_name"] = attribute_name
        if attribute_value is not None:
            context["attribute_value"] = str(attribute_value)
        if attribute_syntax:
            context["attribute_syntax"] = attribute_syntax
        if validation_type:
            context["validation_type"] = validation_type

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class LDIFValidationError(ValidationError):
    """📄 Exception for LDIF format validation failures."""

    def __init__(
        self,
        message: str,
        *,
        line_number: int | None = None,
        ldif_line: str | None = None,
        entry_dn: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize LDIF validation error.

        Args:
            message: Error description
            line_number: Line number in LDIF file
            ldif_line: Content of problematic line
            entry_dn: DN of entry being processed
            **kwargs: Additional arguments for ValidationError

        """
        context = kwargs.get("context", {})
        if line_number:
            context["line_number"] = line_number
        if ldif_line:
            context["ldif_line"] = ldif_line
        if entry_dn:
            context["entry_dn"] = entry_dn

        kwargs["context"] = context
        super().__init__(message, **kwargs)
