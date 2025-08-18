"""FLEXT-LDAP Exceptions.

This module provides comprehensive exception hierarchy for FLEXT-LDAP operations.
Follows FLEXT ecosystem patterns with centralized error handling and FlextResult integration.

Key Features:
- Type-safe exception hierarchy extending flext-core patterns
- Contextual error information for LDAP operations
- Factory methods for consistent error creation
- Integration with FlextResult pattern for type-safe error handling
"""

from __future__ import annotations

from typing import ClassVar

from flext_core import FlextError, get_logger

from flext_ldap.constants import FlextLdapOperationMessages

# =============================================================================
# LDAP DOMAIN EXCEPTIONS - PROFESSIONAL TYPE-SAFE HIERARCHY
# =============================================================================


logger = get_logger(__name__)


class FlextLdapException(FlextError):
    """Base exception for FLEXT-LDAP with optional LDAP context and codes."""

    def __init__(
        self,
        message: str,
        *,
        ldap_result_code: str | None = None,
        ldap_context: dict[str, object] | None = None,
        operation: str | None = None,
        error_code: str | None = None,
    ) -> None:
        """Initialize exception with optional LDAP context details.

        Args:
            message: Error message describing the issue
            ldap_result_code: LDAP server result code
            ldap_context: Additional context for debugging
            operation: LDAP operation that failed
            error_code: Error code for categorization

        """
        super().__init__(message, error_code=error_code)
        self.ldap_result_code = ldap_result_code
        self.ldap_context = ldap_context or {}
        self.operation = operation
        logger.debug(f"LDAP exception created: {message}", extra={
            "operation": operation,
            "ldap_result_code": ldap_result_code,
            "context": ldap_context
        })

    def __str__(self) -> str:
        """Format exception string including LDAP context metadata."""
        parts = [super().__str__()]

        if self.operation:
            parts.append(
                FlextLdapOperationMessages.OPERATION_CONTEXT.format(
                    operation=self.operation
                )
            )

        if self.ldap_result_code:
            parts.append(
                FlextLdapOperationMessages.LDAP_CODE_CONTEXT.format(
                    code=self.ldap_result_code
                )
            )

        if self.ldap_context:
            context_str = ", ".join(f"{k}={v}" for k, v in self.ldap_context.items())
            parts.append(
                FlextLdapOperationMessages.CONTEXT_INFO.format(context=context_str)
            )

        return " | ".join(parts)


# =============================================================================
# CONNECTION AND AUTHENTICATION EXCEPTIONS
# =============================================================================


class FlextLdapConnectionError(FlextLdapException):
    """LDAP connection related errors.

    Raised when connection establishment, maintenance, or termination fails.
    Includes server connectivity issues, network timeouts, and protocol errors.

    This exception follows FLEXT patterns for type-safe error handling
    and integrates with FlextResult for railway-oriented programming.
    """

    def __init__(
        self,
        message: str,
        *,
        server_uri: str | None = None,
        timeout: int | None = None,
        retry_count: int | None = None,
    ) -> None:
        """Initialize connection error with network context.

        Args:
            message: Error description
            server_uri: LDAP server URI that failed
            timeout: Connection timeout used
            retry_count: Number of retries attempted

        """
        context: dict[str, object] = {}
        if server_uri:
            context[FlextLdapOperationMessages.SERVER_URI_KEY] = server_uri
        if timeout:
            context[FlextLdapOperationMessages.TIMEOUT_KEY] = str(timeout)
        if retry_count is not None:
            context[FlextLdapOperationMessages.RETRY_COUNT_KEY] = str(retry_count)

        super().__init__(
            message,
            ldap_context=context,
            operation=FlextLdapOperationMessages.CONNECTION_OPERATION,
            error_code="LDAP_CONNECTION_ERROR",
        )


class FlextLdapAuthenticationError(FlextLdapException):
    """LDAP authentication errors.

    Raised when bind operations fail due to invalid credentials,
    insufficient privileges, or authentication method issues.
    """

    def __init__(
        self,
        message: str,
        *,
        bind_dn: str | None = None,
        auth_method: str | None = None,
        ldap_result_code: str | None = None,
    ) -> None:
        """Initialize authentication error.

        Args:
            message: Error description
            bind_dn: DN used for binding (password omitted for security)
            auth_method: Authentication method attempted
            ldap_result_code: LDAP result code from server

        """
        context: dict[str, object] = {}
        if bind_dn:
            context["bind_dn"] = bind_dn
        if auth_method:
            context["auth_method"] = auth_method

        super().__init__(
            message,
            ldap_result_code=ldap_result_code,
            ldap_context=context,
            operation="authentication",
            error_code="LDAP_AUTH_ERROR",
        )


# =============================================================================
# OPERATION EXCEPTIONS
# =============================================================================


class FlextLdapSearchError(FlextLdapException):
    """LDAP search operation errors.

    Raised when search operations fail due to invalid filters,
    base DN issues, permission problems, or result processing errors.
    """

    def __init__(
        self,
        message: str,
        *,
        base_dn: str | None = None,
        search_filter: str | None = None,
        scope: str | None = None,
        ldap_result_code: str | None = None,
    ) -> None:
        """Initialize search error with query context.

        Args:
            message: Error description
            base_dn: Base DN used in search
            search_filter: LDAP filter expression
            scope: Search scope (base, onelevel, subtree)
            ldap_result_code: LDAP result code from server

        """
        context: dict[str, object] = {}
        if base_dn:
            context["base_dn"] = base_dn
        if search_filter:
            context["filter"] = search_filter
        if scope:
            context["scope"] = scope

        super().__init__(
            message,
            ldap_result_code=ldap_result_code,
            ldap_context=context,
            operation="search",
            error_code="LDAP_SEARCH_ERROR",
        )


class FlextLdapOperationError(FlextLdapException):
    """LDAP modify operations errors (add, modify, delete).

    Raised when directory modification operations fail due to
    schema violations, permission issues, or data constraints.
    """

    def __init__(
        self,
        message: str,
        *,
        target_dn: str | None = None,
        operation_type: str | None = None,
        ldap_result_code: str | None = None,
    ) -> None:
        """Initialize operation error.

        Args:
            message: Error description
            target_dn: DN being operated on
            operation_type: Type of operation (add, modify, delete, etc.)
            ldap_result_code: LDAP result code from server

        """
        context: dict[str, object] = {}
        if target_dn:
            context["target_dn"] = target_dn
        if operation_type:
            context["operation_type"] = operation_type

        super().__init__(
            message,
            ldap_result_code=ldap_result_code,
            ldap_context=context,
            operation=operation_type or "modify",
            error_code="LDAP_OPERATION_ERROR",
        )


# =============================================================================
# DOMAIN-SPECIFIC EXCEPTIONS
# =============================================================================


class FlextLdapUserError(FlextLdapException):
    """LDAP user-specific errors.

    Raised when user operations fail due to user-specific business rules,
    validation errors, or user lifecycle management issues.
    """

    def __init__(
        self,
        message: str,
        *,
        user_dn: str | None = None,
        uid: str | None = None,
        validation_field: str | None = None,
    ) -> None:
        """Initialize user error.

        Args:
            message: Error description
            user_dn: User's distinguished name
            uid: User identifier
            validation_field: Field that failed validation

        """
        context: dict[str, object] = {}
        if user_dn:
            context["user_dn"] = user_dn
        if uid:
            context["uid"] = uid
        if validation_field:
            context["field"] = validation_field

        super().__init__(
            message,
            ldap_context=context,
            operation="user_management",
            error_code="LDAP_USER_ERROR"
        )


class FlextLdapGroupError(FlextLdapException):
    """LDAP group-specific errors.

    Raised when group operations fail due to membership issues,
    group policy violations, or group lifecycle management problems.
    """

    def __init__(
        self,
        message: str,
        *,
        group_dn: str | None = None,
        group_cn: str | None = None,
        member_dn: str | None = None,
    ) -> None:
        """Initialize group error.

        Args:
            message: Error description
            group_dn: Group's distinguished name
            group_cn: Group's common name
            member_dn: Member DN involved in operation

        """
        context: dict[str, object] = {}
        if group_dn:
            context["group_dn"] = group_dn
        if group_cn:
            context["group_cn"] = group_cn
        if member_dn:
            context["member_dn"] = member_dn

        super().__init__(
            message,
            ldap_context=context,
            operation="group_management",
            error_code="LDAP_GROUP_ERROR"
        )


# =============================================================================
# VALIDATION AND CONFIGURATION EXCEPTIONS
# =============================================================================


class FlextLdapValidationError(FlextLdapException):
    """LDAP data validation errors.

    Raised when data validation fails for LDAP attributes, DN formats,
    filter syntax, or business rule validation.
    """

    def __init__(
        self,
        message: str,
        *,
        field_name: str | None = None,
        field_value: str | None = None,
        validation_rule: str | None = None,
    ) -> None:
        """Initialize validation error.

        Args:
            message: Error description
            field_name: Name of field that failed validation
            field_value: Value that failed (may be redacted for security)
            validation_rule: Validation rule that was violated

        """
        context: dict[str, object] = {}
        if field_name:
            context["field"] = field_name
        if field_value:
            # Redact potentially sensitive values
            if field_name and "password" in field_name.lower():
                context["value"] = "[REDACTED]"
            else:
                context["value"] = field_value
        if validation_rule:
            context["rule"] = validation_rule

        super().__init__(
            message,
            ldap_context=context,
            operation="validation",
            error_code="LDAP_VALIDATION_ERROR"
        )


class FlextLdapConfigurationError(FlextLdapException):
    """LDAP configuration and settings errors.

    Raised when configuration is invalid, missing required settings,
    or contains conflicting parameters.
    """

    def __init__(
        self,
        message: str,
        *,
        config_section: str | None = None,
        config_key: str | None = None,
    ) -> None:
        """Initialize configuration error.

        Args:
            message: Error description
            config_section: Configuration section with error
            config_key: Specific configuration key with problem

        """
        context: dict[str, object] = {}
        if config_section:
            context["section"] = config_section
        if config_key:
            context["key"] = config_key

        super().__init__(
            message,
            ldap_context=context,
            operation="configuration",
            error_code="LDAP_CONFIG_ERROR"
        )


class FlextLdapTypeError(FlextLdapException):
    """LDAP type validation and conversion errors.

    Raised when type conversion fails, attribute types are incompatible,
    or schema type constraints are violated.
    """

    def __init__(
        self,
        message: str,
        *,
        expected_type: str | None = None,
        actual_type: str | None = None,
        attribute_name: str | None = None,
    ) -> None:
        """Initialize type error.

        Args:
            message: Error description
            expected_type: Expected data type
            actual_type: Actual data type received
            attribute_name: LDAP attribute name involved

        """
        context: dict[str, object] = {}
        if expected_type:
            context["expected"] = expected_type
        if actual_type:
            context["actual"] = actual_type
        if attribute_name:
            context["attribute"] = attribute_name

        super().__init__(
            message,
            ldap_context=context,
            operation="type_conversion",
            error_code="LDAP_TYPE_ERROR"
        )


# =============================================================================
# EXCEPTION FACTORY - CENTRALIZED ERROR CREATION
# =============================================================================


class FlextLdapExceptionFactory:
    """Factory for creating consistent LDAP exceptions with proper context.

    Provides centralized exception creation to ensure consistent error formatting,
    context preservation, and proper error categorization across the library.
    """

    # Common LDAP result codes for quick reference
    LDAP_RESULT_CODES: ClassVar[dict[str, str]] = {
        "0": "Success",
        "1": "Operations Error",
        "32": "No Such Object",
        "34": "Invalid DN Syntax",
        "49": "Invalid Credentials",
        "50": "Insufficient Access Rights",
        "68": "Entry Already Exists",
    }

    @classmethod
    def connection_failed(
        cls,
        server_uri: str,
        error: str,
        *,
        timeout: int | None = None,
        retry_count: int | None = None,
    ) -> FlextLdapConnectionError:
        """Create connection failure exception."""
        message = f"Failed to connect to LDAP server: {error}"
        return FlextLdapConnectionError(
            message,
            server_uri=server_uri,
            timeout=timeout,
            retry_count=retry_count,
        )

    @classmethod
    def authentication_failed(
        cls,
        bind_dn: str,
        ldap_result_code: str | None = None,
    ) -> FlextLdapAuthenticationError:
        """Create authentication failure exception."""
        message = "LDAP authentication failed"
        if ldap_result_code and ldap_result_code in cls.LDAP_RESULT_CODES:
            message += f": {cls.LDAP_RESULT_CODES[ldap_result_code]}"

        return FlextLdapAuthenticationError(
            message,
            bind_dn=bind_dn,
            ldap_result_code=ldap_result_code,
        )

    @classmethod
    def search_failed(
        cls,
        base_dn: str,
        search_filter: str,
        error: str,
        *,
        ldap_result_code: str | None = None,
    ) -> FlextLdapSearchError:
        """Create search operation failure exception."""
        message = f"LDAP search failed: {error}"
        return FlextLdapSearchError(
            message,
            base_dn=base_dn,
            search_filter=search_filter,
            ldap_result_code=ldap_result_code,
        )

    @classmethod
    def user_creation_failed(
        cls,
        user_dn: str,
        error: str,
        *,
        uid: str | None = None,
        ldap_result_code: str | None = None,
    ) -> FlextLdapUserError:
        """Create user creation failure exception."""
        message = f"User creation failed: {error}"
        if ldap_result_code:
            code_desc = cls.LDAP_RESULT_CODES.get(
                str(ldap_result_code), str(ldap_result_code)
            )
            message = f"{message} (code: {code_desc})"
        return FlextLdapUserError(
            message,
            user_dn=user_dn,
            uid=uid,
        )

    @classmethod
    def validation_failed(
        cls,
        field_name: str,
        error: str,
        *,
        field_value: str | None = None,
        validation_rule: str | None = None,
    ) -> FlextLdapValidationError:
        """Create validation failure exception."""
        message = f"Validation failed for {field_name}: {error}"
        return FlextLdapValidationError(
            message,
            field_name=field_name,
            field_value=field_value,
            validation_rule=validation_rule,
        )

    @classmethod
    def configuration_error(
        cls,
        config_key: str,
        error: str,
        *,
        config_section: str | None = None,
    ) -> FlextLdapConfigurationError:
        """Create configuration error exception."""
        message = f"Configuration error in {config_key}: {error}"
        return FlextLdapConfigurationError(
            message,
            config_section=config_section,
            config_key=config_key,
        )


# Export all exception classes and factory
__all__ = [
    "FlextLdapAuthenticationError",
    "FlextLdapConfigurationError",
    "FlextLdapConnectionError",
    "FlextLdapException",
    "FlextLdapExceptionFactory",
    "FlextLdapGroupError",
    "FlextLdapOperationError",
    "FlextLdapSearchError",
    "FlextLdapTypeError",
    "FlextLdapUserError",
    "FlextLdapValidationError",
]
