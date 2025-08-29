"""LDAP Exceptions - Single FlextLdapExceptions class following FLEXT patterns.

Single class with all LDAP exception definitions, factory methods, and error handling
organized as internal classes for complete backward compatibility.

Examples:
    Basic exceptions:

        from exceptions import FlextLdapExceptions

        # Create connection error
        conn_error = FlextLdapExceptions.LdapConnectionError(
            "Failed to connect",
            server_uri="ldap://localhost:389"
        )

        # Create validation error
        val_error = FlextLdapExceptions.ValidationError(
            "Invalid DN format",
            field_name="dn",
            field_value="invalid-dn"
        )

    Factory methods:

        # Using factory for consistent error creation
        error = FlextLdapExceptions.Factory.connection_failed(
            "ldap://localhost:389",
            "Connection timeout",
            timeout=30
        )

    Legacy compatibility:

        # All previous classes still work as direct imports
        from exceptions import FlextLdapConnectionError, FlextLdapValidationError
        conn_error = FlextLdapConnectionError("Failed to connect")

"""

from __future__ import annotations

from typing import ClassVar, override

from flext_core import FlextExceptions, FlextLogger

from flext_ldap.constants import FlextLdapOperationMessages

logger = FlextLogger(__name__)

# =============================================================================
# SINGLE FLEXT LDAP EXCEPTIONS CLASS - Consolidated exception functionality
# =============================================================================


class FlextLdapExceptions:
    """Single FlextLdapExceptions class with all LDAP exception functionality.

    Consolidates ALL LDAP exception classes, factory methods, and error handling
    into a single class following FLEXT patterns. Everything from connection errors
    to validation errors is available as internal classes with full backward compatibility.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP exception handling consolidated
        - Open/Closed: Extensible without modification
        - Liskov Substitution: Consistent interface across all exception types
        - Interface Segregation: Organized by exception domain for specific access
        - Dependency Inversion: Depends on FlextExceptions abstraction

    Examples:
        Connection and authentication errors:

            conn_error = FlextLdapExceptions.LdapConnectionError(
                "Failed to connect",
                server_uri="ldap://localhost:389"
            )
            auth_error = FlextLdapExceptions.AuthenticationError(
                "Invalid credentials",
                bind_dn="cn=user,dc=example,dc=com"
            )

        Operation and search errors:

            search_error = FlextLdapExceptions.SearchError(
                "Search failed",
                base_dn="dc=example,dc=com",
                search_filter="(uid=john)"
            )
            op_error = FlextLdapExceptions.OperationError(
                "Modify failed",
                target_dn="cn=user,dc=example,dc=com"
            )

        Domain-specific errors:

            user_error = FlextLdapExceptions.UserError(
                "User validation failed",
                user_dn="cn=john,dc=example,dc=com",
                uid="john"
            )
            group_error = FlextLdapExceptions.GroupError(
                "Group membership error",
                group_dn="cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com"
            )

        Using factory methods:

            error = FlextLdapExceptions.Factory.connection_failed(
                "ldap://localhost:389",
                "Connection timeout"
            )

    """

    # =========================================================================
    # BASE ERROR CLASS - Foundation for all LDAP exceptions
    # =========================================================================

    class Error(FlextExceptions):
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
            super().__init__(message, error_code=error_code or "LDAP_ERROR")
            self.ldap_result_code = ldap_result_code
            self.ldap_context = ldap_context or {}
            self.operation = operation
            logger.debug(
                f"LDAP exception created: {message}",
                extra={
                    "operation": operation,
                    "ldap_result_code": ldap_result_code,
                    "context": ldap_context,
                },
            )

        @override
        def __str__(self) -> str:
            """Format exception string including LDAP context metadata."""
            parts = [super().__str__()]

            if self.operation:
                parts.append(
                    FlextLdapOperationMessages.OPERATION_CONTEXT.format(
                        operation=self.operation,
                    ),
                )

            if self.ldap_result_code:
                parts.append(
                    FlextLdapOperationMessages.LDAP_CODE_CONTEXT.format(
                        ldap_code=self.ldap_result_code,
                    ),
                )

            if self.ldap_context:
                context_str = ", ".join(
                    f"{k}={v}" for k, v in self.ldap_context.items()
                )
                parts.append(
                    FlextLdapOperationMessages.CONTEXT_INFO.format(context=context_str),
                )

            return " | ".join(parts)

    # =========================================================================
    # CONNECTION AND AUTHENTICATION EXCEPTIONS
    # =========================================================================

    class LdapConnectionError(Error):
        """LDAP connection related errors.

        Raised when connection establishment, maintenance, or termination fails.
        Includes server connectivity issues, network timeouts, and protocol errors.
        """

        def __init__(
            self,
            message: str,
            *,
            server_uri: str | None = None,
            timeout: int | None = None,
            retry_count: int | None = None,
        ) -> None:
            """Initialize connection error with network context."""
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

    class AuthenticationError(Error):
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
            """Initialize authentication error."""
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

    # =========================================================================
    # OPERATION EXCEPTIONS
    # =========================================================================

    class SearchError(Error):
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
            """Initialize search error with query context."""
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

    class OperationError(Error):
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
            """Initialize operation error."""
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

    # =========================================================================
    # DOMAIN-SPECIFIC EXCEPTIONS
    # =========================================================================

    class UserError(Error):
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
            """Initialize user error."""
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
                error_code="LDAP_USER_ERROR",
            )

    class GroupError(Error):
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
            """Initialize group error."""
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
                error_code="LDAP_GROUP_ERROR",
            )

    # =========================================================================
    # VALIDATION AND CONFIGURATION EXCEPTIONS
    # =========================================================================

    class ValidationError(Error):
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
            """Initialize validation error."""
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
                error_code="LDAP_VALIDATION_ERROR",
            )

    class ConfigurationError(Error):
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
            """Initialize configuration error."""
            context: dict[str, object] = {}
            if config_section:
                context["section"] = config_section
            if config_key:
                context["key"] = config_key

            super().__init__(
                message,
                ldap_context=context,
                operation="configuration",
                error_code="LDAP_CONFIG_ERROR",
            )

    class LdapTypeError(Error):
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
            """Initialize type error."""
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
                error_code="LDAP_TYPE_ERROR",
            )

    # =========================================================================
    # EXCEPTION FACTORY - Centralized error creation
    # =========================================================================

    class Factory:
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
        ) -> FlextLdapExceptions.LdapConnectionError:
            """Create connection failure exception."""
            message = f"Failed to connect to LDAP server: {error}"
            return FlextLdapExceptions.LdapConnectionError(
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
        ) -> FlextLdapExceptions.AuthenticationError:
            """Create authentication failure exception."""
            message = "LDAP authentication failed"
            if ldap_result_code and ldap_result_code in cls.LDAP_RESULT_CODES:
                message += f": {cls.LDAP_RESULT_CODES[ldap_result_code]} (code: {ldap_result_code})"

            return FlextLdapExceptions.AuthenticationError(
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
        ) -> FlextLdapExceptions.SearchError:
            """Create search operation failure exception."""
            message = f"LDAP search failed: {error}"
            return FlextLdapExceptions.SearchError(
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
        ) -> FlextLdapExceptions.UserError:
            """Create user creation failure exception."""
            message = f"User creation failed: {error}"
            if ldap_result_code:
                code_desc = cls.LDAP_RESULT_CODES.get(
                    str(ldap_result_code),
                    "Unknown Error",
                )
                message = f"{message} (code: {ldap_result_code} - {code_desc})"
            return FlextLdapExceptions.UserError(
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
        ) -> FlextLdapExceptions.ValidationError:
            """Create validation failure exception."""
            message = f"Validation failed for {field_name}: {error}"
            return FlextLdapExceptions.ValidationError(
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
        ) -> FlextLdapExceptions.ConfigurationError:
            """Create configuration error exception."""
            message = f"Configuration error in {config_key}: {error}"
            return FlextLdapExceptions.ConfigurationError(
                message,
                config_section=config_section,
                config_key=config_key,
            )


# =============================================================================
# LEGACY COMPATIBILITY CLASSES - Backward Compatibility
# =============================================================================

# Legacy class aliases for backward compatibility
FlextLdapError = FlextLdapExceptions.Error
FlextLdapConnectionError = FlextLdapExceptions.LdapConnectionError
FlextLdapAuthenticationError = FlextLdapExceptions.AuthenticationError
FlextLdapSearchError = FlextLdapExceptions.SearchError
FlextLdapOperationError = FlextLdapExceptions.OperationError
FlextLdapUserError = FlextLdapExceptions.UserError
FlextLdapGroupError = FlextLdapExceptions.GroupError
FlextLdapValidationError = FlextLdapExceptions.ValidationError
FlextLdapConfigurationError = FlextLdapExceptions.ConfigurationError
FlextLdapTypeError = FlextLdapExceptions.LdapTypeError
FlextLdapExceptionFactory = FlextLdapExceptions.Factory


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "FlextLdapAuthenticationError",
    "FlextLdapConfigurationError",
    "FlextLdapConnectionError",
    # Legacy compatibility classes
    "FlextLdapError",
    "FlextLdapExceptionFactory",
    # Primary consolidated class
    "FlextLdapExceptions",
    "FlextLdapGroupError",
    "FlextLdapOperationError",
    "FlextLdapSearchError",
    "FlextLdapTypeError",
    "FlextLdapUserError",
    "FlextLdapValidationError",
]
