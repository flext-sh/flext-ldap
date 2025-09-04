"""LDAP Exceptions - Single FlextLDAPExceptions class following FLEXT patterns.

Single class with all LDAP exception definitions, factory methods, and error handling
organized as internal classes for complete backward compatibility.

Examples:
    Basic exceptions:

        from exceptions import FlextLDAPExceptions

        # Create connection error
        conn_error = FlextLDAPExceptions.LdapConnectionError(
            "Failed to connect",
            server_uri="ldap://localhost:389"
        )

        # Create validation error
        val_error = FlextLDAPExceptions.ValidationError(
            "Invalid DN format",
            field_name="dn",
            field_value="invalid-dn"
        )

    Factory methods:

        # Using factory for consistent error creation
        error = FlextLDAPExceptions.Factory.connection_failed(
            "ldap://localhost:389",
            "Connection timeout",
            timeout=30
        )

    Legacy compatibility:

        # All previous classes still work as direct imports
        from exceptions import FlextLDAPConnectionError, FlextLDAPValidationError
        conn_error = FlextLDAPConnectionError("Failed to connect")

"""

from __future__ import annotations

from typing import ClassVar, override

from flext_core import FlextExceptions, FlextLogger, FlextModels
from pydantic import ConfigDict, Field

from flext_ldap.constants import FlextLDAPConstants

logger = FlextLogger(__name__)

# =============================================================================
# SINGLE FLEXT LDAP EXCEPTIONS CLASS - Consolidated exception functionality
# =============================================================================


class FlextLDAPExceptions:
    """Single FlextLDAPExceptions class with all LDAP exception functionality.

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

            conn_error = FlextLDAPExceptions.LdapConnectionError(
                "Failed to connect",
                server_uri="ldap://localhost:389"
            )
            auth_error = FlextLDAPExceptions.AuthenticationError(
                "Invalid credentials",
                bind_dn="cn=user,dc=example,dc=com"
            )

        Operation and search errors:

            search_error = FlextLDAPExceptions.SearchError(
                "Search failed",
                base_dn="dc=example,dc=com",
                search_filter="(uid=john)"
            )
            op_error = FlextLDAPExceptions.OperationError(
                "Modify failed",
                target_dn="cn=user,dc=example,dc=com"
            )

        Domain-specific errors:

            user_error = FlextLDAPExceptions.UserError(
                "User validation failed",
                user_dn="cn=john,dc=example,dc=com",
                uid="john"
            )
            group_error = FlextLDAPExceptions.GroupError(
                "Group membership error",
                group_dn="cn=admins,dc=example,dc=com"
            )

        Using factory methods:

            error = FlextLDAPExceptions.Factory.connection_failed(
                "ldap://localhost:389",
                "Connection timeout"
            )

    """

    # =========================================================================
    # BASE ERROR CLASS - Foundation for all LDAP exceptions
    # =========================================================================

    class ErrorConfig(FlextModels.Config):
        """Configuration object for LDAP error context - eliminates parameter explosion."""

        message: str
        ldap_result_code: str | None = None
        ldap_context: dict[str, object] | None = None
        operation: str | None = None
        error_code: str | None = None

    # =========================================================================
    # PARAMETER OBJECT CLASSES - ELIMINATES 6+ PARAMETER FUNCTIONS
    # =========================================================================

    class ConnectionParams(FlextModels.Config):
        """Parameter Object for connection operations - reduces 6+ parameters to 1."""

        model_config = ConfigDict(frozen=True, extra="forbid")

        server_uri: str = Field(..., min_length=1)
        error: str = Field(..., min_length=1)
        timeout: int | None = Field(default=None, ge=1, le=300)
        retry_count: int | None = Field(default=None, ge=0, le=10)

    class SearchParams(FlextModels.Config):
        """Parameter Object for search operations - reduces 6+ parameters to 1."""

        model_config = ConfigDict(frozen=True, extra="forbid")

        base_dn: str = Field(..., min_length=1)
        search_filter: str = Field(..., min_length=1)
        error: str = Field(..., min_length=1)
        attributes: list[str] | None = None
        size_limit: int | None = Field(default=None, ge=1)
        time_limit: int | None = Field(default=None, ge=1)

    class UserOperationParams(FlextModels.Config):
        """Parameter Object for user operations - reduces 6+ parameters to 1."""

        model_config = ConfigDict(frozen=True, extra="forbid")

        user_dn: str = Field(..., min_length=1)
        error: str = Field(..., min_length=1)
        uid: str | None = None
        operation: str | None = None

    class ValidationParams(FlextModels.Config):
        """Parameter Object for validation operations - reduces 6+ parameters to 1."""

        model_config = ConfigDict(frozen=True, extra="forbid")

        field_name: str = Field(..., min_length=1)
        error: str = Field(..., min_length=1)
        field_value: str | None = None
        validation_rule: str | None = None

    class Error(Exception):
        """Base exception for FLEXT-LDAP with optional LDAP context and codes."""

        def __init__(self, config: FlextLDAPExceptions.ErrorConfig) -> None:
            """Initialize exception using configuration object - eliminates parameter explosion.

            Args:
                config: ErrorConfig object containing all context details

            """
            super().__init__(config.message)
            self.ldap_result_code = config.ldap_result_code
            self.ldap_context = config.ldap_context or {}
            self.operation = config.operation
            self.error_code = config.error_code
            logger.debug(
                f"LDAP exception created: {config.message}",
                extra={
                    "operation": config.operation,
                    "ldap_result_code": config.ldap_result_code,
                    "context": config.ldap_context,
                },
            )

    class _BaseSpecificError(Error):
        """Base class for specific LDAP errors - Template Method Pattern.

        Eliminates 30-line duplications across UserError, GroupError, LdapTypeError
        by providing a common context building pattern through Template Method Pattern.
        """

        def __init__(self, message: str, **kwargs: str | None) -> None:
            """Initialize specific error using Template Method Pattern.

            Args:
                message: Error message
                **kwargs: Context parameters specific to error type

            """
            context = self._build_context(kwargs)
            config = FlextLDAPExceptions.ErrorConfig(
                message=message,
                ldap_context=context,
                operation=self._get_operation_name(),
                error_code=self._get_error_code(),
            )
            super().__init__(config)

        def _build_context(self, kwargs: dict[str, str | None]) -> dict[str, object]:
            """Template method to build context from parameters.

            Args:
                kwargs: Parameters to include in context

            Returns:
                dict[str, object]: Context dictionary with non-None values

            """
            context: dict[str, object] = {}
            field_mapping = self._get_field_mapping()

            for param_name, param_value in kwargs.items():
                if param_value is not None:
                    context_key = field_mapping.get(param_name, param_name)
                    # Special handling for sensitive data
                    if self._is_sensitive_field(param_name, param_value):
                        context[context_key] = "[REDACTED]"
                    else:
                        context[context_key] = param_value

            return context

        def _get_field_mapping(self) -> dict[str, str]:
            """Get mapping from parameter names to context keys.

            Subclasses can override to customize parameter-to-context mapping.

            Returns:
                dict[str, str]: Mapping from parameter to context key

            """
            return {}

        def _is_sensitive_field(self, field_name: str, _field_value: str) -> bool:
            """Check if field contains sensitive data that should be redacted.

            Args:
                field_name: Name of the field
                field_value: Value of the field

            Returns:
                bool: True if field should be redacted

            """
            return "password" in field_name.lower()

        def _get_operation_name(self) -> str:
            """Get operation name for this error type.

            Must be implemented by subclasses.

            Returns:
                str: Operation name

            """
            msg = "Subclasses must implement _get_operation_name"
            raise NotImplementedError(msg)

        def _get_error_code(self) -> str:
            """Get error code for this error type.

            Must be implemented by subclasses.

            Returns:
                str: Error code

            """
            msg = "Subclasses must implement _get_error_code"
            raise NotImplementedError(msg)

        @override
        def __str__(self) -> str:
            """Format exception string including LDAP context metadata."""
            parts = [super().__str__()]

            if self.operation:
                parts.append(
                    FlextLDAPConstants.Operations.OPERATION_CONTEXT.format(
                        operation=self.operation,
                    ),
                )

            if self.ldap_result_code:
                parts.append(
                    FlextLDAPConstants.Operations.LDAP_CODE_CONTEXT.format(
                        ldap_code=self.ldap_result_code,
                    ),
                )

            if self.ldap_context:
                context_str = ", ".join(
                    f"{k}={v}" for k, v in self.ldap_context.items()
                )
                parts.append(
                    FlextLDAPConstants.Operations.CONTEXT_INFO.format(
                        context=context_str
                    ),
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
                context[FlextLDAPConstants.Operations.SERVER_URI_KEY] = server_uri
            if timeout:
                context[FlextLDAPConstants.Operations.TIMEOUT_KEY] = str(timeout)
            if retry_count is not None:
                context[FlextLDAPConstants.Operations.RETRY_COUNT_KEY] = str(
                    retry_count
                )

            error_config = FlextLDAPExceptions.ErrorConfig(
                message=message,
                ldap_context=context,
                operation=FlextLDAPConstants.Operations.CONNECTION_OPERATION,
                error_code="LDAP_CONNECTION_ERROR",
            )
            super().__init__(error_config)

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

            error_config = FlextLDAPExceptions.ErrorConfig(
                message=message,
                ldap_result_code=ldap_result_code,
                ldap_context=context,
                operation="authentication",
                error_code="LDAP_AUTH_ERROR",
            )
            super().__init__(error_config)

    # =========================================================================
    # OPERATION EXCEPTIONS
    # =========================================================================

    class SearchError(_BaseSpecificError):
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
            super().__init__(
                message,
                base_dn=base_dn,
                search_filter=search_filter,
                scope=scope,
                ldap_result_code=ldap_result_code,
            )

        @override
        def _get_field_mapping(self) -> dict[str, str]:
            """Map search_filter parameter to 'filter' context key."""
            return {"search_filter": "filter"}

        @override
        def _get_operation_name(self) -> str:
            """Return search operation name."""
            return "search"

        @override
        def _get_error_code(self) -> str:
            """Return search error code."""
            return "LDAP_SEARCH_ERROR"

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

            error_config = FlextLDAPExceptions.ErrorConfig(
                message=message,
                error_code="LDAP_OPERATION_ERROR",
                ldap_context=context,
                ldap_result_code=ldap_result_code,
                operation=operation_type or "modify",
            )
            super().__init__(error_config)

    # =========================================================================
    # DOMAIN-SPECIFIC EXCEPTIONS
    # =========================================================================

    class UserError(_BaseSpecificError):
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
            super().__init__(
                message, user_dn=user_dn, uid=uid, validation_field=validation_field
            )

        @override
        def _get_field_mapping(self) -> dict[str, str]:
            """Map validation_field parameter to 'field' context key."""
            return {"validation_field": "field"}

        @override
        def _get_operation_name(self) -> str:
            """Return user management operation name."""
            return "user_management"

        @override
        def _get_error_code(self) -> str:
            """Return user error code."""
            return "LDAP_USER_ERROR"

    class GroupError(_BaseSpecificError):
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
            super().__init__(
                message, group_dn=group_dn, group_cn=group_cn, member_dn=member_dn
            )

        @override
        def _get_operation_name(self) -> str:
            """Return group management operation name."""
            return "group_management"

        @override
        def _get_error_code(self) -> str:
            """Return group error code."""
            return "LDAP_GROUP_ERROR"

    # =========================================================================
    # VALIDATION AND CONFIGURATION EXCEPTIONS
    # =========================================================================

    class ValidationError(_BaseSpecificError):
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
            super().__init__(
                message,
                field_name=field_name,
                field_value=field_value,
                validation_rule=validation_rule,
            )

        @override
        def _get_field_mapping(self) -> dict[str, str]:
            """Map parameter names to context keys for validation errors."""
            return {
                "field_name": "field",
                "field_value": "value",
                "validation_rule": "rule",
            }

        @override
        def _get_operation_name(self) -> str:
            """Return validation operation name."""
            return "validation"

        @override
        def _get_error_code(self) -> str:
            """Return validation error code."""
            return "LDAP_VALIDATION_ERROR"

    class ConfigurationError(_BaseSpecificError):
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
            super().__init__(
                message, config_section=config_section, config_key=config_key
            )

        @override
        def _get_field_mapping(self) -> dict[str, str]:
            """Map parameter names to context keys for configuration errors."""
            return {"config_section": "section", "config_key": "key"}

        @override
        def _get_operation_name(self) -> str:
            """Return configuration operation name."""
            return "configuration"

        @override
        def _get_error_code(self) -> str:
            """Return configuration error code."""
            return "LDAP_CONFIG_ERROR"

    class LdapTypeError(_BaseSpecificError):
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
            super().__init__(
                message,
                expected_type=expected_type,
                actual_type=actual_type,
                attribute_name=attribute_name,
            )

        @override
        def _get_field_mapping(self) -> dict[str, str]:
            """Map parameter names to context keys for type errors."""
            return {
                "expected_type": "expected",
                "actual_type": "actual",
                "attribute_name": "attribute",
            }

        @override
        def _get_operation_name(self) -> str:
            """Return type conversion operation name."""
            return "type_conversion"

        @override
        def _get_error_code(self) -> str:
            """Return type error code."""
            return "LDAP_TYPE_ERROR"

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
            cls, params: FlextLDAPExceptions.ConnectionParams
        ) -> FlextLDAPExceptions.LdapConnectionError:
            """Create connection failure using Parameter Object - reduces 6 params to 1."""
            message = f"LDAP connection failed to {params.server_uri}: {params.error}"
            return FlextLDAPExceptions.LdapConnectionError(
                message,
                server_uri=params.server_uri,
                bind_dn=params.bind_dn or "",
            )

        @classmethod
        def authentication_failed(
            cls,
            bind_dn: str,
            ldap_result_code: str | None = None,
        ) -> FlextExceptions.BaseError:
            """Create authentication failure exception using FlextExceptions.create() factory."""
            message = "LDAP authentication failed"
            if ldap_result_code and ldap_result_code in cls.LDAP_RESULT_CODES:
                message += f": {cls.LDAP_RESULT_CODES[ldap_result_code]} (code: {ldap_result_code})"

            return FlextExceptions.create(
                message,
                operation="ldap_authenticate",
                context={
                    "bind_dn": bind_dn,
                    "ldap_result_code": ldap_result_code,
                },
            )

        @classmethod
        def search_failed(
            cls, params: FlextLDAPExceptions.SearchParams
        ) -> FlextExceptions.BaseError:
            """Create search failure using Parameter Object - reduces 6 params to 1."""
            message = f"LDAP search failed: {params.error}"
            return FlextExceptions.create(
                message,
                operation="ldap_search",
                context={
                    "base_dn": params.base_dn,
                    "search_filter": params.search_filter,
                    "error": params.error,
                    "attributes": params.attributes,
                    "size_limit": params.size_limit,
                    "time_limit": params.time_limit,
                },
            )

        @classmethod
        def user_creation_failed(
            cls, params: FlextLDAPExceptions.UserOperationParams
        ) -> FlextExceptions.BaseError:
            """Create user creation failure using Parameter Object - reduces 6 params to 1."""
            message = f"User creation failed: {params.error}"
            return FlextExceptions.create(
                message,
                operation="ldap_create_user",
                context={
                    "user_dn": params.user_dn,
                    "uid": params.uid,
                    "operation": params.operation,
                    "error": params.error,
                },
            )

        @classmethod
        def validation_failed(
            cls, params: FlextLDAPExceptions.ValidationParams
        ) -> FlextExceptions.BaseError:
            """Create validation failure using Parameter Object - reduces 6 params to 1."""
            message = f"Validation failed for {params.field_name}: {params.error}"
            return FlextExceptions.create(
                message,
                operation="field_validation",
                context={
                    "field_name": params.field_name,
                    "error_detail": params.error,
                    "field_value": params.field_value,
                    "validation_rule": params.validation_rule,
                },
            )

        @classmethod
        def configuration_error(
            cls,
            config_key: str,
            error: str,
            *,
            config_section: str | None = None,
        ) -> FlextExceptions.BaseError:
            """Create configuration error exception using FlextExceptions.create() factory."""
            message = f"Configuration error in {config_key}: {error}"
            context = {
                "config_key": config_key,
                "error_detail": error,
            }
            if config_section is not None:
                context["config_section"] = config_section

            return FlextExceptions.create(
                message, operation="configuration", context=context
            )


# =============================================================================
# LEGACY COMPATIBILITY CLASSES - Backward Compatibility
# =============================================================================

# =============================================================================
# COMPATIBILITY ALIASES
# =============================================================================

# Export aliases eliminated - use FlextLDAPExceptions.* directly following flext-core pattern

# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "FlextLDAPExceptions",
]
