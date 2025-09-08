"""LDAP exceptions module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, override

from flext_core import FlextConstants, FlextLogger, FlextModels, FlextResult, FlextTypes
from pydantic import ConfigDict, Field

from flext_ldap.constants import FlextLDAPConstants

logger = FlextLogger(__name__)


# ===================================================================
# SINGLE FLEXT LDAP EXCEPTIONS CLASS - Consolidated exception functionality
# =============================================================================


class FlextLDAPExceptions:
    """LDAP exception classes and factory methods."""

    # =========================================================================
    # BASE ERROR CLASS - Foundation for all LDAP exceptions
    # =========================================================================

    class ErrorConfig(FlextModels.Config):
        """LDAP error configuration."""

        message: str
        ldap_result_code: str | None = None
        ldap_context: FlextTypes.Core.Dict | None = None
        operation: str | None = None
        error_code: str | None = None

    # =========================================================================
    # PARAMETER OBJECT CLASSES - ELIMINATES 6+ PARAMETER FUNCTIONS
    # =========================================================================

    class ConnectionParams(FlextModels.Config):
        """Connection operation parameters."""

        model_config = ConfigDict(frozen=True, extra="forbid")

        server_uri: str = Field(..., min_length=1)
        error: str = Field(..., min_length=1)
        bind_dn: str | None = Field(default=None)
        timeout: int | None = Field(default=None, ge=1, le=300)
        retry_count: int | None = Field(default=None, ge=0, le=10)

    class UserOperationParams(FlextModels.Config):
        """User operation parameters."""

        model_config = ConfigDict(frozen=True, extra="forbid")

        user_dn: str = Field(..., min_length=1)
        error: str = Field(..., min_length=1)
        uid: str | None = None
        operation: str | None = None

    class ValidationParams(FlextModels.Config):
        """Validation operation parameters."""

        model_config = ConfigDict(frozen=True, extra="forbid")

        field_name: str = Field(..., min_length=1)
        error: str = Field(..., min_length=1)
        field_value: str | None = None
        validation_rule: str | None = None

    class Error(Exception):
        """Base LDAP exception."""

        def __init__(self, config: FlextLDAPExceptions.ErrorConfig) -> None:
            """Initialize exception with configuration."""
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

        def __str__(self) -> str:
            """Format exception message with context."""
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
                        context=context_str,
                    ),
                )

            return " | ".join(parts)

    class _BaseSpecificError(Error):
        """Base class for specific LDAP errors."""

        def __init__(self, message: str, **kwargs: str | None) -> None:
            """Initialize specific error with context."""
            context = self._build_context(kwargs)
            config = FlextLDAPExceptions.ErrorConfig(
                message=message,
                ldap_context=context,
                operation=self._get_operation_name(),
                error_code=self._get_error_code(),
            )
            super().__init__(config)

        def _build_context(self, kwargs: dict[str, str | None]) -> FlextTypes.Core.Dict:
            """Build context from parameters."""
            context: FlextTypes.Core.Dict = {}
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

        def _get_field_mapping(self) -> FlextTypes.Core.Headers:
            """Get parameter-to-context mapping."""
            return {}

        def _is_sensitive_field(self, field_name: str, _field_value: str) -> bool:
            """Check if field should be redacted."""
            return "password" in field_name.lower()

        def _get_operation_name(self) -> str:
            """Get operation name."""
            msg = "Subclasses must implement _get_operation_name"
            raise NotImplementedError(msg)

        def _get_error_code(self) -> str:
            """Get error code."""
            msg = "Subclasses must implement _get_error_code"
            raise NotImplementedError(msg)

        @override
        def __str__(self) -> str:
            """Format exception message with context."""
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
                        context=context_str,
                    ),
                )

            return " | ".join(parts)

    # =========================================================================
    # CONNECTION AND AUTHENTICATION EXCEPTIONS
    # =========================================================================

    class LdapConnectionError(Error):
        """LDAP connection errors."""

        def __init__(
            self,
            message: str,
            *,
            server_uri: str | None = None,
            bind_dn: str | None = None,
            timeout: int | None = None,
            retry_count: int | None = None,
        ) -> None:
            """Initialize connection error."""
            context: FlextTypes.Core.Dict = {}
            if server_uri:
                context[FlextLDAPConstants.Operations.SERVER_URI_KEY] = server_uri
            if bind_dn:
                context["bind_dn"] = bind_dn
            if timeout:
                context[FlextLDAPConstants.Operations.TIMEOUT_KEY] = str(timeout)
            if retry_count is not None:
                context[FlextLDAPConstants.Operations.RETRY_COUNT_KEY] = str(
                    retry_count,
                )

            error_config = FlextLDAPExceptions.ErrorConfig(
                message=message,
                ldap_context=context,
                operation=FlextLDAPConstants.Operations.CONNECTION_OPERATION,
                error_code="LDAP_CONNECTION_ERROR",
            )
            super().__init__(error_config)

    class AuthenticationError(Error):
        """LDAP authentication errors."""

        def __init__(
            self,
            message: str,
            *,
            bind_dn: str | None = None,
            auth_method: str | None = None,
            ldap_result_code: str | None = None,
        ) -> None:
            """Initialize authentication error."""
            context: FlextTypes.Core.Dict = {}
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
        """LDAP search operation errors."""

        def __init__(
            self,
            message: str,
            *,
            base_dn: str | None = None,
            search_filter: str | None = None,
            scope: str | None = None,
            ldap_result_code: str | None = None,
        ) -> None:
            """Initialize search error."""
            super().__init__(
                message,
                base_dn=base_dn,
                search_filter=search_filter,
                scope=scope,
                ldap_result_code=ldap_result_code,
            )

        @override
        def _get_field_mapping(self) -> FlextTypes.Core.Headers:
            """Get field mapping for search errors."""
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
        """LDAP modify operation errors."""

        def __init__(
            self,
            message: str,
            *,
            target_dn: str | None = None,
            operation_type: str | None = None,
            ldap_result_code: str | None = None,
        ) -> None:
            """Initialize operation error."""
            context: FlextTypes.Core.Dict = {}
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
        """LDAP user-specific errors."""

        def __init__(
            self,
            message: str,
            *,
            user_dn: str | None = None,
            uid: str | None = None,
            validation_field: str | None = None,
            ldap_result_code: str | None = None,
        ) -> None:
            """Initialize user error."""
            super().__init__(
                message,
                user_dn=user_dn,
                uid=uid,
                validation_field=validation_field,
                ldap_result_code=ldap_result_code,
            )

        @override
        def _get_field_mapping(self) -> FlextTypes.Core.Headers:
            """Get field mapping for user errors."""
            return {"validation_field": "field"}

        @override
        def _get_operation_name(self) -> str:
            """Get operation name."""
            return "user_management"

        @override
        def _get_error_code(self) -> str:
            """Get error code."""
            return "LDAP_USER_ERROR"

    class GroupError(_BaseSpecificError):
        """LDAP group-specific errors."""

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
                message,
                group_dn=group_dn,
                group_cn=group_cn,
                member_dn=member_dn,
            )

        @override
        def _get_operation_name(self) -> str:
            """Get operation name."""
            return "group_management"

        @override
        def _get_error_code(self) -> str:
            """Get error code."""
            return "LDAP_GROUP_ERROR"

    # =========================================================================
    # VALIDATION AND CONFIGURATION EXCEPTIONS
    # =========================================================================

    class ValidationError(_BaseSpecificError):
        """LDAP data validation errors."""

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
        def _get_field_mapping(self) -> FlextTypes.Core.Headers:
            """Get field mapping for validation errors."""
            return {
                "field_name": "field",
                "field_value": "value",
                "validation_rule": "rule",
            }

        @override
        def _get_operation_name(self) -> str:
            """Get operation name."""
            return "validation"

        @override
        def _get_error_code(self) -> str:
            """Get error code."""
            return "LDAP_VALIDATION_ERROR"

    class ConfigurationError(_BaseSpecificError):
        """LDAP configuration errors."""

        def __init__(
            self,
            message: str,
            *,
            config_section: str | None = None,
            config_key: str | None = None,
        ) -> None:
            """Initialize configuration error."""
            super().__init__(
                message,
                config_section=config_section,
                config_key=config_key,
            )

        @override
        def _get_field_mapping(self) -> FlextTypes.Core.Headers:
            """Get field mapping for configuration errors."""
            return {"config_section": "section", "config_key": "key"}

        @override
        def _get_operation_name(self) -> str:
            """Get operation name."""
            return "configuration"

        @override
        def _get_error_code(self) -> str:
            """Get error code."""
            return "LDAP_CONFIG_ERROR"

    class LdapTypeError(_BaseSpecificError):
        """LDAP type validation errors."""

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
        def _get_field_mapping(self) -> FlextTypes.Core.Headers:
            """Get field mapping for type errors."""
            return {
                "expected_type": "expected",
                "actual_type": "actual",
                "attribute_name": "attribute",
            }

        @override
        def _get_operation_name(self) -> str:
            """Get operation name."""
            return "type_conversion"

        @override
        def _get_error_code(self) -> str:
            """Return type error code."""
            return "LDAP_TYPE_ERROR"

    # =========================================================================
    # CONFIGURATION FACADE — Settings → BaseSystemConfig bridge (dict border)
    # =========================================================================

    @classmethod
    def configure_exceptions_system(
        cls,
        config: FlextTypes.Core.Dict,
    ) -> FlextResult[FlextTypes.Core.Dict]:
        """Configure LDAP exceptions system using flext-core patterns.

        - Validates core fields (environment/log_level/validation_level) via
          flext-core SystemConfigs (model-driven) without changing output shape.
        - Preserves dict compatibility at the border.
        - Adds sane defaults for exception handling behavior.
        """
        try:
            # Ensure environment default and validate against flext-core enums
            validated: FlextTypes.Core.Dict = dict(config)

            if "environment" not in validated:
                validated["environment"] = (
                    FlextConstants.Config.ConfigEnvironment.DEVELOPMENT.value
                )

            # Core validation via flext-core SystemConfigs (bridge compatibility)
            core_validation = {
                "environment": validated.get(
                    "environment",
                    FlextConstants.Config.ConfigEnvironment.DEVELOPMENT.value,
                ),
                "log_level": validated.get(
                    "log_level",
                    FlextConstants.Config.LogLevel.WARNING.value,
                ),
                "validation_level": validated.get(
                    "validation_level",
                    FlextConstants.Config.ValidationLevel.NORMAL.value,
                ),
            }
            _ = FlextModels.SystemConfigs.BaseSystemConfig.model_validate(
                core_validation
            )

            # Derived defaults aligned with flext-core exceptions
            env_value = str(validated.get("environment"))
            if "log_level" not in validated:
                validated["log_level"] = (
                    FlextConstants.Config.LogLevel.ERROR.value
                    if env_value
                    == FlextConstants.Config.ConfigEnvironment.PRODUCTION.value
                    else FlextConstants.Config.LogLevel.WARNING.value
                )
            if "validation_level" not in validated:
                validated["validation_level"] = (
                    FlextConstants.Config.ValidationLevel.STRICT.value
                    if env_value
                    == FlextConstants.Config.ConfigEnvironment.PRODUCTION.value
                    else FlextConstants.Config.ValidationLevel.NORMAL.value
                )

            # LDAP exceptions specific toggles (kept simple and optional)
            validated.setdefault("enable_metrics", True)
            validated.setdefault(
                "enable_stack_traces",
                env_value != FlextConstants.Config.ConfigEnvironment.PRODUCTION.value,
            )
            max_details = validated.get("max_error_details", 1000)
            try:
                validated["max_error_details"] = int(max_details)
            except Exception:
                validated["max_error_details"] = 1000
            validated.setdefault("error_correlation_enabled", True)
            validated.setdefault("enable_ldap_context_enrichment", True)
            validated.setdefault("enable_ldap_code_hints", True)

            return FlextResult[FlextTypes.Core.Dict].ok(validated)
        except Exception as e:
            return FlextResult[FlextTypes.Core.Dict].fail(
                f"Failed to configure LDAP exceptions system: {e}",
            )

    # =========================================================================
    # EXCEPTION FACTORY - Centralized error creation
    # =========================================================================

    class Factory:
        """Factory for creating LDAP exceptions."""

        # Common LDAP result codes for quick reference
        LDAP_RESULT_CODES: ClassVar[FlextTypes.Core.Headers] = {
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
            params: FlextLDAPExceptions.ConnectionParams,
        ) -> FlextLDAPExceptions.LdapConnectionError:
            """Create connection failure exception."""
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
        ) -> FlextLDAPExceptions.AuthenticationError:
            """Create authentication failure exception."""
            message = "LDAP authentication failed"
            if ldap_result_code and ldap_result_code in cls.LDAP_RESULT_CODES:
                message += f": {cls.LDAP_RESULT_CODES[ldap_result_code]} (code: {ldap_result_code})"

            return FlextLDAPExceptions.AuthenticationError(
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
        ) -> FlextLDAPExceptions.SearchError:
            """Create search failure exception."""
            message = f"LDAP search failed: {error}"
            return FlextLDAPExceptions.SearchError(
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
        ) -> FlextLDAPExceptions.UserError:
            """Create user creation failure exception."""
            message = f"User creation failed: {error}"
            return FlextLDAPExceptions.UserError(
                message,
                user_dn=user_dn,
                uid=uid,
                ldap_result_code=ldap_result_code,
            )

        @classmethod
        def validation_failed(
            cls,
            field_name: str,
            error: str,
        ) -> FlextLDAPExceptions.ValidationError:
            """Create validation failure exception."""
            message = f"Validation failed for {field_name}: {error}"
            return FlextLDAPExceptions.ValidationError(
                message,
                field_name=field_name,
            )

        @classmethod
        def configuration_error(
            cls,
            config_key: str,
            error: str,
            *,
            config_section: str | None = None,
        ) -> FlextLDAPExceptions.ConfigurationError:
            """Create configuration error exception."""
            message = f"Configuration error in {config_key}: {error}"
            return FlextLDAPExceptions.ConfigurationError(
                message,
                config_key=config_key,
                config_section=config_section,
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
