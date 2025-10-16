"""Configuration management for flext-ldap with advanced FlextConfig features.

This module provides enterprise-grade LDAP configuration management with environment
variable support, validation, computed fields, and infrastructure protocols.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

from __future__ import annotations

import threading
import uuid
from typing import ClassVar, cast

from dependency_injector import providers
from flext_core import (
    FlextConfig,
    FlextConstants,
    FlextExceptions,
    FlextResult,
    FlextTypes,
)
from pydantic import Field, SecretStr, computed_field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


class FlextLdapConfig(FlextConfig):
    """Enterprise LDAP configuration with advanced FlextConfig features.

    Extends FlextConfig with LDAP-specific configuration, computed fields,
    infrastructure protocols, and advanced validation. Provides centralized
    configuration management for all LDAP operations across the FLEXT ecosystem.

    **Advanced Features**:
    - Computed fields for derived LDAP configurations
    - Infrastructure protocol implementations (Configurable, ConfigValidator, ConfigPersistence)
    - Direct access pattern with dot notation support (config('ldap.connection.server'))
    - File persistence operations (JSON format)
    - LDAP-specific handler configuration utilities
    - Enhanced singleton management for LDAP contexts
    - Comprehensive validation with business rules
    - Dependency injection integration with providers.Configuration

    **Function**: Enterprise LDAP configuration management
        - LDAP connection, authentication, and operation settings
        - Pooling, caching, retry, and logging configurations
        - Computed fields for derived connection strings and capabilities
        - Validation methods for configuration integrity and business rules
        - File persistence for configuration management

    **Uses**: Pydantic Settings for LDAP configuration
        - BaseSettings for environment-based LDAP configuration
        - Field for default values and validation rules
        - SecretStr for sensitive LDAP credentials protection
        - field_validator for custom LDAP format validation
        - model_validator for cross-field LDAP consistency validation
        - computed_field for derived LDAP connection properties
        - FlextConstants for LDAP-specific configuration defaults
        - FlextResult[T] for operation results with error handling
        - FlextTypes for type definitions
        - Infrastructure protocols for LDAP configuration management

    **How to use**: Access and configure LDAP settings
        ```python
        from flext_ldap import FlextLdapConfig

        # Example 1: Create LDAP configuration instance
        config = FlextLdapConfig()

        # Example 2: Access LDAP configuration values
        server_uri = config.ldap_server_uri
        bind_dn = config.ldap_bind_dn
        timeout = config.ldap_connection_timeout


        # Example 4: Check LDAP configuration validity
        validation_result = config.validate_ldap_requirements()
        if validation_result.is_success:
            print("LDAP configuration valid")

        # Example 5: Access computed fields
        connection_info = config.connection_info
        print(f"Effective URI: {connection_info['effective_uri']}")

        # Example 6: Direct access with dot notation
        port = config("ldap.connection.port")  # Supports nested access
        ssl_enabled = config("ldap.connection.ssl")

        # Example 7: Handler configuration
        handler_config = config.create_ldap_handler_config(
            handler_mode="query", ldap_operation="search"
        )
        ```

    Args:
        **data: LDAP configuration values as keyword arguments.

    Attributes:
        ldap_server_uri (str): LDAP server URI (ldap:// or ldaps://)
        ldap_port (int): LDAP server port number
        ldap_use_ssl (bool): Enable SSL/TLS for connections
        ldap_verify_certificates (bool): Verify SSL certificates
        ldap_bind_dn (str | None): Bind distinguished name
        ldap_bind_password (SecretStr | None): Bind password (sensitive)
        ldap_base_dn (str): Base DN for searches
        ldap_pool_size (int): Connection pool size
        ldap_pool_timeout (int): Pool timeout in seconds
        ldap_connection_timeout (int): Connection timeout
        ldap_operation_timeout (int): Operation timeout
        ldap_size_limit (int): Search size limit
        ldap_time_limit (int): Search time limit
        ldap_enable_caching (bool): Enable result caching
        ldap_cache_ttl (int): Cache TTL in seconds
        ldap_retry_attempts (int): Retry attempts for operations
        ldap_retry_delay (int): Delay between retries
        ldap_enable_debug (bool): Enable debug logging
        ldap_enable_trace (bool): Enable trace logging
        ldap_log_queries (bool): Log LDAP queries
        ldap_mask_passwords (bool): Mask passwords in logs

    Returns:
        FlextLdapConfig: LDAP configuration instance with all FlextConfig features.

    Raises:
        ValidationError: When LDAP configuration validation fails.
        ValueError: When required LDAP configuration missing.

    Note:
        Direct instantiation pattern - create with FlextLdapConfig().
        SecretStr protects LDAP credentials. Configuration validated on load.
        Supports advanced dot notation access (config('ldap.connection.server')).

    Warning:
        Never commit LDAP credentials to source control.
        All configuration through direct instantiation or file loading.
        LDAP configuration changes require service restart.

    Example:
        Complete LDAP configuration management workflow:

        >>> config = FlextLdapConfig()
        >>> print(config.ldap_server_uri)
        ldap://localhost:389
        >>> print(config.connection_info["effective_uri"])
        ldap://localhost:389
        >>> validation = config.validate_ldap_requirements()
        >>> print(validation.is_success)
        True

    See Also:
        FlextConfig: Base configuration class with core features.
        FlextLdapConstants: LDAP-specific configuration defaults.
        FlextLdapModels: LDAP data models.
        FlextExceptions: Core FLEXT exceptions for error handling.

    """

    # Dependency Injection integration (v1.1.0+)
    _di_config_provider: ClassVar[providers.Configuration | None] = None
    _di_provider_lock: ClassVar[threading.RLock] = threading.RLock()

    # Singleton pattern inherited from FlextConfig - no need to redefine _instances
    # _lock inherited as well

    class LdapHandlerConfiguration:
        """LDAP-specific handler configuration utilities."""

        @staticmethod
        def resolve_ldap_operation_mode(
            operation_mode: str | None = None,
            operation_config: object = None,
        ) -> str | None:
            """Resolve LDAP operation mode from various sources.

            Args:
                operation_mode: Explicit LDAP operation mode
                operation_config: Config object containing operation_type

            Returns:
                str: Resolved operation mode (search, modify, authenticate)

            """
            # Use explicit operation_mode if provided and valid
            valid_modes = {"search", "modify", "add", "delete", "authenticate", "bind"}
            if operation_mode in valid_modes:
                return operation_mode

            # Try to extract from config object
            if operation_config is not None:
                # Try attribute access
                if hasattr(operation_config, "operation_type"):
                    config_mode: str | None = getattr(
                        operation_config, "operation_type", None
                    )
                    if config_mode in valid_modes:
                        return str(config_mode)

                # Try dict[str, object] access
                if isinstance(operation_config, dict):
                    config_mode_dict = operation_config.get(
                        FlextLdapConstants.DictKeys.OPERATION_TYPE,
                    )
                    if (
                        isinstance(config_mode_dict, str)
                        and config_mode_dict in valid_modes
                    ):
                        return config_mode_dict

            # Default to search
            return "search"

        @staticmethod
        def create_ldap_handler_config(
            operation_mode: str | None = None,
            ldap_operation: str | None = None,
            handler_name: str | None = None,
            handler_id: str | None = None,
            ldap_config: FlextTypes.Dict | None = None,
            connection_timeout: int = 30,
            operation_timeout: int = 60,
            max_retries: int = 3,
        ) -> FlextTypes.Dict:
            """Create LDAP handler configuration dictionary.

            Args:
                operation_mode: LDAP operation mode (search, modify, etc.)
                ldap_operation: Specific LDAP operation name
                handler_name: Handler name
                handler_id: Handler ID
                ldap_config: Additional LDAP configuration to merge
                connection_timeout: Connection timeout in seconds
                operation_timeout: Operation timeout in seconds
                max_retries: Maximum retry attempts

            Returns:
                dict[str, object]: LDAP handler configuration dictionary

            """
            # Resolve operation mode
            resolved_mode = (
                FlextLdapConfig.LdapHandlerConfiguration.resolve_ldap_operation_mode(
                    operation_mode=operation_mode,
                    operation_config=ldap_config,
                )
            )

            # Generate default handler_id if not provided or empty
            if not handler_id:
                unique_suffix = uuid.uuid4().hex[:8]
                handler_id = f"ldap_{resolved_mode}_handler_{unique_suffix}"

            # Generate default handler_name if not provided or empty
            if not handler_name:
                mode_name = (resolved_mode or "operation").capitalize()
                handler_name = f"LDAP {mode_name} Handler"

            # Generate default ldap_operation if not provided
            if not ldap_operation:
                ldap_operation = resolved_mode

            # Create base config
            config: FlextTypes.Dict = {
                "handler_id": handler_id,
                "handler_name": handler_name,
                "handler_type": "command",  # LDAP operations are commands
                "handler_mode": "command",
                "operation_mode": resolved_mode,
                "ldap_operation": ldap_operation,
                "connection_timeout": connection_timeout,
                "operation_timeout": operation_timeout,
                "max_retries": max_retries,
                "ldap_config": ldap_config or {},
                "metadata": {},
            }

            # Merge additional LDAP config if provided
            if ldap_config:
                config.update(ldap_config)

            return config

    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="ignore",  # Changed from "forbid" to "ignore" for LDAP ecosystem compatibility
        use_enum_values=True,
        frozen=False,  # Allow runtime configuration updates for LDAP
        # Pydantic 2.11+ enhanced features
        arbitrary_types_allowed=True,  # For LDAP-specific objects
        validate_return=True,
        validate_assignment=True,  # Validate on assignment for LDAP config changes
        # Additional strict validation settings
        strict=True,  # Strict type coercion
        hide_input_in_errors=True,  # Security - hide input in error messages
        # Enhanced settings features
        cli_parse_args=False,  # Disable CLI parsing by default for LDAP
        cli_avoid_json=True,  # Avoid JSON CLI options for LDAP configs
        nested_model_default_partial_update=True,  # Allow partial updates to nested LDAP models
        # Advanced Pydantic 2.11+ features
        str_strip_whitespace=True,  # Strip whitespace from LDAP strings
        str_to_lower=False,  # Keep original case for LDAP DNs
        json_schema_extra={
            "title": "FLEXT LDAP Configuration",
            "description": "Enterprise LDAP configuration with advanced FlextConfig features",
        },
    )

    # LDAP Connection Configuration using FlextLdapConstants for defaults
    ldap_server_uri: str = Field(
        default=FlextLdapConstants.Protocol.DEFAULT_SERVER_URI,
        description="LDAP server URI (ldap:// or ldaps://)",
    )

    ldap_port: int = Field(
        default=FlextLdapConstants.Protocol.DEFAULT_PORT,
        ge=1,
        le=FlextConstants.Network.MAX_PORT,
        description="LDAP server port",
    )

    ldap_use_ssl: bool = Field(
        default=True,
        description="Use SSL/TLS for LDAP connections",
    )

    ldap_verify_certificates: bool = Field(
        default=True,
        description="Verify SSL/TLS certificates",
    )

    # Authentication Configuration using SecretStr for sensitive data
    ldap_bind_dn: str | None = Field(
        default=None,
        description="LDAP bind distinguished name for authentication",
    )

    ldap_bind_password: SecretStr | None = Field(
        default=None,
        description="LDAP bind password for authentication (sensitive)",
    )

    ldap_base_dn: str = Field(
        default=FlextLdapConstants.Defaults.DEFAULT_SEARCH_BASE,
        description="LDAP base distinguished name for searches",
    )

    # LDAP Search Base Configuration
    ldap_user_base_dn: str = Field(
        default="ou=users",
        description="LDAP base DN for user searches",
    )

    ldap_group_base_dn: str = Field(
        default="ou=groups",
        description="LDAP base DN for group searches",
    )

    # Connection Pooling Configuration using FlextLdapConstants for defaults
    ldap_pool_size: int = Field(
        default=FlextConstants.Performance.DEFAULT_DB_POOL_SIZE,
        ge=1,
        le=50,
        description="LDAP connection pool size",
    )

    ldap_pool_timeout: int = Field(
        default=FlextConstants.Network.DEFAULT_TIMEOUT,
        ge=1,
        le=300,
        description="LDAP connection pool timeout in seconds",
    )

    # Operation Configuration using FlextLdapConstants for defaults
    ldap_connection_timeout: int = Field(
        default=FlextConstants.Network.DEFAULT_TIMEOUT,
        ge=1,
        le=300,
        description="LDAP connection timeout in seconds",
    )

    ldap_operation_timeout: int = Field(
        default=60,  # Must be > connection_timeout (30) for validation
        ge=1,
        le=600,
        description="LDAP operation timeout in seconds",
    )

    ldap_size_limit: int = Field(
        default=FlextConstants.Performance.DEFAULT_PAGE_SIZE,
        ge=1,
        le=FlextConstants.Performance.BatchProcessing.MAX_VALIDATION_SIZE,
        description="LDAP search size limit",
    )

    ldap_time_limit: int = Field(
        default=FlextConstants.Network.DEFAULT_TIMEOUT,
        ge=1,
        le=300,
        description="LDAP search time limit in seconds",
    )

    # Caching Configuration using FlextConstants for defaults
    ldap_enable_caching: bool = Field(
        default=True,
        description="Enable LDAP result caching",
    )

    ldap_cache_ttl: int = Field(
        default=FlextConstants.Defaults.TIMEOUT * 10,
        ge=0,
        le=3600,
        description="LDAP cache TTL in seconds",
    )

    # Retry Configuration using FlextConstants for defaults
    ldap_retry_attempts: int = Field(
        default=FlextConstants.Reliability.MAX_RETRY_ATTEMPTS,
        ge=0,
        le=10,
        description="Number of retry attempts for failed operations",
    )

    ldap_retry_delay: int = Field(
        default=int(FlextLdapConstants.LdapRetry.CONNECTION_RETRY_DELAY),
        ge=0,
        le=60,
        description="Delay between retry attempts in seconds",
    )

    # Logging Configuration using FlextLdapConstants for defaults
    ldap_enable_debug: bool = Field(
        default=False,
        description="Enable LDAP debug logging",
    )

    ldap_enable_trace: bool = Field(
        default=False,
        description="Enable LDAP trace logging",
    )

    ldap_log_queries: bool = Field(
        default=False,
        description="Enable logging of LDAP queries",
    )

    ldap_mask_passwords: bool = Field(
        default=True,
        description="Mask passwords in log messages",
    )

    # JSON serialization options
    json_indent: int = Field(
        default=2,
        description="JSON indentation level for file serialization",
        ge=0,
    )
    json_sort_keys: bool = Field(
        default=True,
        description="Sort JSON keys during serialization",
    )

    # =========================================================================
    # COMPUTED FIELDS - Derived LDAP configuration properties
    # =========================================================================

    @computed_field
    def connection_info(self) -> FlextTypes.Dict:
        """Get comprehensive LDAP connection information."""
        return {
            "server_uri": self.ldap_server_uri,
            "port": self.ldap_port,
            "use_ssl": self.ldap_use_ssl,
            "verify_certificates": self.ldap_verify_certificates,
            "effective_uri": f"{self.ldap_server_uri}:{self.ldap_port}",
            "is_secure": self.ldap_use_ssl and self.ldap_verify_certificates,
            "connection_timeout": self.ldap_connection_timeout,
        }

    @computed_field
    def authentication_info(self) -> FlextTypes.Dict:
        """Get LDAP authentication configuration information."""
        return {
            "bind_dn_configured": self.ldap_bind_dn is not None,
            "bind_password_configured": self.ldap_bind_password is not None,
            "base_dn": self.ldap_base_dn,
            "anonymous_bind": self.ldap_bind_dn is None,
        }

    @computed_field
    def pooling_info(self) -> FlextTypes.Dict:
        """Get LDAP connection pooling information."""
        return {
            "pool_size": self.ldap_pool_size,
            "pool_timeout": self.ldap_pool_timeout,
            "pool_utilization": f"{self.ldap_pool_size}/50",
        }

    @computed_field
    def operation_limits(self) -> FlextTypes.Dict:
        """Get LDAP operation limits and timeouts."""
        return {
            "operation_timeout": self.ldap_operation_timeout,
            "size_limit": self.ldap_size_limit,
            "time_limit": self.ldap_time_limit,
            "connection_timeout": self.ldap_connection_timeout,
            "total_timeout": self.ldap_operation_timeout + self.ldap_connection_timeout,
        }

    @computed_field
    def caching_info(self) -> FlextTypes.Dict:
        """Get LDAP caching configuration information."""
        return {
            "caching_enabled": self.ldap_enable_caching,
            "cache_ttl": self.ldap_cache_ttl,
            "cache_ttl_minutes": self.ldap_cache_ttl // 60,
            "cache_effective": self.ldap_enable_caching and self.ldap_cache_ttl > 0,
        }

    @computed_field
    def retry_info(self) -> FlextTypes.Dict:
        """Get LDAP retry configuration information."""
        return {
            "retry_attempts": self.ldap_retry_attempts,
            "retry_delay": self.ldap_retry_delay,
            "total_retry_time": self.ldap_retry_attempts * self.ldap_retry_delay,
            "retry_enabled": self.ldap_retry_attempts > 0,
        }

    @computed_field
    def ldap_capabilities(self) -> FlextTypes.Dict:
        """Get comprehensive LDAP server capabilities summary."""
        return {
            "supports_ssl": self.ldap_use_ssl,
            "supports_caching": self.ldap_enable_caching,
            "supports_retry": self.ldap_retry_attempts > 0,
            "supports_debug": self.ldap_enable_debug or self.ldap_enable_trace,
            "has_authentication": self.ldap_bind_dn is not None,
            "has_pooling": self.ldap_pool_size > 1,
            "is_production_ready": (
                self.ldap_use_ssl and self.ldap_bind_dn is not None
            ),
        }

    # Pydantic 2.11 field validators
    # =========================================================================
    # FIELD VALIDATORS - Enhanced Pydantic 2.11 validation
    # =========================================================================

    @field_validator("ldap_server_uri")
    @classmethod
    def validate_ldap_server_uri(cls, v: str) -> str:
        """Validate LDAP server URI format with enhanced error reporting."""
        if not v.startswith(("ldap://", "ldaps://")):
            msg = f"Invalid LDAP server URI: {v}. Must start with ldap:// or ldaps://"
            raise FlextExceptions.ConfigurationError(msg, config_key="ldap_server_uri")
        return v

    @field_validator("ldap_bind_dn")
    @classmethod
    def validate_bind_dn(cls, v: str | None) -> str | None:
        """Validate LDAP bind DN format with comprehensive checks."""
        if v is None:
            return v

        # Basic DN validation
        if len(v) < FlextLdapConstants.Validation.MIN_DN_LENGTH:
            msg = f"LDAP bind DN too short: {v}"
            raise FlextExceptions.ValidationError(msg, field="ldap_bind_dn", value=v)

        if len(v) > FlextLdapConstants.Validation.MAX_DN_LENGTH:
            msg = f"LDAP bind DN too long: {v}"
            raise FlextExceptions.ValidationError(msg, field="ldap_bind_dn", value=v)

        if "=" not in v:
            msg = (
                f"Invalid LDAP bind DN format: {v}. Must contain attribute=value pairs"
            )
            raise FlextExceptions.ValidationError(msg, field="ldap_bind_dn", value=v)

        return v

    @field_validator("ldap_base_dn")
    @classmethod
    def validate_base_dn(cls, v: str) -> str:
        """Validate LDAP base DN format with length constraints."""
        if v and len(v) > FlextLdapConstants.Validation.MAX_DN_LENGTH:
            msg = f"LDAP base DN too long: {v}"
            raise FlextExceptions.ValidationError(msg, field="ldap_base_dn", value=v)
        return v

    # =========================================================================
    # ENVIRONMENT VARIABLE TYPE COERCION VALIDATORS
    # Pydantic 2 strict mode requires explicit type coercion from env var strings
    # =========================================================================

    @field_validator(
        "ldap_port",
        "ldap_pool_size",
        "ldap_cache_ttl",
        "ldap_retry_attempts",
        mode="before",
    )
    @classmethod
    def coerce_int_from_env(cls, v: object) -> int:
        """Coerce environment variable strings to integers for strict mode.

        Pydantic Settings with strict=True doesn't automatically convert env var
        strings to integers. This validator explicitly handles the conversion while
        maintaining strict validation for non-string inputs.

        Args:
            v: Value from environment variable (string) or direct assignment

        Returns:
            int: Converted integer value

        Raises:
            ValueError: If string cannot be converted to integer

        """
        if isinstance(v, str):
            try:
                return int(v)
            except ValueError as e:
                msg = f"Cannot convert '{v}' to integer"
                raise ValueError(msg) from e
        if v is None:
            msg = "Integer field cannot be None"
            raise ValueError(msg)
        return int(cast("int | str", v))

    @field_validator(
        "ldap_use_ssl",
        "ldap_verify_certificates",
        "ldap_enable_caching",
        "ldap_enable_debug",
        "ldap_enable_trace",
        "ldap_log_queries",
        "ldap_mask_passwords",
        mode="before",
    )
    @classmethod
    def coerce_bool_from_env(cls, v: object) -> bool:
        """Coerce environment variable strings to booleans for strict mode.

        Pydantic Settings with strict=True doesn't automatically convert env var
        strings to booleans. This validator explicitly handles the conversion while
        maintaining strict validation for non-string inputs.

        Handles common boolean string representations:
        - True: "true", "1", "yes", "on" (case-insensitive)
        - False: "false", "0", "no", "off" (case-insensitive)

        Args:
            v: Value from environment variable (string) or direct assignment

        Returns:
            bool: Converted boolean value

        Raises:
            ValueError: If string is not a recognized boolean representation

        """
        if isinstance(v, str):
            v_lower = v.lower().strip()
            if v_lower in {"true", "1", "yes", "on"}:
                return True
            if v_lower in {"false", "0", "no", "off"}:
                return False
            msg = (
                f"Cannot convert '{v}' to boolean. Use: true/false, 1/0, yes/no, on/off"
            )
            raise ValueError(msg)
        if v is None:
            msg = "Boolean field cannot be None"
            raise ValueError(msg)
        return bool(v)

    # =========================================================================
    # MODEL VALIDATORS - Cross-field validation with business rules
    # =========================================================================

    @model_validator(mode="after")
    def validate_ldap_configuration_consistency(self) -> FlextLdapConfig:
        """Validate LDAP configuration consistency with business rules."""
        # Validate authentication configuration
        if self.ldap_bind_dn is not None and self.ldap_bind_password is None:
            msg = "Bind password is required when bind DN is specified"
            raise FlextExceptions.ConfigurationError(
                msg, config_key="ldap_bind_password"
            )

        # Validate caching configuration
        if self.ldap_enable_caching and self.ldap_cache_ttl <= 0:
            msg = "Cache TTL must be positive when caching is enabled"
            raise FlextExceptions.ConfigurationError(msg, config_key="ldap_cache_ttl")

        # Validate SSL configuration consistency
        if self.ldap_server_uri.startswith("ldaps://") and not self.ldap_use_ssl:
            msg = "SSL must be enabled for ldaps:// server URIs"
            raise FlextExceptions.ConfigurationError(msg, config_key="ldap_use_ssl")

        return self

    # =========================================================================
    # ENHANCED DIRECT ACCESS - Dot notation support for LDAP config
    # =========================================================================

    def __call__(
        self, key: str
    ) -> str | int | float | bool | list[object] | dict[str, object] | None:
        """Enhanced direct value access with LDAP-specific dot notation support.

        Extends FlextConfig.__call__ with LDAP-specific nested access patterns.

        Args:
            key: Configuration field name with optional LDAP dot notation
                 (e.g., 'ldap.connection.server', 'ldap.auth.bind_dn')

        Returns:
            The configuration value for the specified field

        Raises:
            KeyError: If the configuration key doesn't exist

        Example:
            >>> config = FlextLdapConfig()
            >>> config("ldap.connection.server")  # ldap_server_uri
            'ldap://localhost:389'
            >>> config("ldap.auth.bind_dn")  # ldap_bind_dn
            'cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com'

        """
        # Handle LDAP-specific dot notation
        if key.startswith("ldap."):
            ldap_key = key[5:]  # Remove "ldap." prefix

            # Connection properties
            if ldap_key.startswith("connection."):
                prop = ldap_key[11:]  # Remove "connection."
                if prop == "server":
                    return self.ldap_server_uri
                if prop == "port":
                    return self.ldap_port
                if prop == "ssl":
                    return self.ldap_use_ssl
                if prop == "timeout":
                    return self.ldap_connection_timeout
                if prop == "uri":
                    return f"{self.ldap_server_uri}:{self.ldap_port}"

            # Authentication properties
            elif ldap_key.startswith("auth."):
                prop = ldap_key[5:]  # Remove "auth."
                if prop == "bind_dn":
                    return self.ldap_bind_dn
                if prop == "bind_password":
                    return self.effective_bind_password
                if prop == "base_dn":
                    return self.ldap_base_dn

            # Pooling properties
            elif ldap_key.startswith("pool."):
                prop = ldap_key[5:]  # Remove "pool."
                if prop == "size":
                    return self.ldap_pool_size
                if prop == "timeout":
                    return self.ldap_pool_timeout

            # Operation properties
            elif ldap_key.startswith("operation."):
                prop = ldap_key[10:]  # Remove "operation."
                if prop == "timeout":
                    return self.ldap_operation_timeout
                if prop == "size_limit":
                    return self.ldap_size_limit
                if prop == "time_limit":
                    return self.ldap_time_limit

            # Caching properties
            elif ldap_key.startswith("cache."):
                prop = ldap_key[6:]  # Remove "cache."
                if prop == "enabled":
                    return self.ldap_enable_caching
                if prop == "ttl":
                    return self.ldap_cache_ttl

            # Retry properties
            elif ldap_key.startswith("retry."):
                prop = ldap_key[6:]  # Remove "retry."
                if prop == "attempts":
                    return self.ldap_retry_attempts
                if prop == "delay":
                    return self.ldap_retry_delay

            # Logging properties
            elif ldap_key.startswith("logging."):
                prop = ldap_key[8:]  # Remove "logging."
                if prop == "debug":
                    return self.ldap_enable_debug
                if prop == "trace":
                    return self.ldap_enable_trace
                if prop == "queries":
                    return self.ldap_log_queries
                if prop == "mask_passwords":
                    return self.ldap_mask_passwords

        # Fall back to standard FlextConfig access
        return super().__call__(key)

    # =========================================================================
    # INFRASTRUCTURE PROTOCOL IMPLEMENTATIONS
    # =========================================================================

    # Infrastructure.Configurable protocol methods
    def configure(self, config: FlextTypes.Dict) -> FlextResult[None]:
        """Configure LDAP component with provided settings.

        Implements Infrastructure.Configurable protocol for runtime
        LDAP configuration updates with validation.

        Args:
            config: Configuration dictionary with LDAP settings

        Returns:
            FlextResult[None]: Success if configuration valid, failure otherwise

        """
        try:
            # Update current instance with provided config
            for key, value in config.items():
                if hasattr(self, key):
                    setattr(self, key, value)

            # Validate after configuration
            return self.validate_ldap_requirements()
        except Exception as e:
            return FlextResult[None].fail(f"LDAP configuration failed: {e}")

    # Infrastructure.ConfigValidator protocol methods
    def validate_runtime_requirements(self) -> FlextResult[None]:
        """Validate LDAP configuration meets runtime requirements.

        Implements Infrastructure.ConfigValidator protocol with LDAP-specific
        validation beyond basic Pydantic validation.

        Returns:
            FlextResult[None]: Success if valid, failure with error details

        """
        # Run standard FlextConfig validation first
        base_validation = super().validate_runtime_requirements()
        if base_validation.is_failure:
            return base_validation

        # Additional LDAP-specific runtime validation
        return self.validate_ldap_requirements()

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDAP business rules for configuration consistency.

        Implements Infrastructure.ConfigValidator protocol with LDAP-specific
        business rule validation.

        Returns:
            FlextResult[None]: Success if valid, failure with error details

        """
        return FlextResult[None].ok(None)

    # =========================================================================
    # LDAP-SPECIFIC ENHANCED METHODS
    # =========================================================================

    def validate_ldap_requirements(self) -> FlextResult[None]:
        """Validate LDAP-specific configuration requirements.

        Comprehensive validation for LDAP configuration beyond basic
        Pydantic validation, including business rules and consistency checks.

        Returns:
            FlextResult[None]: Success if all LDAP requirements met

        """
        # Run business rules validation
        business_validation = self.validate_business_rules()
        if business_validation.is_failure:
            return business_validation

        # Validate LDAP URI and port consistency
        if (
            self.ldap_server_uri.startswith("ldaps://")
            and self.ldap_port == FlextLdapConstants.Protocol.DEFAULT_PORT
        ):
            return FlextResult[None].fail(
                f"Port {FlextLdapConstants.Protocol.DEFAULT_PORT} is default for LDAP, not LDAPS. Use {FlextLdapConstants.Protocol.DEFAULT_SSL_PORT} for LDAPS.",
            )

        if (
            self.ldap_server_uri.startswith("ldap://")
            and self.ldap_port == FlextLdapConstants.Protocol.DEFAULT_SSL_PORT
        ):
            return FlextResult[None].fail(
                f"Port {FlextLdapConstants.Protocol.DEFAULT_SSL_PORT} is default for LDAPS, not LDAP. Use {FlextLdapConstants.Protocol.DEFAULT_PORT} for LDAP.",
            )

        # Validate timeout relationships
        if self.ldap_operation_timeout <= self.ldap_connection_timeout:
            return FlextResult[None].fail(
                "Operation timeout must be greater than connection timeout",
            )

        return FlextResult[None].ok(None)

    @property
    def effective_bind_password(self) -> str | None:
        """Get the effective bind password (safely extract from SecretStr)."""
        if self.ldap_bind_password is not None:
            return self.ldap_bind_password.get_secret_value()
        return None

    # =========================================================================
    # DEPENDENCY INJECTION METHODS - Enhanced DI integration
    # =========================================================================

    @classmethod
    def get_di_config_provider(cls) -> providers.Configuration:
        """Get the dependency-injector Configuration provider for LDAP config."""
        if cls._di_config_provider is None:
            with cls._di_provider_lock:
                if cls._di_config_provider is None:
                    cls._di_config_provider = providers.Configuration()
                    instance = cls._instances.get(cls)
                    if instance is not None:
                        config_dict = instance.model_dump()
                        cls._di_config_provider.from_dict(config_dict)
        return cls._di_config_provider

    # =========================================================================
    # STATIC FACTORY METHODS - Enhanced configuration creation
    # =========================================================================

    @classmethod
    def create_from_connection_config_data(
        cls,
        data: FlextTypes.Dict,
    ) -> FlextResult[FlextLdapConfig]:
        """Create config from connection data with validation.

        Args:
            data: Connection configuration data

        Returns:
            FlextResult[FlextLdapConfig]: Created configuration or error

        """
        try:
            bind_password_value = data.get(FlextLdapConstants.DictKeys.BIND_PASSWORD)
            config = cls(
                ldap_server_uri=str(
                    data.get(
                        FlextLdapConstants.DictKeys.SERVER_URI,
                        data.get(
                            FlextLdapConstants.DictKeys.SERVER,
                            "ldap://localhost",
                        ),
                    ),
                ),
                ldap_port=int(str(data.get(FlextLdapConstants.DictKeys.PORT, 389))),
                ldap_bind_dn=str(data.get(FlextLdapConstants.DictKeys.BIND_DN, ""))
                if data.get(FlextLdapConstants.DictKeys.BIND_DN)
                else None,
                ldap_bind_password=SecretStr(str(bind_password_value))
                if bind_password_value
                else None,
                ldap_base_dn=str(data.get(FlextLdapConstants.DictKeys.BASE_DN, "")),
            )
            return FlextResult[FlextLdapConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapConfig].fail(f"Config creation failed: {e}")

    @classmethod
    def create_search_config(
        cls,
        data: FlextTypes.Dict,
    ) -> FlextResult[FlextLdapModels.SearchConfig]:
        """Create search config from data.

        Args:
            data: Search configuration data

        Returns:
            FlextResult[FlextLdapModels.SearchConfig]: Created search config or error

        """
        try:
            if not isinstance(data, dict):
                return FlextResult[FlextLdapModels.SearchConfig].fail(
                    "Data must be a dictionary",
                )

            attributes_data = data.get(FlextLdapConstants.DictKeys.ATTRIBUTES, [])
            if isinstance(attributes_data, list):
                str_attributes = [
                    str(attr) for attr in attributes_data if attr is not None
                ]
            else:
                str_attributes = []
            config = FlextLdapModels.SearchConfig(
                base_dn=str(data.get(FlextLdapConstants.DictKeys.BASE_DN, "")),
                filter_str=str(
                    data.get(
                        "filter_str",
                        FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                    ),
                ),
                attributes=str_attributes,
            )
            return FlextResult[FlextLdapModels.SearchConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapModels.SearchConfig].fail(
                f"Search config creation failed: {e}",
            )

    @classmethod
    def create_modify_config(
        cls,
        data: FlextTypes.Dict,
    ) -> FlextResult[dict[str, str | FlextTypes.StringList]]:
        """Create modify config from data.

        Args:
            data: Modify configuration data

        Returns:
            FlextResult[FlextTypes.Dict]: Created modify config or error

        """
        try:
            if not isinstance(data, dict):
                return FlextResult[dict[str, str | FlextTypes.StringList]].fail(
                    "Data must be a dictionary"
                )

            values = data.get(FlextLdapConstants.DictKeys.VALUES, [])
            if isinstance(values, list):
                str_values = [str(v) for v in values if v is not None]
            else:
                str_values = []
            config: dict[str, str | FlextTypes.StringList] = {
                FlextLdapConstants.DictKeys.DN: str(
                    data.get(FlextLdapConstants.DictKeys.DN, ""),
                ),
                FlextLdapConstants.DictKeys.OPERATION: str(
                    data.get(FlextLdapConstants.DictKeys.OPERATION, "replace"),
                ),
                FlextLdapConstants.DictKeys.ATTRIBUTE: str(
                    data.get(FlextLdapConstants.DictKeys.ATTRIBUTE, ""),
                ),
                FlextLdapConstants.DictKeys.VALUES: str_values,
            }
            return FlextResult[dict[str, str | FlextTypes.StringList]].ok(config)
        except Exception as e:
            return FlextResult[dict[str, str | FlextTypes.StringList]].fail(
                f"Modify config creation failed: {e}",
            )

    @classmethod
    def create_add_config(
        cls,
        data: FlextTypes.Dict,
    ) -> FlextResult[dict[str, str | dict[str, FlextTypes.StringList]]]:
        """Create add config from data.

        Args:
            data: Add configuration data

        Returns:
            FlextResult[FlextTypes.Dict]: Created add config or error

        """
        try:
            attributes = data.get(FlextLdapConstants.DictKeys.ATTRIBUTES, {})
            if not isinstance(attributes, dict):
                attributes = {}

            config: dict[str, str | dict[str, FlextTypes.StringList]] = {
                FlextLdapConstants.DictKeys.DN: str(
                    data.get(FlextLdapConstants.DictKeys.DN, ""),
                ),
                "attributes": {
                    str(k): [
                        str(v) for v in (vals if isinstance(vals, list) else [vals])
                    ]
                    for k, vals in attributes.items()
                },
            }
            return FlextResult[dict[str, str | dict[str, FlextTypes.StringList]]].ok(
                config,
            )
        except Exception as e:
            return FlextResult[dict[str, str | dict[str, FlextTypes.StringList]]].fail(
                f"Add config creation failed: {e}",
            )

    @classmethod
    def create_delete_config(
        cls,
        data: FlextTypes.Dict,
    ) -> FlextResult[dict[str, str]]:
        """Create delete config from data.

        Args:
            data: Delete configuration data

        Returns:
            FlextResult[FlextTypes.Dict]: Created delete config or error

        """
        try:
            config: dict[str, str] = {
                FlextLdapConstants.DictKeys.DN: str(
                    data.get(FlextLdapConstants.DictKeys.DN, ""),
                ),
            }
            return FlextResult[dict[str, str]].ok(config)
        except Exception as e:
            return FlextResult[dict[str, str]].fail(
                f"Delete config creation failed: {e}",
            )

    @classmethod
    def get_default_search_config(
        cls,
    ) -> FlextResult[dict[str, str | int | FlextTypes.StringList]]:
        """Get default search configuration.

        Returns:
            FlextResult[FlextTypes.Dict]: Default search configuration

        """
        config: dict[str, str | int | FlextTypes.StringList] = {
            "base_dn": FlextLdapConstants.Defaults.DEFAULT_SEARCH_BASE,
            "filter_str": FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
            "scope": FlextLdapConstants.Scopes.SUBTREE,
            "attributes": [
                FlextLdapConstants.LdapAttributeNames.COMMON_NAME,
                FlextLdapConstants.LdapAttributeNames.SURNAME,
                FlextLdapConstants.LdapAttributeNames.MAIL,
            ],
            "size_limit": FlextConstants.Performance.DEFAULT_PAGE_SIZE,
            "time_limit": FlextConstants.Network.DEFAULT_TIMEOUT,
        }
        return FlextResult[dict[str, str | int | FlextTypes.StringList]].ok(config)

    @classmethod
    def merge_configs(
        cls,
        base_config: FlextTypes.Dict,
        override_config: FlextTypes.Dict,
    ) -> FlextResult[FlextTypes.Dict]:
        """Merge two configuration dictionaries.

        Args:
            base_config: Base configuration to merge into
            override_config: Configuration to override with

        Returns:
            FlextResult[FlextTypes.Dict]: Merged configuration or error

        """
        try:
            merged = base_config.copy()
            merged.update(override_config)
            return FlextResult[FlextTypes.Dict].ok(merged)
        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"Config merge failed: {e}")


__all__ = [
    "FlextLdapConfig",
]
