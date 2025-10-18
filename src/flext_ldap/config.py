"""Configuration management for flext-ldap with advanced FlextConfig features.

This module provides enterprise-grade LDAP configuration management with environment
variable support, validation, computed fields, and infrastructure protocols.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: ldap3 type stubs have limitations:
- Method return types not specified in official stubs
- Properties not fully typed (conn.entries, entry_dn)
- Entry attributes have incomplete type information
"""

from __future__ import annotations

import threading
import uuid
from typing import Any, ClassVar, Self, cast

from dependency_injector import providers
from flext_core import (
    FlextConfig,
    FlextConstants,
    FlextExceptions,
    FlextResult,
)
from pydantic import Field, SecretStr, computed_field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


class FlextLdapConfig(FlextConfig):
    """Enterprise LDAP configuration with FlextConfig features.

    Extends FlextConfig with LDAP-specific settings, computed fields, infrastructure
    protocols, and validation. Provides centralized configuration management for FLEXT LDAP operations.

    **Features**: Computed fields (connection, auth, pooling, operation limits, caching, retry, capabilities),
    infrastructure protocols (configure, validate_runtime_requirements, validate_business_rules),
    dot notation access (config("ldap.connection.port")), field/model validators, dependency injection,
    factory methods for search/modify/add/delete configs.

    **Core Attributes**: ldap_server_uri, ldap_port, ldap_bind_dn, ldap_bind_password, ldap_base_dn,
    ldap_pool_size, ldap_connection_timeout, ldap_operation_timeout, ldap_cache_ttl, ldap_retry_attempts,
    ldap_enable_caching, ldap_use_ssl.

    Example:
        >>> config = FlextLdapConfig()
        >>> port = config("ldap.connection.port")  # Dot notation access
        >>> info = config.connection_info  # Computed field
        >>> result = config.validate_ldap_requirements()  # Validation
        >>> factory_result = FlextLdapConfig.create_config(
        ...     "search", {...}
        ... )  # Factory method

    """

    # Dependency Injection integration (v1.1.0+)
    _di_config_provider: ClassVar[providers.Configuration | None] = None
    _di_provider_lock: ClassVar[threading.RLock] = threading.RLock()

    # Singleton pattern inherited from FlextConfig - no need to redefine _instances
    # _lock inherited as well

    def __new__(cls, *args: Any, **kwargs: Any) -> Self:
        """Create FlextLdapConfig instance with SecretStr preprocessing."""
        processed_kwargs = {
            key: (value.get_secret_value() if isinstance(value, SecretStr) else value)
            for key, value in kwargs.items()
        }
        return super().__new__(cls, *args, **processed_kwargs)

    # =========================================================================
    # HANDLER CONFIGURATION UTILITIES - Integrated from LdapHandlerConfiguration
    # =========================================================================

    @staticmethod
    def resolve_ldap_operation_mode(
        operation_mode: str | None = None,
        operation_config: object | None = None,
    ) -> str | None:
        """Resolve LDAP operation mode from various sources."""
        valid_modes = {"search", "modify", "add", "delete", "authenticate", "bind"}
        if operation_mode in valid_modes:
            return operation_mode

        if operation_config is not None:
            if hasattr(operation_config, "operation_type"):
                config_mode: str | None = getattr(
                    operation_config, "operation_type", None
                )
                if config_mode in valid_modes:
                    return str(config_mode)

            if isinstance(operation_config, dict):
                config_mode_dict = operation_config.get(
                    FlextLdapConstants.LdapDictKeys.OPERATION_TYPE,
                )
                if (
                    isinstance(config_mode_dict, str)
                    and config_mode_dict in valid_modes
                ):
                    return config_mode_dict

        return "search"

    @staticmethod
    def create_ldap_handler_config(
        operation_mode: str | None = None,
        ldap_operation: str | None = None,
        handler_name: str | None = None,
        handler_id: str | None = None,
        ldap_config: dict[str, object] | None = None,
        connection_timeout: int = 30,
        operation_timeout: int = 60,
        max_retries: int = 3,
    ) -> dict[str, object]:
        """Create LDAP handler configuration dictionary."""
        resolved_mode = FlextLdapConfig.resolve_ldap_operation_mode(
            operation_mode=operation_mode,
            operation_config=ldap_config,
        )

        handler_id_final = (
            handler_id or f"ldap_{resolved_mode}_handler_{uuid.uuid4().hex[:8]}"
        )
        handler_name_final = (
            handler_name
            or f"LDAP {(resolved_mode or 'operation').capitalize()} Handler"
        )
        ldap_operation_final = ldap_operation or resolved_mode

        config: dict[str, object] = {
            "handler_id": handler_id_final,
            "handler_name": handler_name_final,
            "handler_type": "command",
            "handler_mode": "command",
            "operation_mode": resolved_mode,
            "ldap_operation": ldap_operation_final,
            "connection_timeout": connection_timeout,
            "operation_timeout": operation_timeout,
            "max_retries": max_retries,
            "ldap_config": ldap_config or {},
            "metadata": {},
        }

        if ldap_config:
            config.update(ldap_config)

        return config

    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="ignore",  # For LDAP ecosystem compatibility
        use_enum_values=True,
        frozen=False,  # Allow runtime updates
        arbitrary_types_allowed=True,
        validate_return=True,
        validate_assignment=True,
        strict=True,
        hide_input_in_errors=True,
        cli_parse_args=False,
        cli_avoid_json=True,
        nested_model_default_partial_update=True,
        str_strip_whitespace=True,
        str_to_lower=False,
        json_schema_extra={
            "title": "FLEXT LDAP Configuration",
            "description": "Enterprise LDAP config with FlextConfig features",
        },
    )

    # LDAP Connection Configuration using FlextLdapConstants for defaults
    ldap_server_uri: str = Field(
        default=FlextLdapConstants.Protocol.DEFAULT_SERVER_URI,
        pattern=r"^ldaps?://",  # Must start with ldap:// or ldaps://
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
        min_length=FlextLdapConstants.Validation.MIN_DN_LENGTH,
        max_length=FlextLdapConstants.Validation.MAX_DN_LENGTH,
        description="LDAP bind distinguished name for authentication",
    )

    ldap_bind_password: SecretStr | None = Field(
        default=None,
        description="LDAP bind password for authentication (sensitive)",
    )

    ldap_base_dn: str = Field(
        default=FlextLdapConstants.Defaults.DEFAULT_SEARCH_BASE,
        max_length=FlextLdapConstants.Validation.MAX_DN_LENGTH,
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
    def connection_info(self) -> FlextLdapModels.ConnectionInfo:
        """Get comprehensive LDAP connection information."""
        return FlextLdapModels.ConnectionInfo(
            server=self.ldap_server_uri,
            port=self.ldap_port,
            use_ssl=self.ldap_use_ssl,
            use_tls=False,
            bind_dn=self.ldap_bind_dn,
            bind_password=self.ldap_bind_password,
            timeout=self.ldap_connection_timeout,
            pool_size=self.ldap_pool_size,
            pool_keepalive=self.ldap_cache_ttl,
            verify_certificates=self.ldap_verify_certificates,
        )

    @computed_field
    def authentication_info(
        self,
    ) -> FlextLdapModels.ConfigRuntimeMetadata.Authentication:
        """Get LDAP authentication configuration information."""
        return FlextLdapModels.ConfigRuntimeMetadata.Authentication(
            bind_dn_configured=self.ldap_bind_dn is not None,
            bind_password_configured=self.ldap_bind_password is not None,
            base_dn=self.ldap_base_dn,
            anonymous_bind=self.ldap_bind_dn is None,
        )

    @computed_field
    def pooling_info(self) -> FlextLdapModels.ConfigRuntimeMetadata.Pooling:
        """Get LDAP connection pooling information."""
        return FlextLdapModels.ConfigRuntimeMetadata.Pooling(
            pool_size=self.ldap_pool_size,
            pool_timeout=self.ldap_pool_timeout,
            pool_utilization=f"{self.ldap_pool_size}/50",
        )

    @computed_field
    def operation_limits(self) -> FlextLdapModels.ConfigRuntimeMetadata.OperationLimits:
        """Get LDAP operation limits and timeouts."""
        return FlextLdapModels.ConfigRuntimeMetadata.OperationLimits(
            operation_timeout=self.ldap_operation_timeout,
            size_limit=self.ldap_size_limit,
            time_limit=self.ldap_time_limit,
            connection_timeout=self.ldap_connection_timeout,
            total_timeout=self.ldap_operation_timeout + self.ldap_connection_timeout,
        )

    @computed_field
    def caching_info(self) -> FlextLdapModels.ConfigRuntimeMetadata.Caching:
        """Get LDAP caching configuration information."""
        return FlextLdapModels.ConfigRuntimeMetadata.Caching(
            caching_enabled=self.ldap_enable_caching,
            cache_ttl=self.ldap_cache_ttl,
            cache_ttl_minutes=self.ldap_cache_ttl // 60,
            cache_effective=self.ldap_enable_caching and self.ldap_cache_ttl > 0,
        )

    @computed_field
    def retry_info(self) -> FlextLdapModels.ConfigRuntimeMetadata.Retry:
        """Get LDAP retry configuration information."""
        return FlextLdapModels.ConfigRuntimeMetadata.Retry(
            retry_attempts=self.ldap_retry_attempts,
            retry_delay=self.ldap_retry_delay,
            total_retry_time=self.ldap_retry_attempts * self.ldap_retry_delay,
            retry_enabled=self.ldap_retry_attempts > 0,
        )

    @computed_field
    def ldap_capabilities(self) -> FlextLdapModels.ConfigCapabilities:
        """Get comprehensive LDAP server capabilities summary."""
        return FlextLdapModels.ConfigCapabilities(
            supports_ssl=self.ldap_use_ssl,
            supports_caching=self.ldap_enable_caching,
            supports_retry=self.ldap_retry_attempts > 0,
            supports_debug=self.ldap_enable_debug or self.ldap_enable_trace,
            has_authentication=self.ldap_bind_dn is not None,
            has_pooling=self.ldap_pool_size > 1,
            is_production_ready=(self.ldap_use_ssl and self.ldap_bind_dn is not None),
        )

    # Pydantic 2.11 field validators
    # =========================================================================
    # FIELD VALIDATORS - Enhanced Pydantic 2.11 validation
    # =========================================================================

    @field_validator("ldap_bind_dn")
    @classmethod
    def validate_bind_dn(cls, v: str | None) -> str | None:
        """Validate LDAP bind DN format (Pydantic handles length constraints via Field).

        Focus on business logic: must contain attribute=value pairs.
        """
        if v is None:
            return v

        # Check for required attribute=value pairs (length already validated by Field)
        if "=" not in v:
            msg = (
                f"Invalid LDAP bind DN format: {v}. Must contain attribute=value pairs"
            )
            raise FlextExceptions.ValidationError(msg, field="ldap_bind_dn", value=v)

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
    def validate_int_fields_ldap(cls, v: int | str) -> int:
        """Coerce LDAP integer fields from environment variables.

        Delegates to FlextConfig's validate_int_field for consistency.
        """
        return cls.validate_int_field(v)

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
    def validate_bool_fields_ldap(cls, v: bool | str | int) -> bool:
        """Coerce LDAP boolean fields from environment variables.

        Delegates to FlextConfig's validate_boolean_field for consistency.
        """
        return cls.validate_boolean_field(v)

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
    ) -> str | int | float | bool | list[Any] | dict[str, Any] | None:
        """Enhanced direct value access with LDAP-specific dot notation support.

        Extends FlextConfig.__call__ with LDAP-specific nested access patterns
        using Python 3.13+ pattern matching for optimized property resolution.

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
            'cn=admin,dc=example,dc=com'

        """
        # Handle LDAP dot notation with pattern matching
        if key.startswith("ldap."):
            # Split into category and property (e.g., "conn.server")
            parts = key[5:].split(".", 1)
            expected_split_length: int = 2
            if len(parts) != expected_split_length:
                return cast(
                    "str | int | float | bool | list[Any] | dict[str, Any] | None",
                    super().__call__(key),
                )

            category, prop = parts

            # Match on category and resolve properties efficiently
            match category:
                case "connection":
                    match prop:
                        case "server":
                            return self.ldap_server_uri
                        case "port":
                            return self.ldap_port
                        case "ssl":
                            return self.ldap_use_ssl
                        case "timeout":
                            return self.ldap_connection_timeout
                        case "uri":
                            return f"{self.ldap_server_uri}:{self.ldap_port}"
                case "auth":
                    match prop:
                        case "bind_dn":
                            return self.ldap_bind_dn
                        case "bind_password":
                            return self.effective_bind_password
                        case "base_dn":
                            return self.ldap_base_dn
                case "pool":
                    match prop:
                        case "size":
                            return self.ldap_pool_size
                        case "timeout":
                            return self.ldap_pool_timeout
                case "operation":
                    match prop:
                        case "timeout":
                            return self.ldap_operation_timeout
                        case "size_limit":
                            return self.ldap_size_limit
                        case "time_limit":
                            return self.ldap_time_limit
                case "cache":
                    match prop:
                        case "enabled":
                            return self.ldap_enable_caching
                        case "ttl":
                            return self.ldap_cache_ttl
                case "retry":
                    match prop:
                        case "attempts":
                            return self.ldap_retry_attempts
                        case "delay":
                            return self.ldap_retry_delay
                case "logging":
                    match prop:
                        case "debug":
                            return self.ldap_enable_debug
                        case "trace":
                            return self.ldap_enable_trace
                        case "queries":
                            return self.ldap_log_queries
                        case "mask_passwords":
                            return self.ldap_mask_passwords

        # Fall back to standard FlextConfig access
        return cast(
            "str | int | float | bool | list[Any] | dict[str, Any] | None",
            super().__call__(key),
        )

    # =========================================================================
    # INFRASTRUCTURE PROTOCOL IMPLEMENTATIONS
    # =========================================================================

    # Infrastructure.Configurable protocol methods
    def configure(self, config: dict[str, object]) -> FlextResult[None]:
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
            port = FlextLdapConstants.Protocol.DEFAULT_PORT
            ssl_port = FlextLdapConstants.Protocol.DEFAULT_SSL_PORT
            msg = f"Port {port} is for LDAP, not LDAPS. Use {ssl_port}."
            return FlextResult[None].fail(msg)

        if (
            self.ldap_server_uri.startswith("ldap://")
            and self.ldap_port == FlextLdapConstants.Protocol.DEFAULT_SSL_PORT
        ):
            ssl_port = FlextLdapConstants.Protocol.DEFAULT_SSL_PORT
            port = FlextLdapConstants.Protocol.DEFAULT_PORT
            msg = f"Port {ssl_port} is for LDAPS, not LDAP. Use {port}."
            return FlextResult[None].fail(msg)

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
    # UNIFIED FACTORY METHODS - Pattern-matched configuration creation
    # =========================================================================

    @classmethod
    def create_config(
        cls,
        config_type: str,
        data: dict[str, object] | None = None,
        override_data: dict[str, object] | None = None,
    ) -> FlextResult[Any]:
        """Unified config factory using Python 3.13+ pattern matching.

        Args:
            config_type: Type of config (connection, search, modify, add, delete, default_search, merge)
            data: Configuration data for creation
            override_data: Override data for merge operations

        Returns:
            FlextResult: Created configuration or error

        """
        if data is None:
            data = {}

        def _extract_str_list(
            source: dict[str, object], key: str, default: list[str] | None = None
        ) -> list[str]:
            """Extract and convert list to strings."""
            items = source.get(key, default or [])
            return (
                [str(i) for i in items if i is not None]
                if isinstance(items, list)
                else []
            )

        try:
            match config_type:
                case "connection":
                    config_kwargs: dict[str, object] = {
                        "ldap_server_uri": str(
                            data.get(
                                FlextLdapConstants.LdapDictKeys.SERVER_URI,
                                data.get(
                                    FlextLdapConstants.LdapDictKeys.SERVER,
                                    "ldap://localhost",
                                ),
                            ),
                        ),
                        "ldap_port": int(
                            str(data.get(FlextLdapConstants.LdapDictKeys.PORT, 389))
                        ),
                        "ldap_base_dn": str(
                            data.get(FlextLdapConstants.LdapDictKeys.BASE_DN, "")
                        ),
                    }
                    bind_dn = data.get(FlextLdapConstants.LdapDictKeys.BIND_DN)
                    if bind_dn:
                        config_kwargs["ldap_bind_dn"] = str(bind_dn)
                    bind_pwd = data.get(FlextLdapConstants.LdapDictKeys.BIND_PASSWORD)
                    if bind_pwd:
                        config_kwargs["ldap_bind_password"] = SecretStr(str(bind_pwd))
                    conn_cfg: FlextLdapConfig = FlextLdapConfig.model_validate(
                        config_kwargs
                    )
                    return FlextResult[FlextLdapConfig].ok(conn_cfg)

                case "search":
                    if not isinstance(data, dict):
                        return FlextResult[FlextLdapModels.SearchConfig].fail(
                            "Data must be a dictionary"
                        )
                    search_cfg: FlextLdapModels.SearchConfig = (
                        FlextLdapModels.SearchConfig(
                            base_dn=str(
                                data.get(FlextLdapConstants.LdapDictKeys.BASE_DN, "")
                            ),
                            filter_str=str(
                                data.get(
                                    "filter_str",
                                    FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                                ),
                            ),
                            attributes=_extract_str_list(
                                data, FlextLdapConstants.LdapDictKeys.ATTRIBUTES
                            ),
                        )
                    )
                    return FlextResult[FlextLdapModels.SearchConfig].ok(search_cfg)

                case "modify":
                    if not isinstance(data, dict):
                        return FlextResult[dict[str, str | list[str]]].fail(
                            "Data must be a dictionary"
                        )
                    modify_cfg: dict[str, str | list[str]] = {
                        FlextLdapConstants.LdapDictKeys.DN: str(
                            data.get(FlextLdapConstants.LdapDictKeys.DN, ""),
                        ),
                        FlextLdapConstants.LdapDictKeys.OPERATION: str(
                            data.get(
                                FlextLdapConstants.LdapDictKeys.OPERATION, "replace"
                            ),
                        ),
                        FlextLdapConstants.LdapDictKeys.ATTRIBUTE: str(
                            data.get(FlextLdapConstants.LdapDictKeys.ATTRIBUTE, ""),
                        ),
                        FlextLdapConstants.LdapDictKeys.VALUES: _extract_str_list(
                            data, FlextLdapConstants.LdapDictKeys.VALUES
                        ),
                    }
                    return FlextResult[dict[str, str | list[str]]].ok(modify_cfg)

                case "add":
                    attributes = data.get(
                        FlextLdapConstants.LdapDictKeys.ATTRIBUTES, {}
                    )
                    if not isinstance(attributes, dict):
                        attributes = {}
                    add_cfg: dict[str, str | dict[str, list[str]]] = {
                        FlextLdapConstants.LdapDictKeys.DN: str(
                            data.get(FlextLdapConstants.LdapDictKeys.DN, ""),
                        ),
                        "attributes": {
                            str(k): [
                                str(v)
                                for v in (vals if isinstance(vals, list) else [vals])
                            ]
                            for k, vals in attributes.items()
                        },
                    }
                    return FlextResult[dict[str, str | dict[str, list[str]]]].ok(
                        add_cfg
                    )

                case "delete":
                    del_cfg: dict[str, str] = {
                        FlextLdapConstants.LdapDictKeys.DN: str(
                            data.get(FlextLdapConstants.LdapDictKeys.DN, ""),
                        ),
                    }
                    return FlextResult[dict[str, str]].ok(del_cfg)

                case "default_search":
                    def_cfg: dict[str, str | int | list[str]] = {
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
                    return FlextResult[dict[str, str | int | list[str]]].ok(def_cfg)

                case "merge":
                    merged: dict[str, object] = data.copy()
                    if override_data:
                        merged.update(override_data)
                    return FlextResult[dict[str, object]].ok(merged)

                case _:
                    return FlextResult[dict[str, object]].fail(
                        f"Unknown config type: {config_type}"
                    )

        except Exception as e:
            error_msg = f"Config creation failed ({config_type}): {e}"
            return FlextResult[dict[str, object]].fail(error_msg)


__all__ = [
    "FlextLdapConfig",
]
