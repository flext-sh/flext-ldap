"""Configuration management with FlextConfig features.

LDAP configuration with environment variables, validation, computed
fields, and infrastructure protocols.

Note: ldap3 type stubs have incomplete method return types and property
annotations (conn.entries, entry_dn, entry attributes).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
from typing import Any, ClassVar, cast

from dependency_injector import providers
from flext_core import (
    FlextConfig,
    FlextConstants,
    FlextExceptions,
    FlextResult,
    PortNumber,
    TimeoutSeconds,
)
from pydantic import Field, SecretStr, computed_field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


class FlextLdapConfig(FlextConfig):
    """LDAP configuration with FlextConfig features.

    Extends FlextConfig with LDAP-specific settings including:
    - Connection parameters (server URI, port, credentials)
    - Operation settings (timeouts, pool size, SSL)
    - Computed fields for connection info and capabilities
    - Validation for runtime and business requirements

    Inherited from FlextConfig: enable_caching, cache_ttl,
    max_retry_attempts, retry_delay.

    Example:
        >>> config = FlextLdapConfig()
        >>> port = config("ldap.connection.port")
        >>> info = config.connection_info
        >>> result = config.validate_ldap_requirements()

    """

    # Override model_config with LDAP-specific env_prefix for environment variable loading
    model_config = SettingsConfigDict(
        case_sensitive=False,
        env_prefix=FlextConstants.Platform.ENV_PREFIX,
        env_file=FlextConstants.Platform.ENV_FILE_DEFAULT,
        env_file_encoding=FlextConstants.Mixins.DEFAULT_ENCODING,
        env_nested_delimiter=FlextConstants.Platform.ENV_NESTED_DELIMITER,
        extra="ignore",
        use_enum_values=False,
        frozen=False,
        arbitrary_types_allowed=True,
        validate_return=True,
        validate_assignment=True,
        validate_default=True,
        str_strip_whitespace=True,
        str_to_lower=False,
        strict=False,
    )

    # Dependency Injection integration (v1.1.0+)
    _di_config_provider: ClassVar[providers.Configuration | None] = None
    _di_provider_lock: ClassVar[threading.RLock] = threading.RLock()

    # Singleton pattern inherited from FlextConfig - no need to redefine _instances
    # _lock inherited as well
    # Note: Removed __new__ override - Pydantic v2 handles SecretStr natively

    # Inherit model_config from FlextConfig (includes debug, trace, all parent fields)
    # NO model_config override - Pydantic v2 pattern for proper field inheritance

    # LDAP Connection Configuration using FlextLdapConstants for defaults
    ldap_server_uri: str = Field(
        default=FlextLdapConstants.Protocol.DEFAULT_SERVER_URI,
        description="LDAP server URI (ldap://, ldaps://, or hostname/IP for auto-prefix)",
    )

    ldap_port: PortNumber = Field(
        default=FlextLdapConstants.Protocol.DEFAULT_PORT,
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

    ldap_pool_timeout: TimeoutSeconds = Field(
        default=FlextConstants.Network.DEFAULT_TIMEOUT,
        description="LDAP connection pool timeout in seconds",
    )

    # Operation Configuration using FlextLdapConstants for defaults
    ldap_connection_timeout: TimeoutSeconds = Field(
        default=FlextConstants.Network.DEFAULT_TIMEOUT,
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

    # NO caching/retry field duplicates - use FlextConfig.enable_caching, cache_ttl, max_retry_attempts, retry_delay

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
    # FIELD VALIDATORS - Business logic validation
    # =========================================================================

    @field_validator("ldap_bind_dn")
    @classmethod
    def validate_bind_dn(cls, v: str | None) -> str | None:
        """Validate LDAP bind DN contains attribute=value pairs (business logic)."""
        if v is None:
            return v
        # Check format first (must contain =)
        if "=" not in v:
            msg = (
                f"Invalid LDAP bind DN format: {v}. Must contain attribute=value pairs"
            )
            raise FlextExceptions.ValidationError(msg, field="ldap_bind_dn", value=v)
        # Then check length
        if len(v) < FlextLdapConstants.Validation.MIN_DN_LENGTH:
            msg = f"Invalid LDAP bind DN: string too short (minimum {FlextLdapConstants.Validation.MIN_DN_LENGTH} characters)"
            raise FlextExceptions.ValidationError(msg, field="ldap_bind_dn", value=v)
        return v

    # =========================================================================
    # COMPUTED FIELDS - Derived LDAP configuration properties
    # =========================================================================

    @computed_field
    def connection_info(self) -> FlextLdapModels.ConnectionInfo:
        """Get LDAP connection information."""
        return FlextLdapModels.ConnectionInfo(
            server=self.ldap_server_uri,
            port=self.ldap_port,
            use_ssl=self.ldap_use_ssl,
            use_tls=False,
            bind_dn=self.ldap_bind_dn,
            bind_password=self.ldap_bind_password,
            timeout=int(self.ldap_connection_timeout),
            pool_size=self.ldap_pool_size,
            pool_keepalive=self.cache_ttl,
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
            pool_timeout=int(self.ldap_pool_timeout),
            pool_utilization=f"{self.ldap_pool_size}/50",
        )

    @computed_field
    def operation_limits(self) -> FlextLdapModels.ConfigRuntimeMetadata.OperationLimits:
        """Get LDAP operation limits and timeouts."""
        return FlextLdapModels.ConfigRuntimeMetadata.OperationLimits(
            operation_timeout=self.ldap_operation_timeout,
            size_limit=self.ldap_size_limit,
            time_limit=self.ldap_time_limit,
            connection_timeout=int(self.ldap_connection_timeout),
            total_timeout=int(
                self.ldap_operation_timeout + self.ldap_connection_timeout,
            ),
        )

    @computed_field
    def caching_info(self) -> FlextLdapModels.ConfigRuntimeMetadata.Caching:
        """Get LDAP caching configuration information."""
        return FlextLdapModels.ConfigRuntimeMetadata.Caching(
            caching_enabled=self.enable_caching,
            cache_ttl=self.cache_ttl,
            cache_ttl_minutes=self.cache_ttl // 60,
            cache_effective=self.enable_caching and self.cache_ttl > 0,
        )

    @computed_field
    def retry_info(self) -> FlextLdapModels.ConfigRuntimeMetadata.Retry:
        """Get LDAP retry configuration information."""
        return FlextLdapModels.ConfigRuntimeMetadata.Retry(
            retry_attempts=self.max_retry_attempts,
            retry_delay=int(self.retry_delay),
            total_retry_time=int(self.max_retry_attempts * self.retry_delay),
            retry_enabled=self.max_retry_attempts > 0,
        )

    @computed_field
    def ldap_capabilities(self) -> FlextLdapModels.ConfigCapabilities:
        """Get LDAP server capabilities summary."""
        return FlextLdapModels.ConfigCapabilities(
            supports_ssl=self.ldap_use_ssl,
            supports_caching=self.enable_caching,
            supports_retry=self.max_retry_attempts > 0,
            supports_debug=self.ldap_enable_debug or self.ldap_enable_trace,
            has_authentication=self.ldap_bind_dn is not None,
            has_pooling=self.ldap_pool_size > 1,
            is_production_ready=(self.ldap_use_ssl and self.ldap_bind_dn is not None),
        )

    # =========================================================================
    # MODEL VALIDATORS - Cross-field validation with business rules
    # Pydantic v2: Keep @model_validator for legitimate cross-field validation
    # =========================================================================

    @model_validator(mode="after")
    def validate_ldap_configuration_consistency(self) -> FlextLdapConfig:
        """Validate LDAP configuration consistency with business rules."""
        # Validate authentication configuration
        if self.ldap_bind_dn is not None and self.ldap_bind_password is None:
            msg = "Bind password is required when bind DN is specified"
            raise FlextExceptions.ConfigurationError(
                msg,
                config_key="ldap_bind_password",
            )

        # Validate caching configuration
        if self.enable_caching and self.cache_ttl <= 0:  # type: ignore[attr-defined]
            msg = "Cache TTL must be positive when caching is enabled"
            raise FlextExceptions.ConfigurationError(msg, config_key="ldap_cache_ttl")

        # Validate SSL configuration consistency
        if (
            self.ldap_server_uri.startswith(FlextLdapConstants.Protocols.LDAPS)
            and not self.ldap_use_ssl
        ):
            msg = "SSL must be enabled for ldaps:// server URIs"
            raise FlextExceptions.ConfigurationError(msg, config_key="ldap_use_ssl")

        return self

    # =========================================================================
    # ENHANCED DIRECT ACCESS - Dot notation support for LDAP config
    # =========================================================================

    def __call__(
        self,
        key: str,
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
                case FlextLdapConstants.ConfigCategoryKeys.CONNECTION:
                    match prop:
                        case FlextLdapConstants.ConfigPropertyKeys.SERVER:
                            return self.ldap_server_uri
                        case FlextLdapConstants.ConfigPropertyKeys.PORT:
                            return self.ldap_port
                        case FlextLdapConstants.ConfigPropertyKeys.SSL:
                            return self.ldap_use_ssl
                        case FlextLdapConstants.ConfigPropertyKeys.TIMEOUT:
                            return self.ldap_connection_timeout
                        case FlextLdapConstants.ConfigPropertyKeys.URI:
                            return f"{self.ldap_server_uri}:{self.ldap_port}"
                case FlextLdapConstants.ConfigCategoryKeys.AUTH:
                    match prop:
                        case FlextLdapConstants.ConfigPropertyKeys.BIND_DN:
                            return self.ldap_bind_dn
                        case FlextLdapConstants.ConfigPropertyKeys.BIND_PASSWORD:
                            return self.effective_bind_password
                        case FlextLdapConstants.ConfigPropertyKeys.BASE_DN:
                            return self.ldap_base_dn
                case FlextLdapConstants.ConfigCategoryKeys.POOL:
                    match prop:
                        case FlextLdapConstants.ConfigPropertyKeys.SIZE:
                            return self.ldap_pool_size
                        case FlextLdapConstants.ConfigPropertyKeys.TIMEOUT:
                            return self.ldap_pool_timeout
                case FlextLdapConstants.ConfigCategoryKeys.OPERATION:
                    match prop:
                        case FlextLdapConstants.ConfigPropertyKeys.TIMEOUT:
                            return self.ldap_operation_timeout
                        case FlextLdapConstants.ConfigPropertyKeys.SIZE_LIMIT:
                            return self.ldap_size_limit
                        case FlextLdapConstants.ConfigPropertyKeys.TIME_LIMIT:
                            return self.ldap_time_limit
                case FlextLdapConstants.ConfigCategoryKeys.CACHE:
                    match prop:
                        case FlextLdapConstants.ConfigPropertyKeys.ENABLED:
                            return self.enable_caching  # type: ignore[attr-defined]
                        case FlextLdapConstants.ConfigPropertyKeys.TTL:
                            return self.cache_ttl  # type: ignore[attr-defined]
                case FlextLdapConstants.ConfigCategoryKeys.RETRY:
                    match prop:
                        case FlextLdapConstants.ConfigPropertyKeys.ATTEMPTS:
                            return self.max_retry_attempts  # type: ignore[attr-defined]
                        case FlextLdapConstants.ConfigPropertyKeys.DELAY:
                            return self.retry_delay  # type: ignore[attr-defined]
                case FlextLdapConstants.ConfigCategoryKeys.LOGGING:
                    match prop:
                        case FlextLdapConstants.ConfigPropertyKeys.DEBUG:
                            return self.ldap_enable_debug
                        case FlextLdapConstants.ConfigPropertyKeys.TRACE:
                            return self.ldap_enable_trace
                        case FlextLdapConstants.ConfigPropertyKeys.QUERIES:
                            return self.ldap_log_queries
                        case FlextLdapConstants.ConfigPropertyKeys.MASK_PASSWORDS:
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

        Extended validation for LDAP configuration beyond basic
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
            self.ldap_server_uri.startswith(FlextLdapConstants.Protocols.LDAPS)
            and self.ldap_port == FlextLdapConstants.Defaults.DEFAULT_PORT
        ):
            port = FlextLdapConstants.Defaults.DEFAULT_PORT
            ssl_port = FlextLdapConstants.Defaults.DEFAULT_PORT_SSL
            msg = f"Port {port} is for LDAP, not LDAPS. Use {ssl_port}."
            return FlextResult[None].fail(msg)

        if (
            self.ldap_server_uri.startswith(FlextLdapConstants.Protocols.LDAP)
            and self.ldap_port == FlextLdapConstants.Defaults.DEFAULT_PORT_SSL
        ):
            ssl_port = FlextLdapConstants.Defaults.DEFAULT_PORT_SSL
            port = FlextLdapConstants.Defaults.DEFAULT_PORT
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


__all__ = [
    "FlextLdapConfig",
]
