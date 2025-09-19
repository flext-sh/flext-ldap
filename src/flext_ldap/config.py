"""Configuration management for flext-ldap.

This module provides LDAP configuration management with environment
variable support, validation, and singleton patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Self, cast, final

from pydantic import (
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import SettingsConfigDict

from flext_core import FlextConfig, FlextLogger, FlextModels, FlextResult
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

# Type alias for ConnectionConfig - clean separation of types and runtime
if TYPE_CHECKING:
    ConnectionConfigType = FlextLdapModels.ConnectionConfig
else:
    ConnectionConfigType = object  # Runtime placeholder


@final
class FlextLdapConfigs(FlextConfig):
    """FLEXT-LDAP Configuration singleton extending FlextConfig with LDAP-specific fields.

    This class provides a singleton configuration instance for LDAP operations,
    extending the base FlextConfig with LDAP-specific fields and validation rules.
    It serves as the single source of truth for LDAP configuration across the
    entire flext-ldap library.

    Features:
    - SINGLETON GLOBAL INSTANCE - One source of truth for LDAP configuration
    - LDAP-specific fields with proper validation
    - Environment variable integration with FLEXT_LDAP_ prefix
    - Parameter override support for runtime behavior changes
    - Clean Architecture integration with flext-core patterns
    - Unified type definitions within the class
    """

    # Pydantic model configuration
    model_config = SettingsConfigDict(
        env_prefix="FLEXT_LDAP_",
        env_file_encoding="utf-8",
        extra="ignore",  # Allow extra environment variables from other projects
        case_sensitive=False,
        arbitrary_types_allowed=True,
        populate_by_name=True,
        validate_assignment=True,
        use_enum_values=True,
    )

    # SINGLETON pattern implementation - use global instance
    _global_instance: ClassVar[FlextConfig | None] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    # === TYPE DEFINITIONS (CONSOLIDATED) ===
    # These replace the loose type aliases from module level
    class Types:
        """Unified type definitions for LDAP configuration."""

        ConfigDict = dict[str, object]
        ConnectionName = str
        ConfigPath = str | Path

    # NOTE: ConnectionConfig type alias is defined at module level, not class level
    # Access runtime ConnectionConfig through FlextLdapModels.ConnectionConfig

    # === LDAP CONNECTION CONFIGURATION ===
    # Connection to LDAP servers (can be a single or multiple connections)
    ldap_default_connection: ConnectionConfigType | None = Field(
        default=None,
        description="Default LDAP connection configuration",
        alias="ldap_connection",
    )

    # Bind DN and password for authentication (if not provided in connection config)
    ldap_bind_dn: str | None = Field(
        default=None,
        description="LDAP bind distinguished name for authentication",
        alias="bind_dn",
    )
    ldap_bind_password: SecretStr | None = Field(
        default=None,
        description="LDAP bind password for authentication",
        alias="bind_password",
    )

    # SSL/TLS configuration
    ldap_use_ssl: bool = Field(
        default=True,
        description="Use SSL/TLS for LDAP connections",
        alias="use_ssl",
    )
    ldap_verify_certificates: bool = Field(
        default=True,
        description="Verify SSL/TLS certificates",
        alias="verify_certificates",
    )

    # === LDAP BEHAVIOR CONFIGURATION ===
    # Debug and logging
    ldap_enable_debug: bool = Field(
        default=False,
        description="Enable debug mode for LDAP operations",
        alias="debug",
    )
    ldap_log_queries: bool = Field(
        default=False,
        description="Log LDAP queries",
        alias="log_queries",
    )
    ldap_log_responses: bool = Field(
        default=False,
        description="Log LDAP responses",
        alias="log_responses",
    )
    ldap_structured_logging: bool = Field(
        default=True,
        description="Use structured logging for LDAP operations",
        alias="structured_logging",
    )

    # Caching
    ldap_enable_caching: bool = Field(
        default=False,
        description="Enable caching for LDAP operations",
        alias="enable_caching",
    )
    ldap_cache_ttl: int = Field(
        default=300,
        description="Cache time-to-live in seconds",
        alias="cache_ttl",
        ge=0,
    )

    # === LDAP OPERATION LIMITS ===
    # Search limits
    ldap_size_limit: int = Field(
        default=1000,
        description="Maximum number of entries to return in search",
        alias="size_limit",
        ge=0,
    )
    ldap_time_limit: int = Field(
        default=30,
        description="Maximum time in seconds for search operations",
        alias="time_limit",
        ge=0,
    )
    ldap_page_size: int = Field(
        default=100,
        description="Page size for paged searches",
        alias="page_size",
        ge=1,
        le=1000,
    )

    # Connection pool settings
    ldap_pool_size: int = Field(
        default=10,
        description="Maximum number of connections in pool",
        alias="pool_size",
        ge=1,
        le=100,
    )
    ldap_pool_timeout: int = Field(
        default=30,
        description="Timeout for getting connection from pool (seconds)",
        alias="pool_timeout",
        ge=1,
    )

    # Retry configuration
    ldap_retry_attempts: int = Field(
        default=3,
        description="Number of retry attempts for failed operations",
        alias="retry_attempts",
        ge=0,
        le=10,
    )
    ldap_retry_delay: int = Field(
        default=1,
        description="Delay between retry attempts (seconds)",
        alias="retry_delay",
        ge=0,
        le=60,
    )
    ldap_enable_test_mode: bool = Field(
        default=False,
        description="Enable test mode for LDAP operations",
        alias="enable_test_mode",
    )

    # === VALIDATION METHODS ===
    @field_validator("ldap_bind_dn")
    @classmethod
    def validate_bind_dn(cls, value: str | None) -> str | None:
        """Validate bind DN format if provided."""
        if value is None:
            return value

        # Basic DN validation using value objects
        dn_result = FlextLdapModels.ValueObjects.DistinguishedName.create(value)
        if dn_result.is_failure:
            msg = f"Invalid LDAP bind DN format: {value}"
            raise ValueError(msg)

        return value

    def validate_configuration_consistency(self) -> Self:
        """Validate configuration consistency and business rules."""
        # Validation 1: Connection configuration consistency
        if self.ldap_default_connection is None:
            # Create default connection if not provided
            default_server = FlextLdapConstants.LDAP.DEFAULT_SERVER_URI
            try:
                self.ldap_default_connection = FlextLdapModels.ConnectionConfig(
                    server=default_server,
                )
            except Exception as e:
                msg = f"Failed to create default LDAP connection: {e}"
                raise ValueError(msg) from e

        # Validation 2: Caching configuration
        if self.ldap_enable_caching and self.ldap_cache_ttl <= 0:
            msg = "Cache TTL must be positive when caching is enabled"
            raise ValueError(msg)

        # Validation 3: Pool configuration
        if self.ldap_pool_size <= 0:
            msg = "Pool size must be positive"
            raise ValueError(msg)

        # Validation 4: Retry configuration
        if self.ldap_retry_attempts > 0 and self.ldap_retry_delay < 0:
            msg = "Retry delay must be non-negative when retries are enabled"
            raise ValueError(msg)

        return self

    @model_validator(mode="after")
    def _validate_configuration_consistency_model(self) -> FlextLdapConfigs:
        """Pydantic model validator that calls the runtime validation method."""
        return self.validate_configuration_consistency()

    # === SINGLETON PATTERN IMPLEMENTATION ===
    @classmethod
    def get_global_instance(cls) -> FlextLdapConfigs:
        """Get or create the global singleton instance.

        Returns:
            The global FlextLdapConfigs instance

        """
        if cls._global_instance is None:
            with cls._lock:
                if cls._global_instance is None:
                    cls._global_instance = cls()
        # Type cast is safe since we ensure it's FlextLdapConfigs
        return cast("FlextLdapConfigs", cls._global_instance)

    @classmethod
    def set_global_instance(cls, config: FlextConfig) -> None:
        """Set the global singleton instance.

        Args:
            config: New FlextConfig instance to set as global

        """
        if not isinstance(config, FlextLdapConfigs):
            msg = f"Expected FlextLdapConfigs, got {type(config)}"
            raise TypeError(msg)
        with cls._lock:
            cls._global_instance = config

    @classmethod
    def reset_global_instance(cls) -> None:
        """Reset the global singleton instance (mainly for testing)."""
        with cls._lock:
            cls._global_instance = None

    # === BUSINESS LOGIC VALIDATION ===
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDAP configuration business rules.

        Returns:
            FlextResult indicating validation success or failure

        """
        try:
            # Rule 1: Connection configuration must be valid
            if self.ldap_default_connection is None:
                return FlextResult[None].fail("Default LDAP connection is required")

            # Rule 2: If authentication is configured, both DN and password are needed
            if self.ldap_bind_dn is not None and self.ldap_bind_password is None:
                return FlextResult[None].fail(
                    "Bind password is required when bind DN is specified",
                )

            # Rule 3: Cache TTL must be reasonable
            max_cache_ttl = 3600  # 1 hour
            if self.ldap_enable_caching and self.ldap_cache_ttl > max_cache_ttl:
                return FlextResult[None].fail(
                    f"Cache TTL cannot exceed {max_cache_ttl} seconds",
                )

            # Rule 4: Pool size must be reasonable for environment
            max_pool_size = 50
            if self.ldap_pool_size > max_pool_size:
                return FlextResult[None].fail(
                    f"Pool size cannot exceed {max_pool_size}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Configuration validation failed: {e}")

    # === UTILITY METHODS ===
    def get_effective_server_uri(self) -> str:
        """Get the effective server URI for LDAP connections.

        Returns:
            The effective server URI

        """
        if self.ldap_default_connection and self.ldap_default_connection.server:
            return self.ldap_default_connection.server
        return FlextLdapConstants.LDAP.DEFAULT_SERVER_URI

    def get_effective_bind_dn(self) -> str | None:
        """Get the effective bind DN for authentication.

        Returns:
            The effective bind DN or None

        """
        return self.ldap_bind_dn

    def get_effective_bind_password(self) -> str | None:
        """Get the effective bind password for authentication.

        Returns:
            The effective bind password or None

        """
        return (
            self.ldap_bind_password.get_secret_value()
            if self.ldap_bind_password
            else None
        )

    def is_ssl_enabled(self) -> bool:
        """Check if SSL/TLS is enabled.

        Returns:
            True if SSL/TLS is enabled

        """
        return self.ldap_use_ssl

    def is_debug_enabled(self) -> bool:
        """Check if debug mode is enabled.

        Returns:
            True if debug mode is enabled

        """
        return self.ldap_enable_debug

    @classmethod
    def create_development_ldap_config(
        cls, **overrides: str | float | bool | None,
    ) -> FlextResult[FlextLdapConfigs]:
        """Create development LDAP configuration with appropriate defaults.

        Args:
            **overrides: Additional configuration overrides

        Returns:
            FlextResult containing development configuration

        """
        try:
            # Create config data with typed values
            config_data: dict[str, object] = {
                "environment": "development",
                "debug": True,
                "ldap_enable_debug": True,
                "ldap_log_queries": True,
                "ldap_log_responses": True,
                "ldap_enable_caching": False,
                "ldap_verify_certificates": False,
                "ldap_size_limit": 1000,
                "ldap_time_limit": 60,
            }

            # Apply overrides if any
            if overrides:
                config_data.update(overrides)

            # Use model_validate for proper type handling
            config = cls.model_validate(config_data)
            return FlextResult[FlextLdapConfigs].ok(config)
        except Exception as e:
            return FlextResult["FlextLdapConfigs"].fail(
                f"Failed to create development config: {e}",
            )

    @classmethod
    def create_test_ldap_config(
        cls, **overrides: str | float | bool | None,
    ) -> FlextResult[FlextLdapConfigs]:
        """Create test LDAP configuration with appropriate defaults.

        Args:
            **overrides: Additional configuration overrides

        Returns:
            FlextResult containing test configuration

        """
        try:
            # Create config data with typed values
            config_data: dict[str, object] = {
                "environment": "test",
                "debug": False,
                "ldap_enable_debug": False,
                "ldap_log_queries": False,
                "ldap_log_responses": False,
                "ldap_enable_caching": False,
                "ldap_verify_certificates": False,
                "ldap_size_limit": 500,
                "ldap_time_limit": 30,
                "ldap_enable_test_mode": True,
            }

            # Apply overrides if any
            if overrides:
                config_data.update(overrides)

            # Use model_validate for proper type handling
            config = cls.model_validate(config_data)
            return FlextResult[FlextLdapConfigs].ok(config)
        except Exception as e:
            return FlextResult["FlextLdapConfigs"].fail(
                f"Failed to create test config: {e}",
            )

    @classmethod
    def create_production_ldap_config(
        cls, **overrides: dict[str, object],
    ) -> FlextResult[FlextLdapConfigs]:
        """Create production LDAP configuration with appropriate defaults.

        Args:
            **overrides: Additional configuration overrides

        Returns:
            FlextResult containing production configuration

        """
        try:
            production_defaults: dict[str, object] = {
                "environment": "production",
                "debug": False,
                "ldap_enable_debug": False,
                "ldap_log_queries": False,
                "ldap_log_responses": False,
                "ldap_enable_caching": True,  # Enable caching in production
                "ldap_cache_ttl": 3600,  # 1 hour cache
                "ldap_verify_certificates": True,  # Strict SSL in production
                "ldap_size_limit": 5000,  # Higher limits for production
                "ldap_time_limit": 120,
                "ldap_pool_size": 10,  # Connection pooling
            }
            production_defaults.update(overrides)
            config = cls.model_validate(production_defaults)
            return FlextResult["FlextLdapConfigs"].ok(config)
        except Exception as e:
            return FlextResult["FlextLdapConfigs"].fail(
                f"Failed to create production config: {e}",
            )

    def apply_ldap_overrides(self, overrides: dict[str, object]) -> FlextResult[None]:
        """Apply LDAP configuration overrides to current instance.

        Args:
            overrides: Dictionary of configuration overrides

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # Map override keys to actual field names
            field_mapping = {
                "size_limit": "ldap_size_limit",
                "time_limit": "ldap_time_limit",
                "enable_caching": "ldap_enable_caching",
                "cache_ttl": "ldap_cache_ttl",
                "log_queries": "ldap_log_queries",
                "log_responses": "ldap_log_responses",
                "structured_logging": "ldap_structured_logging",
                "enable_debug": "ldap_enable_debug",
                "verify_certificates": "ldap_verify_certificates",
                "use_ssl": "ldap_use_ssl",
                "pool_size": "ldap_pool_size",
                "page_size": "ldap_page_size",
                "retry_attempts": "ldap_retry_attempts",
                "retry_delay": "ldap_retry_delay",
            }

            # Apply overrides using setattr
            for key, value in overrides.items():
                field_name = field_mapping.get(key, key)
                if hasattr(self, field_name):
                    setattr(self, field_name, value)
                # Try direct field name for non-mapped fields
                elif hasattr(self, key):
                    setattr(self, key, value)
                else:
                    return FlextResult[None].fail(f"Unknown configuration field: {key}")

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Failed to apply overrides: {e}")

    def get_ldap_search_config(self) -> dict[str, object]:
        """Get LDAP search-related configuration.

        Returns:
            Dictionary containing search configuration

        """
        return {
            "size_limit": self.ldap_size_limit,
            "time_limit": self.ldap_time_limit,
            "page_size": self.ldap_page_size,
        }

    def get_ldap_performance_config(self) -> dict[str, object]:
        """Get LDAP performance-related configuration.

        Returns:
            Dictionary containing performance configuration

        """
        return {
            "enable_caching": self.ldap_enable_caching,
            "cache_ttl": self.ldap_cache_ttl,
            "pool_size": self.ldap_pool_size,
            "pool_timeout": self.ldap_pool_timeout,
            "retry_attempts": self.ldap_retry_attempts,
            "retry_delay": self.ldap_retry_delay,
        }

    def get_ldap_logging_config(self) -> dict[str, object]:
        """Get LDAP logging-related configuration.

        Returns:
            Dictionary containing logging configuration

        """
        return {
            "log_queries": self.ldap_log_queries,
            "log_responses": self.ldap_log_responses,
            "structured_logging": self.ldap_structured_logging,
            "enable_debug": self.ldap_enable_debug,
        }

    def get_effective_connection(self) -> Types.ConfigDict | None:
        """Get effective connection configuration.

        Returns:
            Dictionary containing connection details or None

        """
        if not self.ldap_default_connection:
            return None

        return {
            "server": self.ldap_default_connection.server,
            "port": self.ldap_default_connection.port,
            "use_ssl": self.ldap_use_ssl,
            "verify_certificates": self.ldap_verify_certificates,
        }

    def get_effective_auth_config(self) -> dict[str, object]:
        """Get effective authentication configuration.

        Returns:
            Dictionary containing authentication details

        """
        return {
            "bind_dn": self.get_effective_bind_dn(),
            "use_ssl": self.ldap_use_ssl,
            "verify_certificates": self.ldap_verify_certificates,
        }

    class LdapConnection(FlextConfig):
        """LDAP connection configuration with validation."""

        model_config = SettingsConfigDict(
            extra="ignore",  # Allow ALGAR and other project-specific environment variables
            validate_assignment=True,
            str_strip_whitespace=True,
        )

        def model_post_init(
            self, __context: dict[str, object] | None = None, /,
        ) -> None:
            """Post-initialization setup for LDAP configuration."""
            super().model_post_init(__context)
            self._logger = FlextLogger(__name__)

        # Basic Connection Settings
        server: str = Field(
            default=FlextLdapConstants.LDAP.DEFAULT_SERVER_URI,
            description=f"LDAP server URI (e.g., '{FlextLdapConstants.LDAP.PROTOCOL_PREFIX_LDAP}host' or '{FlextLdapConstants.LDAP.PROTOCOL_PREFIX_LDAPS}host:{FlextLdapConstants.LDAP.DEFAULT_SSL_PORT}')",
            min_length=1,
        )

        port: int = Field(
            default=FlextLdapConstants.LDAP.DEFAULT_PORT,
            description=f"LDAP server port ({FlextLdapConstants.LDAP.DEFAULT_PORT} for LDAP, {FlextLdapConstants.LDAP.DEFAULT_SSL_PORT} for LDAPS)",
            ge=1,
            le=65535,
        )

        use_ssl: bool = Field(
            default=False,
            description="Use SSL/TLS encryption (LDAPS)",
        )

        # Authentication Settings
        bind_dn: str = Field(
            default="",
            description="Bind Distinguished Name for authentication",
        )

        bind_password: str = Field(
            default="",
            description="Password for bind DN",
            repr=False,  # Hide password in repr
        )

        # Connection Pool Settings
        timeout: int = Field(
            default=FlextLdapConstants.LDAP.DEFAULT_TIMEOUT,
            description="Connection timeout in seconds",
            ge=1,
            le=300,
        )

        pool_size: int = Field(
            default=FlextLdapConstants.LDAP.DEFAULT_POOL_SIZE,
            description="Maximum number of connections in pool",
            ge=1,
            le=50,
        )

        # TLS/SSL Settings
        ca_cert_file: Path | None = Field(
            default=None,
            description="Path to CA certificate file for SSL verification",
        )

        client_cert_file: Path | None = Field(
            default=None,
            description="Path to client certificate file",
        )

        client_key_file: Path | None = Field(
            default=None,
            description="Path to client private key file",
        )

        verify_ssl: bool = Field(
            default=True,
            description="Verify SSL certificates",
        )

        @field_validator("server")
        @classmethod
        def validate_server_uri(cls, v: str) -> str:
            """Validate LDAP server URI format using FlextModels.Url validation."""
            if not v or not v.strip():
                msg = "Server URI cannot be empty"
                raise ValueError(msg)

            v = v.strip()

            # Convert LDAP schemes to HTTP for FlextModels.Url validation
            temp_url = v
            if v.startswith("ldap://"):
                temp_url = v.replace("ldap://", "http://", 1)
            elif v.startswith("ldaps://"):
                temp_url = v.replace("ldaps://", "https://", 1)
            else:
                msg = "LDAP URI must start with 'ldap://' or 'ldaps://'"
                raise ValueError(msg)

            # Use FlextModels.Url for comprehensive validation
            url_result = FlextModels.Url.create(temp_url)
            if url_result.is_failure:
                msg = f"Invalid LDAP URI format: {url_result.error}"
                raise ValueError(msg)

            return v

        @field_validator("ca_cert_file", "client_cert_file", "client_key_file")
        @classmethod
        def validate_cert_files(cls, v: Path | None) -> Path | None:
            """Validate certificate files using direct validation."""
            if v is None:
                return v

            # Use direct validation for file path validation
            path_str = str(v)
            if not path_str or not path_str.strip():
                msg = "Certificate file path invalid"
                raise ValueError(msg)

            # File existence validation
            if not v.exists():
                msg = f"Certificate file does not exist: {v}"
                raise ValueError(msg)

            return v

        def get_server_uri(self) -> str:
            """Get complete server URI including port if non-standard."""
            if ":" in self.server and not self.server.endswith(f":{self.port}"):
                # Server already includes port
                return self.server

            # Add port if non-standard - use constants
            standard_port = (
                FlextLdapConstants.LDAP.DEFAULT_SSL_PORT
                if self.use_ssl
                else FlextLdapConstants.LDAP.DEFAULT_PORT
            )
            if self.port != standard_port:
                base_uri = self.server.rstrip("/")
                return f"{base_uri}:{self.port}"

            return self.server

        def validate_configuration(self) -> FlextResult[None]:
            """Validate the complete configuration.

            Returns:
                str:: Description of return value.

            """
            try:
                # Additional validation logic here
                if self.use_ssl and self.verify_ssl and not self.ca_cert_file:
                    self._logger.warning(
                        "SSL verification enabled but no CA certificate file specified",
                    )

                return FlextResult.ok(None)
            except Exception as e:
                return FlextResult.fail(f"Configuration validation failed: {e}")


__all__ = [
    "FlextLdapConfigs",
]
