"""Configuration management for flext-ldap.

This module provides LDAP configuration management with environment
variable support, validation, and singleton patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""
# type: ignore[attr-defined]

from __future__ import annotations

from typing import ClassVar, override

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import SettingsConfigDict

from flext_core import FlextConfig, FlextResult
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapConfigs(FlextConfig):
    """FLEXT-LDAP Configuration singleton extending FlextConfig with LDAP-specific fields.

    This class provides a singleton configuration instance for LDAP operations,
    extending the base FlextConfig with LDAP-specific fields and validation rules.
    It serves as the single source of truth for LDAP configuration across the
    entire flext-ldap library.

    Features:
    - SINGLETON GLOBAL INSTANCE - One source of truth for LDAP configuration
    - LDAP-specific fields with proper validation
    - Environment variable support with FLEXT_LDAP_ prefix
    - Thread-safe singleton pattern
    - Centralized configuration management
    """

    # Pydantic model configuration using flext-core patterns
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

    # SINGLETON pattern inherited from FlextConfig with proper typing
    _global_instance: ClassVar[FlextLdapConfigs | None] = None

    # === CONSTANTS ===
    MAX_CACHE_TTL_SECONDS: ClassVar[int] = 3600  # 1 hour
    MAX_POOL_SIZE: ClassVar[int] = 50

    # === LDAP CONFIGURATION FIELDS ===
    # LDAP configuration fields using FlextLdapModels.ConnectionConfig directly

    # === LDAP CONNECTION CONFIGURATION ===
    # Connection to LDAP servers (can be a single or multiple connections)
    ldap_default_connection: FlextLdapModels.ConnectionConfig | None = Field(
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
        description="Enable LDAP debug logging",
        alias="enable_debug",
    )
    ldap_enable_trace: bool = Field(
        default=False,
        description="Enable LDAP trace logging",
        alias="enable_trace",
    )

    # Connection pooling
    ldap_pool_size: int = Field(
        default=10,
        description="LDAP connection pool size",
        alias="pool_size",
        ge=1,
        le=50,
    )
    ldap_pool_timeout: int = Field(
        default=30,
        description="LDAP connection pool timeout in seconds",
        alias="pool_timeout",
        ge=1,
        le=300,
    )

    # Caching
    ldap_enable_caching: bool = Field(
        default=True,
        description="Enable LDAP result caching",
        alias="enable_caching",
    )
    ldap_cache_ttl: int = Field(
        default=300,
        description="LDAP cache TTL in seconds",
        alias="cache_ttl",
        ge=0,
        le=3600,
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
        description="Delay between retry attempts in seconds",
        alias="retry_delay",
        ge=0,
        le=60,
    )

    # Timeout configuration
    ldap_connection_timeout: int = Field(
        default=30,
        description="LDAP connection timeout in seconds",
        alias="connection_timeout",
        ge=1,
        le=300,
    )
    ldap_operation_timeout: int = Field(
        default=60,
        description="LDAP operation timeout in seconds",
        alias="operation_timeout",
        ge=1,
        le=600,
    )

    # Additional LDAP configuration fields
    ldap_size_limit: int = Field(
        default=100,
        description="LDAP search size limit",
        alias="size_limit",
        ge=1,
        le=10000,
    )
    ldap_time_limit: int = Field(
        default=30,
        description="LDAP search time limit in seconds",
        alias="time_limit",
        ge=1,
        le=300,
    )
    ldap_log_queries: bool = Field(
        default=False,
        description="Enable logging of LDAP queries",
        alias="log_queries",
    )

    # =========================================================================
    # VALIDATION METHODS - Integrated from FlextLdapConfigValidationMixin
    # =========================================================================

    def validate_business_rules_base(self) -> FlextResult[None]:
        """Common business rules validation."""
        try:
            # Rule 1: Connection configuration must be valid
            if (
                hasattr(self, "ldap_default_connection")
                and getattr(self, "ldap_default_connection", None) is None
            ):
                return FlextResult[None].fail("Default LDAP connection is required")

            # Rule 2: If authentication is configured, both DN and password are needed
            bind_dn = getattr(self, "ldap_bind_dn", None)
            bind_password = getattr(self, "ldap_bind_password", None)
            if bind_dn is not None and bind_password is None:
                return FlextResult[None].fail(
                    "Bind password is required when bind DN is specified",
                )

            # Rule 3: Cache TTL must be reasonable
            enable_caching = getattr(self, "ldap_enable_caching", False)
            cache_ttl = getattr(self, "ldap_cache_ttl", 0)
            if enable_caching and cache_ttl > self.MAX_CACHE_TTL_SECONDS:
                return FlextResult[None].fail(
                    f"Cache TTL cannot exceed {self.MAX_CACHE_TTL_SECONDS} seconds",
                )

            # Rule 4: Pool size must be reasonable for environment
            pool_size = getattr(self, "ldap_pool_size", 0)
            if pool_size > self.MAX_POOL_SIZE:
                return FlextResult[None].fail(
                    f"Pool size cannot exceed {self.MAX_POOL_SIZE}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Configuration validation failed: {e}")

    # =========================================================================
    # CREATION METHODS - Integrated from FlextLdapConfigCreationMixin
    # =========================================================================

    @classmethod
    def create_config_with_defaults(
        cls,
        environment: str,
        config_data: dict[str, object],
        **overrides: object,
    ) -> FlextResult[object]:
        """Create configuration with environment-specific defaults."""
        try:
            # Apply overrides if any
            if overrides:
                config_data.update(overrides)

            # Use model_validate for proper type handling
            config = cls.model_validate(config_data)
            return FlextResult[object].ok(config)
        except Exception as e:
            return FlextResult[object].fail(
                f"Failed to create {environment} config: {e}"
            )

    @classmethod
    def create_from_connection_config_data(
        cls,
        connection_data: FlextLdapTypes.ConnectionConfigData,
    ) -> FlextResult[FlextLdapConfigs]:
        """Create configuration from ConnectionConfigData structure.

        Args:
            connection_data: Connection configuration data using DataStructures types

        Returns:
            FlextResult containing the created configuration or error

        """
        try:
            # Convert DataStructures format to config format
            config_data = {
                "ldap_default_connection": FlextLdapModels.ConnectionConfig(
                    **connection_data
                ),
                "ldap_use_ssl": connection_data.get("use_ssl", True),
                "ldap_bind_dn": connection_data.get("bind_dn"),
                "ldap_bind_password": connection_data.get("bind_password"),
            }

            config = cls.model_validate(config_data)
            return FlextResult[FlextLdapConfigs].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapConfigs].fail(
                f"Failed to create config from connection data: {e}"
            )

    # =========================================================================
    # SINGLETON METHODS - Override to return correct type
    # =========================================================================

    @classmethod
    @override
    def get_global_instance(cls) -> FlextLdapConfigs:
        """Get the global singleton instance of FlextLdapConfigs."""
        if cls._global_instance is None:
            cls._global_instance = cls()
        return cls._global_instance

    @classmethod
    @override
    def reset_global_instance(cls) -> None:
        """Reset the global FlextLdapConfigs instance (mainly for testing)."""
        cls._global_instance = None

    # =========================================================================
    # API METHODS - Methods expected by FlextLdapAPI
    # =========================================================================

    def get_effective_server_uri(self) -> str:
        """Get the effective server URI from configuration."""
        if self.ldap_default_connection and hasattr(
            self.ldap_default_connection, "server"
        ):
            server = getattr(self.ldap_default_connection, "server", None)
            if isinstance(server, str):
                return server
        return "ldap://localhost:389"

    def get_effective_bind_dn(self) -> str | None:
        """Get the effective bind DN from configuration."""
        if self.ldap_bind_dn:
            return self.ldap_bind_dn
        if self.ldap_default_connection and hasattr(
            self.ldap_default_connection, "bind_dn"
        ):
            return self.ldap_default_connection.bind_dn
        return None

    def get_effective_bind_password(self) -> str | None:
        """Get the effective bind password from configuration."""
        if self.ldap_bind_password:
            return self.ldap_bind_password.get_secret_value()
        if self.ldap_default_connection and hasattr(
            self.ldap_default_connection, "bind_password"
        ):
            bind_password = getattr(self.ldap_default_connection, "bind_password", None)
            if bind_password and hasattr(bind_password, "get_secret_value"):
                result = bind_password.get_secret_value()
                if isinstance(result, str):
                    return result
        return None

    # =========================================================================
    # FIELD VALIDATORS - Pydantic field validation
    # =========================================================================

    @field_validator("ldap_bind_dn")
    @classmethod
    def validate_bind_dn(cls, v: str | None) -> str | None:
        """Validate LDAP bind DN format."""
        if v is None:
            return v
        validation_result = FlextLdapValidations.validate_dn(v, "LDAP bind DN")
        if validation_result.is_failure:
            error_msg = f"Invalid LDAP bind DN format: {validation_result.error}"
            raise ValueError(error_msg)
        return v

    # =========================================================================
    # BASE METHODS - Common functionality for LDAP configurations
    # =========================================================================

    # Note: create_logging_field method removed to avoid type annotation issues
    # Use Field() directly when needed

    # Common validation helper methods
    @staticmethod
    def validate_bind_dn_field(value: str | None) -> str | None:
        """Common bind DN validation using centralized validation."""
        if value is None:
            return value

        # Basic DN validation using value objects
        dn_result = FlextLdapModels.DistinguishedName.create(value)
        if dn_result.is_failure:
            msg = f"Invalid LDAP bind DN format: {value}"
            raise ValueError(msg)

        return value

    @staticmethod
    def validate_configuration_consistency_base(config_instance: FlextConfig) -> None:
        """Common configuration consistency validation."""
        # Validation 1: Caching configuration
        if hasattr(config_instance, "ldap_enable_caching") and hasattr(
            config_instance, "ldap_cache_ttl"
        ):
            enable_caching = getattr(config_instance, "ldap_enable_caching", False)
            cache_ttl = getattr(config_instance, "ldap_cache_ttl", 0)
            if enable_caching and cache_ttl <= 0:
                msg = "Cache TTL must be positive when caching is enabled"
                raise ValueError(msg)

        # Validation 2: Pool configuration
        if hasattr(config_instance, "ldap_pool_size"):
            pool_size = getattr(config_instance, "ldap_pool_size", 0)
            if pool_size <= 0:
                msg = "Pool size must be positive"
                raise ValueError(msg)

        # Validation 3: Retry configuration
        if hasattr(config_instance, "ldap_retry_attempts") and hasattr(
            config_instance, "ldap_retry_delay"
        ):
            retry_attempts = getattr(config_instance, "ldap_retry_attempts", 0)
            retry_delay = getattr(config_instance, "ldap_retry_delay", 0)
            if retry_attempts > 0 and retry_delay < 0:
                msg = "Retry delay must be non-negative when retries are enabled"
                raise ValueError(msg)

    # =========================================================================
    # FACTORY METHODS - Create predefined configurations
    # =========================================================================

    @classmethod
    def create_development_ldap_config(cls) -> FlextResult[FlextLdapConfigs]:
        """Create a development LDAP configuration."""
        try:
            config = cls.model_validate({
                "ldap_use_ssl": False,
                "ldap_enable_debug": True,
                "ldap_log_queries": True,
                "ldap_size_limit": 100,
                "ldap_time_limit": 30,
                "ldap_pool_size": 5,
                "ldap_retry_attempts": 1,
            })
            return FlextResult[FlextLdapConfigs].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapConfigs].fail(
                f"Failed to create development config: {e}"
            )

    @classmethod
    def create_test_ldap_config(cls) -> FlextResult[FlextLdapConfigs]:
        """Create a test LDAP configuration."""
        try:
            config = cls.model_validate({
                "ldap_use_ssl": False,
                "ldap_enable_debug": False,
                "ldap_log_queries": False,
                "ldap_size_limit": 50,
                "ldap_time_limit": 10,
                "ldap_pool_size": 2,
                "ldap_retry_attempts": 1,
            })
            return FlextResult[FlextLdapConfigs].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapConfigs].fail(
                f"Failed to create test config: {e}"
            )

    @classmethod
    def create_production_ldap_config(cls) -> FlextResult[FlextLdapConfigs]:
        """Create a production LDAP configuration."""
        try:
            config = cls.model_validate({
                "ldap_use_ssl": True,
                "ldap_enable_debug": False,
                "ldap_log_queries": False,
                "ldap_size_limit": 1000,
                "ldap_time_limit": 60,
                "ldap_pool_size": 20,
                "ldap_retry_attempts": 3,
            })
            return FlextResult[FlextLdapConfigs].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapConfigs].fail(
                f"Failed to create production config: {e}"
            )


# Removed backward compatibility alias - use FlextLdapConfigs directly
__all__ = [
    "FlextLdapConfigs",
]
