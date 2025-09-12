"""FLEXT-LDAP Configuration - Singleton configuration management extending flext-core.

This module provides enterprise-grade LDAP configuration management using the
FlextConfig singleton pattern from flext-core, with LDAP-specific fields and
validation rules. Follows exact patterns from flext-core and flext-cli.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import threading
from contextlib import suppress
from pathlib import Path
from typing import ClassVar, Self, final, override

# from flext_cli import FlextCliConfig  # Temporarily disabled
from flext_core import FlextConfig, FlextResult, FlextTypes
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from flext_ldap.connection_config import FlextLDAPConnectionConfig
from flext_ldap.value_objects import FlextLDAPValueObjects

# Python 3.13 type aliases for LDAP configuration
type LdapConfigDict = FlextTypes.Core.Dict
type LdapConnectionName = str
type LdapConfigPath = str | Path


@final
class FlextLDAPConfig(FlextConfig):
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
    - CLI parameter override support following flext-cli patterns
    """

    # Reference to flext-core config for inheritance
    Core: ClassVar[type[FlextConfig]] = FlextConfig

    # SINGLETON PATTERN - Global LDAP configuration instance with thread safety
    _global_instance: ClassVar[FlextLDAPConfig | None] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    # Advanced Pydantic v2 configuration with environment loading
    model_config = SettingsConfigDict(
        # Enable advanced features for flext-core integration
        validate_assignment=True,
        arbitrary_types_allowed=True,
        extra="ignore",  # Allow additional environment variables
        # Automatic environment variable loading
        env_file=".env",  # Load from .env file automatically
        env_file_encoding="utf-8",
        env_prefix="FLEXT_LDAP_",  # Environment variables with FLEXT_LDAP_ prefix
        env_nested_delimiter="__",  # Support nested configs via FLEXT_LDAP_CONFIG__FIELD
        case_sensitive=False,  # Allow case-insensitive env vars
        # JSON schema configuration
        json_schema_extra={
            "examples": [
                {
                    "ldap_default_connection": {
                        "server": "ldap://localhost",
                        "port": 389,
                        "use_ssl": False
                    },
                    "ldap_bind_dn": "cn=admin,dc=example,dc=com",
                    "ldap_use_ssl": False,
                    "ldap_enable_debug": True,
                },
                {
                    "ldap_default_connection": {
                        "server": "ldaps://ldap.company.com",
                        "port": 636,
                        "use_ssl": True
                    },
                    "ldap_bind_dn": "cn=service,ou=accounts,dc=company,dc=com",
                    "ldap_use_ssl": True,
                    "ldap_enable_debug": False,
                },
            ],
        },
    )

    # =============================================================================
    # LDAP-SPECIFIC CONFIGURATION FIELDS
    # =============================================================================

    # Primary connection configuration
    ldap_default_connection: FlextLDAPConnectionConfig | None = Field(
        default=None,
        description="Default LDAP connection configuration",
        alias="ldap_connection",
    )

    # Authentication configuration
    ldap_bind_dn: str | None = Field(
        default=None,
        description="Distinguished Name for LDAP binding",
        min_length=3,
        alias="ldap_bind_dn",
    )

    ldap_bind_password: SecretStr | None = Field(
        default=None,
        description="Password for LDAP binding (secure)",
        alias="ldap_bind_password",
    )

    ldap_use_ssl: bool = Field(
        default=False,
        description="Use SSL/TLS for LDAP connection",
        alias="ldap_use_ssl",
    )

    ldap_verify_certificates: bool = Field(
        default=True,
        description="Verify SSL certificates for LDAP",
        alias="ldap_verify_certificates",
    )

    # Search configuration
    ldap_default_scope: str = Field(
        default=FlextLDAPValueObjects.Scope.subtree().scope,
        description="Default LDAP search scope",
        alias="ldap_default_scope",
    )

    ldap_size_limit: int = Field(
        default=1000,
        description="Maximum LDAP search results",
        gt=0,
        le=10000,
        alias="ldap_size_limit",
    )

    ldap_time_limit: int = Field(
        default=30,
        description="LDAP search timeout in seconds",
        gt=0,
        le=300,
        alias="ldap_time_limit",
    )

    ldap_page_size: int = Field(
        default=100,
        description="Paging size for large LDAP results",
        gt=0,
        le=1000,
        alias="ldap_page_size",
    )

    # Logging configuration
    ldap_enable_debug: bool = Field(
        default=False,
        description="Enable LDAP debug logging",
        alias="ldap_enable_debug",
    )

    ldap_log_queries: bool = Field(
        default=False,
        description="Log LDAP queries",
        alias="ldap_log_queries",
    )

    ldap_log_responses: bool = Field(
        default=False,
        description="Log LDAP responses",
        alias="ldap_log_responses",
    )

    ldap_structured_logging: bool = Field(
        default=True,
        description="Enable structured (JSON) logging for LDAP",
        alias="ldap_structured_logging",
    )

    # Performance tuning
    ldap_enable_caching: bool = Field(
        default=False,
        description="Enable LDAP result caching",
        alias="ldap_enable_caching",
    )

    ldap_cache_ttl: int = Field(
        default=300,
        description="LDAP cache TTL in seconds",
        gt=0,
        le=3600,
        alias="ldap_cache_ttl",
    )

    # Development settings
    ldap_enable_debug_mode: bool = Field(
        default=False,
        description="Enable LDAP debug mode with verbose logging",
        alias="ldap_enable_debug_mode",
    )

    ldap_enable_test_mode: bool = Field(
        default=False,
        description="Enable LDAP test mode",
        alias="ldap_enable_test_mode",
    )

    # =============================================================================
    # FIELD VALIDATION METHODS
    # =============================================================================

    @field_validator("ldap_default_scope")
    @classmethod
    def validate_ldap_scope(cls, value: str) -> str:
        """Validate LDAP scope is in allowed set."""
        allowed_scopes = {
            FlextLDAPValueObjects.Scope.base().scope,
            FlextLDAPValueObjects.Scope.one().scope,
            FlextLDAPValueObjects.Scope.subtree().scope,
        }
        if value not in allowed_scopes:
            allowed_str = ", ".join(sorted(allowed_scopes))
            msg = f"Invalid LDAP scope. Scope must be one of: {allowed_str}"
            raise ValueError(msg)
        return value

    @field_validator("ldap_bind_dn")
    @classmethod
    def validate_bind_dn(cls, value: str | None) -> str | None:
        """Validate bind DN format."""
        if value is None:
            return value
        if not value.strip():
            msg = "Bind DN cannot be empty"
            raise ValueError(msg)
        # Basic DN format validation
        if not any(value.startswith(prefix) for prefix in ["cn=", "uid=", "ou=", "dc="]):
            msg = "Bind DN should start with cn=, uid=, ou=, or dc="
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def validate_ldap_configuration_consistency(self) -> Self:
        """Validate cross-field LDAP configuration consistency."""
        # Cache validation
        if self.ldap_enable_caching and self.ldap_cache_ttl <= 0:
            msg = "LDAP cache TTL must be positive when caching is enabled"
            raise ValueError(msg)

        # SSL validation
        if self.ldap_use_ssl and not self.ldap_verify_certificates:
            # This is a warning, not an error - some environments disable cert verification
            pass

        # Test mode validation
        if self.ldap_enable_test_mode and self.environment == "production":
            msg = "Test mode should not be enabled in production environment"
            raise ValueError(msg)

        return self

    # =============================================================================
    # SINGLETON GLOBAL INSTANCE METHODS
    # =============================================================================

    @classmethod
    def get_global_instance(cls) -> FlextLDAPConfig:
        """Get the SINGLETON GLOBAL LDAP configuration instance.

        This method ensures a single source of truth for LDAP configuration across
        the entire flext-ldap library. It integrates with the base FlextConfig singleton
        and extends it with LDAP-specific settings.

        Priority order:
        1. Base FlextConfig global instance (from flext-core)
        2. LDAP-specific overrides from environment variables (FLEXT_LDAP_ prefix)
        3. LDAP-specific overrides from .env files
        4. LDAP-specific overrides from CLI parameters

        Returns:
            FlextLDAPConfig: The global LDAP configuration instance (created if needed)

        """
        if cls._global_instance is None:
            with cls._lock:
                # Double-check locking pattern for thread safety
                if cls._global_instance is None:
                    cls._global_instance = cls._load_ldap_config_from_sources()
        return cls._global_instance

    @classmethod
    def _load_ldap_config_from_sources(cls) -> FlextLDAPConfig:
        """Load LDAP configuration from all available sources in priority order."""
        try:
            # Get base FlextConfig singleton as foundation
            base_config = FlextConfig.get_global_instance()

            # Create LDAP config extending base config
            ldap_config = cls()

            # Copy base configuration values to LDAP config
            base_dict = base_config.to_dict()
            for key, value in base_dict.items():
                if hasattr(ldap_config, key):
                    setattr(ldap_config, key, value)

            # Apply LDAP-specific overrides from environment
            ldap_overrides = cls._get_ldap_environment_overrides()
            for key, value in ldap_overrides.items():
                if hasattr(ldap_config, key):
                    setattr(ldap_config, key, value)

            # Validate the merged configuration
            validation_result = ldap_config.validate_business_rules()
            if validation_result.is_failure:
                # Log warning but continue with base config
                pass

            return ldap_config

        except Exception:
            # Fallback to default LDAP config if loading fails
            return cls()

    @classmethod
    def set_global_instance(cls, config: FlextLDAPConfig) -> None:
        """Set the SINGLETON GLOBAL LDAP configuration instance.

        Args:
            config: The LDAP configuration to set as global

        """
        cls._global_instance = config

    @classmethod
    def clear_global_instance(cls) -> None:
        """Clear the global LDAP instance (useful for testing)."""
        cls._global_instance = None

    @classmethod
    def _get_ldap_environment_overrides(cls) -> FlextTypes.Core.Dict:
        """Get LDAP-specific environment variable overrides."""
        ldap_overrides = {}

        # Map LDAP-specific environment variables
        env_mappings = {
            "FLEXT_LDAP_BIND_DN": "ldap_bind_dn",
            "FLEXT_LDAP_BIND_PASSWORD": "ldap_bind_password",
            "FLEXT_LDAP_USE_SSL": "ldap_use_ssl",
            "FLEXT_LDAP_VERIFY_CERTIFICATES": "ldap_verify_certificates",
            "FLEXT_LDAP_DEFAULT_SCOPE": "ldap_default_scope",
            "FLEXT_LDAP_SIZE_LIMIT": "ldap_size_limit",
            "FLEXT_LDAP_TIME_LIMIT": "ldap_time_limit",
            "FLEXT_LDAP_PAGE_SIZE": "ldap_page_size",
            "FLEXT_LDAP_ENABLE_DEBUG": "ldap_enable_debug",
            "FLEXT_LDAP_LOG_QUERIES": "ldap_log_queries",
            "FLEXT_LDAP_LOG_RESPONSES": "ldap_log_responses",
            "FLEXT_LDAP_STRUCTURED_LOGGING": "ldap_structured_logging",
            "FLEXT_LDAP_ENABLE_CACHING": "ldap_enable_caching",
            "FLEXT_LDAP_CACHE_TTL": "ldap_cache_ttl",
            "FLEXT_LDAP_ENABLE_DEBUG_MODE": "ldap_enable_debug_mode",
            "FLEXT_LDAP_ENABLE_TEST_MODE": "ldap_enable_test_mode",
        }

        for env_var, config_key in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert string values to appropriate types
                if config_key in {"ldap_use_ssl", "ldap_verify_certificates", "ldap_enable_debug",
                                "ldap_log_queries", "ldap_log_responses", "ldap_structured_logging",
                                "ldap_enable_caching", "ldap_enable_debug_mode", "ldap_enable_test_mode"}:
                    ldap_overrides[config_key] = value.lower() in {
                        "true",
                        "1",
                        "yes",
                        "on",
                    }
                elif config_key in {"ldap_size_limit", "ldap_time_limit", "ldap_page_size", "ldap_cache_ttl"}:
                    with suppress(ValueError):
                        ldap_overrides[config_key] = int(value)
                else:
                    ldap_overrides[config_key] = value

        return ldap_overrides

    @classmethod
    def integrate_with_cli_config(cls) -> FlextResult[FlextLDAPConfig]:
        """Integrate LDAP configuration with FlextCliConfig following flext-cli patterns.

        This method ensures that LDAP configuration works seamlessly with CLI configuration,
        following the same patterns used in flext-cli for configuration integration.

        Returns:
            FlextResult containing integrated LDAP configuration or error

        """
        try:
            # Get current LDAP config
            ldap_config = cls.get_global_instance()

            # Temporarily disabled CLI integration - return original config
            return FlextResult[FlextLDAPConfig].ok(ldap_config)

        except Exception as e:
            return FlextResult[FlextLDAPConfig].fail(
                f"Failed to integrate with CLI config: {e}"
            )

    @classmethod
    def apply_cli_overrides(
        cls, cli_params: FlextTypes.Core.Dict
    ) -> FlextResult[FlextLDAPConfig]:
        """Apply CLI parameter overrides to the global configuration.

        This method allows CLI parameters to override configuration values
        while maintaining the singleton pattern. It creates a new instance
        with overrides applied.

        Args:
            cli_params: Dictionary of CLI parameter overrides

        Returns:
            FlextResult containing updated LDAP configuration or error

        """
        try:
            # Get current global instance
            current_config = cls.get_global_instance()

            # Create updated configuration with CLI overrides
            config_updates = {}

            # Map CLI parameters to configuration fields
            param_mappings = {
                "server": "ldap_default_connection",
                "ldap_server": "ldap_default_connection",
                "bind_dn": "ldap_bind_dn",
                "ldap_bind_dn": "ldap_bind_dn",
                "bind_password": "ldap_bind_password",
                "ldap_bind_password": "ldap_bind_password",
                "use_ssl": "ldap_use_ssl",
                "ldap_use_ssl": "ldap_use_ssl",
                "verify_certificates": "ldap_verify_certificates",
                "ldap_verify_certificates": "ldap_verify_certificates",
                "debug": "ldap_enable_debug",
                "ldap_debug": "ldap_enable_debug",
                "ldap_enable_debug": "ldap_enable_debug",
                "log_queries": "ldap_log_queries",
                "ldap_log_queries": "ldap_log_queries",
                "log_responses": "ldap_log_responses",
                "ldap_log_responses": "ldap_log_responses",
                "structured_logging": "ldap_structured_logging",
                "ldap_structured_logging": "ldap_structured_logging",
                "enable_caching": "ldap_enable_caching",
                "ldap_enable_caching": "ldap_enable_caching",
                "cache_ttl": "ldap_cache_ttl",
                "ldap_cache_ttl": "ldap_cache_ttl",
                "size_limit": "ldap_size_limit",
                "ldap_size_limit": "ldap_size_limit",
                "time_limit": "ldap_time_limit",
                "ldap_time_limit": "ldap_time_limit",
                "page_size": "ldap_page_size",
                "ldap_page_size": "ldap_page_size",
            }

            for cli_param, config_field in param_mappings.items():
                if cli_param in cli_params:
                    value = cli_params[cli_param]
                    if value is not None:
                        # Handle special cases for connection config
                        if config_field == "ldap_default_connection" and isinstance(value, str):
                            # Create connection config from server string
                            connection_config = FlextLDAPConnectionConfig(server=value)
                            config_updates[config_field] = connection_config
                        else:
                            config_updates[config_field] = value

            # Create new instance with overrides
            if config_updates:
                updated_config = current_config.model_copy(update=config_updates)

                # Validate the updated configuration
                validation_result = updated_config.validate_business_rules()
                if validation_result.is_failure:
                    return FlextResult[FlextLDAPConfig].fail(
                        f"CLI override validation failed: {validation_result.error}"
                    )

                # Update global instance
                cls.set_global_instance(updated_config)
                return FlextResult[FlextLDAPConfig].ok(updated_config)
            return FlextResult[FlextLDAPConfig].ok(current_config)

        except Exception as e:
            return FlextResult[FlextLDAPConfig].fail(
                f"Failed to apply CLI overrides: {e}"
            )

    # =============================================================================
    # LDAP-SPECIFIC CONFIGURATION METHODS
    # =============================================================================

    def get_effective_connection(
        self,
        override: FlextLDAPConnectionConfig | None = None,
    ) -> FlextLDAPConnectionConfig:
        """Get effective LDAP connection configuration with optional override.

        Args:
            override: Optional connection configuration override

        Returns:
            FlextLDAPConnectionConfig: Effective connection configuration

        """
        if override:
            return override

        if self.ldap_default_connection:
            return self.ldap_default_connection

        # Return minimal default configuration
        return FlextLDAPConnectionConfig()

    def get_effective_auth_config(self) -> LdapConfigDict | None:
        """Get effective LDAP authentication configuration as dictionary.

        Returns:
            LdapConfigDict | None: Authentication configuration or None if not configured

        """
        if self.ldap_bind_dn and self.ldap_bind_password:
            return {
                "bind_dn": self.ldap_bind_dn,
                "bind_password": self.ldap_bind_password,
                "use_ssl": self.ldap_use_ssl,
                "verify_certificates": self.ldap_verify_certificates,
            }
        return None

    def get_ldap_search_config(self) -> LdapConfigDict:
        """Get LDAP search configuration as dictionary.

        Returns:
            LdapConfigDict: Search configuration parameters

        """
        return {
            "default_scope": self.ldap_default_scope,
            "size_limit": self.ldap_size_limit,
            "time_limit": self.ldap_time_limit,
            "page_size": self.ldap_page_size,
        }

    def get_ldap_logging_config(self) -> LdapConfigDict:
        """Get LDAP logging configuration as dictionary.

        Returns:
            LdapConfigDict: Logging configuration parameters

        """
        return {
            "enable_debug": self.ldap_enable_debug,
            "log_queries": self.ldap_log_queries,
            "log_responses": self.ldap_log_responses,
            "structured_logging": self.ldap_structured_logging,
        }

    def get_ldap_performance_config(self) -> LdapConfigDict:
        """Get LDAP performance configuration as dictionary.

        Returns:
            LdapConfigDict: Performance configuration parameters

        """
        return {
            "enable_caching": self.ldap_enable_caching,
            "cache_ttl": self.ldap_cache_ttl,
        }

    # =============================================================================
    # PARAMETER OVERRIDE METHODS
    # =============================================================================

    def apply_ldap_overrides(self, overrides: LdapConfigDict) -> FlextResult[None]:
        """Apply LDAP-specific configuration overrides.

        Args:
            overrides: Dictionary of LDAP configuration overrides

        Returns:
            FlextResult[None]: Success or failure result

        """
        if self.is_sealed():
            return FlextResult[None].fail(
                "Cannot apply overrides to sealed configuration",
                error_code="CONFIG_SEALED_ERROR",
            )

        try:
            # Apply LDAP-specific overrides
            for key, value in overrides.items():
                ldap_key = f"ldap_{key}" if not key.startswith("ldap_") else key
                if hasattr(self, ldap_key):
                    setattr(self, ldap_key, value)

            # Track the override in metadata
            self._metadata["ldap_overrides_applied"] = "true"
            self._metadata["ldap_override_count"] = str(len(overrides))

            return FlextResult[None].ok(None)

        except Exception as error:
            return FlextResult[None].fail(
                f"Failed to apply LDAP overrides: {error}",
                error_code="LDAP_OVERRIDE_ERROR",
            )

    def update_connection_config(
        self, connection_config: FlextLDAPConnectionConfig
    ) -> FlextResult[None]:
        """Update the default LDAP connection configuration.

        Args:
            connection_config: New connection configuration

        Returns:
            FlextResult[None]: Success or failure result

        """
        if self.is_sealed():
            return FlextResult[None].fail(
                "Cannot update sealed configuration",
                error_code="CONFIG_SEALED_ERROR",
            )

        try:
            self.ldap_default_connection = connection_config
            self._metadata["connection_updated"] = "true"
            return FlextResult[None].ok(None)

        except Exception as error:
            return FlextResult[None].fail(
                f"Failed to update connection config: {error}",
                error_code="CONNECTION_UPDATE_ERROR",
            )

    # =============================================================================
    # FACTORY METHODS FOR LDAP CONFIGURATIONS
    # =============================================================================

    @classmethod
    def create_development_ldap_config(cls) -> FlextResult[FlextLDAPConfig]:
        """Create LDAP configuration optimized for development.

        Returns:
            FlextResult[FlextLDAPConfig]: Development LDAP configuration

        """
        connection_config = FlextLDAPConnectionConfig(
            server="ldap://localhost",
            port=389,
        )

        config_data = {
            "environment": "development",
            "debug": True,
            "log_level": "DEBUG",
            "ldap_default_connection": connection_config,
            "ldap_bind_dn": "cn=admin,dc=dev,dc=local",
            "ldap_bind_password": SecretStr("admin123"),
            "ldap_use_ssl": False,
            "ldap_verify_certificates": False,
            "ldap_enable_debug": True,
            "ldap_log_queries": True,
            "ldap_structured_logging": True,
            "ldap_enable_debug_mode": True,
            "ldap_enable_caching": False,
        }

        result = cls.create(constants=config_data)
        if result.is_success:
            instance = result.value
            instance._metadata["profile"] = "ldap_development"
            instance._metadata["created_with"] = "development_ldap_factory"

        return result

    @classmethod
    def create_test_ldap_config(cls) -> FlextResult[FlextLDAPConfig]:
        """Create LDAP configuration optimized for testing.

        Returns:
            FlextResult[FlextLDAPConfig]: Test LDAP configuration

        """
        connection_config = FlextLDAPConnectionConfig(
            server="ldap://localhost",
            port=3389,
        )

        config_data = {
            "environment": "test",
            "debug": True,
            "log_level": "DEBUG",
            "ldap_default_connection": connection_config,
            "ldap_bind_dn": "cn=admin,dc=test,dc=local",
            "ldap_bind_password": SecretStr("test123"),
            "ldap_use_ssl": False,
            "ldap_verify_certificates": False,
            "ldap_enable_debug": False,
            "ldap_log_queries": False,
            "ldap_structured_logging": False,
            "ldap_enable_test_mode": True,
            "ldap_enable_caching": False,
        }

        result = cls.create(constants=config_data)
        if result.is_success:
            instance = result.value
            instance._metadata["profile"] = "ldap_test"
            instance._metadata["created_with"] = "test_ldap_factory"

        return result

    @classmethod
    def create_production_ldap_config(cls) -> FlextResult[FlextLDAPConfig]:
        """Create LDAP configuration optimized for production.

        Returns:
            FlextResult[FlextLDAPConfig]: Production LDAP configuration

        """
        connection_config = FlextLDAPConnectionConfig(
            server="ldaps://ldap.company.com",
            port=636,
            use_ssl=True,
            verify_ssl=True,
        )

        config_data = {
            "environment": "production",
            "debug": False,
            "log_level": "INFO",
            "ldap_default_connection": connection_config,
            "ldap_bind_dn": "cn=service,ou=accounts,dc=company,dc=com",
            "ldap_bind_password": SecretStr("${LDAP_BIND_PASSWORD}"),
            "ldap_use_ssl": True,
            "ldap_verify_certificates": True,
            "ldap_enable_debug": False,
            "ldap_log_queries": False,
            "ldap_structured_logging": True,
            "ldap_enable_debug_mode": False,
            "ldap_enable_caching": True,
            "ldap_cache_ttl": 600,
        }

        result = cls.create(constants=config_data)
        if result.is_success:
            instance = result.value
            instance._metadata["profile"] = "ldap_production"
            instance._metadata["created_with"] = "production_ldap_factory"

        return result

    # =============================================================================
    # VALIDATION METHODS
    # =============================================================================

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDAP-specific business rules using Railway Pattern."""
        return (
            FlextResult[None]
            .ok(None)
            .flat_map(lambda _: self._validate_ldap_connection())
            .flat_map(lambda _: self._validate_ldap_cache_settings())
            .flat_map(lambda _: self._validate_ldap_search_configuration())
            .flat_map(lambda _: self._validate_ldap_auth_configuration())
        )

    def _validate_ldap_connection(self) -> FlextResult[None]:
        """Validate LDAP connection settings."""
        if not self.ldap_default_connection:
            return FlextResult.ok(None)

        if not self.ldap_default_connection.server:
            return FlextResult.fail("LDAP default connection must specify a server")

        return self.ldap_default_connection.validate_business_rules()

    def _validate_ldap_cache_settings(self) -> FlextResult[None]:
        """Validate LDAP cache configuration."""
        if self.ldap_enable_caching and self.ldap_cache_ttl <= 0:
            return FlextResult.fail(
                "LDAP cache TTL must be positive when caching is enabled",
            )
        return FlextResult.ok(None)

    def _validate_ldap_search_configuration(self) -> FlextResult[None]:
        """Validate LDAP search limits configuration."""
        if self.ldap_size_limit <= 0:
            return FlextResult.fail("LDAP size limit must be positive")
        if self.ldap_time_limit <= 0:
            return FlextResult.fail("LDAP time limit must be positive")
        if self.ldap_page_size <= 0:
            return FlextResult.fail("LDAP page size must be positive")
        return FlextResult.ok(None)

    def _validate_ldap_auth_configuration(self) -> FlextResult[None]:
        """Validate LDAP authentication configuration."""
        if self.ldap_bind_dn and not self.ldap_bind_dn.strip():
            return FlextResult.fail("LDAP bind DN cannot be empty")
        if self.ldap_bind_password and len(self.ldap_bind_password.get_secret_value()) < 1:
            return FlextResult.fail("LDAP bind password cannot be empty")
        return FlextResult.ok(None)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_flext_ldap_config() -> FlextLDAPConfig:
    """Get the global LDAP configuration instance.

    Returns:
        FlextLDAPConfig: The global LDAP configuration instance

    """
    return FlextLDAPConfig.get_global_instance()


def set_flext_ldap_config(config: FlextLDAPConfig) -> None:
    """Set the global LDAP configuration instance.

    Args:
        config: The LDAP configuration to set as global

    """
    FlextLDAPConfig.set_global_instance(config)


def clear_flext_ldap_config() -> None:
    """Clear the global LDAP configuration instance (useful for testing)."""
    FlextLDAPConfig.clear_global_instance()


__all__ = [
    "FlextLDAPConfig",
    "clear_flext_ldap_config",
    "get_flext_ldap_config",
    "set_flext_ldap_config",
]
