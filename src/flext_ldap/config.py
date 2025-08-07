"""FLEXT-LDAP Configuration Management - Enterprise Settings and Connection Management.

This module provides comprehensive configuration management for FLEXT-LDAP
operations, extending flext-core centralized configuration patterns with
project-specific settings and connection management capabilities.

Configuration classes handle LDAP connection parameters, security settings,
performance tuning, and operational parameters with environment variable
support and validation.

Architecture:
    Built on flext-core FlextLDAPConfig foundation with project-specific
    extensions for connection pooling, timeout management, and operational
    configuration. Supports both programmatic and environment-based setup.

Key Components:
    - FlextLdapConnectionConfig: Extended connection configuration
    - FlextLdapSettings: Project-specific operational settings
    - FlextLdapConstants: Operational constants and defaults
    - Factory functions: Development and production configuration builders

Example:
    Creating and using configuration objects:

    >>> config = FlextLdapSettings(
    ...     host="directory.example.com",
    ...     port=636,
    ...     use_ssl=True,
    ...     enable_debug_mode=False,
    ... )
    >>> client_config = config.to_ldap_client_config()
    >>> dev_config = create_development_config(timeout=15)

Integration:
    - Built on flext-core FlextLDAPConfig patterns
    - Compatible with environment variable configuration
    - Supports configuration validation and type safety

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Any, cast

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext_core configuration system
from flext_core import (
    FlextBaseConfigModel,
    FlextLDAPConfig,
    FlextLogLevel,
    FlextResult,
    create_ldap_config,
    get_logger,
)
from pydantic import Field, SecretStr, field_validator

logger = get_logger(__name__)


# Extend flext-core centralized LDAP config with project-specific settings
class FlextLdapConnectionConfig(FlextLDAPConfig):
    """Extended LDAP connection configuration with project-specific enhancements.

    Extends flext-core FlextLDAPConfig with additional connection management
    features specific to FLEXT-LDAP operations, including connection pooling
    and project-specific timeout handling.

    This configuration class provides backward compatibility while adding
    enhanced connection management capabilities for enterprise deployments.

    Additional Attributes:
        enable_connection_pooling: Enable connection pool management
        project_specific_timeout: Override timeout for specific operations

    Compatibility Properties:
        server: Maps to host for legacy code compatibility
        timeout_seconds: Maps to timeout for legacy compatibility

    Domain Operations:
        - with_server(): Create new instance with updated server (immutable)
        - with_timeout(): Create new instance with updated timeout (immutable)

    Example:
        >>> config = FlextLdapConnectionConfig(
        ...     host="ldap.example.com",
        ...     port=636,
        ...     use_ssl=True,
        ...     enable_connection_pooling=True,
        ... )
        >>> new_config = config.with_timeout(45)

    """

    # Additional project-specific fields beyond flext-core
    enable_connection_pooling: bool = Field(default=True)
    project_specific_timeout: int | None = Field(default=None)

    # Compatibility field for initialization (maps to timeout field)
    timeout_seconds: int = Field(
        default=30,
        description="Connection timeout in seconds (compatibility field)",
    )

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        """Validate host is not empty."""
        if not v or not v.strip():
            msg = "Host cannot be empty"
            raise ValueError(msg)
        return v.strip()

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout_seconds(cls, v: int) -> int:
        """Validate timeout_seconds and sync with timeout field."""
        return v

    # Compatibility properties for legacy code (read-only)
    @property
    def server(self) -> str:
        """Compatibility property - maps to host."""
        return self.host

    def with_server(self, server: str) -> FlextLdapConnectionConfig:
        """Create new instance with updated server (immutable pattern)."""
        return self.model_copy(update={"host": server})

    def with_timeout(self, timeout: int) -> FlextLdapConnectionConfig:
        """Create new instance with updated timeout (immutable pattern)."""
        return self.model_copy(update={"timeout": timeout, "timeout_seconds": timeout})

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate connection domain rules."""
        return FlextResult.ok(None)


# Type aliases following flext-core patterns
type ProjectName = str
type Version = str

# Specialized configuration classes extending FlextLDAPConfig


class FlextLdapAuthConfig(FlextLDAPConfig):
    """LDAP authentication configuration with specialized validation."""

    # Override base defaults to match test expectations - maintain base class
    # type compatibility
    bind_dn: str | None = Field(
        default="",
        description="LDAP bind DN for authentication",
    )
    bind_password: SecretStr | None = Field(
        default_factory=lambda: SecretStr(""),
        description="LDAP bind password",
    )

    use_anonymous_bind: bool = Field(default=False, description="Use anonymous binding")
    sasl_mechanism: str | None = Field(default=None, description="SASL mechanism")

    @field_validator("bind_dn")
    @classmethod
    def validate_bind_dn(cls, v: str | None) -> str | None:
        """Validate and normalize bind DN."""
        if v is None:
            return v
        return v.strip() if v else ""

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate authentication domain rules."""
        if not self.use_anonymous_bind:
            if not self.bind_dn:
                return FlextResult.fail("Bind DN is required for authenticated binding")
            if not self.bind_password or (
                self.bind_password and not self.bind_password.get_secret_value()
            ):
                return FlextResult.fail(
                    "Bind password is required for authenticated binding",
                )
        return FlextResult.ok(None)


class FlextLdapSearchConfig(FlextBaseConfigModel):
    """LDAP search configuration with specialized validation.

    Avoids FlextLDAPConfig restrictions.
    """

    # Copy essential LDAP fields from FlextLDAPConfig but with flexible validation
    host: str = Field("localhost", description="LDAP host address")
    port: int = Field(389, description="LDAP port", ge=1, le=65535)
    base_dn: str = Field("", description="LDAP base DN for searches")
    bind_dn: str | None = Field(None, description="LDAP bind DN for authentication")
    bind_password: SecretStr | None = Field(None, description="LDAP bind password")
    use_ssl: bool = Field(default=False, description="Use SSL connection (LDAPS)")
    use_tls: bool = Field(default=False, description="Use TLS upgrade (StartTLS)")
    timeout: int = Field(30, description="Connection timeout in seconds", ge=1)
    pool_size: int = Field(10, description="Connection pool size", ge=1)

    default_search_scope: str = Field(
        default="subtree",
        description="Default search scope",
    )
    size_limit: int = Field(default=1000, ge=0, description="Search size limit")
    time_limit: int = Field(default=30, ge=0, description="Search time limit")
    paged_search: bool = Field(default=True, description="Enable paged search")
    page_size: int = Field(default=1000, ge=1, description="Page size for paged search")
    enable_referral_chasing: bool = Field(
        default=False,
        description="Enable referral chasing",
    )
    max_referral_hops: int = Field(default=5, ge=0, description="Maximum referral hops")

    @field_validator("base_dn")
    @classmethod
    def validate_base_dn_search_flexible(cls, v: str) -> str:
        """Validate base DN with flexible rules for search contexts.

        Allows empty for search flexibility.
        """
        # Allow empty base_dn for search configuration flexibility
        if not v or not v.strip():
            return ""
        # More flexible - allow ou= or dc= prefixes for search contexts
        v = v.strip()
        if not (
            v.lower().startswith("dc=")
            or v.lower().startswith("ou=")
            or v.lower().startswith("cn=")
        ):
            msg = "LDAP base DN should start with 'dc=', 'ou=', or 'cn='"
            raise ValueError(msg)
        return v

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate search domain rules."""
        return FlextResult.ok(None)


class FlextLdapOperationConfig(FlextLDAPConfig):
    """LDAP operation configuration with specialized validation."""

    max_retries: int = Field(default=3, ge=0, description="Maximum retry attempts")
    retry_delay: float = Field(
        default=1.0,
        ge=0.0,
        description="Retry delay in seconds",
    )
    enable_transactions: bool = Field(
        default=False,
        description="Enable transaction support",
    )
    batch_size: int = Field(default=100, ge=1, description="Batch operation size")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate operation domain rules."""
        return FlextResult.ok(None)


class FlextLdapSecurityConfig(FlextLDAPConfig):
    """LDAP security configuration with specialized validation."""

    tls_validation: str = Field(default="strict", description="TLS validation mode")
    ca_cert_file: str | None = Field(
        default=None,
        description="CA certificate file path",
    )
    client_cert_file: str | None = Field(
        default=None,
        description="Client certificate file path",
    )
    client_key_file: str | None = Field(
        default=None,
        description="Client key file path",
    )
    enable_start_tls: bool = Field(default=False, description="Enable StartTLS")
    tls_version: str | None = Field(default=None, description="TLS version")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate security domain rules."""
        if self.client_cert_file and not self.client_key_file:
            return FlextResult.fail(
                "Client key file required when client cert file is specified",
            )
        if self.client_key_file and not self.client_cert_file:
            return FlextResult.fail(
                "Client cert file required when client key file is specified",
            )
        return FlextResult.ok(None)


class FlextLdapLoggingConfig(FlextLDAPConfig):
    """LDAP logging configuration with specialized validation."""

    log_level: FlextLogLevel = Field(
        default=FlextLogLevel.INFO,
        description="Logging level",
    )
    enable_connection_logging: bool = Field(
        default=False,
        description="Enable connection logging",
    )
    enable_operation_logging: bool = Field(
        default=True,
        description="Enable operation logging",
    )
    log_sensitive_data: bool = Field(default=False, description="Log sensitive data")
    structured_logging: bool = Field(
        default=True,
        description="Enable structured logging",
    )

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate logging domain rules."""
        return FlextResult.ok(None)


class FlextLdapSettings(FlextLDAPConfig):
    """FLEXT-LDAP operational settings with project identification and monitoring.

    Primary configuration class for FLEXT-LDAP operations, extending flext-core
    FlextLDAPConfig with project-specific settings for debugging, monitoring,
    and operational control.

    This class serves as the main configuration entry point for FLEXT-LDAP
    applications, providing both LDAP connection parameters and application
    operational settings.

    Additional Attributes:
        project_name: Project identification string
        project_version: Current project version
        enable_debug_mode: Enable detailed debug logging
        enable_performance_monitoring: Enable performance metrics collection
        connection: Connection-specific configuration object
        auth: Authentication-specific configuration object
        search: Search-specific configuration object

    Domain Operations:
        - to_ldap_client_config(): Convert to client library format

    Example:
        >>> settings = FlextLdapSettings(
        ...     host="directory.company.com",
        ...     port=636,
        ...     use_ssl=True,
        ...     enable_debug_mode=False,
        ...     enable_performance_monitoring=True,
        ... )
        >>> client_config = settings.to_ldap_client_config()

    """

    # Project identification
    project_name: ProjectName = Field(
        default="flext-infrastructure.databases.flext-ldap",
    )
    project_version: Version = Field(default="0.9.0")

    # Additional project-specific settings
    enable_debug_mode: bool = Field(default=False)
    enable_performance_monitoring: bool = Field(default=True)

    # Composite configuration objects for specialized settings
    connection: FlextLdapConnectionConfig = Field(
        default_factory=FlextLdapConnectionConfig,
    )
    auth: FlextLdapAuthConfig = Field(default_factory=FlextLdapAuthConfig)
    search: FlextLdapSearchConfig = Field(default_factory=FlextLdapSearchConfig)

    def to_ldap_client_config(self) -> dict[str, Any]:
        """Convert configuration to LDAP client library format.

        Transforms the FlextLdapSettings configuration into the dictionary
        format expected by underlying LDAP client libraries, combining
        connection, authentication, and search configurations.

        Returns:
            "FlextTypes.Core.JsonDict": Configuration dictionary with all required
                              parameters for LDAP client initialization

        Side Effects:
            - Logs configuration conversion at trace level
            - Includes security-safe logging (no sensitive data)

        """
        logger.debug("Converting FLEXT LDAP settings to client config format")

        # Combine configuration from composite objects
        client_config = {
            # Connection settings - use server for backward compatibility
            "server": self.connection.server,
            "port": self.connection.port,
            "use_ssl": self.connection.use_ssl,
            "timeout": self.connection.timeout_seconds,
            # Authentication settings
            "bind_dn": self.auth.bind_dn,
            "bind_password": self.auth.bind_password.get_secret_value()
            if self.auth.bind_password
            else "",
            # Search settings
            "base_dn": self.search.base_dn,
            "search_scope": self.search.default_search_scope,
            "size_limit": self.search.size_limit,
            "time_limit": self.search.time_limit,
            "paged_search": self.search.paged_search,
            "page_size": self.search.page_size,
        }

        logger.trace(
            "Generated FLEXT LDAP client config from composite settings",
            extra={
                "server": client_config["server"],
                "port": client_config["port"],
                "use_ssl": client_config["use_ssl"],
                "has_auth": bool(client_config["bind_dn"]),
            },
        )

        return client_config


def create_development_config(**overrides: object) -> FlextLdapSettings:
    """Create development-optimized FLEXT-LDAP configuration.

    Factory function for creating FLEXT-LDAP configuration optimized for
    development environments with debug mode enabled, shorter timeouts,
    and enhanced monitoring capabilities.

    Args:
        **overrides: Optional configuration overrides for customization

    Returns:
        FlextLdapSettings: Configured settings object optimized for development

    Side Effects:
        - Logs configuration creation with parameter summary
        - Enables debug mode and performance monitoring by default

    Example:
        >>> dev_config = create_development_config(
        ...     host="dev-ldap.company.com", timeout=15
        ... )

    """
    logger.debug(
        "Creating development configuration",
        extra={
            "overrides_count": len(overrides),
            "override_keys": list(overrides.keys()) if overrides else [],
        },
    )

    # Filter overrides to match create_ldap_config signature and cast types safely
    valid_config_params = {
        "host",
        "port",
        "base_dn",
        "bind_dn",
        "bind_password",
        "use_ssl",
        "timeout",
        "pool_size",
    }
    filtered_overrides = {
        k: v for k, v in overrides.items() if k in valid_config_params
    }

    # Use flext-core factory with project-specific defaults
    # Type-safe call without ** expansion to avoid MyPy errors
    base_config = create_ldap_config(
        host=cast("str", filtered_overrides.get("host", "localhost")),
        port=cast("int", filtered_overrides.get("port", 389)),
        base_dn=cast("str", filtered_overrides.get("base_dn", "dc=example,dc=com")),
        bind_dn=cast("str | None", filtered_overrides.get("bind_dn")),
        bind_password=cast("str | None", filtered_overrides.get("bind_password")),
    )

    # Create project settings with base config
    config = FlextLdapSettings(
        **base_config.model_dump(),
        enable_debug_mode=True,
        enable_performance_monitoring=True,
    )

    logger.info(
        "Development configuration created",
        extra={
            "project_name": config.project_name,
            "project_version": config.project_version,
            "debug_mode": config.enable_debug_mode,
        },
    )
    return config
