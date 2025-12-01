"""Configuration management for LDAP operations.

This module defines configuration settings using Pydantic v2 models with validation.
Provides singleton pattern configuration classes for LDAP operations with environment
variable support and thread-safe instance management.

Modules: FlextLdapConfig
Scope: LDAP connection configuration, environment variable loading
Pattern: Singleton with dependency injection support, Pydantic v2 BaseSettings

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextConfig
from pydantic import Field
from pydantic_settings import SettingsConfigDict

from flext_ldap.constants import FlextLdapConstants


@FlextConfig.auto_register("ldap")
class FlextLdapConfig(FlextConfig):
    """Pydantic v2 configuration for LDAP operations.

    **ARCHITECTURAL PATTERN**: Zero-Boilerplate Configuration

    This class provides:
    - Singleton pattern (thread-safe)
    - Environment variable loading from FLEXT_LDAP_* variables
    - .env file loading (production/development)
    - Automatic type conversion and validation via Pydantic v2

    **Environment Variables** (via .env or environment):
        FLEXT_LDAP_HOST=localhost
        FLEXT_LDAP_PORT=389
        FLEXT_LDAP_USE_SSL=false
        FLEXT_LDAP_USE_TLS=false
        FLEXT_LDAP_BIND_DN=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
        FLEXT_LDAP_BIND_PASSWORD=secret
        FLEXT_LDAP_BASE_DN=dc=example,dc=com
        FLEXT_LDAP_TIMEOUT=30
        FLEXT_LDAP_AUTO_BIND=true
        FLEXT_LDAP_AUTO_RANGE=true
        FLEXT_LDAP_POOL_SIZE=5
        FLEXT_LDAP_POOL_LIFETIME=3600
        FLEXT_LDAP_MAX_RESULTS=1000
        FLEXT_LDAP_CHUNK_SIZE=100

    **Usage**:
        config = FlextLdapConfig.get_instance()
        print(config.host, config.port, config.bind_dn)
    """

    # Use FlextConfig.resolve_env_file() to ensure all FLEXT configs use same .env
    model_config = SettingsConfigDict(
        env_prefix="FLEXT_LDAP_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="forbid",
        case_sensitive=False,
        use_enum_values=True,
    )

    # Connection Configuration
    host: str = Field(
        default="localhost",
        description="LDAP server hostname",
    )

    port: int = Field(
        default=FlextLdapConstants.ConnectionDefaults.PORT,
        ge=1,
        le=65535,
        description="LDAP server port",
    )

    use_ssl: bool = Field(
        default=False,
        description="Use SSL/TLS for connection",
    )

    use_tls: bool = Field(
        default=False,
        description="Use STARTTLS for connection",
    )

    bind_dn: str | None = Field(
        default=None,
        description="Bind DN for authentication",
    )

    bind_password: str | None = Field(
        default=None,
        description="Bind password for authentication",
    )

    timeout: int = Field(
        default=FlextLdapConstants.ConnectionDefaults.TIMEOUT,
        ge=1,
        description="Connection timeout in seconds",
    )

    auto_bind: bool = Field(
        default=FlextLdapConstants.ConnectionDefaults.AUTO_BIND,
        description="Automatically bind after connection",
    )

    auto_range: bool = Field(
        default=FlextLdapConstants.ConnectionDefaults.AUTO_RANGE,
        description="Automatically handle range queries",
    )

    pool_size: int = Field(
        default=FlextLdapConstants.ConnectionDefaults.POOL_SIZE,
        ge=1,
        description="Connection pool size",
    )

    pool_lifetime: int = Field(
        default=FlextLdapConstants.ConnectionDefaults.POOL_LIFETIME,
        ge=1,
        description="Connection pool lifetime in seconds",
    )

    # Processing Configuration
    max_results: int = Field(
        default=1000,
        ge=1,
        description="Maximum number of search results",
    )

    chunk_size: int = Field(
        default=100,
        ge=1,
        description="Chunk size for batch operations",
    )

    base_dn: str | None = Field(
        default=None,
        description="Base DN for LDAP operations",
    )


__all__ = ["FlextLdapConfig"]
