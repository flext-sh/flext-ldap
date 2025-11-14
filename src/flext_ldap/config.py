"""Configuration management for LDAP operations.

This module defines configuration settings using Pydantic models with validation.
Reuses patterns from flext-ldif for consistency.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextConfig
from pydantic import Field

from flext_ldap.constants import FlextLdapConstants


class FlextLdapConfig(FlextConfig):
    """Pydantic 2 Settings class for flext-ldap using FlextConfig.

    Leverages FlextConfig's features:
    - Centralized configuration management
    - Enhanced singleton pattern
    - Integrated environment variable handling
    - Validation and type safety
    - Automatic dependency injection integration
    """

    # LDAP Connection Configuration
    ldap_host: str = Field(
        default="localhost",
        description="LDAP server hostname or IP address",
    )

    ldap_port: int = Field(
        default=FlextLdapConstants.ConnectionDefaults.PORT,
        ge=1,
        le=65535,
        description="LDAP server port",
    )

    ldap_use_ssl: bool = Field(
        default=False,
        description="Use SSL/TLS for LDAP connection",
    )

    ldap_use_tls: bool = Field(
        default=False,
        description="Use STARTTLS for LDAP connection",
    )

    ldap_bind_dn: str | None = Field(
        default=None,
        description="LDAP bind DN for authentication",
    )

    ldap_bind_password: str | None = Field(
        default=None,
        description="LDAP bind password for authentication",
    )

    ldap_timeout: int = Field(
        default=FlextLdapConstants.ConnectionDefaults.TIMEOUT,
        ge=1,
        description="LDAP connection timeout in seconds",
    )

    ldap_auto_bind: bool = Field(
        default=FlextLdapConstants.ConnectionDefaults.AUTO_BIND,
        description="Automatically bind after connection",
    )

    ldap_auto_range: bool = Field(
        default=FlextLdapConstants.ConnectionDefaults.AUTO_RANGE,
        description="Automatically handle range queries",
    )

    ldap_pool_size: int = Field(
        default=FlextLdapConstants.ConnectionDefaults.POOL_SIZE,
        ge=1,
        description="Connection pool size",
    )

    ldap_pool_lifetime: int = Field(
        default=FlextLdapConstants.ConnectionDefaults.POOL_LIFETIME,
        ge=1,
        description="Connection pool lifetime in seconds",
    )

    # Processing Configuration (reuses flext-ldif patterns)
    ldap_max_results: int = Field(
        default=1000,
        ge=1,
        description="Maximum number of search results",
    )

    ldap_chunk_size: int = Field(
        default=100,
        ge=1,
        description="Chunk size for batch operations",
    )
