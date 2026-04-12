"""Configuration management for LDAP operations.

This module defines configuration settings using Pydantic v2 models with validation.
Provides singleton pattern configuration classes for LDAP operations with environment
variable support and thread-safe instance management.

Modules: FlextLdapSettings
Scope: LDAP connection configuration, environment variable loading
Pattern: Singleton with dependency injection support, Pydantic v2 BaseSettings

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from pydantic import Field
from pydantic_settings import SettingsConfigDict

from flext_core import FlextSettings
from flext_ldap import c, t


@FlextSettings.auto_register("ldap")
class FlextLdapSettings(FlextSettings):
    """LDAP runtime settings."""

    model_config: ClassVar[SettingsConfigDict] = SettingsConfigDict(
        env_prefix="FLEXT_LDAP_", extra="ignore"
    )

    host: Annotated[str, Field(default=c.LOCALHOST, description="LDAP server host")]
    port: Annotated[
        t.PortNumber,
        Field(default=c.Ldap.ConnectionDefaults.PORT, description="LDAP server port"),
    ]
    use_ssl: Annotated[
        bool,
        Field(
            default=c.Ldap.ConnectionDefaults.DEFAULT_USE_SSL,
            description="Enable LDAPS",
        ),
    ]
    use_tls: Annotated[
        bool,
        Field(
            default=c.Ldap.ConnectionDefaults.DEFAULT_USE_TLS,
            description="Enable STARTTLS",
        ),
    ]
    bind_dn: Annotated[
        str,
        Field(
            default=c.Ldap.ConnectionDefaults.DEFAULT_BIND_DN,
            description="LDAP bind distinguished name",
        ),
    ]
    bind_password: Annotated[
        str,
        Field(
            default=c.Ldap.ConnectionDefaults.DEFAULT_BIND_PASSWORD,
            description="LDAP bind password",
        ),
    ]
    timeout: Annotated[
        t.PositiveInt,
        Field(
            default=c.Ldap.ConnectionDefaults.TIMEOUT,
            description="LDAP operation timeout in seconds",
        ),
    ]
    auto_bind: Annotated[
        bool,
        Field(
            default=c.Ldap.ConnectionDefaults.AUTO_BIND,
            description="Auto-bind connection after connect",
        ),
    ]
    auto_range: Annotated[
        bool,
        Field(
            default=c.Ldap.ConnectionDefaults.AUTO_RANGE,
            description="Enable LDAP range retrieval",
        ),
    ]


__all__ = ["FlextLdapSettings"]
