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

from pydantic_settings import BaseSettings

from flext_core import FlextSettingsBase, u
from flext_ldap import c, t
from flext_ldif import m


class FlextLdapSettings(FlextSettingsBase, BaseSettings):
    """LDAP runtime settings."""

    model_config: ClassVar[m.SettingsConfigDict] = m.SettingsConfigDict(
        env_prefix="FLEXT_LDAP_", extra="ignore"
    )

    host: Annotated[str, u.Field(description="LDAP server host")] = c.LOCALHOST
    port: Annotated[t.PortNumber, u.Field(description="LDAP server port")] = c.Ldap.PORT
    use_ssl: Annotated[
        bool,
        u.Field(
            description="Enable LDAPS",
        ),
    ] = c.Ldap.DEFAULT_USE_SSL
    use_tls: Annotated[
        bool,
        u.Field(
            description="Enable STARTTLS",
        ),
    ] = c.Ldap.DEFAULT_USE_TLS
    bind_dn: Annotated[
        str,
        u.Field(
            description="LDAP bind distinguished name",
        ),
    ] = c.Ldap.DEFAULT_BIND_DN
    bind_password: Annotated[
        str,
        u.Field(
            description="LDAP bind password",
        ),
    ] = c.Ldap.DEFAULT_BIND_PASSWORD
    timeout: Annotated[
        t.PositiveInt,
        u.Field(
            description="LDAP operation timeout in seconds",
        ),
    ] = c.Ldap.TIMEOUT
    auto_bind: Annotated[
        bool,
        u.Field(
            description="Auto-bind connection after connect",
        ),
    ] = c.Ldap.AUTO_BIND
    auto_range: Annotated[
        bool,
        u.Field(
            description="Enable LDAP range retrieval",
        ),
    ] = c.Ldap.AUTO_RANGE


__all__: list[str] = ["FlextLdapSettings"]
