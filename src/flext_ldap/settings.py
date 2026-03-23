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

from typing import Annotated

from flext_core import FlextSettings
from pydantic import Field

from flext_ldap import c


class FlextLdapSettings(FlextSettings):
    """LDAP runtime settings."""

    host: Annotated[
        str,
        Field(
            default=c.LOCALHOST,
            description="LDAP server host",
        ),
    ]
    port: Annotated[
        int,
        Field(
            default=c.Ldap.ConnectionDefaults.PORT,
            ge=1,
            le=65535,
            description="LDAP server port",
        ),
    ]
    use_ssl: Annotated[bool, Field(default=False, description="Enable LDAPS")]
    use_tls: Annotated[bool, Field(default=False, description="Enable STARTTLS")]
    bind_dn: Annotated[
        str,
        Field(default="", description="LDAP bind distinguished name"),
    ]
    bind_password: Annotated[str, Field(default="", description="LDAP bind password")]
    timeout: Annotated[
        int,
        Field(
            default=c.Ldap.ConnectionDefaults.TIMEOUT,
            ge=1,
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
