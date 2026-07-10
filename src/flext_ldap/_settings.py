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

from pydantic import BaseModel, Field
from pydantic_settings import SettingsConfigDict

from flext_ldif import FlextLdifSettings


class FlextLdapSettings(FlextLdifSettings):
    """LDAP runtime settings."""

    model_config: ClassVar[SettingsConfigDict] = SettingsConfigDict(
        env_prefix="FLEXT_LDAP_",
        extra="ignore",
    )

    class LdapSettings(BaseModel):
        """Namespaced LDAP runtime settings."""

        host: Annotated[str, Field(description="LDAP server host")] = "localhost"
        port: Annotated[
            int,
            Field(ge=1, le=65535, description="LDAP server port"),
        ] = 389
        use_ssl: Annotated[bool, Field(description="Enable LDAPS")] = False
        use_tls: Annotated[bool, Field(description="Enable STARTTLS")] = False
        bind_dn: Annotated[
            str,
            Field(description="LDAP bind distinguished name"),
        ] = ""
        bind_password: Annotated[str, Field(description="LDAP bind password")] = ""
        timeout: Annotated[
            int,
            Field(ge=1, description="LDAP operation timeout in seconds"),
        ] = 30
        auto_bind: Annotated[
            bool,
            Field(description="Auto-bind connection after connect"),
        ] = True
        auto_range: Annotated[
            bool,
            Field(description="Enable LDAP range retrieval"),
        ] = True

    Ldap: LdapSettings = Field(
        default_factory=LdapSettings,
        description="Namespaced LDAP settings branch.",
    )


settings: FlextLdapSettings = FlextLdapSettings.fetch_global()
"""Pre-instantiated project settings singleton — ``from flext_ldap import settings``."""

__all__: list[str] = ["FlextLdapSettings", "settings"]
