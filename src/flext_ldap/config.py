"""Configuration management for LDAP operations.

This module defines configuration settings using Pydantic models with validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import ClassVar, Self

from flext_core import FlextConfig
from flext_ldif.config import FlextLdifConfig
from pydantic import Field
from pydantic_settings import SettingsConfigDict

from flext_ldap.constants import FlextLdapConstants

# Use FlextConfig.auto_register and FlextConfig.AutoConfig directly
# These are class attributes that exist at runtime
_auto_register_decorator = getattr(FlextConfig, "auto_register", None)
_AutoConfig_class = getattr(FlextConfig, "AutoConfig", None)

if _auto_register_decorator is None:
    msg = "FlextConfig.auto_register not found"
    raise AttributeError(msg)
if _AutoConfig_class is None:
    msg = "FlextConfig.AutoConfig not found"
    raise AttributeError(msg)


@_auto_register_decorator("ldap")
class FlextLdapConfig(_AutoConfig_class):
    """Pydantic v2 configuration for LDAP operations.

    **ARCHITECTURAL PATTERN**: Zero-Boilerplate Auto-Registration

    This class uses FlextConfig.AutoConfig for automatic:
    - Singleton pattern (thread-safe)
    - Namespace registration (accessible via config.ldap)
    - Environment variable loading from FLEXT_LDAP_* variables
    - .env file loading (production/development)
    - Automatic type conversion and validation via Pydantic v2

    **Environment Variables** (via .env or environment):
        FLEXT_LDAP_HOST=localhost
        FLEXT_LDAP_PORT=389
        FLEXT_LDAP_USE_SSL=false
        FLEXT_LDAP_USE_TLS=false
        FLEXT_LDAP_BIND_DN=cn=admin,dc=example,dc=com
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

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_LDAP_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
        case_sensitive=False,
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


class LdapFlextConfig(FlextConfig):
    """FlextConfig TIPADO com namespaces do projeto flext-ldap.

    Provides typed access to:
    - self.ldap → FlextLdapConfig
    - self.ldif → FlextLdifConfig (consumed dependency)

    Usage in services:
        class MyService(FlextLdapServiceBase[MyResult]):
            def execute(self) -> FlextResult[MyResult]:
                host = self.config.ldap.host  # Typed access!
                encoding = self.config.ldif.ldif_encoding  # Typed access!
    """

    _ldap_global: ClassVar[LdapFlextConfig | None] = None

    @property
    def ldap(self) -> FlextLdapConfig:
        """Get FlextLdapConfig namespace (typed access)."""
        config = FlextConfig.get_global_instance()
        # get_namespace is a method of FlextConfig instances
        get_namespace_method = getattr(config, "get_namespace", None)
        if get_namespace_method is None:
            msg = "FlextConfig instance does not have get_namespace method"
            raise AttributeError(msg)
        namespace = get_namespace_method("ldap", FlextLdapConfig)
        if not isinstance(namespace, FlextLdapConfig):
            msg = f"Namespace 'ldap' is {type(namespace).__name__}, not FlextLdapConfig"
            raise TypeError(msg)
        return namespace

    @property
    def ldif(self) -> FlextLdifConfig:
        """Get FlextLdifConfig namespace (typed access)."""
        config = FlextConfig.get_global_instance()
        # get_namespace is a method of FlextConfig instances
        get_namespace_method = getattr(config, "get_namespace", None)
        if get_namespace_method is None:
            msg = "FlextConfig instance does not have get_namespace method"
            raise AttributeError(msg)
        namespace = get_namespace_method("ldif", FlextLdifConfig)
        if not isinstance(namespace, FlextLdifConfig):
            msg = f"Namespace 'ldif' is {type(namespace).__name__}, not FlextLdifConfig"
            raise TypeError(msg)
        return namespace

    @classmethod
    def get_global_instance(cls) -> LdapFlextConfig:
        """Get singleton instance of LdapFlextConfig."""
        if cls._ldap_global is None:
            with cls._lock:
                if cls._ldap_global is None:
                    cls._ldap_global = cls()
        return cls._ldap_global

    def clone(self, **overrides: object) -> Self:
        """Clone config with overrides."""
        data = self.model_dump()
        data.update(overrides)
        return type(self)(**data)

    @classmethod
    def reset_for_testing(cls) -> None:
        """Reset singleton for testing."""
        with cls._lock:
            cls._ldap_global = None


__all__ = ["FlextLdapConfig", "LdapFlextConfig"]
