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

from __future__ import annotations

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from flext_core import FlextConfig, FlextConstants, FlextResult
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


class FlextLdapConfig(FlextConfig):
    """Single Pydantic 2 Settings class for flext-ldap extending FlextConfig.

    Follows standardized pattern:
    - Extends FlextConfig from flext-core
    - No nested classes within Config
    - All defaults from FlextLdapConstants
    - Uses enhanced singleton pattern with inverse dependency injection
    - Uses Pydantic 2.11+ features (SecretStr for secrets)
    """

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_LDAP_",
        case_sensitive=False,
        extra="ignore",
        # Inherit enhanced Pydantic 2.11+ features from FlextConfig
        validate_assignment=True,
        str_strip_whitespace=True,
        json_schema_extra={
            "title": "FLEXT LDAP Configuration",
            "description": "Enterprise LDAP configuration extending FlextConfig",
        },
    )

    # LDAP Connection Configuration using FlextLdapConstants for defaults
    ldap_server_uri: str = Field(
        default=FlextLdapConstants.Protocol.DEFAULT_SERVER_URI,
        description="LDAP server URI (ldap:// or ldaps://)",
    )

    ldap_port: int = Field(
        default=FlextLdapConstants.Protocol.DEFAULT_PORT,
        ge=1,
        le=FlextLdapConstants.Protocol.MAX_PORT,
        description="LDAP server port",
    )

    ldap_use_ssl: bool = Field(
        default=True,
        description="Use SSL/TLS for LDAP connections",
    )

    ldap_verify_certificates: bool = Field(
        default=True,
        description="Verify SSL/TLS certificates",
    )

    # Authentication Configuration using SecretStr for sensitive data
    ldap_bind_dn: str | None = Field(
        default=None,
        description="LDAP bind distinguished name for authentication",
    )

    ldap_bind_password: SecretStr | None = Field(
        default=None,
        description="LDAP bind password for authentication (sensitive)",
    )

    ldap_base_dn: str = Field(
        default=FlextLdapConstants.LdapDefaults.DEFAULT_SEARCH_BASE,
        description="LDAP base distinguished name for searches",
    )

    # Connection Pooling Configuration using FlextLdapConstants for defaults
    ldap_pool_size: int = Field(
        default=FlextLdapConstants.Protocol.DEFAULT_POOL_SIZE,
        ge=1,
        le=50,
        description="LDAP connection pool size",
    )

    ldap_pool_timeout: int = Field(
        default=FlextLdapConstants.Protocol.DEFAULT_TIMEOUT_SECONDS,
        ge=1,
        le=300,
        description="LDAP connection pool timeout in seconds",
    )

    # Operation Configuration using FlextLdapConstants for defaults
    ldap_connection_timeout: int = Field(
        default=FlextLdapConstants.Protocol.DEFAULT_TIMEOUT_SECONDS,
        ge=1,
        le=300,
        description="LDAP connection timeout in seconds",
    )

    ldap_operation_timeout: int = Field(
        default=60,
        ge=1,
        le=600,
        description="LDAP operation timeout in seconds",
    )

    ldap_size_limit: int = Field(
        default=FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE,
        ge=1,
        le=FlextLdapConstants.Connection.MAX_SIZE_LIMIT,
        description="LDAP search size limit",
    )

    ldap_time_limit: int = Field(
        default=FlextLdapConstants.Protocol.DEFAULT_TIMEOUT_SECONDS,
        ge=1,
        le=300,
        description="LDAP search time limit in seconds",
    )

    # Caching Configuration using FlextConstants for defaults
    ldap_enable_caching: bool = Field(
        default=True,
        description="Enable LDAP result caching",
    )

    ldap_cache_ttl: int = Field(
        default=300,  # 5 minutes
        ge=0,
        le=3600,
        description="LDAP cache TTL in seconds",
    )

    # Retry Configuration using FlextConstants for defaults
    ldap_retry_attempts: int = Field(
        default=FlextConstants.Reliability.MAX_RETRY_ATTEMPTS,
        ge=0,
        le=10,
        description="Number of retry attempts for failed operations",
    )

    ldap_retry_delay: int = Field(
        default=1,
        ge=0,
        le=60,
        description="Delay between retry attempts in seconds",
    )

    # Logging Configuration using FlextLdapConstants for defaults
    ldap_enable_debug: bool = Field(
        default=False,
        description="Enable LDAP debug logging",
    )

    ldap_enable_trace: bool = Field(
        default=False,
        description="Enable LDAP trace logging",
    )

    ldap_log_queries: bool = Field(
        default=False,
        description="Enable logging of LDAP queries",
    )

    ldap_mask_passwords: bool = Field(
        default=True,
        description="Mask passwords in log messages",
    )

    # Pydantic 2.11 field validators
    @field_validator("ldap_server_uri")
    @classmethod
    def validate_ldap_server_uri(cls, v: str) -> str:
        """Validate LDAP server URI format."""
        if not v.startswith(("ldap://", "ldaps://")):
            msg = f"Invalid LDAP server URI: {v}. Must start with ldap:// or ldaps://"
            raise ValueError(msg)
        return v

    @field_validator("ldap_bind_dn")
    @classmethod
    def validate_bind_dn(cls, v: str | None) -> str | None:
        """Validate LDAP bind DN format."""
        if v is None:
            return v

        # Basic DN validation
        if len(v) < FlextLdapConstants.LdapValidation.MIN_DN_LENGTH:
            msg = f"LDAP bind DN too short: {v}"
            raise ValueError(msg)

        if len(v) > FlextLdapConstants.LdapValidation.MAX_DN_LENGTH:
            msg = f"LDAP bind DN too long: {v}"
            raise ValueError(msg)

        if "=" not in v:
            msg = (
                f"Invalid LDAP bind DN format: {v}. Must contain attribute=value pairs"
            )
            raise ValueError(msg)

        return v

    @field_validator("ldap_base_dn")
    @classmethod
    def validate_base_dn(cls, v: str) -> str:
        """Validate LDAP base DN format."""
        if v and len(v) > FlextLdapConstants.LdapValidation.MAX_DN_LENGTH:
            msg = f"LDAP base DN too long: {v}"
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def validate_ldap_configuration_consistency(self) -> FlextLdapConfig:
        """Validate LDAP configuration consistency."""
        # Validate authentication configuration
        if self.ldap_bind_dn is not None and self.ldap_bind_password is None:
            msg = "Bind password is required when bind DN is specified"
            raise ValueError(msg)

        # Validate caching configuration
        if self.ldap_enable_caching and self.ldap_cache_ttl <= 0:
            msg = "Cache TTL must be positive when caching is enabled"
            raise ValueError(msg)

        # Validate SSL configuration consistency
        if self.ldap_server_uri.startswith("ldaps://") and not self.ldap_use_ssl:
            msg = "SSL must be enabled for ldaps:// server URIs"
            raise ValueError(msg)

        return self

    # LDAP-specific methods for getting configuration contexts
    def get_connection_config(self) -> dict[str, object]:
        """Get LDAP connection configuration context."""
        return {
            "server_uri": self.ldap_server_uri,
            "port": self.ldap_port,
            "use_ssl": self.ldap_use_ssl,
            "verify_certificates": self.ldap_verify_certificates,
            "bind_dn": self.ldap_bind_dn,
            "bind_password_configured": self.ldap_bind_password is not None,
            "base_dn": self.ldap_base_dn,
            "timeout": self.ldap_connection_timeout,
        }

    def get_pool_config(self) -> dict[str, object]:
        """Get LDAP connection pool configuration context."""
        return {
            "pool_size": self.ldap_pool_size,
            "pool_timeout": self.ldap_pool_timeout,
            "max_retries": self.ldap_retry_attempts,
            "retry_delay": self.ldap_retry_delay,
        }

    def get_operation_config(self) -> dict[str, object]:
        """Get LDAP operation configuration context."""
        return {
            "operation_timeout": self.ldap_operation_timeout,
            "size_limit": self.ldap_size_limit,
            "time_limit": self.ldap_time_limit,
            "enable_caching": self.ldap_enable_caching,
            "cache_ttl": self.ldap_cache_ttl,
        }

    def get_ldap_logging_config(self) -> dict[str, object]:
        """Get LDAP logging configuration context."""
        return {
            "enable_debug": self.ldap_enable_debug,
            "enable_trace": self.ldap_enable_trace,
            "log_queries": self.ldap_log_queries,
            "mask_passwords": self.ldap_mask_passwords,
        }

    @classmethod
    def create_for_environment(
        cls, environment: str, **overrides: object
    ) -> FlextLdapConfig:
        """Create configuration for specific environment using enhanced singleton pattern."""
        return super().get_or_create_shared_instance(
            project_name="flext-ldap", environment=environment, **overrides
        )

    @classmethod
    def create_default(cls) -> FlextLdapConfig:
        """Create default configuration instance using enhanced singleton pattern."""
        return super().get_or_create_shared_instance(project_name="flext-ldap")

    def get_effective_bind_password(self) -> str | None:
        """Get the effective bind password (safely extract from SecretStr)."""
        if self.ldap_bind_password is not None:
            return self.ldap_bind_password.get_secret_value()
        return None

    @classmethod
    def get_global_instance(cls) -> FlextLdapConfig:
        """Get the global singleton instance using enhanced FlextConfig pattern."""
        # Force creation of the correct type by calling the constructor
        try:
            return cls()
        except Exception:
            # Fallback to parent method with type override
            return super().get_global_instance()

    @classmethod
    def reset_global_instance(cls) -> None:
        """Reset the global FlextLdapConfig instance (mainly for testing)."""
        # Use the enhanced FlextConfig reset mechanism
        super().reset_global_instance()

    @staticmethod
    def create_from_connection_config_data(
        data: dict[str, object],
    ) -> FlextResult[FlextLdapConfig]:
        """Create config from connection data."""
        try:
            # Create new instance with the provided values
            bind_password_value = data.get("bind_password")
            config_kwargs = {
                "ldap_server_uri": str(
                    data.get("server_uri", data.get("server", "ldap://localhost"))
                ),
                "ldap_port": int(str(data.get("port", 389))),
                "ldap_bind_dn": str(data.get("bind_dn", ""))
                if data.get("bind_dn")
                else None,
                "ldap_bind_password": SecretStr(str(bind_password_value))
                if bind_password_value
                else None,
                "ldap_base_dn": str(data.get("base_dn", "")),
            }
            config = FlextLdapConfig(**config_kwargs)
            return FlextResult[FlextLdapConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapConfig].fail(f"Config creation failed: {e}")

    @staticmethod
    def create_search_config(
        data: dict[str, object],
    ) -> FlextResult[FlextLdapModels.SearchConfig]:
        """Create search config from data."""
        try:
            attributes_data = data.get("attributes", [])
            if not isinstance(attributes_data, list):
                attributes_data = []
            # Ensure all attributes are strings
            str_attributes = [str(attr) for attr in attributes_data if attr is not None]
            config = FlextLdapModels.SearchConfig(
                base_dn=str(data.get("base_dn", "")),
                search_filter=str(data.get("filter_str", "(objectClass=*)")),
                attributes=str_attributes,
            )
            return FlextResult[FlextLdapModels.SearchConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapModels.SearchConfig].fail(
                f"Search config creation failed: {e}"
            )

    @staticmethod
    def create_modify_config(data: dict[str, object]) -> FlextResult[dict[str, object]]:
        """Create modify config from data."""
        try:
            config = {
                "dn": str(data.get("dn", "")),
                "operation": str(data.get("operation", "replace")),
                "attribute": str(data.get("attribute", "")),
                "values": data.get("values", []),
            }
            return FlextResult[dict[str, object]].ok(dict(config))
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Modify config creation failed: {e}"
            )

    @staticmethod
    def create_add_config(data: dict[str, object]) -> FlextResult[dict[str, object]]:
        """Create add config from data."""
        try:
            config = {
                "dn": str(data.get("dn", "")),
                "attributes": data.get("attributes", {}),
            }
            return FlextResult[dict[str, object]].ok(dict(config))
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Add config creation failed: {e}"
            )

    @staticmethod
    def create_delete_config(data: dict[str, object]) -> FlextResult[dict[str, object]]:
        """Create delete config from data."""
        try:
            config = {
                "dn": str(data.get("dn", "")),
            }
            return FlextResult[dict[str, object]].ok(dict(config))
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Delete config creation failed: {e}"
            )

    @staticmethod
    def get_default_search_config() -> FlextResult[dict[str, object]]:
        """Get default search configuration."""
        config = {
            "base_dn": "dc=example,dc=com",
            "filter_str": "(objectClass=*)",
            "scope": "subtree",
            "attributes": ["cn", "sn", "mail"],
            "size_limit": 100,
            "time_limit": 30,
        }
        return FlextResult[dict[str, object]].ok(dict(config))

    @staticmethod
    def merge_configs(
        base_config: dict[str, object], override_config: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Merge two configuration dictionaries."""
        try:
            merged = base_config.copy()
            merged.update(override_config)
            return FlextResult[dict[str, object]].ok(dict(merged))
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Config merge failed: {e}")

    def get_effective_server_uri(self) -> str:
        """Get effective server URI."""
        return self.ldap_server_uri

    def get_effective_bind_dn(self) -> str | None:
        """Get effective bind DN."""
        return self.ldap_bind_dn

    @property
    def ldap_default_connection(self) -> dict[str, object]:
        """Get default connection configuration."""
        return {
            "server": self.ldap_server_uri,
            "port": self.ldap_port,
            "bind_dn": self.ldap_bind_dn,
            "bind_password": self.get_effective_bind_password(),
        }


# Removed backward compatibility alias - use FlextLdapConfig directly
__all__ = [
    "FlextLdapConfig",
]
