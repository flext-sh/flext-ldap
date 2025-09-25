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

import os
from typing import ClassVar

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import SettingsConfigDict

from flext_core import FlextConfig, FlextResult
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapConfig(FlextConfig):
    """FLEXT-LDAP Configuration singleton extending FlextConfig with LDAP-specific fields.

    This class provides a singleton configuration instance for LDAP operations,
    extending the base FlextConfig with LDAP-specific fields and validation rules.
    It serves as the single source of truth for LDAP configuration across the
    entire flext-ldap library.

    Features:
    - SINGLETON GLOBAL INSTANCE - One source of truth for LDAP configuration
    - LDAP-specific fields with proper validation
    - Environment variable support with FLEXT_LDAP_ prefix
    - Thread-safe singleton pattern
    - Centralized configuration management
    """

    # Pydantic model configuration using flext-core patterns
    model_config = SettingsConfigDict(
        env_prefix="FLEXT_LDAP_",
        env_file_encoding="utf-8",
        extra="ignore",  # Allow extra environment variables from other projects
        case_sensitive=False,
        arbitrary_types_allowed=True,
        populate_by_name=True,
        validate_assignment=True,
        use_enum_values=True,
    )

    # SINGLETON pattern inherited from FlextConfig with proper typing
    _global_instance: ClassVar[FlextLdapConfig | None] = None

    # === CONSTANTS ===
    MAX_CACHE_TTL_SECONDS: ClassVar[int] = 3600  # 1 hour
    MAX_POOL_SIZE: ClassVar[int] = 50

    # === LDAP CONFIGURATION FIELDS ===
    # LDAP configuration fields using FlextLdapModels.ConnectionConfig directly

    # === LDAP CONNECTION CONFIGURATION ===
    # Connection to LDAP servers (can be a single or multiple connections)
    ldap_default_connection: FlextLdapModels.ConnectionConfig | None = Field(
        default=None,
        description="Default LDAP connection configuration",
        alias="ldap_connection",
    )

    # Bind DN and password for authentication (if not provided in connection config)
    ldap_bind_dn: str | None = Field(
        default=None,
        description="LDAP bind distinguished name for authentication",
        alias="bind_dn",
    )
    ldap_bind_password: SecretStr | None = Field(
        default=None,
        description="LDAP bind password for authentication",
        alias="bind_password",
    )

    # SSL/TLS configuration
    ldap_use_ssl: bool = Field(
        default=True,
        description="Use SSL/TLS for LDAP connections",
        alias="use_ssl",
    )
    ldap_verify_certificates: bool = Field(
        default=True,
        description="Verify SSL/TLS certificates",
        alias="verify_certificates",
    )

    # === LDAP BEHAVIOR CONFIGURATION ===
    # Debug and logging
    ldap_enable_debug: bool = Field(
        default=False,
        description="Enable LDAP debug logging",
        alias="enable_debug",
    )
    ldap_enable_trace: bool = Field(
        default=False,
        description="Enable LDAP trace logging",
        alias="enable_trace",
    )

    # Connection pooling
    ldap_pool_size: int = Field(
        default=10,
        description="LDAP connection pool size",
        alias="pool_size",
        ge=1,
        le=50,
    )
    ldap_pool_timeout: int = Field(
        default=30,
        description="LDAP connection pool timeout in seconds",
        alias="pool_timeout",
        ge=1,
        le=300,
    )

    # Caching
    ldap_enable_caching: bool = Field(
        default=True,
        description="Enable LDAP result caching",
        alias="enable_caching",
    )
    ldap_cache_ttl: int = Field(
        default=300,
        description="LDAP cache TTL in seconds",
        alias="cache_ttl",
        ge=0,
        le=3600,
    )

    # Retry configuration
    ldap_retry_attempts: int = Field(
        default=3,
        description="Number of retry attempts for failed operations",
        alias="retry_attempts",
        ge=0,
        le=10,
    )
    ldap_retry_delay: int = Field(
        default=1,
        description="Delay between retry attempts in seconds",
        alias="retry_delay",
        ge=0,
        le=60,
    )

    # Timeout configuration
    ldap_connection_timeout: int = Field(
        default=30,
        description="LDAP connection timeout in seconds",
        alias="connection_timeout",
        ge=1,
        le=300,
    )
    ldap_operation_timeout: int = Field(
        default=60,
        description="LDAP operation timeout in seconds",
        alias="operation_timeout",
        ge=1,
        le=600,
    )

    # Additional LDAP configuration fields
    ldap_size_limit: int = Field(
        default=100,
        description="LDAP search size limit",
        alias="size_limit",
        ge=1,
        le=10000,
    )
    ldap_time_limit: int = Field(
        default=30,
        description="LDAP search time limit in seconds",
        alias="time_limit",
        ge=1,
        le=300,
    )
    ldap_log_queries: bool = Field(
        default=False,
        description="Enable logging of LDAP queries",
        alias="log_queries",
    )

    # =========================================================================
    # VALIDATION METHODS - Integrated from FlextLdapConfigValidationMixin
    # =========================================================================

    def validate_business_rules_base(self) -> FlextResult[None]:
        """Common business rules validation."""
        try:
            # Rule 1: Connection configuration must be valid
            if (
                hasattr(self, "ldap_default_connection")
                and getattr(self, "ldap_default_connection", None) is None
            ):
                return FlextResult[None].fail("Default LDAP connection is required")

            # Rule 2: If authentication is configured, both DN and password are needed
            bind_dn = getattr(self, "ldap_bind_dn", None)
            bind_password = getattr(self, "ldap_bind_password", None)
            if bind_dn is not None and bind_password is None:
                return FlextResult[None].fail(
                    "Bind password is required when bind DN is specified",
                )

            # Rule 3: Cache TTL must be reasonable
            enable_caching = getattr(self, "ldap_enable_caching", False)
            cache_ttl = getattr(self, "ldap_cache_ttl", 0)
            if enable_caching and cache_ttl > self.MAX_CACHE_TTL_SECONDS:
                return FlextResult[None].fail(
                    f"Cache TTL cannot exceed {self.MAX_CACHE_TTL_SECONDS} seconds",
                )

            # Rule 4: Pool size must be reasonable for environment
            pool_size = getattr(self, "ldap_pool_size", 0)
            if pool_size > self.MAX_POOL_SIZE:
                return FlextResult[None].fail(
                    f"Pool size cannot exceed {self.MAX_POOL_SIZE}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Configuration validation failed: {e}")

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for LDAP configuration.

        This method provides the standard validate_business_rules interface
        expected by examples and other code using FlextLdapConfig.

        Returns:
            FlextResult indicating success or failure with detailed error messages.

        """
        return self.validate_business_rules_base()

    def validate_filter_format(self, filter_str: str) -> FlextResult[bool]:
        """Validate LDAP filter format.

        Args:
            filter_str: LDAP filter string to validate

        Returns:
            FlextResult with True if valid, False if invalid

        """
        try:
            if not filter_str or not filter_str.strip():
                return FlextResult[bool].fail("Invalid filter format: empty filter")

            # Basic LDAP filter validation
            # Check for balanced parentheses
            if filter_str.count("(") != filter_str.count(")"):
                return FlextResult[bool].fail(
                    "Invalid filter format: unbalanced parentheses"
                )

            # Check for basic filter structure
            if not filter_str.startswith("(") or not filter_str.endswith(")"):
                return FlextResult[bool].fail(
                    "Invalid filter format: must start and end with parentheses"
                )

            # Check for basic attribute=value pattern
            inner_filter = filter_str[1:-1]  # Remove outer parentheses
            if "=" not in inner_filter:
                return FlextResult[bool].fail(
                    "Invalid filter format: missing attribute=value pattern"
                )

            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(f"Invalid filter format: {e}")

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate LDAP Distinguished Name format.

        Args:
            dn: Distinguished Name string to validate

        Returns:
            FlextResult with validation result

        """
        try:
            if not dn:
                return FlextResult[bool].fail("DN cannot be empty")

            # Use FlextLdapValidations to validate the DN
            validation_result = FlextLdapValidations.validate_dn(dn)
            if validation_result.is_failure:
                return FlextResult[bool].fail(
                    f"Invalid DN format: {validation_result.error}"
                )

            return FlextResult[bool].ok(True)
        except Exception as e:
            return FlextResult[bool].fail(f"Failed to validate DN format: {e}")

    def get_default_connection_config(
        self,
    ) -> FlextResult[FlextLdapModels.ConnectionConfig]:
        """Get default connection configuration.

        Returns:
            FlextResult with default connection configuration

        """
        return self._create_connection_config()

    def _create_connection_config(
        self,
    ) -> FlextResult[FlextLdapModels.ConnectionConfig]:
        """Create connection configuration from current settings.

        Returns:
            FlextResult with connection configuration

        """
        try:
            server_uri = self.get_effective_server_uri()
            # Parse server URI to extract server and port
            if "://" in server_uri:
                protocol, host_port = server_uri.split("://", 1)
                if ":" in host_port:
                    server, port_str = host_port.split(":", 1)
                    port = int(port_str)
                else:
                    server = host_port
                    port = 389 if protocol == "ldap" else 636
                use_ssl = protocol == "ldaps"
            else:
                server = server_uri
                port = 389
                use_ssl = False

            config = FlextLdapModels.ConnectionConfig(
                server=server,
                port=port,
                use_ssl=use_ssl,
                bind_dn=self.get_effective_bind_dn(),
                bind_password=self.get_effective_bind_password(),
                timeout=self.ldap_connection_timeout,
            )
            return FlextResult[FlextLdapModels.ConnectionConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapModels.ConnectionConfig].fail(
                f"Failed to create connection config: {e}"
            )

    def merge_configs(
        self, base_config: dict[str, object], override_config: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Merge configuration dictionaries.

        Args:
            base_config: Base configuration dictionary
            override_config: Override configuration dictionary

        Returns:
            FlextResult with merged configuration

        """
        try:
            merged = base_config.copy()
            merged.update(override_config)
            return FlextResult[dict[str, object]].ok(merged)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Failed to merge Config: {e}")

    def create_modify_config(
        self, modify_data: dict[str, object]
    ) -> FlextResult[FlextLdapModels.ModifyConfig]:
        """Create modify configuration from data.

        Args:
            modify_data: Modify operation data

        Returns:
            FlextResult with modify configuration

        """
        try:
            validation_result = self._validate_modify_data(modify_data)
            if validation_result.is_failure:
                return FlextResult[FlextLdapModels.ModifyConfig].fail(
                    validation_result.error or "Validation failed"
                )

            config = FlextLdapModels.ModifyConfig(
                dn=str(modify_data.get("dn", "")),
                changes=modify_data.get("changes", {}),  # type: ignore[arg-type]
            )
            return FlextResult[FlextLdapModels.ModifyConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapModels.ModifyConfig].fail(
                f"Failed to create modify config: {e}"
            )

    def _validate_modify_data(
        self, modify_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Validate modify data.

        Args:
            modify_data: Modify operation data

        Returns:
            FlextResult with validation result

        """
        try:
            if not modify_data:
                return FlextResult[dict[str, object]].fail(
                    "Modify data cannot be empty"
                )

            if "dn" not in modify_data:
                return FlextResult[dict[str, object]].fail(
                    "DN is required for modify operations"
                )

            if "changes" not in modify_data:
                return FlextResult[dict[str, object]].fail(
                    "Changes are required for modify operations"
                )

            return FlextResult[dict[str, object]].ok({"valid": True})
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to validate modify data: {e}"
            )

    def _validate_connection_data(
        self, connection_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Validate connection data.

        Args:
            connection_data: Connection operation data

        Returns:
            FlextResult with validation result

        """
        try:
            if not connection_data:
                return FlextResult[dict[str, object]].fail(
                    "Connection data cannot be empty"
                )

            if "server_uri" not in connection_data:
                return FlextResult[dict[str, object]].fail(
                    "Server URI is required for connection operations"
                )

            # Check for other required fields
            missing_fields = []
            if "bind_dn" not in connection_data:
                missing_fields.append("bind_dn")
            if "bind_password" not in connection_data:
                missing_fields.append("bind_password")
            if "base_dn" not in connection_data:
                missing_fields.append("base_dn")

            if missing_fields:
                return FlextResult[dict[str, object]].fail(
                    f"Missing required fields: {', '.join(missing_fields)}"
                )

            return FlextResult[dict[str, object]].ok({"valid": True})
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to validate connection data: {e}"
            )

    def _validate_search_data(
        self, search_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Validate search data.

        Args:
            search_data: Search operation data

        Returns:
            FlextResult with validation result

        """
        try:
            if not search_data:
                return FlextResult[dict[str, object]].fail(
                    "Search data cannot be empty"
                )

            if "base_dn" not in search_data:
                return FlextResult[dict[str, object]].fail(
                    "Base DN is required for search operations"
                )

            if "filter_str" not in search_data:
                return FlextResult[dict[str, object]].fail(
                    "Filter string is required for search operations"
                )

            return FlextResult[dict[str, object]].ok({"valid": True})
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to validate search data: {e}"
            )

    def _validate_add_data(
        self, add_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Validate add data.

        Args:
            add_data: Add operation data

        Returns:
            FlextResult with validation result

        """
        try:
            if not add_data:
                return FlextResult[dict[str, object]].fail("Add data cannot be empty")

            if "dn" not in add_data:
                return FlextResult[dict[str, object]].fail(
                    "DN is required for add operations"
                )

            if "attributes" not in add_data:
                return FlextResult[dict[str, object]].fail(
                    "Attributes are required for add operations"
                )

            return FlextResult[dict[str, object]].ok({"valid": True})
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to validate add data: {e}"
            )

    def _validate_delete_data(
        self, delete_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Validate delete data.

        Args:
            delete_data: Delete operation data

        Returns:
            FlextResult with validation result

        """
        try:
            if not delete_data:
                return FlextResult[dict[str, object]].fail(
                    "Delete data cannot be empty"
                )

            if "dn" not in delete_data:
                return FlextResult[dict[str, object]].fail(
                    "DN is required for delete operations"
                )

            return FlextResult[dict[str, object]].ok({"valid": True})
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to validate delete data: {e}"
            )

    def create_connection_config(
        self, connection_data: dict[str, object]
    ) -> FlextResult[FlextLdapModels.ConnectionConfig]:
        """Create connection configuration from data.

        Args:
            connection_data: Connection operation data

        Returns:
            FlextResult with connection configuration

        """
        try:
            validation_result = self._validate_connection_data(connection_data)
            if validation_result.is_failure:
                return FlextResult[FlextLdapModels.ConnectionConfig].fail(
                    validation_result.error or "Validation failed"
                )

            server_uri = str(connection_data.get("server_uri", "ldap://localhost:389"))
            # Parse server URI to extract server and port
            if "://" in server_uri:
                protocol, host_port = server_uri.split("://", 1)
                if ":" in host_port:
                    server, port_str = host_port.split(":", 1)
                    port = int(port_str)
                else:
                    server = host_port
                    port = 389 if protocol == "ldap" else 636
                use_ssl = protocol == "ldaps"
            else:
                server = server_uri
                port = 389
                use_ssl = False

            config = FlextLdapModels.ConnectionConfig(
                server=server,
                port=port,
                use_ssl=use_ssl,
                bind_dn=str(connection_data.get("bind_dn"))
                if connection_data.get("bind_dn") is not None
                else None,
                bind_password=str(connection_data.get("password"))
                if connection_data.get("password") is not None
                else None,
                timeout=self.ldap_connection_timeout,
            )
            return FlextResult[FlextLdapModels.ConnectionConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapModels.ConnectionConfig].fail(
                f"Failed to create connection config: {e}"
            )

    def create_connection_config_from_env(
        self,
    ) -> FlextResult[FlextLdapModels.ConnectionConfig]:
        """Create connection configuration from environment variables.

        Returns:
            FlextResult with connection configuration

        """
        try:
            # Get environment variables
            server_uri = os.getenv("LDAP_SERVER_URI")
            bind_dn = os.getenv("LDAP_BIND_DN")
            bind_password = os.getenv("LDAP_BIND_PASSWORD")
            base_dn = os.getenv("LDAP_BASE_DN")

            # Check for missing required environment variables
            missing_vars = []
            if not server_uri:
                missing_vars.append("LDAP_SERVER_URI")
            if not bind_dn:
                missing_vars.append("LDAP_BIND_DN")
            if not bind_password:
                missing_vars.append("LDAP_BIND_PASSWORD")
            if not base_dn:
                missing_vars.append("LDAP_BASE_DN")

            if missing_vars:
                return FlextResult[FlextLdapModels.ConnectionConfig].fail(
                    f"Missing required environment variables: {', '.join(missing_vars)}"
                )

            # Create connection data
            connection_data = {
                "server_uri": server_uri,
                "bind_dn": bind_dn,
                "bind_password": bind_password,
                "base_dn": base_dn,
            }

            # Validate the data
            validation_result = self._validate_connection_data(dict(connection_data))
            if validation_result.is_failure:
                return FlextResult[FlextLdapModels.ConnectionConfig].fail(
                    validation_result.error or "Validation failed"
                )

            # Create the config
            config = FlextLdapModels.ConnectionConfig(
                server=str(server_uri),
                port=389,
                use_ssl=False,
                bind_dn=bind_dn,
                bind_password=bind_password,
                timeout=30,
            )
            return FlextResult[FlextLdapModels.ConnectionConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapModels.ConnectionConfig].fail(
                f"Failed to create connection config from env: {e}"
            )

    def create_search_config(
        self, search_data: dict[str, object]
    ) -> FlextResult[FlextLdapModels.SearchConfig]:
        """Create search configuration from data.

        Args:
            search_data: Search operation data

        Returns:
            FlextResult with search configuration

        """
        try:
            validation_result = self._validate_search_data(search_data)
            if validation_result.is_failure:
                return FlextResult[FlextLdapModels.SearchConfig].fail(
                    validation_result.error or "Validation failed"
                )

            config = FlextLdapModels.SearchConfig(
                base_dn=str(search_data.get("base_dn", "")),
                search_filter=str(search_data.get("search_filter", "")),
                attributes=search_data.get("attributes", []),  # type: ignore[arg-type]
            )
            return FlextResult[FlextLdapModels.SearchConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapModels.SearchConfig].fail(
                f"Failed to create search config: {e}"
            )

    def create_add_config(
        self, add_data: dict[str, object]
    ) -> FlextResult[FlextLdapModels.AddConfig]:
        """Create add configuration from data.

        Args:
            add_data: Add operation data

        Returns:
            FlextResult with add configuration

        """
        try:
            validation_result = self._validate_add_data(add_data)
            if validation_result.is_failure:
                return FlextResult[FlextLdapModels.AddConfig].fail(
                    validation_result.error or "Validation failed"
                )

            config = FlextLdapModels.AddConfig(
                dn=str(add_data.get("dn", "")),
                attributes=add_data.get("attributes", {}),  # type: ignore[arg-type]
            )
            return FlextResult[FlextLdapModels.AddConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapModels.AddConfig].fail(
                f"Failed to create add config: {e}"
            )

    def create_delete_config(
        self, delete_data: dict[str, object]
    ) -> FlextResult[FlextLdapModels.DeleteConfig]:
        """Create delete configuration from data.

        Args:
            delete_data: Delete operation data

        Returns:
            FlextResult with delete configuration

        """
        try:
            validation_result = self._validate_delete_data(delete_data)
            if validation_result.is_failure:
                return FlextResult[FlextLdapModels.DeleteConfig].fail(
                    validation_result.error or "Validation failed"
                )

            config = FlextLdapModels.DeleteConfig(
                dn=str(delete_data.get("dn", "")),
            )
            return FlextResult[FlextLdapModels.DeleteConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapModels.DeleteConfig].fail(
                f"Failed to create delete config: {e}"
            )

    def _create_search_config(
        self, search_data: dict[str, object]
    ) -> FlextResult[FlextLdapModels.SearchConfig]:
        """Create search configuration from data.

        Args:
            search_data: Search operation data

        Returns:
            FlextResult with search configuration

        """
        try:
            validation_result = self._validate_search_data(search_data)
            if validation_result.is_failure:
                return FlextResult[FlextLdapModels.SearchConfig].fail(
                    validation_result.error or "Validation failed"
                )

            config = FlextLdapModels.SearchConfig(
                base_dn=str(search_data.get("base_dn", "")),
                search_filter=str(search_data.get("search_filter", "")),
                attributes=search_data.get("attributes", []),  # type: ignore[arg-type]
            )
            return FlextResult[FlextLdapModels.SearchConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapModels.SearchConfig].fail(
                f"Failed to create search config: {e}"
            )

    def get_default_search_config(
        self,
    ) -> FlextResult[FlextLdapModels.SearchConfig]:
        """Get default search configuration.

        Returns:
            FlextResult with default search configuration

        """
        try:
            default_data = {
                "base_dn": "dc=example,dc=com",
                "search_filter": "(objectClass=*)",
                "attributes": ["*"],
            }
            return self._create_search_config(dict(default_data))
        except Exception as e:
            return FlextResult[FlextLdapModels.SearchConfig].fail(
                f"Failed to get default search config: {e}"
            )

    # =========================================================================
    # CREATION METHODS - Integrated from FlextLdapConfigCreationMixin
    # =========================================================================

    @classmethod
    def create_config_with_defaults(
        cls,
        environment: str,
        config_data: dict[str, object],
        **overrides: object,
    ) -> FlextResult[FlextLdapConfig]:
        """Create configuration with environment-specific defaults."""
        try:
            # Apply overrides if any
            if overrides:
                config_data.update(overrides)

            # Use model_validate for proper type handling
            config: FlextLdapConfig = cls.model_validate(config_data)
            return FlextResult[FlextLdapConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapConfig].fail(
                f"Failed to create {environment} config: {e}"
            )

    @classmethod
    def create_from_connection_config_data(
        cls,
        connection_data: FlextLdapTypes.LdapConfig.ConnectionConfigData,
    ) -> FlextResult[FlextLdapConfig]:
        """Create configuration from FlextLdapTypes.LdapConfig.ConnectionConfigData structure.

        Args:
            connection_data: Connection configuration data using DataStructures types

        Returns:
            FlextResult containing the created configuration or error

        """
        try:
            # Convert DataStructures format to config format with proper type handling
            server_val = connection_data.get(
                "server_uri", connection_data.get("server", "")
            )
            port_val = connection_data.get("port", 389)
            use_ssl_val = connection_data.get("use_ssl", True)
            bind_dn_val = connection_data.get("bind_dn")
            bind_password_val = connection_data.get("bind_password")
            timeout_val = connection_data.get("timeout", 30)

            config_data = {
                "ldap_default_connection": FlextLdapModels.ConnectionConfig(
                    server=str(server_val) if server_val is not None else "",
                    port=int(port_val) if isinstance(port_val, (int, str)) else 389,
                    use_ssl=bool(use_ssl_val) if use_ssl_val is not None else True,
                    bind_dn=str(bind_dn_val) if bind_dn_val is not None else None,
                    bind_password=str(bind_password_val)
                    if bind_password_val is not None
                    else None,
                    timeout=int(timeout_val)
                    if isinstance(timeout_val, (int, str))
                    else 30,
                ),
                "ldap_use_ssl": connection_data.get("use_ssl", True),
                "ldap_bind_dn": connection_data.get("bind_dn"),
                "ldap_bind_password": connection_data.get("bind_password"),
            }

            config: FlextLdapConfig = cls.model_validate(config_data)
            return FlextResult[FlextLdapConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapConfig].fail(
                f"Failed to create config from connection data: {e}"
            )

    # =========================================================================
    # SINGLETON METHODS - Override to return correct type
    # =========================================================================

    @classmethod
    def get_global_instance(cls) -> FlextLdapConfig:
        """Get the global singleton instance of FlextLdapConfig."""
        if cls._global_instance is None:
            cls._global_instance = cls()
        return cls._global_instance

    @classmethod
    def reset_global_instance(cls) -> None:
        """Reset the global FlextLdapConfig instance (mainly for testing)."""
        cls._global_instance = None

    # =========================================================================
    # API METHODS - Methods expected by FlextLdapAPI
    # =========================================================================

    def get_effective_server_uri(self) -> str:
        """Get the effective server URI from configuration."""
        if self.ldap_default_connection and hasattr(
            self.ldap_default_connection, "server"
        ):
            server = getattr(self.ldap_default_connection, "server", None)
            if isinstance(server, str):
                return server
        return "ldap://localhost:389"

    def get_effective_bind_dn(self) -> str | None:
        """Get the effective bind DN from configuration."""
        if self.ldap_bind_dn:
            return self.ldap_bind_dn
        if self.ldap_default_connection and hasattr(
            self.ldap_default_connection, "bind_dn"
        ):
            return self.ldap_default_connection.bind_dn
        return None

    def get_effective_bind_password(self) -> str | None:
        """Get the effective bind password from configuration."""
        if self.ldap_bind_password:
            return self.ldap_bind_password.get_secret_value()
        if self.ldap_default_connection and hasattr(
            self.ldap_default_connection, "bind_password"
        ):
            bind_password = getattr(self.ldap_default_connection, "bind_password", None)
            if bind_password and hasattr(bind_password, "get_secret_value"):
                result = bind_password.get_secret_value()
                if isinstance(result, str):
                    return result
        return None

    # =========================================================================
    # FIELD VALIDATORS - Pydantic field validation
    # =========================================================================

    @field_validator("ldap_bind_dn")
    @classmethod
    def validate_bind_dn(cls, v: str | None) -> str | None:
        """Validate LDAP bind DN format."""
        if v is None:
            return v
        validation_result: FlextResult[None] = FlextLdapValidations.validate_dn(
            v, "LDAP bind DN"
        )
        if validation_result.is_failure:
            error_msg = f"Invalid LDAP bind DN format: {validation_result.error}"
            raise ValueError(error_msg)
        return v

    # =========================================================================
    # BASE METHODS - Common functionality for LDAP configurations
    # =========================================================================

    # Note: create_logging_field method removed to avoid type annotation issues
    # Use Field() directly when needed

    # Common validation helper methods
    @staticmethod
    def validate_bind_dn_field(value: str | None) -> str | None:
        """Common bind DN validation using centralized validation."""
        if value is None:
            return value

        # Basic DN validation using value objects
        dn_result: FlextResult[FlextLdapModels.DistinguishedName] = (
            FlextLdapModels.DistinguishedName.create(value)
        )
        if dn_result.is_failure:
            msg = f"Invalid LDAP bind DN format: {value}"
            raise ValueError(msg)

        return value

    @staticmethod
    def validate_configuration_consistency_base(config_instance: FlextConfig) -> None:
        """Common configuration consistency validation."""
        # Validation 1: Caching configuration
        if hasattr(config_instance, "ldap_enable_caching") and hasattr(
            config_instance, "ldap_cache_ttl"
        ):
            enable_caching = getattr(config_instance, "ldap_enable_caching", False)
            cache_ttl = getattr(config_instance, "ldap_cache_ttl", 0)
            if enable_caching and cache_ttl <= 0:
                msg = "Cache TTL must be positive when caching is enabled"
                raise ValueError(msg)

        # Validation 2: Pool configuration
        if hasattr(config_instance, "ldap_pool_size"):
            pool_size = getattr(config_instance, "ldap_pool_size", 0)
            if pool_size <= 0:
                msg = "Pool size must be positive"
                raise ValueError(msg)

        # Validation 3: Retry configuration
        if hasattr(config_instance, "ldap_retry_attempts") and hasattr(
            config_instance, "ldap_retry_delay"
        ):
            retry_attempts = getattr(config_instance, "ldap_retry_attempts", 0)
            retry_delay = getattr(config_instance, "ldap_retry_delay", 0)
            if retry_attempts > 0 and retry_delay < 0:
                msg = "Retry delay must be non-negative when retries are enabled"
                raise ValueError(msg)

    # =========================================================================
    # FACTORY METHODS - Create predefined configurations
    # =========================================================================

    @classmethod
    def create_development_ldap_config(cls) -> FlextResult[FlextLdapConfig]:
        """Create a development LDAP configuration."""
        try:
            config: FlextLdapConfig = cls.model_validate({
                "ldap_use_ssl": False,
                "ldap_enable_debug": True,
                "ldap_log_queries": True,
                "ldap_size_limit": 100,
                "ldap_time_limit": 30,
                "ldap_pool_size": 5,
                "ldap_retry_attempts": 1,
            })
            return FlextResult[FlextLdapConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapConfig].fail(
                f"Failed to create development config: {e}"
            )

    @classmethod
    def create_test_ldap_config(cls) -> FlextResult[FlextLdapConfig]:
        """Create a test LDAP configuration."""
        try:
            config: FlextLdapConfig = cls.model_validate({
                "ldap_use_ssl": False,
                "ldap_enable_debug": False,
                "ldap_log_queries": False,
                "ldap_size_limit": 50,
                "ldap_time_limit": 10,
                "ldap_pool_size": 2,
                "ldap_retry_attempts": 1,
            })
            return FlextResult[FlextLdapConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapConfig].fail(
                f"Failed to create test config: {e}"
            )

    @classmethod
    def create_production_ldap_config(cls) -> FlextResult[FlextLdapConfig]:
        """Create a production LDAP configuration."""
        try:
            config: FlextLdapConfig = cls.model_validate({
                "ldap_use_ssl": True,
                "ldap_enable_debug": False,
                "ldap_log_queries": False,
                "ldap_size_limit": 1000,
                "ldap_time_limit": 60,
                "ldap_pool_size": 20,
                "ldap_retry_attempts": 3,
            })
            return FlextResult[FlextLdapConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextLdapConfig].fail(
                f"Failed to create production config: {e}"
            )


# Removed backward compatibility alias - use FlextLdapConfig directly
__all__ = [
    "FlextLdapConfig",
]
