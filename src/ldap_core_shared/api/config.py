"""LDAP Configuration Module - Value Object with Enterprise Delegation.

This module contains the LDAPConfig Value Object that delegates to the enterprise
configuration system while providing a clean, simple interface.

TRUE FACADE PATTERN: VALUE OBJECT + ENTERPRISE DELEGATION
=========================================================

The LDAPConfig class is now a Value Object facade that delegates to the enterprise
core.config system for validation, type safety, and advanced configuration features.

DELEGATION TARGET: core.config.LDAPConnectionConfig - Enterprise LDAP configuration
with comprehensive validation, environment management, security standards.

DESIGN PATTERN: VALUE OBJECT + DELEGATION
- Immutable configuration data
- Auto-detection capabilities
- Enterprise validation and security
- Integration with existing config modules
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

# Delegate to enterprise configuration infrastructure
from ldap_core_shared.core.config import (
    LDAPConnectionConfig as EnterpriseLDAPConnectionConfig,
)

if TYPE_CHECKING:
    from pathlib import Path


class LDAPConfig:
    """LDAP Configuration Value Object - Enterprise Delegation Facade.

    TRUE FACADE PATTERN: VALUE OBJECT + ENTERPRISE DELEGATION
    ========================================================

    This class represents immutable configuration data for LDAP connections
    while delegating to the enterprise configuration system for validation,
    type safety, and advanced configuration features.

    DELEGATION TARGET: core.config.LDAPConnectionConfig - Enterprise LDAP config
    with comprehensive validation, environment management, security standards.

    RESPONSIBILITIES:
    - Store LDAP connection parameters (delegated to enterprise config)
    - Auto-detect configuration from server URLs
    - Provide sensible defaults for common scenarios
    - Enterprise-grade validation and type safety

    USAGE PATTERNS:
    - Minimal configuration (server + auth):
        >>> config = LDAPConfig(
        ...     server="ldaps://ldap.company.com",
        ...     auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
        ...     auth_password="secret",
        ...     base_dn="dc=company,dc=com"
        ... )

    - Auto-detection from URL:
        >>> config = LDAPConfig(
        ...     server="ldaps://ldap.company.com:636",  # Auto-detects TLS + port
        ...     auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
        ...     auth_password="secret",
        ...     base_dn="dc=company,dc=com"
        ... )

    - Enterprise configuration:
        >>> config = LDAPConfig(
        ...     server="ldap://primary.company.com",
        ...     auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
        ...     auth_password="secret",
        ...     base_dn="dc=company,dc=com",
        ...     pool_size=20,
        ...     timeout=60,
        ...     verify_certs=True
        ... )

    INTEGRATION:
    This Value Object delegates to enterprise configuration objects and is
    automatically converted for use with enterprise components.
    """

    def __init__(
        self,
        server: str,
        auth_dn: str,
        auth_password: str,
        base_dn: str,
        *,  # Force keyword-only arguments
        port: int | None = None,
        use_tls: bool = True,
        verify_certs: bool = True,
        timeout: int = 30,
        pool_size: int = 5,
        **kwargs: Any,
    ) -> None:
        """Initialize LDAP config with enterprise delegation.

        Args:
            server: Server URL or hostname
            auth_dn: Authentication DN
            auth_password: Authentication password
            base_dn: Base DN for operations (stored for API compatibility)
            port: Port (auto-detected from server URL if not specified)
            use_tls: Use TLS encryption (auto-detected from URL)
            verify_certs: Verify certificates in TLS mode
            timeout: Connection timeout in seconds
            pool_size: Connection pool size for enterprise mode
            **kwargs: Additional arguments passed to enterprise config

        """
        # Store base_dn for API compatibility (not used by enterprise config)
        self._base_dn = base_dn
        self._original_server = server

        # Auto-configure settings from server URL
        parsed_server, parsed_port, parsed_use_tls = self._parse_server_url(
            server,
            port,
            use_tls,
        )

        # Build server list for enterprise config
        protocol = "ldaps" if parsed_use_tls else "ldap"
        server_url = f"{protocol}://{parsed_server}:{parsed_port}"

        # Delegate to enterprise LDAP connection configuration
        self._enterprise_config = EnterpriseLDAPConnectionConfig(
            servers=[server_url],
            bind_dn=auth_dn,
            bind_password=auth_password,
            use_tls=parsed_use_tls,
            tls_verify=verify_certs,
            connection_timeout=float(timeout),
            pool_size=pool_size,
            **kwargs,
        )

    def _parse_server_url(
        self,
        server: str,
        port: int | None,
        use_tls: bool,
    ) -> tuple[str, int, bool]:
        """Parse server URL for auto-configuration.

        Auto-detection rules:
        - ldaps:// URLs → use_tls=True, port=636 (if not specified)
        - ldap:// URLs → use_tls=False, port=389 (if not specified)
        - Plain hostnames → use current use_tls setting, default ports
        """
        parsed_server = server
        parsed_port = port
        parsed_use_tls = use_tls

        if "://" in server:
            # Parse URL for auto-configuration
            if server.startswith("ldaps://"):
                parsed_use_tls = True
                parsed_port = port or 636
            elif server.startswith("ldap://"):
                parsed_use_tls = False
                parsed_port = port or 389

            # Extract hostname from URL
            url_parts = server.split("://")[1]
            if ":" in url_parts:
                parsed_server = url_parts.split(":")[0]
                if not parsed_port:
                    parsed_port = int(url_parts.split(":")[1])
            else:
                parsed_server = url_parts
        # Plain hostname - only set port if not already specified
        elif parsed_port is None:
            parsed_port = 636 if parsed_use_tls else 389

        return parsed_server, parsed_port, parsed_use_tls

    @property
    def server(self) -> str:
        """Get server hostname from enterprise config."""
        if self._enterprise_config.servers:
            server_url = self._enterprise_config.servers[0]
            return server_url.split("://")[1].split(":")[0]
        return self._original_server.split("://")[-1].split(":")[0]

    @property
    def auth_dn(self) -> str:
        """Get authentication DN from enterprise config."""
        return self._enterprise_config.bind_dn or ""

    @property
    def auth_password(self) -> str:
        """Get authentication password from enterprise config."""
        if self._enterprise_config.bind_password:
            return self._enterprise_config.bind_password.get_secret_value()
        return ""

    @property
    def base_dn(self) -> str:
        """Get base DN for API compatibility."""
        return self._base_dn

    @property
    def port(self) -> int:
        """Get port from enterprise config."""
        if self._enterprise_config.servers:
            server_url = self._enterprise_config.servers[0]
            if ":" in server_url.split("://")[1]:
                return int(server_url.split(":")[-1])
            return 636 if self._enterprise_config.use_tls else 389
        return 389

    @property
    def use_tls(self) -> bool:
        """Get TLS setting from enterprise config."""
        return self._enterprise_config.use_tls

    @property
    def verify_certs(self) -> bool:
        """Get certificate verification setting from enterprise config."""
        return self._enterprise_config.tls_verify

    @property
    def timeout(self) -> int:
        """Get timeout from enterprise config."""
        return int(self._enterprise_config.connection_timeout)

    @property
    def pool_size(self) -> int:
        """Get pool size from enterprise config."""
        return self._enterprise_config.pool_size


@dataclass
class MigrationConfig:
    """Generic migration configuration for LDAP migration projects.

    This configuration class provides common migration settings that can be
    used by any LDAP migration project (like client-a-OUD-Migration).
    """

    # Source and output paths
    source_ldif_path: str
    output_path: str

    # Migration processing settings
    batch_size: int = 1000
    max_workers: int = 4
    continue_on_errors: bool = False
    generate_summary: bool = True
    enable_transformations: bool = True

    # LDAP operation settings
    search_timeout: int = 30
    bind_timeout: int = 30
    page_size: int = 1000
    scope: str = "SUBTREE"

    # Validation settings
    enable_strict_validation: bool = True
    validation_stop_on_error: bool = False
    max_validation_errors: int = 100

    # Output formatting
    output_encoding: str = "utf-8"
    line_wrap_length: int = 76
    include_headers: bool = True

    # Additional required fields for client-a compatibility
    base_dn: str = ""
    log_level: str = "INFO"
    rules_file_path: str = "rules.json"

    @property
    def source_ldif_path_obj(self) -> Path:
        """Get source path as Path object."""
        from pathlib import Path

        return Path(self.source_ldif_path)

    @property
    def output_path_obj(self) -> Path:
        """Get output path as Path object."""
        from pathlib import Path

        return Path(self.output_path)


def validate_configuration_value(name: str, value: any) -> None:
    """Validate configuration value is not None or empty.

    Args:
        name: Configuration parameter name
        value: Configuration value to validate

    Raises:
        ValueError: If value is None or empty

    """
    if value is None:
        msg = f"Configuration parameter '{name}' cannot be None"
        raise ValueError(msg)

    if isinstance(value, str) and not value.strip():
        msg = f"Configuration parameter '{name}' cannot be empty"
        raise ValueError(msg)


def load_migration_config_from_env(env_prefix: str = "") -> MigrationConfig:
    """Load migration configuration from environment variables.

    Args:
        env_prefix: Optional prefix for environment variables

    Returns:
        MigrationConfig instance with values from environment

    Raises:
        ValueError: If required environment variables are missing

    """
    import os

    # Get required environment variables
    source_path = os.getenv(f"{env_prefix}SOURCE_LDIF_PATH")
    output_path = os.getenv(f"{env_prefix}OUTPUT_PATH")
    base_dn = os.getenv(f"{env_prefix}BASE_DN", "")

    if not source_path:
        msg = "SOURCE_LDIF_PATH environment variable is required"
        raise ValueError(msg)
    if not output_path:
        msg = "OUTPUT_PATH environment variable is required"
        raise ValueError(msg)

    # Get optional environment variables with defaults
    batch_size = int(
        os.getenv(
            f"{env_prefix}MIGRATION_BATCH_SIZE",
            os.getenv(f"{env_prefix}BATCH_SIZE", "1000"),
        ),
    )
    max_workers = int(
        os.getenv(
            f"{env_prefix}MIGRATION_MAX_WORKERS",
            os.getenv(f"{env_prefix}MAX_WORKERS", "4"),
        ),
    )
    search_timeout = int(
        os.getenv(
            f"{env_prefix}LDAP_SEARCH_TIMEOUT",
            os.getenv(f"{env_prefix}SEARCH_TIMEOUT", "30"),
        ),
    )
    bind_timeout = int(os.getenv(f"{env_prefix}LDAP_BIND_TIMEOUT", "30"))
    page_size = int(os.getenv(f"{env_prefix}LDAP_PAGE_SIZE", "1000"))
    scope = os.getenv(f"{env_prefix}LDAP_SCOPE", "SUBTREE")

    continue_on_errors = (
        os.getenv(
            f"{env_prefix}MIGRATION_CONTINUE_ON_ERRORS",
            os.getenv(f"{env_prefix}CONTINUE_ON_ERRORS", "false"),
        ).lower()
        == "true"
    )
    generate_summary = (
        os.getenv(
            f"{env_prefix}MIGRATION_GENERATE_SUMMARY",
            os.getenv(f"{env_prefix}GENERATE_SUMMARY", "true"),
        ).lower()
        == "true"
    )
    enable_transformations = (
        os.getenv(f"{env_prefix}ENABLE_TRANSFORMATIONS", "true").lower() == "true"
    )
    enable_strict_validation = (
        os.getenv(f"{env_prefix}ENABLE_STRICT_VALIDATION", "true").lower() == "true"
    )

    log_level = os.getenv(f"{env_prefix}LOG_LEVEL", "INFO")

    return MigrationConfig(
        source_ldif_path=source_path,
        output_path=output_path,
        base_dn=base_dn,
        batch_size=batch_size,
        max_workers=max_workers,
        search_timeout=search_timeout,
        bind_timeout=bind_timeout,
        page_size=page_size,
        scope=scope,
        continue_on_errors=continue_on_errors,
        generate_summary=generate_summary,
        enable_transformations=enable_transformations,
        enable_strict_validation=enable_strict_validation,
        log_level=log_level,
    )
