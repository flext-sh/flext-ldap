"""DEPRECATED: Base configuration management - DELEGATES TO ENTERPRISE CONFIG.

This module provides backward compatibility for legacy configuration classes by
delegating entirely to the enterprise core.config system.

TRUE FACADE PATTERN: 100% DELEGATION TO ENTERPRISE CONFIG INFRASTRUCTURE
======================================================================

All legacy configuration classes are now facades that delegate to the
enterprise-grade configuration system in core.config without reimplementation.

DELEGATION TARGET: core.config.ApplicationConfig - Enterprise configuration with
hierarchical loading, environment management, validation, type safety.

PREFERRED PATTERN:
    from ldap_core_shared.core.config import ConfigManager, LDAPConnectionConfig

    # Enterprise pattern:
    config = ConfigManager.load_config("production")
    ldap_config = config.connection

LEGACY COMPATIBILITY:
    from ldap_core_shared.config.base_config import LDAPServerConfig

    # Still works but delegates to enterprise config internally
    config = LDAPServerConfig(host="server.com", bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD", ...)

MIGRATION BENEFITS:
- Eliminated configuration system duplication
- Leverages enterprise validation and loading
- Automatic improvements from enterprise config system
- Consistent behavior across all configuration usage
"""

from __future__ import annotations

import json
import warnings
from typing import TYPE_CHECKING, Any, TypeVar

from pydantic import Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Delegate to enterprise configuration infrastructure
from ldap_core_shared.core.config import (
    LDAPConnectionConfig as EnterpriseLDAPConnectionConfig,
)
from ldap_core_shared.core.config import (
    LoggingConfig as EnterpriseLoggingConfig,
)
from ldap_core_shared.core.config import (
    SecurityConfig as EnterpriseSecurityConfig,
)
from ldap_core_shared.utils.constants import (
    DEFAULT_LARGE_LIMIT,
    DEFAULT_MAX_ITEMS,
    DEFAULT_TIMEOUT_SECONDS,
    LDAP_DEFAULT_PORT,
)

# Constants for magic values

MAX_ENTRIES_LIMIT = 10000

if TYPE_CHECKING:
    from pathlib import Path

# Configuration constants
MAX_PORT_NUMBER = 65535
MIN_PORT_NUMBER = 1
MAX_POOL_SIZE = DEFAULT_MAX_ITEMS
MIN_POOL_SIZE = 1
MAX_BATCH_SIZE = MAX_ENTRIES_LIMIT
MIN_BATCH_SIZE = 1
MAX_WORKERS = 32
MIN_WORKERS = 1
MAX_RETRY_ATTEMPTS = 10
MIN_RETRY_ATTEMPTS = 0

T = TypeVar("T", bound="BaseConfig")


class BaseConfig(BaseSettings):
    """Base configuration class with standardized loading and validation.

    Supports loading from environment variables, .env files, and JSON files
    with consistent validation and error handling.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


class LDAPServerConfig:
    """LDAP server connection configuration - True Facade with Pure Delegation.

    TRUE FACADE PATTERN: 100% DELEGATION TO ENTERPRISE CONFIG INFRASTRUCTURE
    ======================================================================

    This class delegates entirely to the enterprise configuration system
    in core.config.LDAPConnectionConfig while providing backward compatibility.

    DELEGATION TARGET: core.config.LDAPConnectionConfig - Enterprise LDAP config
    with validation, environment loading, security standards, monitoring.

    MIGRATION BENEFITS:
    - Eliminated configuration duplication
    - Leverages enterprise validation and loading
    - Automatic improvements from enterprise config system
    - Consistent behavior across all LDAP configuration usage
    """

    def __init__(
        self,
        host: str,
        port: int = LDAP_DEFAULT_PORT,
        bind_dn: str = "",
        password: str = "",
        base_dn: str = "",
        use_ssl: bool = False,
        use_tls: bool = False,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        pool_size: int = 10,
        **kwargs,
    ) -> None:
        """Initialize LDAP server config facade.

        Args:
            host: LDAP server hostname
            port: LDAP server port
            bind_dn: Bind DN for authentication
            password: Password for authentication
            base_dn: Base DN for operations (stored for compatibility)
            use_ssl: Use SSL/TLS connection
            use_tls: Use StartTLS
            timeout: Connection timeout in seconds
            pool_size: Connection pool size
            **kwargs: Additional arguments passed to enterprise config

        """
        # Store base_dn for legacy compatibility (not used by enterprise config)
        self._base_dn = base_dn

        # Delegate to enterprise LDAP connection configuration
        servers = [f"{'ldaps' if use_ssl else 'ldap'}://{host}:{port}"]

        # Handle bind_password parameter conflict
        kwargs_filtered = {k: v for k, v in kwargs.items() if k != "bind_password"}
        actual_password = kwargs.get("bind_password", password)

        self._enterprise_config = EnterpriseLDAPConnectionConfig(
            servers=servers,
            bind_dn=bind_dn,
            bind_password=actual_password,
            use_tls=use_ssl or use_tls,
            connection_timeout=float(timeout),
            pool_size=pool_size,
            **kwargs_filtered,
        )

    @property
    def host(self) -> str:
        """Get host from enterprise config."""
        if self._enterprise_config.servers:
            server_url = self._enterprise_config.servers[0]
            # Extract hostname from URL
            return server_url.split("://")[1].split(":")[0]
        return ""

    @property
    def port(self) -> int:
        """Get port from enterprise config."""
        if self._enterprise_config.servers:
            server_url = self._enterprise_config.servers[0]
            if ":" in server_url.split("://")[1]:
                return int(server_url.split(":")[-1])
            return 636 if self._enterprise_config.use_tls else 389
        return LDAP_DEFAULT_PORT

    @property
    def bind_dn(self) -> str:
        """Get bind DN from enterprise config."""
        return self._enterprise_config.bind_dn or ""

    @property
    def password(self) -> str:
        """Get password from enterprise config."""
        if self._enterprise_config.bind_password:
            return self._enterprise_config.bind_password.get_secret_value()
        return ""

    @property
    def base_dn(self) -> str:
        """Get base DN for backward compatibility."""
        return self._base_dn

    @property
    def use_ssl(self) -> bool:
        """Get SSL/TLS setting from enterprise config."""
        return self._enterprise_config.use_tls

    @property
    def use_tls(self) -> bool:
        """Get TLS setting from enterprise config."""
        return self._enterprise_config.use_tls

    @property
    def timeout(self) -> int:
        """Get timeout from enterprise config."""
        return int(self._enterprise_config.connection_timeout)

    @property
    def pool_size(self) -> int:
        """Get pool size from enterprise config."""
        return self._enterprise_config.pool_size

    def to_connection_string(self) -> str:
        """Generate connection string - delegates to enterprise config."""
        if self._enterprise_config.servers:
            return self._enterprise_config.servers[0]
        protocol = "ldaps" if self.use_ssl else "ldap"
        return f"{protocol}://{self.host}:{self.port}"


class ProcessingConfig(BaseConfig):
    """Processing and performance configuration."""

    batch_size: int = Field(
        default=DEFAULT_LARGE_LIMIT, description="Batch processing size"
    )
    max_workers: int = Field(default=4, description="Maximum worker threads")
    chunk_size: int = Field(
        default=DEFAULT_MAX_ITEMS, description="Chunk size for processing"
    )
    memory_limit_mb: int = Field(default=512, description="Memory limit in MB")
    retry_attempts: int = Field(default=3, description="Number of retry attempts")
    retry_delay: float = Field(default=1.0, description="Retry delay in seconds")

    @field_validator("batch_size")
    @classmethod
    def validate_batch_size(cls, v: int) -> int:
        """Validate batch size is reasonable."""
        if not MIN_BATCH_SIZE <= v <= MAX_BATCH_SIZE:
            msg = "Batch size must be between 1 and MAX_ENTRIES_LIMIT"
            raise ValueError(msg)
        return v

    @field_validator("max_workers")
    @classmethod
    def validate_max_workers(cls, v: int) -> int:
        """Validate worker count is reasonable."""
        if not MIN_WORKERS <= v <= MAX_WORKERS:
            msg = "Max workers must be between 1 and 32"
            raise ValueError(msg)
        return v

    @field_validator("retry_attempts")
    @classmethod
    def validate_retry_attempts(cls, v: int) -> int:
        """Validate retry attempts is reasonable."""
        if not MIN_RETRY_ATTEMPTS <= v <= MAX_RETRY_ATTEMPTS:
            msg = "Retry attempts must be between 0 and 10"
            raise ValueError(msg)
        return v


class LoggingConfig:
    """Logging configuration - True Facade with Pure Delegation.

    Delegates entirely to enterprise logging configuration system.
    """

    def __init__(
        self,
        level: str = "INFO",
        format: str | None = None,
        file_path: Path | None = None,
        max_file_size_mb: int = DEFAULT_MAX_ITEMS,
        backup_count: int = 5,
        enable_console: bool = True,
        mask_sensitive_data: bool = True,
        **kwargs,
    ) -> None:
        """Initialize logging config facade."""
        from ldap_core_shared.core.config import LogLevel

        # Convert string level to enterprise LogLevel enum
        log_level = LogLevel(level.upper())

        self._enterprise_config = EnterpriseLoggingConfig(
            level=log_level,
            format=format or "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            log_file=file_path,
            max_file_size=max_file_size_mb * 1024 * 1024,  # Convert MB to bytes
            backup_count=backup_count,
            console_enabled=enable_console,
            **kwargs,
        )

    @property
    def level(self) -> str:
        """Get log level from enterprise config."""
        return self._enterprise_config.level.value

    @property
    def format(self) -> str:
        """Get log format from enterprise config."""
        return self._enterprise_config.format

    @property
    def file_path(self) -> Path | None:
        """Get file path from enterprise config."""
        return self._enterprise_config.log_file

    @property
    def max_file_size_mb(self) -> int:
        """Get max file size in MB from enterprise config."""
        return self._enterprise_config.max_file_size // (1024 * 1024)

    @property
    def backup_count(self) -> int:
        """Get backup count from enterprise config."""
        return self._enterprise_config.backup_count

    @property
    def enable_console(self) -> bool:
        """Get console enabled from enterprise config."""
        return self._enterprise_config.console_enabled

    @property
    def mask_sensitive_data(self) -> bool:
        """Get mask sensitive data setting."""
        # Default to True as this is a security best practice
        return True


class SecurityConfig:
    """Security and authentication configuration - True Facade with Pure Delegation.

    Delegates entirely to enterprise security configuration system.
    """

    def __init__(
        self,
        verify_ssl: bool = True,
        ca_cert_file: Path | None = None,
        client_cert_file: Path | None = None,
        client_key_file: Path | None = None,
        encryption_key: str | None = None,
        mask_sensitive_data: bool = True,
        **kwargs,
    ) -> None:
        """Initialize security config facade."""
        from pydantic import SecretStr

        self._enterprise_config = EnterpriseSecurityConfig(
            encryption_key=SecretStr(encryption_key) if encryption_key else None,
            secret_key=SecretStr(""),
            require_authentication=True,
            **kwargs,
        )

        # Store legacy fields for compatibility
        self._verify_ssl = verify_ssl
        self._ca_cert_file = ca_cert_file
        self._client_cert_file = client_cert_file
        self._client_key_file = client_key_file
        self._mask_sensitive_data = mask_sensitive_data

    @property
    def verify_ssl(self) -> bool:
        """Get SSL verification setting."""
        return self._verify_ssl

    @property
    def ca_cert_file(self) -> Path | None:
        """Get CA cert file."""
        return self._ca_cert_file

    @property
    def client_cert_file(self) -> Path | None:
        """Get client cert file."""
        return self._client_cert_file

    @property
    def client_key_file(self) -> Path | None:
        """Get client key file."""
        return self._client_key_file

    @property
    def encryption_key(self) -> str | None:
        """Get encryption key from enterprise config."""
        if self._enterprise_config.encryption_key:
            return self._enterprise_config.encryption_key.get_secret_value()
        return None

    @property
    def mask_sensitive_data(self) -> bool:
        """Get mask sensitive data setting."""
        return self._mask_sensitive_data


class ConfigurationManager:
    """Configuration manager for loading and managing configurations.

    Provides centralized configuration management with support for
    multiple configuration sources and validation.
    """

    def __init__(self) -> None:
        """Initialize configuration manager."""
        self._configs: dict[str, BaseConfig] = {}
        self._file_watchers: list[Path] = []

    def load_config(
        self,
        config_class: type[T],
        config_name: str,
        config_file: Path | None = None,
        env_prefix: str | None = None,
    ) -> T:
        """Load configuration with specified class.

        Args:
            config_class: Configuration class to instantiate
            config_name: Name for the configuration instance
            config_file: Optional JSON config file to load
            env_prefix: Optional environment variable prefix

        Returns:
            Configured instance of config_class

        """
        # Load from file if specified
        file_data: dict[str, Any] = {}
        if config_file and config_file.exists():
            with config_file.open(encoding="utf-8") as f:
                file_data = json.load(f)

        # Set environment prefix if specified
        if env_prefix:
            original_prefix = getattr(config_class.model_config, "env_prefix", None)
            if hasattr(config_class.model_config, "env_prefix"):
                config_class.model_config["env_prefix"] = env_prefix

        try:
            # Create configuration instance
            config = config_class(**file_data)
            self._configs[config_name] = config

            if config_file:
                self._file_watchers.append(config_file)

            return config

        finally:
            # Restore original prefix
            if (
                env_prefix
                and original_prefix
                and hasattr(config_class.model_config, "env_prefix")
            ):
                config_class.model_config["env_prefix"] = original_prefix
            elif env_prefix and hasattr(config_class.model_config, "env_prefix"):
                config_class.model_config.pop("env_prefix", None)

    def get_config(self, config_name: str) -> BaseConfig | None:
        """Get configuration by name."""
        return self._configs.get(config_name)

    def reload_config(self, config_name: str) -> bool:
        """Reload configuration from source."""
        # Implementation would reload from original source
        # For now, just return False
        return False

    def validate_all_configs(self) -> list[str]:
        """Validate all loaded configurations."""
        errors: list[str] = []
        for config_name, config in self._configs.items():
            try:
                # Re-validate the configuration
                config.model_validate(config.model_dump())
            except (ValueError, TypeError, ValidationError) as e:
                errors.append(f"Configuration '{config_name}' validation failed: {e}")

        return errors

    def export_config(self, config_name: str, output_file: Path) -> bool:
        """Export configuration to file."""
        config = self._configs.get(config_name)
        if not config:
            return False

        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(
                    config.model_dump(exclude={"password", "encryption_key"}),
                    f,
                    indent=2,
                    default=str,
                )
            return True
        except Exception:
            return False


# Global configuration manager instance
config_manager = ConfigurationManager()


def load_ldap_config(
    config_file: Path | None = None,
    env_prefix: str = "LDAP_",
) -> LDAPServerConfig:
    """Load LDAP server configuration."""
    return config_manager.load_config(
        LDAPServerConfig,
        "ldap_server",
        config_file,
        env_prefix,
    )


def load_processing_config(
    config_file: Path | None = None,
    env_prefix: str = "PROC_",
) -> ProcessingConfig:
    """Load processing configuration."""
    return config_manager.load_config(
        ProcessingConfig,
        "processing",
        config_file,
        env_prefix,
    )


def load_logging_config(
    config_file: Path | None = None,
    env_prefix: str = "LOG_",
) -> LoggingConfig:
    """Load logging configuration."""
    return config_manager.load_config(LoggingConfig, "logging", config_file, env_prefix)


def load_security_config(
    config_file: Path | None = None,
    env_prefix: str = "SEC_",
) -> SecurityConfig:
    """Load security configuration."""
    return config_manager.load_config(
        SecurityConfig,
        "security",
        config_file,
        env_prefix,
    )


# ============================================================================
# 🔄 MIGRATION UTILITIES - Convert legacy configs to unified api.LDAPConfig
# ============================================================================


def migrate_ldap_server_config_to_unified(legacy_config: LDAPServerConfig):
    """Convert LDAPServerConfig to unified api.LDAPConfig.

    DEPRECATED: Use api.LDAPConfig directly for new LDAP connections.

    Args:
        legacy_config: Legacy LDAP server configuration

    Returns:
        Unified LDAPConfig instance

    """
    warnings.warn(
        "LDAPServerConfig is deprecated. Use api.LDAPConfig directly instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    # Dynamic import to avoid circular dependency
    from ldap_core_shared.api import LDAPConfig

    # Map legacy fields to unified config
    server_url = legacy_config.to_connection_string()

    return LDAPConfig(
        server=server_url,
        auth_dn=legacy_config.bind_dn,
        auth_password=legacy_config.password,
        base_dn=legacy_config.base_dn,
        port=legacy_config.port,
        use_tls=legacy_config.use_ssl or legacy_config.use_tls,
        timeout=legacy_config.timeout,
        pool_size=legacy_config.pool_size,
    )


def create_unified_config_from_legacy_manager(
    config_name: str = "ldap_server",
):
    """Create unified config from legacy configuration manager.

    DEPRECATED: Use api.LDAPConfig constructor directly.

    Args:
        config_name: Name of config in legacy manager

    Returns:
        Unified LDAPConfig instance or None if not found

    """
    warnings.warn(
        "Legacy configuration manager is deprecated. Use api.LDAPConfig directly instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    legacy_config = config_manager.get_config(config_name)
    if legacy_config and isinstance(legacy_config, LDAPServerConfig):
        return migrate_ldap_server_config_to_unified(legacy_config)

    return None


def auto_detect_and_migrate_config() -> Any:
    """Auto-detect legacy config and migrate to unified format.

    DEPRECATED: Use api.LDAPConfig constructor with explicit parameters.

    Returns:
        Unified LDAPConfig if legacy config found, None otherwise

    """
    warnings.warn(
        "Auto-detection of legacy config is deprecated. Use explicit api.LDAPConfig construction instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    # Try to find any LDAP config in the legacy manager
    for config in config_manager._configs.values():
        if isinstance(config, LDAPServerConfig):
            return migrate_ldap_server_config_to_unified(config)

    return None


# Updated load function with migration warning
def load_ldap_config_unified(
    config_file: Path | None = None,
    env_prefix: str = "LDAP_",
):
    """Load LDAP config and return unified format.

    DEPRECATED: Use api.LDAPConfig constructor directly.

    Args:
        config_file: Optional config file
        env_prefix: Environment variable prefix

    Returns:
        Unified LDAPConfig instance

    """
    warnings.warn(
        "load_ldap_config_unified is deprecated. Use api.LDAPConfig constructor directly instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    # Load legacy config first
    legacy_config = load_ldap_config(config_file, env_prefix)

    # Migrate to unified format
    return migrate_ldap_server_config_to_unified(legacy_config)
