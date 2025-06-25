"""Base configuration management for LDAP projects.

Provides standardized configuration loading, validation, and management
across tap-ldap, target-ldap, and flx-ldap projects.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, TypeVar, Union

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

if TYPE_CHECKING:
    from pathlib import Path

# Configuration constants
MAX_PORT_NUMBER = 65535
MIN_PORT_NUMBER = 1
MAX_POOL_SIZE = 100
MIN_POOL_SIZE = 1
MAX_BATCH_SIZE = 10000
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


class LDAPServerConfig(BaseConfig):
    """LDAP server connection configuration."""

    host: str = Field(..., description="LDAP server hostname")
    port: int = Field(default=389, description="LDAP server port")
    bind_dn: str = Field(..., description="Bind DN for authentication")
    password: str = Field(..., description="Password for authentication", repr=False)
    base_dn: str = Field(..., description="Base DN for operations")
    use_ssl: bool = Field(default=False, description="Use SSL/TLS connection")
    use_tls: bool = Field(default=False, description="Use StartTLS")
    timeout: int = Field(default=30, description="Connection timeout in seconds")
    pool_size: int = Field(default=10, description="Connection pool size")

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        """Validate port is in valid range."""
        if not MIN_PORT_NUMBER <= v <= MAX_PORT_NUMBER:
            msg = "Port must be between 1 and 65535"
            raise ValueError(msg)
        return v

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        """Validate timeout is positive."""
        if v <= 0:
            msg = "Timeout must be positive"
            raise ValueError(msg)
        return v

    @field_validator("pool_size")
    @classmethod
    def validate_pool_size(cls, v: int) -> int:
        """Validate pool size is reasonable."""
        if not MIN_POOL_SIZE <= v <= MAX_POOL_SIZE:
            msg = "Pool size must be between 1 and 100"
            raise ValueError(msg)
        return v

    def to_connection_string(self) -> str:
        """Generate connection string."""
        protocol = "ldaps" if self.use_ssl else "ldap"
        return f"{protocol}://{self.host}:{self.port}"


class ProcessingConfig(BaseConfig):
    """Processing and performance configuration."""

    batch_size: int = Field(default=1000, description="Batch processing size")
    max_workers: int = Field(default=4, description="Maximum worker threads")
    chunk_size: int = Field(default=100, description="Chunk size for processing")
    memory_limit_mb: int = Field(default=512, description="Memory limit in MB")
    retry_attempts: int = Field(default=3, description="Number of retry attempts")
    retry_delay: float = Field(default=1.0, description="Retry delay in seconds")

    @field_validator("batch_size")
    @classmethod
    def validate_batch_size(cls, v: int) -> int:
        """Validate batch size is reasonable."""
        if not MIN_BATCH_SIZE <= v <= MAX_BATCH_SIZE:
            msg = "Batch size must be between 1 and 10000"
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


class LoggingConfig(BaseConfig):
    """Logging configuration."""

    level: str = Field(default="INFO", description="Log level")
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format",
    )
    file_path: Union[Path, None] = Field(None, description="Log file path")
    max_file_size_mb: int = Field(default=100, description="Max log file size in MB")
    backup_count: int = Field(default=5, description="Number of backup log files")
    enable_console: bool = Field(default=True, description="Enable console logging")

    @field_validator("level")
    @classmethod
    def validate_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            msg = f"Log level must be one of: {valid_levels}"
            raise ValueError(msg)
        return v_upper


class SecurityConfig(BaseConfig):
    """Security and authentication configuration."""

    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    ca_cert_file: Union[Path, None] = Field(None, description="CA certificate file")
    client_cert_file: Union[Path, None] = Field(
        None, description="Client certificate file"
    )
    client_key_file: Union[Path, None] = Field(None, description="Client key file")
    encryption_key: Union[str, None] = Field(
        None, description="Encryption key", repr=False
    )
    mask_sensitive_data: bool = Field(
        default=True,
        description="Mask sensitive data in logs",
    )

    @field_validator("ca_cert_file", "client_cert_file", "client_key_file")
    @classmethod
    def validate_cert_files(cls, v: Union[Path, None]) -> Union[Path, None]:
        """Validate certificate files exist if specified."""
        if v is not None and not v.exists():
            msg = f"Certificate file does not exist: {v}"
            raise ValueError(msg)
        return v


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
        file_data: dict = {}
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
        errors: list = []
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
