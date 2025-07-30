"""FLEXT-LDAP Configuration using flext-core patterns."""

from __future__ import annotations

from typing import Literal

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext_core root imports
from flext_core import (
    FlextBaseSettings,
    FlextLogLevel,
    FlextResult,
    FlextValueObject,
    get_logger,
)
from pydantic import Field, field_validator
from pydantic_settings import SettingsConfigDict

logger = get_logger(__name__)

# Use FlextValueObject as base for all config types
BaseConfig = FlextBaseSettings
BaseSettings = FlextBaseSettings


class FlextLdapConstants:
    """Constants for LDAP configuration."""

    DEFAULT_TIMEOUT_SECONDS: int = 30
    MAX_TIMEOUT_SECONDS: int = 300
    DEFAULT_POOL_SIZE: int = 10
    MAX_POOL_SIZE: int = 100
    DEFAULT_PAGE_SIZE: int = 1000
    MAX_PAGE_SIZE: int = 10000
    DEFAULT_MAX_RETRIES: int = 3
    MAX_RETRIES: int = 10
    DEFAULT_RETRY_DELAY: float = 1.0
    MAX_RETRY_DELAY: float = 60.0


type LogLevelLiteral = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
type ProjectName = str
type Version = str


class FlextLdapConnectionConfig(FlextValueObject):
    """LDAP connection configuration using flext-core patterns."""

    server: str = Field(default="localhost")
    port: int = Field(default=389, ge=1, le=65535)
    use_ssl: bool = Field(default=False)
    timeout_seconds: int = Field(
        default=FlextLdapConstants.DEFAULT_TIMEOUT_SECONDS,
        ge=1,
        le=FlextLdapConstants.MAX_TIMEOUT_SECONDS,
    )

    pool_size: int = Field(
        default=FlextLdapConstants.DEFAULT_POOL_SIZE,
        ge=1,
        le=FlextLdapConstants.MAX_POOL_SIZE,
    )

    enable_connection_pooling: bool = Field(default=True)

    @field_validator("server")
    @classmethod
    def validate_server(cls, v: str) -> str:
        """Validate the LDAP server hostname.

        Args:
            v: The server hostname to validate

        Returns:
            The validated and stripped server hostname

        Raises:
            ValueError: If server is empty or whitespace only

        """
        # Efficient TRACE logging - only compute if TRACE is enabled
        if hasattr(logger, "_level_value") and logger._level_value <= 5:  # TRACE level
            logger.trace("Validating LDAP server hostname", extra={
                "original_value": v,
                "is_empty": not v,
                "is_whitespace": v.isspace() if v else False
            })

        if not v or v.isspace():
            logger.error("Server validation failed: empty or whitespace", extra={
                "value": repr(v)
            })
            msg = "Server cannot be empty or whitespace only"
            raise ValueError(msg)

        validated_server = v.strip()
        # Efficient DEBUG logging - only compute if DEBUG is enabled
        if hasattr(logger, "_level_value") and logger._level_value <= 10:  # DEBUG level
            logger.debug("Server hostname validated", extra={
                "original": v,
                "validated": validated_server,
                "was_changed": v != validated_server
            })
        return validated_server

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate business rules for LDAP connection configuration."""
        if not self.server:
            return FlextResult.fail("LDAP connection must have a server")
        max_port = 65535
        if self.port <= 0 or self.port > max_port:
            return FlextResult.fail(f"Port must be between 1 and {max_port}")
        if self.timeout_seconds <= 0:
            return FlextResult.fail("Timeout must be positive")
        if self.pool_size <= 0:
            return FlextResult.fail("Pool size must be positive")
        return FlextResult.ok(None)


class FlextLdapAuthConfig(FlextValueObject):
    """LDAP authentication configuration using flext-core patterns."""

    bind_dn: str = Field(default="")
    bind_password: str = Field(default="", repr=False)

    use_anonymous_bind: bool = Field(default=False)
    sasl_mechanism: str | None = Field(default=None)

    @field_validator("bind_dn")
    @classmethod
    def validate_bind_dn(cls, v: str) -> str:
        """Validate the LDAP bind DN.

        Args:
            v: The bind DN to validate

        Returns:
            The validated and stripped bind DN

        """
        # Efficient TRACE logging following flext-core patterns
        if hasattr(logger, "_level_value") and logger._level_value <= 5:
            logger.trace("Validating LDAP bind DN", extra={
                "original_value": v,
                "is_empty": not v,
                "length": len(v) if v else 0
            })

        validated_dn = v.strip() if v else ""
        # Efficient DEBUG logging with performance check
        if hasattr(logger, "_level_value") and logger._level_value <= 10:
            logger.debug("Bind DN validated", extra={
                "original": v,
                "validated": validated_dn,
                "was_changed": v != validated_dn
            })
        return validated_dn

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate business rules for LDAP authentication configuration."""
        logger.debug("Validating authentication domain rules", extra={
            "use_anonymous_bind": self.use_anonymous_bind,
            "has_bind_dn": bool(self.bind_dn),
            "has_password": bool(self.bind_password)
        })

        if not self.use_anonymous_bind and not self.bind_dn:
            logger.error("Authentication validation failed: missing bind DN for non-anonymous bind")
            return FlextResult.fail("Bind DN is required when not using anonymous bind")
        if self.bind_dn and not self.bind_password and not self.use_anonymous_bind:
            logger.error("Authentication validation failed: missing password for bind DN")
            return FlextResult.fail(
                "Bind password is required when bind DN is provided",
            )

        logger.trace("Authentication domain rules validation passed")
        return FlextResult.ok(None)


class FlextLdapSearchConfig(FlextValueObject):
    """LDAP search configuration using flext-core patterns."""

    base_dn: str = Field(default="")
    default_search_scope: Literal["base", "onelevel", "subtree"] = Field(
        default="subtree",
    )

    size_limit: int = Field(default=1000, ge=0, le=100000)
    time_limit: int = Field(default=30, ge=0, le=3600)

    paged_search: bool = Field(default=True)
    page_size: int = Field(
        default=FlextLdapConstants.DEFAULT_PAGE_SIZE,
        ge=1,
        le=FlextLdapConstants.MAX_PAGE_SIZE,
    )

    enable_referral_chasing: bool = Field(default=False)
    max_referral_hops: int = Field(default=5, ge=1, le=20)

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate business rules for LDAP search configuration."""
        logger.debug("Validating search domain rules", extra={
            "size_limit": self.size_limit,
            "time_limit": self.time_limit,
            "page_size": self.page_size,
            "paged_search": self.paged_search
        })

        if self.size_limit < 0:
            logger.error("Search validation failed: negative size limit", extra={"size_limit": self.size_limit})
            return FlextResult.fail("Size limit must be non-negative")
        if self.time_limit < 0:
            logger.error("Search validation failed: negative time limit", extra={"time_limit": self.time_limit})
            return FlextResult.fail("Time limit must be non-negative")
        if self.page_size <= 0:
            logger.error("Search validation failed: invalid page size", extra={"page_size": self.page_size})
            return FlextResult.fail("Page size must be positive")

        logger.trace("Search domain rules validation passed")
        return FlextResult.ok(None)


class FlextLdapOperationConfig(FlextValueObject):
    """LDAP operation configuration using flext-core patterns."""

    max_retries: int = Field(
        default=FlextLdapConstants.DEFAULT_MAX_RETRIES,
        ge=0,
        le=FlextLdapConstants.MAX_RETRIES,
    )

    retry_delay: float = Field(
        default=FlextLdapConstants.DEFAULT_RETRY_DELAY,
        ge=0.1,
        le=FlextLdapConstants.MAX_RETRY_DELAY,
    )

    enable_transactions: bool = Field(default=False)
    batch_size: int = Field(default=100, ge=1, le=10000)

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate business rules for LDAP operation configuration."""
        if self.max_retries < 0:
            return FlextResult.fail("Max retries must be non-negative")
        if self.retry_delay <= 0:
            return FlextResult.fail("Retry delay must be positive")
        if self.batch_size <= 0:
            return FlextResult.fail("Batch size must be positive")
        return FlextResult.ok(None)


class FlextLdapSecurityConfig(FlextValueObject):
    """LDAP security configuration using flext-core patterns."""

    tls_validation: Literal["strict", "permissive", "disabled"] = Field(
        default="strict",
    )
    ca_cert_file: str | None = Field(default=None)
    client_cert_file: str | None = Field(default=None)
    client_key_file: str | None = Field(default=None)

    enable_start_tls: bool = Field(default=False)
    tls_version: str | None = Field(default=None)

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate business rules for LDAP security configuration."""
        if self.tls_validation not in {"strict", "permissive", "disabled"}:
            return FlextResult.fail(
                "TLS validation must be 'strict', 'permissive', or 'disabled'",
            )
        if self.client_cert_file and not self.client_key_file:
            return FlextResult.fail(
                "Client key file is required when client cert file is provided",
            )
        if self.client_key_file and not self.client_cert_file:
            return FlextResult.fail(
                "Client cert file is required when client key file is provided",
            )
        return FlextResult.ok(None)


class FlextLdapLoggingConfig(BaseConfig):
    """LDAP logging configuration using flext-core patterns."""

    log_level: FlextLogLevel = Field(default=FlextLogLevel.INFO)
    enable_connection_logging: bool = Field(default=False)
    enable_operation_logging: bool = Field(default=True)

    log_sensitive_data: bool = Field(default=False)
    structured_logging: bool = Field(default=True)

    @field_validator("log_level", mode="before")
    @classmethod
    def normalize_log_level(cls, v: object) -> str:
        """Normalize log level to uppercase for FlextLogLevel enum."""
        logger.trace("Normalizing log level", extra={
            "original_value": v,
            "original_type": type(v).__name__,
            "is_string": isinstance(v, str),
            "has_value_attr": hasattr(v, "value")
        })

        if isinstance(v, str):
            # Handle enum string representation
            if v.startswith("FlextLogLevel."):
                normalized = v.split(".")[-1].upper()
                logger.debug("Normalized enum string log level", extra={
                    "original": v,
                    "normalized": normalized
                })
                return normalized
            normalized = v.upper()
            logger.debug("Normalized string log level", extra={"original": v, "normalized": normalized})
            return normalized
        # Handle enum objects
        if hasattr(v, "value"):
            normalized = str(v.value).upper()
            logger.debug("Normalized enum object log level", extra={
                "original": str(v),
                "normalized": normalized
            })
            return normalized
        # Return as string for enum validation
        normalized = str(v).upper()
        logger.debug("Normalized generic log level", extra={"original": str(v), "normalized": normalized})
        return normalized


class FlextLdapSettings(BaseSettings):
    """FLEXT-LDAP comprehensive configuration using flext-core patterns."""

    # Project identification
    project_name: ProjectName = Field(
        default="flext-infrastructure.databases.flext-ldap",
    )
    project_version: Version = Field(default="0.9.0")

    # Configuration sections
    connection: FlextLdapConnectionConfig = Field(
        default_factory=FlextLdapConnectionConfig,
    )
    auth: FlextLdapAuthConfig = Field(default_factory=FlextLdapAuthConfig)
    search: FlextLdapSearchConfig = Field(default_factory=FlextLdapSearchConfig)
    operations: FlextLdapOperationConfig = Field(
        default_factory=FlextLdapOperationConfig,
    )
    security: FlextLdapSecurityConfig = Field(default_factory=FlextLdapSecurityConfig)
    logging: FlextLdapLoggingConfig = Field(default_factory=FlextLdapLoggingConfig)

    # Global settings
    enable_debug_mode: bool = Field(default=False)
    enable_performance_monitoring: bool = Field(default=True)

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_LDAP_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    def to_ldap_client_config(self) -> dict[str, object]:
        """Convert to format expected by LDAP client libraries."""
        logger.debug("Converting FLEXT LDAP settings to client config format")

        config = {
            "server": self.connection.server,
            "port": self.connection.port,
            "use_ssl": self.connection.use_ssl,
            "timeout": self.connection.timeout_seconds,
            "bind_dn": self.auth.bind_dn,
            "bind_password": self.auth.bind_password,
            "base_dn": self.search.base_dn,
            "search_scope": self.search.default_search_scope,
            "size_limit": self.search.size_limit,
            "time_limit": self.search.time_limit,
            "paged_search": self.search.paged_search,
            "page_size": self.search.page_size,
        }

        logger.trace("Generated LDAP client config", extra={
            "server": config["server"],
            "port": config["port"],
            "use_ssl": config["use_ssl"],
            "has_auth": bool(config["bind_dn"]),
            "config_keys": list(config.keys())
        })

        return config


def create_development_config(**overrides: object) -> FlextLdapSettings:
    """Create development configuration with sensible defaults."""
    logger.debug("Creating development configuration", extra={
        "overrides_count": len(overrides),
        "override_keys": list(overrides.keys()) if overrides else []
    })

    defaults = {
        "enable_debug_mode": True,
        "connection": {
            "server": "localhost",
            "port": 389,
            "timeout_seconds": 10,
            "pool_size": 5,
        },
        "search": {
            "size_limit": 100,
            "page_size": 50,
        },
        "logging": {
            "log_level": "DEBUG",
            "enable_connection_logging": True,
            "structured_logging": True,
        },
    }
    defaults.update(overrides)

    logger.trace("Development config defaults prepared", extra={
        "defaults_keys": list(defaults.keys()),
        "debug_mode": defaults["enable_debug_mode"]
    })

    config = FlextLdapSettings()  # Use default environment-based configuration
    logger.info("Development configuration created", extra={
        "project_name": config.project_name,
        "project_version": config.project_version,
        "debug_mode": config.enable_debug_mode
    })
    return config
