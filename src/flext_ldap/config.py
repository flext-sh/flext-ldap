"""FLEXT-LDAP Configuration using flext-core patterns."""

from __future__ import annotations

from typing import Any, Literal

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext_core root imports
from flext_core import FlextCoreSettings, FlextLogLevel, FlextValueObject
from pydantic import Field, field_validator
from pydantic_settings import SettingsConfigDict

# Use FlextValueObject as base for all config types
BaseConfig = FlextCoreSettings
BaseSettings = FlextCoreSettings


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
        if not v or v.isspace():
            msg = "Server cannot be empty or whitespace only"
            raise ValueError(msg)
        return v.strip()

    def validate_domain_rules(self) -> None:
        """Validate business rules for LDAP connection configuration."""
        if not self.server:
            msg = "LDAP connection must have a server"
            raise ValueError(msg)
        if self.port <= 0 or self.port > 65535:
            msg = "Port must be between 1 and 65535"
            raise ValueError(msg)
        if self.timeout_seconds <= 0:
            msg = "Timeout must be positive"
            raise ValueError(msg)
        if self.pool_size <= 0:
            msg = "Pool size must be positive"
            raise ValueError(msg)


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
        return v.strip() if v else ""

    def validate_domain_rules(self) -> None:
        """Validate business rules for LDAP authentication configuration."""
        if not self.use_anonymous_bind and not self.bind_dn:
            msg = "Bind DN is required when not using anonymous bind"
            raise ValueError(msg)
        if self.bind_dn and not self.bind_password and not self.use_anonymous_bind:
            msg = "Bind password is required when bind DN is provided"
            raise ValueError(msg)


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

    def validate_domain_rules(self) -> None:
        """Validate business rules for LDAP search configuration."""
        if self.size_limit < 0:
            msg = "Size limit must be non-negative"
            raise ValueError(msg)
        if self.time_limit < 0:
            msg = "Time limit must be non-negative"
            raise ValueError(msg)
        if self.page_size <= 0:
            msg = "Page size must be positive"
            raise ValueError(msg)


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

    def validate_domain_rules(self) -> None:
        """Validate business rules for LDAP operation configuration."""
        if self.max_retries < 0:
            msg = "Max retries must be non-negative"
            raise ValueError(msg)
        if self.retry_delay <= 0:
            msg = "Retry delay must be positive"
            raise ValueError(msg)
        if self.batch_size <= 0:
            msg = "Batch size must be positive"
            raise ValueError(msg)


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

    def validate_domain_rules(self) -> None:
        """Validate business rules for LDAP security configuration."""
        if self.tls_validation not in {"strict", "permissive", "disabled"}:
            msg = "TLS validation must be 'strict', 'permissive', or 'disabled'"
            raise ValueError(
                msg,
            )
        if self.client_cert_file and not self.client_key_file:
            msg = "Client key file is required when client cert file is provided"
            raise ValueError(
                msg,
            )
        if self.client_key_file and not self.client_cert_file:
            msg = "Client cert file is required when client key file is provided"
            raise ValueError(
                msg,
            )


class FlextLdapLoggingConfig(BaseConfig):
    """LDAP logging configuration using flext-core patterns."""

    log_level: FlextLogLevel = Field(default=FlextLogLevel.INFO)
    enable_connection_logging: bool = Field(default=False)
    enable_operation_logging: bool = Field(default=True)

    log_sensitive_data: bool = Field(default=False)
    structured_logging: bool = Field(default=True)

    @field_validator("log_level", mode="before")
    @classmethod
    def normalize_log_level(cls, v: Any) -> str:
        """Normalize log level to uppercase for FlextLogLevel enum."""
        if isinstance(v, str):
            return v.upper()
        # Return as string for enum validation
        return str(v)


class FlextLdapSettings(BaseSettings):
    """FLEXT-LDAP comprehensive configuration using flext-core patterns."""

    # Project identification
    project_name: ProjectName = Field(
        default="flext-infrastructure.databases.flext-ldap",
    )
    project_version: Version = Field(default="0.7.0")

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

    def to_ldap_client_config(self) -> dict[str, Any]:
        """Convert to format expected by LDAP client libraries."""
        return {
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


def create_development_config(**overrides: Any) -> FlextLdapSettings:
    """Create development configuration with sensible defaults."""
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

    return FlextLdapSettings()  # Use default environment-based configuration
