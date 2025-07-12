"""FLEXT-LDAP Configuration using flext-core patterns."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import field_validator  # Only decorator, not Field
from pydantic_settings import SettingsConfigDict

from flext_core.config.base import BaseConfig, BaseSettings
from flext_core.domain.pydantic_base import DomainValueObject, Field


class LDAPConstants:
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


class LDAPConnectionConfig(DomainValueObject):
    """LDAP connection configuration using flext-core patterns."""

    server: str = Field(default="localhost")
    port: int = Field(default=389, ge=1, le=65535)
    use_ssl: bool = Field(default=False)
    timeout_seconds: int = Field(
        default=LDAPConstants.DEFAULT_TIMEOUT_SECONDS,
        ge=1,
        le=LDAPConstants.MAX_TIMEOUT_SECONDS,
    )

    pool_size: int = Field(
        default=LDAPConstants.DEFAULT_POOL_SIZE,
        ge=1,
        le=LDAPConstants.MAX_POOL_SIZE,
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
            msg = "Server cannot be empty"
            raise ValueError(msg)
        return v.strip()


class LDAPAuthConfig(DomainValueObject):
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


class LDAPSearchConfig(DomainValueObject):
    """LDAP search configuration using flext-core patterns."""

    base_dn: str = Field(default="")
    default_search_scope: Literal["base", "onelevel", "subtree"] = Field(
        default="subtree",
    )

    size_limit: int = Field(default=1000, ge=0, le=100000)
    time_limit: int = Field(default=30, ge=0, le=3600)

    paged_search: bool = Field(default=True)
    page_size: int = Field(
        default=LDAPConstants.DEFAULT_PAGE_SIZE,
        ge=1,
        le=LDAPConstants.MAX_PAGE_SIZE,
    )

    enable_referral_chasing: bool = Field(default=False)
    max_referral_hops: int = Field(default=5, ge=1, le=20)


class LDAPOperationConfig(DomainValueObject):
    """LDAP operation configuration using flext-core patterns."""

    max_retries: int = Field(
        default=LDAPConstants.DEFAULT_MAX_RETRIES,
        ge=0,
        le=LDAPConstants.MAX_RETRIES,
    )

    retry_delay: float = Field(
        default=LDAPConstants.DEFAULT_RETRY_DELAY,
        ge=0.1,
        le=LDAPConstants.MAX_RETRY_DELAY,
    )

    enable_transactions: bool = Field(default=False)
    batch_size: int = Field(default=100, ge=1, le=10000)


class LDAPSecurityConfig(DomainValueObject):
    """LDAP security configuration using flext-core patterns."""

    tls_validation: Literal["strict", "permissive", "disabled"] = Field(
        default="strict",
    )
    ca_cert_file: str | None = Field(default=None)
    client_cert_file: str | None = Field(default=None)
    client_key_file: str | None = Field(default=None)

    enable_start_tls: bool = Field(default=False)
    tls_version: str | None = Field(default=None)


class LDAPLoggingConfig(BaseConfig):
    """LDAP logging configuration using flext-core patterns."""

    log_level: LogLevelLiteral = Field(default="INFO")
    enable_connection_logging: bool = Field(default=False)
    enable_operation_logging: bool = Field(default=True)

    log_sensitive_data: bool = Field(default=False)
    structured_logging: bool = Field(default=True)


class FlextLDAPSettings(BaseSettings):
    """FLEXT-LDAP comprehensive configuration using flext-core patterns."""

    # Project identification
    project_name: ProjectName = Field(default="flext-ldap")
    project_version: Version = Field(default="0.7.0")

    # Configuration sections
    connection: LDAPConnectionConfig = Field(default_factory=LDAPConnectionConfig)
    auth: LDAPAuthConfig = Field(default_factory=LDAPAuthConfig)
    search: LDAPSearchConfig = Field(default_factory=LDAPSearchConfig)
    operations: LDAPOperationConfig = Field(default_factory=LDAPOperationConfig)
    security: LDAPSecurityConfig = Field(default_factory=LDAPSecurityConfig)
    logging: LDAPLoggingConfig = Field(default_factory=LDAPLoggingConfig)

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


def create_development_config(**overrides: Any) -> FlextLDAPSettings:  # noqa: ANN401
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

    return FlextLDAPSettings()  # Use default environment-based configuration
