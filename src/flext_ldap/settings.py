"""FLEXT LDAP Settings Configuration.

Project-specific operational settings for FLEXT-LDAP.
"""

import json
from pathlib import Path
from typing import final, override

from flext_core import FlextConfig, FlextLogger, FlextResult
from pydantic import ConfigDict, Field, SecretStr

from flext_ldap.connection_config import FlextLdapConnectionConfig
from flext_ldap.fields import FlextLdapScopeEnum


# TEMPORARY: Inline dependencies to avoid circular imports - will be extracted
@final
class FlextLdapAuthConfig(FlextConfig):
    """LDAP authentication configuration."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
    )

    bind_dn: str = Field(
        ...,
        description="Distinguished Name for binding",
        min_length=3,
    )
    bind_password: SecretStr = Field(
        ...,
        description="Password for binding (secure)",
    )
    use_ssl: bool = Field(
        default=False,
        description="Use SSL/TLS for connection",
    )
    verify_certificates: bool = Field(
        default=True,
        description="Verify SSL certificates",
    )

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate authentication configuration."""
        if not self.bind_dn.strip():
            return FlextResult[None].fail("Bind DN cannot be empty")

        if len(self.bind_password.get_secret_value()) < 1:
            return FlextResult[None].fail("Bind password cannot be empty")

        return FlextResult[None].ok(None)


@final
class FlextLdapSearchConfig(FlextConfig):
    """LDAP search operation configuration."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    default_scope: FlextLdapScopeEnum = Field(
        default=FlextLdapScopeEnum.SUBTREE,
        description="Default search scope",
    )
    size_limit: int = Field(
        default=1000,
        description="Maximum search results",
        gt=0,
        le=10000,
    )
    time_limit: int = Field(
        default=30,
        description="Search timeout in seconds",
        gt=0,
        le=300,
    )
    page_size: int = Field(
        default=100,
        description="Paging size for large results",
        gt=0,
        le=1000,
    )

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate search configuration."""
        if self.size_limit <= 0:
            return FlextResult[None].fail("Size limit must be positive")

        if self.time_limit <= 0:
            return FlextResult[None].fail("Time limit must be positive")

        if self.page_size <= 0:
            return FlextResult[None].fail("Page size must be positive")

        return FlextResult[None].ok(None)


@final
class FlextLdapLoggingConfig(FlextConfig):
    """LDAP logging configuration."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    enable_debug: bool = Field(
        default=False,
        description="Enable debug logging",
    )
    log_queries: bool = Field(
        default=False,
        description="Log LDAP queries",
    )
    log_responses: bool = Field(
        default=False,
        description="Log LDAP responses",
    )
    structured_logging: bool = Field(
        default=True,
        description="Enable structured (JSON) logging",
    )

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate logging configuration."""
        return FlextResult[None].ok(None)


try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

logger = FlextLogger(__name__)


@final
class FlextLdapSettings(FlextConfig):
    """Project-specific operational settings for FLEXT-LDAP."""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
        validate_assignment=True,
        use_enum_values=True,
    )

    # Primary connection configuration
    default_connection: FlextLdapConnectionConfig | None = Field(
        default=None,
        description="Default connection configuration",
        alias="connection",
    )

    # Authentication configuration
    auth: FlextLdapAuthConfig | None = Field(
        default=None,
        description="Authentication configuration",
    )

    # Search configuration
    search: FlextLdapSearchConfig = Field(
        default_factory=FlextLdapSearchConfig,
        description="Search operation configuration",
    )

    # Logging configuration
    logging: FlextLdapLoggingConfig = Field(
        default_factory=FlextLdapLoggingConfig,
        description="Logging configuration",
    )

    # Performance tuning
    enable_caching: bool = Field(
        default=False,
        description="Enable result caching",
    )
    cache_ttl: int = Field(
        default=300,
        description="Cache TTL in seconds",
        gt=0,
        le=3600,
    )

    # Development settings
    enable_debug_mode: bool = Field(
        default=False,
        description="Enable debug mode with verbose logging",
    )
    enable_test_mode: bool = Field(
        default=False,
        description="Enable test mode",
    )

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate complete settings configuration."""
        if self.default_connection:
            if not self.default_connection.server:
                return FlextResult[None].fail(
                    "Default connection must specify a server",
                )

            conn_validation = self.default_connection.validate_business_rules()
            if not conn_validation.is_success:
                return conn_validation

        # Validate cache settings
        if self.enable_caching and self.cache_ttl <= 0:
            return FlextResult[None].fail(
                "Cache TTL must be positive when caching is enabled",
            )

        # Validate sub-configurations
        search_validation = self.search.validate_business_rules()
        if not search_validation.is_success:
            return search_validation

        logging_validation = self.logging.validate_business_rules()
        if not logging_validation.is_success:
            return logging_validation

        return FlextResult[None].ok(None)

    def get_effective_connection(
        self,
        override: FlextLdapConnectionConfig | None = None,
    ) -> FlextLdapConnectionConfig:
        """Get effective connection configuration with optional override."""
        if override:
            return override

        if self.default_connection:
            return self.default_connection

        # Return minimal default configuration
        return FlextLdapConnectionConfig()

    def get_effective_auth_config(self) -> FlextLdapAuthConfig | None:
        """Get effective authentication configuration."""
        # Return the auth config from settings, not from connection
        return self.auth

    # Testing convenience: expose `.connection` attribute used by some callers/tests
    @property
    def connection(self) -> FlextLdapConnectionConfig | None:
        """Get connection configuration."""
        return self.default_connection

    @connection.setter
    def connection(self, value: FlextLdapConnectionConfig | None) -> None:
        """Set connection configuration."""
        self.default_connection = value

    # Back-compat alias used in some tests
    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules (alias for validate_business_rules)."""
        return self.validate_business_rules()

    @classmethod
    def from_env(cls) -> "FlextLdapSettings":
        """Create FlextLdapSettings from environment variables.

        Raises:
            ValueError: If required environment variables are missing.

        """
        # Error messages as constants
        host_error = "FLEXT_LDAP_HOST environment variable is required"
        port_error = "FLEXT_LDAP_PORT environment variable is required"
        bind_dn_error = "FLEXT_LDAP_BIND_DN environment variable is required"
        bind_credential_error = (
            "FLEXT_LDAP_BIND_PASSWORD environment variable is required"
        )
        base_dn_error = "FLEXT_LDAP_BASE_DN environment variable is required"

        # Check for required environment variables
        host_result = cls.get_env_with_validation("FLEXT_LDAP_HOST", required=True)
        if not host_result.is_success:
            raise ValueError(host_error)

        port_result = cls.get_env_with_validation("FLEXT_LDAP_PORT", required=True)
        if not port_result.is_success:
            raise ValueError(port_error)

        bind_dn_result = cls.get_env_with_validation(
            "FLEXT_LDAP_BIND_DN", required=True
        )
        if not bind_dn_result.is_success:
            raise ValueError(bind_dn_error)

        bind_password_result = cls.get_env_with_validation(
            "FLEXT_LDAP_BIND_PASSWORD", required=True
        )
        if not bind_password_result.is_success:
            raise ValueError(bind_credential_error)

        base_dn_result = cls.get_env_with_validation(
            "FLEXT_LDAP_BASE_DN", required=True
        )
        if not base_dn_result.is_success:
            raise ValueError(base_dn_error)

        # Get optional values
        use_ssl_result = cls.get_env_with_validation(
            "FLEXT_LDAP_USE_SSL", required=False, default="false"
        )
        use_ssl = use_ssl_result.value.lower() in {"true", "1", "yes", "on"}

        # Create auth config
        auth_config = FlextLdapAuthConfig(
            bind_dn=bind_dn_result.value,
            bind_password=SecretStr(bind_password_result.value),
            use_ssl=use_ssl,
        )

        # Create connection config - only with valid fields
        connection_config = FlextLdapConnectionConfig(
            server=host_result.value,
            port=int(port_result.value),
        )

        # Create settings using alias field name for Pydantic
        config_data: dict[str, object] = {
            "default_connection": connection_config,
            "auth": auth_config,
        }
        return cls.model_validate(config_data)

    @classmethod
    def from_file(cls, file_path: str) -> "FlextLdapSettings":
        """Create FlextLdapSettings from YAML/JSON file.

        Args:
            file_path: Path to configuration file

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format is invalid

        """
        # Error messages as constants
        file_not_found_msg = f"Configuration file not found: {file_path}"
        yaml_import_error_msg = (
            "Failed to parse configuration file: YAML parsing requires PyYAML package"
        )
        file_read_error_msg = f"Failed to read configuration file: {file_path}"

        # Check if file exists
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            raise FileNotFoundError(file_not_found_msg)

        try:
            with file_path_obj.open(encoding="utf-8") as f:
                content = f.read()

            # Try to parse as JSON first
            try:
                config_dict = json.loads(content)
            except json.JSONDecodeError:
                # Try to parse as YAML
                if yaml is None:
                    raise ValueError(yaml_import_error_msg) from None
                try:
                    config_dict = yaml.safe_load(content)
                except yaml.YAMLError as e:
                    yaml_format_error_msg = (
                        f"Failed to parse configuration file: Invalid YAML format: {e}"
                    )
                    raise ValueError(yaml_format_error_msg) from e
        except Exception as e:
            if isinstance(e, (FileNotFoundError, ValueError)):
                raise
            raise ValueError(file_read_error_msg) from e

        return cls.model_validate(config_dict)


# Factory functions for different environments
def create_development_config() -> FlextLdapSettings:
    """Create development configuration."""
    connection_config = FlextLdapConnectionConfig(
        server="localhost",
        port=389,
    )

    auth_config = FlextLdapAuthConfig(
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=dev,dc=local",
        bind_password=SecretStr("REDACTED_LDAP_BIND_PASSWORD123"),
        use_ssl=False,
        verify_certificates=False,
    )

    # Use model_validate to avoid pyright false positives with alias fields
    config_data: dict[str, object] = {
        "default_connection": connection_config,
        "auth": auth_config,
        "logging": FlextLdapLoggingConfig(
            enable_debug=True,
            log_queries=True,
            structured_logging=True,
        ),
        "enable_debug_mode": True,
        "enable_caching": False,
    }
    return FlextLdapSettings.model_validate(config_data)


def create_test_config() -> FlextLdapSettings:
    """Create test configuration."""
    connection_config = FlextLdapConnectionConfig(
        server="localhost",
        port=3389,
    )

    auth_config = FlextLdapAuthConfig(
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
        bind_password=SecretStr("test123"),
        use_ssl=False,
        verify_certificates=False,
    )

    # Use model_validate to avoid pyright false positives with alias fields
    config_data: dict[str, object] = {
        "default_connection": connection_config,
        "auth": auth_config,
        "logging": FlextLdapLoggingConfig(
            enable_debug=False,
            log_queries=False,
            structured_logging=False,
        ),
        "enable_test_mode": True,
        "enable_caching": False,
    }
    return FlextLdapSettings.model_validate(config_data)


def create_production_config() -> FlextLdapSettings:
    """Create production configuration."""
    connection_config = FlextLdapConnectionConfig(
        server="ldap.company.com",
        port=636,
        use_ssl=True,
        verify_ssl=True,
    )

    auth_config = FlextLdapAuthConfig(
        bind_dn="cn=service,ou=accounts,dc=company,dc=com",
        bind_password=SecretStr("${LDAP_BIND_PASSWORD}"),
        use_ssl=True,
        verify_certificates=True,
    )

    # Use model_validate to avoid pyright false positives with alias fields
    config_data: dict[str, object] = {
        "default_connection": connection_config,
        "auth": auth_config,
        "logging": FlextLdapLoggingConfig(
            enable_debug=False,
            log_queries=False,
            structured_logging=True,
        ),
        "enable_debug_mode": False,
        "enable_caching": True,
        "cache_ttl": 600,
    }
    return FlextLdapSettings.model_validate(config_data)


__all__ = [
    "FlextLdapAuthConfig",
    "FlextLdapLoggingConfig",
    "FlextLdapSearchConfig",
    "FlextLdapSettings",
    "create_development_config",
    "create_production_config",
    "create_test_config",
]
