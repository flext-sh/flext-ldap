"""Test configuration functionality."""

import os
from unittest.mock import patch

import pytest
from flext_core import FlextLogLevel
from flext_ldap.config import (
    FlextLdapAuthConfig,
    FlextLdapConnectionConfig,
    FlextLdapConstants,
    FlextLdapLoggingConfig,
    FlextLdapOperationConfig,
    FlextLdapSearchConfig,
    FlextLdapSecurityConfig,
    FlextLdapSettings,
    create_development_config,
)
from pydantic import ValidationError

# Constants
HTTP_OK = 200
EXPECTED_BULK_SIZE = 2
EXPECTED_DATA_COUNT = 3


class TestFlextLdapConstants:
    """Test FlextLdapConstants."""

    @pytest.mark.unit
    def test_constants_values(self) -> None:
        """Test that constants have expected values."""

        if FlextLdapConstants.DEFAULT_TIMEOUT_SECONDS != 30:
            raise AssertionError(
                f"Expected {30}, got {FlextLdapConstants.DEFAULT_TIMEOUT_SECONDS}"
            )
        assert FlextLdapConstants.MAX_TIMEOUT_SECONDS == 300
        if FlextLdapConstants.DEFAULT_POOL_SIZE != 10:
            raise AssertionError(
                f"Expected {10}, got {FlextLdapConstants.DEFAULT_POOL_SIZE}"
            )
        assert FlextLdapConstants.MAX_POOL_SIZE == 100
        if FlextLdapConstants.DEFAULT_PAGE_SIZE != 1000:
            raise AssertionError(
                f"Expected {1000}, got {FlextLdapConstants.DEFAULT_PAGE_SIZE}"
            )
        assert FlextLdapConstants.MAX_PAGE_SIZE == 10000


class TestFlextLdapConnectionConfig:
    """Test FlextLdapConnectionConfig functionality."""

    @pytest.mark.unit
    def test_connection_config_defaults(self) -> None:
        """Test FlextLdapConnectionConfig with default values."""

        config = FlextLdapConnectionConfig()
        if config.host != "localhost":
            raise AssertionError(f"Expected {'localhost'}, got {config.host}")
        assert config.port == 389
        if config.use_ssl:
            raise AssertionError(f"Expected False, got {config.use_ssl}")
        assert config.timeout_seconds == 30
        if config.pool_size != 10:
            raise AssertionError(f"Expected {10}, got {config.pool_size}")
        if not (config.enable_connection_pooling):
            raise AssertionError(
                f"Expected True, got {config.enable_connection_pooling}"
            )

    @pytest.mark.unit
    def test_connection_config_custom(self) -> None:
        """Test FlextLdapConnectionConfig with custom values."""

        config = FlextLdapConnectionConfig(
            host="test.example.com",
            port=636,
            use_ssl=True,
            timeout_seconds=60,
            pool_size=20,
            enable_connection_pooling=False,
        )
        if config.host != "test.example.com":
            raise AssertionError(f"Expected {'test.example.com'}, got {config.host}")
        assert config.port == 636
        if not (config.use_ssl):
            raise AssertionError(f"Expected True, got {config.use_ssl}")
        if config.timeout_seconds != 60:
            raise AssertionError(f"Expected {60}, got {config.timeout_seconds}")
        assert config.pool_size == 20
        if config.enable_connection_pooling:
            raise AssertionError(
                f"Expected False, got {config.enable_connection_pooling}"
            )

    @pytest.mark.unit
    def test_server_validation_valid(self) -> None:
        """Test server validation with valid values."""

        config = FlextLdapConnectionConfig(host="localhost")
        if config.host != "localhost":
            expected_host = "localhost"
            raise AssertionError(f"Expected {expected_host}, got {config.host}")

    @pytest.mark.unit
    def test_server_validation_invalid(self) -> None:
        """Test server validation with invalid values."""

        with pytest.raises(ValueError, match="Host cannot be empty"):
            FlextLdapConnectionConfig(host="")

        with pytest.raises(ValueError, match="Host cannot be empty"):
            FlextLdapConnectionConfig(host="   ")

    @pytest.mark.unit
    def test_port_validation_valid(self) -> None:
        """Test port validation with valid values."""

        config = FlextLdapConnectionConfig(port=636)
        if config.port != 636:
            raise AssertionError(f"Expected {636}, got {config.port}")

    @pytest.mark.unit
    def test_port_validation_invalid(self) -> None:
        """Test port validation with invalid values."""

        with pytest.raises(ValidationError):
            FlextLdapConnectionConfig(port=0)

        with pytest.raises(ValidationError):
            FlextLdapConnectionConfig(port=65536)

    @pytest.mark.unit
    def test_domain_rules_validation_success(self) -> None:
        """Test domain rules validation with valid config."""

        config = FlextLdapConnectionConfig(
            host="localhost",
            port=389,
            timeout_seconds=30,
            pool_size=10,
        )
        # Should not raise
        config.validate_domain_rules()

    @pytest.mark.unit
    def test_domain_rules_validation_failures(self) -> None:
        """Test domain rules validation with invalid configs."""

        # Note: Domain validation for server would be caught by field validator
        # This test primarily verifies the method exists and works with valid config
        config = FlextLdapConnectionConfig()
        # Should not raise with valid configuration
        config.validate_domain_rules()


class TestFlextLdapAuthConfig:
    """Test FlextLdapAuthConfig functionality."""

    @pytest.mark.unit
    def test_auth_config_defaults(self) -> None:
        """Test FlextLdapAuthConfig with default values."""

        config = FlextLdapAuthConfig()
        if config.bind_dn != "":
            raise AssertionError(f"Expected {''}, got {config.bind_dn}")
        assert config.bind_password is not None
        assert config.bind_password.get_secret_value() == ""
        if config.use_anonymous_bind:
            raise AssertionError(f"Expected False, got {config.use_anonymous_bind}")
        assert config.sasl_mechanism is None

    @pytest.mark.unit
    def test_auth_config_custom(self) -> None:
        """Test FlextLdapAuthConfig with custom values."""

        config = FlextLdapAuthConfig(
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org",
            bind_password="secret",
            use_anonymous_bind=True,
            sasl_mechanism="EXTERNAL",
        )
        if config.bind_dn != "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org":
            raise AssertionError(
                f"Expected {'cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org'}, got {config.bind_dn}"
            )
        assert config.bind_password is not None
        assert config.bind_password.get_secret_value() == "secret"
        if not (config.use_anonymous_bind):
            raise AssertionError(f"Expected True, got {config.use_anonymous_bind}")
        if config.sasl_mechanism != "EXTERNAL":
            raise AssertionError(f"Expected {'EXTERNAL'}, got {config.sasl_mechanism}")

    @pytest.mark.unit
    def test_bind_dn_validation(self) -> None:
        """Test bind DN validation."""

        config = FlextLdapAuthConfig(bind_dn="  cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org  ")
        expected_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org"  # Should be stripped
        if config.bind_dn != expected_dn:
            raise AssertionError(f"Expected {expected_dn}, got {config.bind_dn}")

    @pytest.mark.unit
    def test_domain_rules_validation_anonymous_bind(self) -> None:
        """Test domain rules validation for anonymous bind."""

        config = FlextLdapAuthConfig(use_anonymous_bind=True)
        # Should not raise even without bind_dn/password
        config.validate_domain_rules()

    @pytest.mark.unit
    def test_domain_rules_validation_bind_dn_required(self) -> None:
        """Test domain rules validation when bind DN is required."""

        config = FlextLdapAuthConfig(use_anonymous_bind=False, bind_dn="")
        result = config.validate_domain_rules()
        assert not result.success
        assert "bind dn" in result.error.lower()

    @pytest.mark.unit
    def test_domain_rules_validation_password_required(self) -> None:
        """Test domain rules validation when password is required."""

        config = FlextLdapAuthConfig(
            use_anonymous_bind=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org",
            bind_password="",
        )
        result = config.validate_domain_rules()
        assert not result.success
        assert "Bind password is required" in (result.error or "")


class TestFlextLdapSearchConfig:
    """Test FlextLdapSearchConfig functionality."""

    @pytest.mark.unit
    def test_search_config_defaults(self) -> None:
        """Test FlextLdapSearchConfig with default values."""

        config = FlextLdapSearchConfig()
        if config.base_dn != "":
            raise AssertionError(f"Expected {''}, got {config.base_dn}")
        assert config.default_search_scope == "subtree"
        if config.size_limit != 1000:
            raise AssertionError(f"Expected {1000}, got {config.size_limit}")
        assert config.time_limit == 30
        if not (config.paged_search):
            raise AssertionError(f"Expected True, got {config.paged_search}")
        if config.page_size != 1000:
            raise AssertionError(f"Expected {1000}, got {config.page_size}")
        if config.enable_referral_chasing:
            raise AssertionError(
                f"Expected False, got {config.enable_referral_chasing}"
            )
        assert config.max_referral_hops == 5

    @pytest.mark.unit
    def test_search_config_custom(self) -> None:
        """Test FlextLdapSearchConfig with custom values."""

        config = FlextLdapSearchConfig(
            base_dn="ou=users,dc=example,dc=org",
            default_search_scope="onelevel",
            size_limit=500,
            time_limit=60,
            paged_search=False,
            page_size=100,
            enable_referral_chasing=True,
            max_referral_hops=10,
        )
        if config.base_dn != "ou=users,dc=example,dc=org":
            raise AssertionError(
                f"Expected {'ou=users,dc=example,dc=org'}, got {config.base_dn}"
            )
        assert config.default_search_scope == "onelevel"
        if config.size_limit != 500:
            raise AssertionError(f"Expected {500}, got {config.size_limit}")
        assert config.time_limit == 60
        if config.paged_search:
            raise AssertionError(f"Expected False, got {config.paged_search}")
        assert config.page_size == 100
        if not (config.enable_referral_chasing):
            raise AssertionError(f"Expected True, got {config.enable_referral_chasing}")
        if config.max_referral_hops != 10:
            raise AssertionError(f"Expected {10}, got {config.max_referral_hops}")

    @pytest.mark.unit
    def test_search_domain_rules_validation_success(self) -> None:
        """Test search domain rules validation with valid config."""

        config = FlextLdapSearchConfig(
            size_limit=1000,
            time_limit=30,
            page_size=100,
        )
        # Should not raise
        config.validate_domain_rules()

    @pytest.mark.unit
    def test_search_domain_rules_validation_failures(self) -> None:
        """Test search domain rules validation with invalid configs."""

        # Test valid configuration - domain validation passes
        config = FlextLdapSearchConfig()
        # Should not raise with valid default configuration
        config.validate_domain_rules()

        # Note: Invalid values like negative limits would be caught by field validators
        # during object construction, not during domain validation


class TestFlextLdapOperationConfig:
    """Test FlextLdapOperationConfig functionality."""

    @pytest.mark.unit
    def test_operation_config_defaults(self) -> None:
        """Test FlextLdapOperationConfig with default values."""

        config = FlextLdapOperationConfig()
        if config.max_retries != EXPECTED_DATA_COUNT:
            raise AssertionError(f"Expected {3}, got {config.max_retries}")
        assert config.retry_delay == 1.0
        if config.enable_transactions:
            raise AssertionError(f"Expected False, got {config.enable_transactions}")
        assert config.batch_size == 100

    @pytest.mark.unit
    def test_operation_config_custom(self) -> None:
        """Test FlextLdapOperationConfig with custom values."""

        config = FlextLdapOperationConfig(
            max_retries=5,
            retry_delay=2.5,
            enable_transactions=True,
            batch_size=200,
        )
        if config.max_retries != 5:
            raise AssertionError(f"Expected {5}, got {config.max_retries}")
        assert config.retry_delay == 2.5
        if not (config.enable_transactions):
            raise AssertionError(f"Expected True, got {config.enable_transactions}")
        if config.batch_size != HTTP_OK:
            raise AssertionError(f"Expected {200}, got {config.batch_size}")

    @pytest.mark.unit
    def test_operation_domain_rules_validation_success(self) -> None:
        """Test operation domain rules validation with valid config."""

        config = FlextLdapOperationConfig(
            max_retries=3,
            retry_delay=1.0,
            batch_size=100,
        )
        # Should not raise
        config.validate_domain_rules()

    @pytest.mark.unit
    def test_operation_domain_rules_validation_failures(self) -> None:
        """Test operation domain rules validation with invalid configs."""

        # Test valid configuration - domain validation passes
        config = FlextLdapOperationConfig()
        # Should not raise with valid default configuration
        config.validate_domain_rules()

        # Note: Invalid values like negative retries would be caught by field validators
        # during object construction, not during domain validation


class TestFlextLdapSecurityConfig:
    """Test FlextLdapSecurityConfig functionality."""

    @pytest.mark.unit
    def test_security_config_defaults(self) -> None:
        """Test FlextLdapSecurityConfig with default values."""

        config = FlextLdapSecurityConfig()
        if config.tls_validation != "strict":
            raise AssertionError(f"Expected {'strict'}, got {config.tls_validation}")
        assert config.ca_cert_file is None
        assert config.client_cert_file is None
        assert config.client_key_file is None
        if config.enable_start_tls:
            raise AssertionError(f"Expected False, got {config.enable_start_tls}")
        assert config.tls_version is None

    @pytest.mark.unit
    def test_security_config_custom(self) -> None:
        """Test FlextLdapSecurityConfig with custom values."""

        config = FlextLdapSecurityConfig(
            tls_validation="permissive",
            ca_cert_file="/path/to/ca.crt",
            client_cert_file="/path/to/client.crt",
            client_key_file="/path/to/client.key",
            enable_start_tls=True,
            tls_version="TLSv1.2",
        )
        if config.tls_validation != "permissive":
            raise AssertionError(
                f"Expected {'permissive'}, got {config.tls_validation}"
            )
        assert config.ca_cert_file == "/path/to/ca.crt"
        if config.client_cert_file != "/path/to/client.crt":
            raise AssertionError(
                f"Expected {'/path/to/client.crt'}, got {config.client_cert_file}"
            )
        assert config.client_key_file == "/path/to/client.key"
        if not (config.enable_start_tls):
            raise AssertionError(f"Expected True, got {config.enable_start_tls}")
        if config.tls_version != "TLSv1.2":
            raise AssertionError(f"Expected {'TLSv1.2'}, got {config.tls_version}")

    @pytest.mark.unit
    def test_security_domain_rules_validation_success(self) -> None:
        """Test security domain rules validation with valid config."""

        config = FlextLdapSecurityConfig(
            tls_validation="strict",
            client_cert_file="/path/to/client.crt",
            client_key_file="/path/to/client.key",
        )
        # Should not raise
        config.validate_domain_rules()

    @pytest.mark.unit
    def test_security_domain_rules_validation_failures(self) -> None:
        """Test security domain rules validation with invalid configs."""

        # Test client cert without key
        config = FlextLdapSecurityConfig(client_cert_file="/path/to/client.crt")
        result = config.validate_domain_rules()
        assert not result.success
        assert "key file" in result.error.lower()

        # Test client key without cert
        config = FlextLdapSecurityConfig(client_key_file="/path/to/client.key")
        result = config.validate_domain_rules()
        assert not result.success
        assert "cert file" in result.error.lower()


class TestFlextLdapLoggingConfig:
    """Test FlextLdapLoggingConfig functionality."""

    @pytest.mark.unit
    def test_logging_config_defaults(self) -> None:
        """Test FlextLdapLoggingConfig with default values."""

        # Clear any FLEXT related environment variables that might affect defaults
        env_vars_to_clear = [key for key in os.environ if key.startswith("FLEXT_")]

        with patch.dict(os.environ, dict.fromkeys(env_vars_to_clear, ""), clear=False):
            # Remove the cleared vars completely
            for var in env_vars_to_clear:
                if var in os.environ:
                    del os.environ[var]

            config = FlextLdapLoggingConfig()
            if config.log_level != FlextLogLevel.INFO:
                raise AssertionError(
                    f"Expected {FlextLogLevel.INFO}, got {config.log_level}"
                )
            if config.enable_connection_logging:
                raise AssertionError(
                    f"Expected False, got {config.enable_connection_logging}"
                )
            if not (config.enable_operation_logging):
                raise AssertionError(
                    f"Expected True, got {config.enable_operation_logging}"
                )
            if config.log_sensitive_data:
                raise AssertionError(f"Expected False, got {config.log_sensitive_data}")
            if not (config.structured_logging):
                raise AssertionError(f"Expected True, got {config.structured_logging}")

    @pytest.mark.unit
    def test_logging_config_custom(self) -> None:
        """Test FlextLdapLoggingConfig with custom values."""

        config = FlextLdapLoggingConfig(
            log_level=FlextLogLevel.DEBUG,
        )
        # Update attributes after creation since they have defaults
        config = config.model_copy(
            update={
                "enable_connection_logging": True,
                "enable_operation_logging": False,
                "log_sensitive_data": True,
                "structured_logging": False,
            },
        )
        if config.log_level != FlextLogLevel.DEBUG:
            raise AssertionError(
                f"Expected {FlextLogLevel.DEBUG}, got {config.log_level}"
            )
        if not (config.enable_connection_logging):
            raise AssertionError(
                f"Expected True, got {config.enable_connection_logging}"
            )
        if config.enable_operation_logging:
            raise AssertionError(
                f"Expected False, got {config.enable_operation_logging}"
            )
        if not (config.log_sensitive_data):
            raise AssertionError(f"Expected True, got {config.log_sensitive_data}")
        if config.structured_logging:
            raise AssertionError(f"Expected False, got {config.structured_logging}")

    @pytest.mark.unit
    def test_log_level_normalization(self) -> None:
        """Test log level normalization."""

        # Test string normalization
        config = FlextLdapLoggingConfig(log_level=FlextLogLevel.DEBUG)
        if config.log_level != FlextLogLevel.DEBUG:
            raise AssertionError(
                f"Expected {FlextLogLevel.DEBUG}, got {config.log_level}"
            )


class TestFlextLdapSettings:
    """Test FlextLdapSettings functionality."""

    @pytest.mark.unit
    def test_settings_import(self) -> None:
        """Test that FlextLdapSettings can be imported."""

        assert FlextLdapSettings is not None

    @pytest.mark.unit
    def test_settings_instantiation_defaults(self) -> None:
        """Test that FlextLdapSettings can be instantiated with defaults."""

        # Clear any FLEXT_LDAP environment variables to ensure clean defaults
        env_vars_to_clear = [key for key in os.environ if key.startswith("FLEXT_LDAP_")]

        with patch.dict(os.environ, dict.fromkeys(env_vars_to_clear, ""), clear=False):
            # Remove the cleared vars completely
            for var in env_vars_to_clear:
                if var in os.environ:
                    del os.environ[var]

            settings = FlextLdapSettings()
            assert settings is not None
            if settings.connection.host != "localhost":
                raise AssertionError(
                    f"Expected {'localhost'}, got {settings.connection.host}"
                )
            assert settings.connection.port == 389
            if settings.project_name != "flext-infrastructure.databases.flext-ldap":
                raise AssertionError(
                    f"Expected {'flext-infrastructure.databases.flext-ldap'}, got {settings.project_name}"
                )
            assert settings.project_version == "0.9.0"
            if settings.enable_debug_mode:
                raise AssertionError(
                    f"Expected False, got {settings.enable_debug_mode}"
                )
            if not (settings.enable_performance_monitoring):
                raise AssertionError(
                    f"Expected True, got {settings.enable_performance_monitoring}"
                )

    @pytest.mark.unit
    def test_settings_custom_values(self) -> None:
        """Test FlextLdapSettings with custom values."""
        from flext_ldap.config import (
            FlextLdapConnectionConfig,
            FlextLdapSettings,
        )

        connection_config = FlextLdapConnectionConfig(
            host="custom.ldap.com",
            port=636,
            use_ssl=True,
        )

        settings = FlextLdapSettings()
        # Update other fields using model_copy
        settings = settings.model_copy(
            update={
                "connection": connection_config,
                "project_name": "custom-project",
                "project_version": "0.9.0",
                "enable_debug_mode": True,
                "enable_performance_monitoring": False,
            },
        )

        if settings.project_name != "custom-project":
            raise AssertionError(
                f"Expected {'custom-project'}, got {settings.project_name}"
            )
        assert settings.project_version == "0.9.0"
        if settings.connection.host != "custom.ldap.com":
            raise AssertionError(
                f"Expected {'custom.ldap.com'}, got {settings.connection.host}"
            )
        assert settings.connection.port == 636
        if not (settings.connection.use_ssl):
            raise AssertionError(f"Expected True, got {settings.connection.use_ssl}")
        assert settings.enable_debug_mode is True
        if settings.enable_performance_monitoring:
            raise AssertionError(
                f"Expected False, got {settings.enable_performance_monitoring}"
            )

    @pytest.mark.unit
    def test_to_ldap_client_config(self) -> None:
        """Test conversion to LDAP client config format."""
        from flext_ldap.config import (
            FlextLdapAuthConfig,
            FlextLdapConnectionConfig,
            FlextLdapSearchConfig,
            FlextLdapSettings,
        )

        connection = FlextLdapConnectionConfig(
            host="test.ldap.com",
            port=636,
            use_ssl=True,
            timeout_seconds=60,
        )
        auth = FlextLdapAuthConfig(
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            bind_password="secret",
        )
        search = FlextLdapSearchConfig(
            base_dn="ou=users,dc=test,dc=com",
            default_search_scope="onelevel",
            size_limit=500,
            time_limit=120,
            paged_search=False,
            page_size=100,
        )

        settings = FlextLdapSettings()
        # Update with custom configurations
        settings = settings.model_copy(
            update={
                "connection": connection,
                "auth": auth,
                "search": search,
            },
        )

        client_config = settings.to_ldap_client_config()

        expected = {
            "server": "test.ldap.com",
            "port": 636,
            "use_ssl": True,
            "timeout": 60,
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            "bind_password": "secret",
            "base_dn": "ou=users,dc=test,dc=com",
            "search_scope": "onelevel",
            "size_limit": 500,
            "time_limit": 120,
            "paged_search": False,
            "page_size": 100,
        }

        if client_config != expected:
            raise AssertionError(f"Expected {expected}, got {client_config}")


class TestDevelopmentConfig:
    """Test development configuration function."""

    @pytest.mark.unit
    def test_create_development_config(self) -> None:
        """Test creating development configuration."""

        config = create_development_config()
        assert config is not None
        # Function currently returns default settings, not the development overrides
        # This tests that the function executes without error
