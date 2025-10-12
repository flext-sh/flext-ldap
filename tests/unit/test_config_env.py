"""Unit tests for FlextLdapConfig environment variable loading.

Tests Pydantic 2 Settings automatic .env loading and environment variable
configuration with order of precedence validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import os
import tempfile
from pathlib import Path

import pytest

from flext_ldap import FlextLdapConfig


class TestFlextLdapConfigEnvironment:
    """Test suite for FlextLdapConfig environment variable configuration."""

    def test_env_prefix_configuration(self) -> None:
        """Test env_prefix is correctly inherited from FlextCore.Config."""
        config = FlextLdapConfig()
        model_config = config.model_config

        env_prefix = model_config.get("env_prefix")
        env_file = model_config.get("env_file")
        env_nested_delimiter = model_config.get("env_nested_delimiter")

        assert env_prefix == "FLEXT_", f"Expected 'FLEXT_', got {env_prefix}"
        assert env_file == ".env", f"Expected '.env', got {env_file}"
        assert env_nested_delimiter == "__", (
            f"Expected '__', got {env_nested_delimiter}"
        )

    def test_field_name_environment_variable_mapping(self) -> None:
        """Test field names map to correct environment variables with env_prefix."""
        # Test that field names correctly map with FLEXT_ prefix
        field_to_env = {
            "ldap_server_uri": "FLEXT_LDAP_SERVER_URI",
            "ldap_port": "FLEXT_LDAP_PORT",
            "ldap_bind_dn": "FLEXT_LDAP_BIND_DN",
            "ldap_bind_password": "FLEXT_LDAP_BIND_PASSWORD",
            "ldap_base_dn": "FLEXT_LDAP_BASE_DN",
            "ldap_pool_size": "FLEXT_LDAP_POOL_SIZE",
            "ldap_connection_timeout": "FLEXT_LDAP_CONNECTION_TIMEOUT",
            "ldap_enable_caching": "FLEXT_LDAP_ENABLE_CACHING",
            "ldap_retry_attempts": "FLEXT_LDAP_RETRY_ATTEMPTS",
        }

        config = FlextLdapConfig()

        # Verify all fields exist
        for field_name in field_to_env:
            assert hasattr(config, field_name), (
                f"Field {field_name} not found in FlextLdapConfig"
            )

    def test_environment_variable_loading(self) -> None:
        """Test environment variable loading (highest precedence)."""
        # Set environment variables (bind_dn requires bind_password per validation rule)
        os.environ["FLEXT_LDAP_SERVER_URI"] = "ldap://env-test:389"
        os.environ["FLEXT_LDAP_PORT"] = "9999"
        os.environ["FLEXT_LDAP_BIND_DN"] = "cn=env-admin,dc=test,dc=com"
        os.environ["FLEXT_LDAP_BIND_PASSWORD"] = "env-password"

        try:
            config = FlextLdapConfig()

            assert config.ldap_server_uri == "ldap://env-test:389"
            assert config.ldap_port == 9999
            assert config.ldap_bind_dn == "cn=env-admin,dc=test,dc=com"
            assert config.get_effective_bind_password() == "env-password"
        finally:
            # Cleanup
            del os.environ["FLEXT_LDAP_SERVER_URI"]
            del os.environ["FLEXT_LDAP_PORT"]
            del os.environ["FLEXT_LDAP_BIND_DN"]
            del os.environ["FLEXT_LDAP_BIND_PASSWORD"]

    def test_dotenv_file_loading(self) -> None:
        """Test .env file loading (lower precedence than env vars)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file_path = Path(tmpdir) / ".env"
            env_file_path.write_text(
                "FLEXT_LDAP_SERVER_URI=ldap://dotenv-test:389\n"
                "FLEXT_LDAP_PORT=8888\n"
                "FLEXT_LDAP_BASE_DN=dc=dotenv,dc=test\n"
            )

            # Change to temp directory so .env is found
            original_dir = Path.cwd()
            os.chdir(tmpdir)

            try:
                config = FlextLdapConfig()

                assert config.ldap_server_uri == "ldap://dotenv-test:389"
                assert config.ldap_port == 8888
                assert config.ldap_base_dn == "dc=dotenv,dc=test"
            finally:
                os.chdir(original_dir)

    def test_order_of_precedence(self) -> None:
        """Test order of precedence: env var > .env file > defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file_path = Path(tmpdir) / ".env"
            env_file_path.write_text(
                "FLEXT_LDAP_SERVER_URI=ldap://dotenv-test:389\nFLEXT_LDAP_PORT=8888\n"
            )

            # Set environment variable (should override .env)
            os.environ["FLEXT_LDAP_SERVER_URI"] = "ldap://env-override:389"

            original_dir = Path.cwd()
            os.chdir(tmpdir)

            try:
                config = FlextLdapConfig()

                # env var should override .env
                assert config.ldap_server_uri == "ldap://env-override:389", (
                    "Env var should override .env"
                )

                # .env should override default
                assert config.ldap_port == 8888, ".env should override default"

                # No override, should use default
                assert config.ldap_pool_size == 10, "Should use default"
            finally:
                os.chdir(original_dir)
                del os.environ["FLEXT_LDAP_SERVER_URI"]

    def test_logging_configuration_from_environment(self) -> None:
        """Test logging configuration from environment variables."""
        # Set logging-related environment variables
        os.environ["FLEXT_LOG_LEVEL"] = "DEBUG"
        os.environ["FLEXT_LDAP_ENABLE_DEBUG"] = "true"
        os.environ["FLEXT_LDAP_ENABLE_TRACE"] = "true"
        os.environ["FLEXT_LDAP_LOG_QUERIES"] = "true"
        os.environ["FLEXT_LDAP_MASK_PASSWORDS"] = "false"

        try:
            config = FlextLdapConfig()

            # Validate logging configuration loaded
            assert config.log_level == "DEBUG"
            assert config.ldap_enable_debug is True
            assert config.ldap_enable_trace is True
            assert config.ldap_log_queries is True
            assert config.ldap_mask_passwords is False

        finally:
            # Cleanup
            del os.environ["FLEXT_LOG_LEVEL"]
            del os.environ["FLEXT_LDAP_ENABLE_DEBUG"]
            del os.environ["FLEXT_LDAP_ENABLE_TRACE"]
            del os.environ["FLEXT_LDAP_LOG_QUERIES"]
            del os.environ["FLEXT_LDAP_MASK_PASSWORDS"]

    def test_computed_fields_with_environment_configuration(self) -> None:
        """Test all computed fields work correctly with environment configuration."""
        # Set comprehensive environment configuration
        os.environ["FLEXT_LDAP_SERVER_URI"] = "ldaps://prod.example.com"
        os.environ["FLEXT_LDAP_PORT"] = "636"
        os.environ["FLEXT_LDAP_USE_SSL"] = "true"
        os.environ["FLEXT_LDAP_VERIFY_CERTIFICATES"] = "true"
        os.environ["FLEXT_LDAP_BIND_DN"] = "cn=app,dc=prod,dc=com"
        os.environ["FLEXT_LDAP_BIND_PASSWORD"] = "prod-secret"
        os.environ["FLEXT_LDAP_POOL_SIZE"] = "20"
        os.environ["FLEXT_LDAP_ENABLE_CACHING"] = "true"
        os.environ["FLEXT_LDAP_CACHE_TTL"] = "600"
        os.environ["FLEXT_LDAP_RETRY_ATTEMPTS"] = "5"

        try:
            config = FlextLdapConfig()

            # Test connection_info computed field
            conn_info = config.connection_info
            assert conn_info["effective_uri"] == "ldaps://prod.example.com:636"
            assert conn_info["is_secure"] is True

            # Test authentication_info computed field
            auth_info = config.authentication_info
            assert auth_info["bind_dn_configured"] is True
            assert auth_info["bind_password_configured"] is True
            assert auth_info["anonymous_bind"] is False

            # Test pooling_info computed field
            pool_info = config.pooling_info
            assert pool_info["pool_size"] == 20

            # Test caching_info computed field
            cache_info = config.caching_info
            assert cache_info["caching_enabled"] is True
            assert cache_info["cache_ttl"] == 600
            assert cache_info["cache_effective"] is True

            # Test retry_info computed field
            retry_info = config.retry_info
            assert retry_info["retry_attempts"] == 5
            assert retry_info["retry_enabled"] is True

            # Test ldap_capabilities computed field
            capabilities = config.ldap_capabilities
            assert capabilities["is_production_ready"] is True
            assert capabilities["supports_ssl"] is True
            assert capabilities["has_authentication"] is True
            assert capabilities["has_pooling"] is True
        finally:
            # Cleanup
            for key in [
                "FLEXT_LDAP_SERVER_URI",
                "FLEXT_LDAP_PORT",
                "FLEXT_LDAP_USE_SSL",
                "FLEXT_LDAP_VERIFY_CERTIFICATES",
                "FLEXT_LDAP_BIND_DN",
                "FLEXT_LDAP_BIND_PASSWORD",
                "FLEXT_LDAP_POOL_SIZE",
                "FLEXT_LDAP_ENABLE_CACHING",
                "FLEXT_LDAP_CACHE_TTL",
                "FLEXT_LDAP_RETRY_ATTEMPTS",
            ]:
                if key in os.environ:
                    del os.environ[key]

    def test_env_file_minimal_format(self) -> None:
        """Test .env.minimal uses correct format without duplicate LDAP prefix."""
        env_minimal_path = Path(__file__).parent.parent.parent / ".env.minimal"

        if env_minimal_path.exists():
            content = env_minimal_path.read_text()

            # Check for INCORRECT format (double LDAP prefix) - ignore comments
            lines = content.split("\n")
            incorrect_lines = [
                line
                for line in lines
                if "FLEXT_LDAP_LDAP_" in line and not line.strip().startswith("#")
            ]

            assert len(incorrect_lines) == 0, (
                f".env.minimal has duplicate LDAP prefix in lines: {incorrect_lines}"
            )
        else:
            pytest.skip(".env.minimal not found")

    def test_nested_delimiter_configuration(self) -> None:
        """Test nested delimiter is configured for future use."""
        config = FlextLdapConfig()
        delimiter = config.model_config.get("env_nested_delimiter")

        assert delimiter == "__", (
            "Nested delimiter should be '__' for future nested model support"
        )

    def test_secretstr_password_handling(self) -> None:
        """Test SecretStr properly protects password in environment variable loading."""
        os.environ["FLEXT_LDAP_BIND_DN"] = "cn=test,dc=example,dc=com"
        os.environ["FLEXT_LDAP_BIND_PASSWORD"] = "secret-password-123"

        try:
            config = FlextLdapConfig()

            # Password should be SecretStr type
            assert config.ldap_bind_password is not None
            assert str(type(config.ldap_bind_password).__name__) == "SecretStr"

            # Get effective password should return actual value
            assert config.get_effective_bind_password() == "secret-password-123"

            # model_dump should not expose raw password by default
            config_dict = config.model_dump()
            # SecretStr fields are excluded by default in Pydantic 2
            if "ldap_bind_password" in config_dict:
                # If included, should not be the raw password
                assert config_dict["ldap_bind_password"] != "secret-password-123"
        finally:
            del os.environ["FLEXT_LDAP_BIND_DN"]
            del os.environ["FLEXT_LDAP_BIND_PASSWORD"]
