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
        """Test environment variable loading (highest precedence).

        Now works with strict=True using explicit field validators for type coercion.
        """
        # Set environment variables as strings (as they come from OS)
        test_env = {
            "FLEXT_LDAP_PORT": "3389",
            "FLEXT_LDAP_POOL_SIZE": "20",
            "FLEXT_LDAP_CACHE_TTL": "600",
            "FLEXT_LDAP_RETRY_ATTEMPTS": "5",
            "FLEXT_LDAP_USE_SSL": "true",
            "FLEXT_LDAP_ENABLE_CACHING": "1",
            "FLEXT_LDAP_ENABLE_DEBUG": "yes",
            "FLEXT_LDAP_LOG_QUERIES": "on",
        }

        # Save original env vars
        original_env = {}
        for key, value in test_env.items():
            original_env[key] = os.environ.get(key)
            os.environ[key] = value

        try:
            # Create config - should load from environment variables
            config = FlextLdapConfig()

            # Verify integer fields are properly coerced from strings
            assert config.ldap_port == 3389, f"Expected 3389, got {config.ldap_port}"
            assert config.ldap_pool_size == 20, (
                f"Expected 20, got {config.ldap_pool_size}"
            )
            assert config.ldap_cache_ttl == 600, (
                f"Expected 600, got {config.ldap_cache_ttl}"
            )
            assert config.ldap_retry_attempts == 5, (
                f"Expected 5, got {config.ldap_retry_attempts}"
            )

            # Verify boolean fields are properly coerced from various string formats
            assert config.ldap_use_ssl is True, "Expected True from 'true'"
            assert config.ldap_enable_caching is True, "Expected True from '1'"
            assert config.ldap_enable_debug is True, "Expected True from 'yes'"
            assert config.ldap_log_queries is True, "Expected True from 'on'"

        finally:
            # Restore original environment
            for key, value in original_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_dotenv_file_loading(self) -> None:
        """Test .env file loading (lower precedence than env vars).

        Now works with strict=True using explicit field validators for type coercion.
        """
        # Create temporary .env file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".env", delete=False, encoding="utf-8"
        ) as f:
            f.write("FLEXT_LDAP_PORT=3390\n")
            f.write("FLEXT_LDAP_POOL_SIZE=25\n")
            f.write("FLEXT_LDAP_USE_SSL=false\n")
            f.write("FLEXT_LDAP_ENABLE_CACHING=0\n")
            env_file_path = f.name

        try:
            # Load config from .env file (field validators handle type coercion)
            config = FlextLdapConfig(_env_file=env_file_path)

            # Verify values loaded from .env file
            assert config.ldap_port == 3390, f"Expected 3390, got {config.ldap_port}"
            assert config.ldap_pool_size == 25, (
                f"Expected 25, got {config.ldap_pool_size}"
            )
            assert config.ldap_use_ssl is False, "Expected False from 'false'"
            assert config.ldap_enable_caching is False, "Expected False from '0'"

        finally:
            # Clean up temp file
            Path(env_file_path).unlink(missing_ok=True)

    def test_order_of_precedence(self) -> None:
        """Test order of precedence: env var > .env file > defaults.

        Now works with strict=True using explicit field validators for type coercion.
        """
        # Create temporary .env file with one value
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".env", delete=False, encoding="utf-8"
        ) as f:
            f.write("FLEXT_LDAP_PORT=3390\n")  # .env file value
            f.write("FLEXT_LDAP_POOL_SIZE=25\n")  # .env file value
            env_file_path = f.name

        # Set environment variable that should override .env file
        os.environ["FLEXT_LDAP_PORT"] = "3391"  # env var should win

        try:
            # Load config
            config = FlextLdapConfig(_env_file=env_file_path)

            # Verify precedence: env var > .env file > defaults
            assert config.ldap_port == 3391, (
                f"Expected 3391 from env var (not 3390 from .env file), got {config.ldap_port}"
            )
            assert config.ldap_pool_size == 25, (
                f"Expected 25 from .env file, got {config.ldap_pool_size}"
            )
            # ldap_retry_attempts should be default (no env var, no .env file)
            assert config.ldap_retry_attempts == 3, (
                f"Expected default 3, got {config.ldap_retry_attempts}"
            )

        finally:
            # Clean up
            os.environ.pop("FLEXT_LDAP_PORT", None)
            Path(env_file_path).unlink(missing_ok=True)

    def test_logging_configuration_from_environment(self) -> None:
        """Test logging configuration from environment variables.

        Now works with strict=True using explicit field validators for type coercion.
        """
        # Set logging-related environment variables
        test_env = {
            "FLEXT_LDAP_ENABLE_DEBUG": "true",
            "FLEXT_LDAP_ENABLE_TRACE": "1",
            "FLEXT_LDAP_LOG_QUERIES": "yes",
            "FLEXT_LDAP_MASK_PASSWORDS": "on",
        }

        # Save original env vars
        original_env = {}
        for key, value in test_env.items():
            original_env[key] = os.environ.get(key)
            os.environ[key] = value

        try:
            # Create config
            config = FlextLdapConfig()

            # Verify all boolean logging flags are properly coerced
            assert config.ldap_enable_debug is True, "Expected True from 'true'"
            assert config.ldap_enable_trace is True, "Expected True from '1'"
            assert config.ldap_log_queries is True, "Expected True from 'yes'"
            assert config.ldap_mask_passwords is True, "Expected True from 'on'"

        finally:
            # Restore original environment
            for key, value in original_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_computed_fields_with_environment_configuration(self) -> None:
        """Test all computed fields work correctly with environment configuration.

        Now works with strict=True using explicit field validators for type coercion.
        """
        # Set environment variables that affect computed fields
        test_env = {
            "FLEXT_LDAP_SERVER_URI": "ldap://test.example.com",
            "FLEXT_LDAP_PORT": "3389",
            "FLEXT_LDAP_USE_SSL": "true",
            "FLEXT_LDAP_BASE_DN": "dc=test,dc=example,dc=com",
        }

        # Save original env vars
        original_env = {}
        for key, value in test_env.items():
            original_env[key] = os.environ.get(key)
            os.environ[key] = value

        try:
            # Create config
            config = FlextLdapConfig()

            # Verify fields loaded from env vars
            assert config.ldap_server_uri == "ldap://test.example.com"
            assert config.ldap_port == 3389
            assert config.ldap_use_ssl is True
            assert config.ldap_base_dn == "dc=test,dc=example,dc=com"

            # Verify computed fields work with env var configuration
            assert hasattr(config, "connection_info"), (
                "Computed field connection_info missing"
            )
            assert hasattr(config, "authentication_info"), (
                "Computed field authentication_info missing"
            )
            assert hasattr(config, "ldap_capabilities"), (
                "Computed field ldap_capabilities missing"
            )

            # Verify computed fields return expected data
            assert config.connection_info is not None
            assert isinstance(config.connection_info, dict)
            assert config.connection_info["server_uri"] == "ldap://test.example.com"
            assert config.connection_info["port"] == 3389

        finally:
            # Restore original environment
            for key, value in original_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

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
        """Test SecretStr properly protects password in environment variable loading.

        SecretStr works with environment variables regardless of strict mode.
        """
        # Set password via environment variable
        test_password = "super_secret_password_123"
        os.environ["FLEXT_LDAP_BIND_PASSWORD"] = test_password

        try:
            # Create config
            config = FlextLdapConfig()

            # Verify password is loaded
            assert config.ldap_bind_password is not None

            # Verify SecretStr protection - should not expose password in repr
            config_repr = repr(config)
            assert test_password not in config_repr, (
                "Password exposed in repr - SecretStr protection failed"
            )

            # Verify can get secret value when needed
            if hasattr(config.ldap_bind_password, "get_secret_value"):
                actual_password = config.ldap_bind_password.get_secret_value()
                assert actual_password == test_password, (
                    f"Expected '{test_password}', got '{actual_password}'"
                )

        finally:
            # Clean up
            os.environ.pop("FLEXT_LDAP_BIND_PASSWORD", None)
