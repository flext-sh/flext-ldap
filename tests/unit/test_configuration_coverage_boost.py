"""Focused tests to boost configuration.py coverage to 100%.

This test file targets specific uncovered lines in configuration.py
to reach 100% coverage systematically.
"""

from __future__ import annotations

import os
import pathlib
import tempfile
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError

from flext_ldap import (
    FlextLdapAuthConfig,
    FlextLdapConnectionConfig,
    FlextLdapSearchConfig,
    FlextLdapSettings,
)


class TestFlextLdapConnectionConfigCoverage:
    """Test FlextLdapConnectionConfig uncovered branches."""

    def test_connection_config_validation_failures(self) -> None:
        """Test validation failures in FlextLdapConnectionConfig."""
        # Test invalid server (covers lines 52-58)
        with pytest.raises(
            ValidationError, match="String should have at least 1 character"
        ):
            FlextLdapConnectionConfig(server="", port=389)

        with pytest.raises(
            ValidationError, match="String should have at least 1 character"
        ):
            FlextLdapConnectionConfig(server="   ", port=389)

        # Test invalid port (covers additional validation)
        with pytest.raises(ValidationError, match="Input should be greater than 0"):
            FlextLdapConnectionConfig(server="test.com", port=0)

        with pytest.raises(
            ValidationError, match="Input should be less than or equal to 65535"
        ):
            FlextLdapConnectionConfig(server="test.com", port=70000)

    def test_connection_config_from_uri_edge_cases(self) -> None:
        """Test URI parsing functionality - REMOVED (method doesn't exist)."""
        # FlextLdapConnectionConfig.from_uri method was removed during architectural cleanup
        # Test removed to match actual implementation

        # Test basic configuration creation instead
        config = FlextLdapConnectionConfig(server="test.example.com", port=389)
        assert config.server == "test.example.com"
        assert config.port == 389

    def test_connection_config_properties(self) -> None:
        """Test connection config computed properties."""
        # Test URI generation with auth config (current architecture)

        auth_ssl = FlextLdapAuthConfig(
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test", bind_password="password", use_ssl=True
        )
        config_ssl = FlextLdapConnectionConfig(
            server="test.com", port=636, auth=auth_ssl
        )

        auth_no_ssl = FlextLdapAuthConfig(
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test", bind_password="password", use_ssl=False
        )
        config_no_ssl = FlextLdapConnectionConfig(
            server="test.com", port=389, auth=auth_no_ssl
        )

        # Test URI generation includes SSL protocol based on auth config
        assert config_ssl.uri == "ldaps://test.com:636"
        assert config_no_ssl.uri == "ldap://test.com:389"

    def test_connection_config_uri_property(self) -> None:
        """Test URI property generation without auth config."""
        # Test basic URI generation without auth (defaults to ldap://)
        config = FlextLdapConnectionConfig(server="test.com", port=389)
        assert config.uri == "ldap://test.com:389"


class TestFlextLdapAuthConfigCoverage:
    """Test FlextLdapAuthConfig uncovered branches."""

    def test_auth_config_validation(self) -> None:
        """Test authentication config validation."""
        # Test empty bind_dn - expect Pydantic validation error

        with pytest.raises(ValidationError, match="String should have at least"):
            FlextLdapAuthConfig(bind_dn="", bind_password="test")

        with pytest.raises(ValidationError, match="String should have at least"):
            FlextLdapAuthConfig(bind_dn="   ", bind_password="test")


class TestFlextLdapSearchConfigCoverage:
    """Test FlextLdapSearchConfig uncovered branches."""

    def test_search_config_validation_branches(self) -> None:
        """Test search config validation edge cases."""
        # Test invalid size_limit (covers validation branches)
        with pytest.raises(ValidationError, match="Input should be greater than 0"):
            FlextLdapSearchConfig(size_limit=0)

        with pytest.raises(ValidationError, match="Input should be greater than 0"):
            FlextLdapSearchConfig(size_limit=-1)

        # Test invalid time_limit
        with pytest.raises(ValidationError, match="Input should be greater than 0"):
            FlextLdapSearchConfig(time_limit=0)


class TestFlextLdapSettingsCoverage:
    """Test FlextLdapSettings uncovered branches and methods."""

    def test_settings_default_construction(self) -> None:
        """Test settings with default values."""
        # Test default construction (covers default value branches)
        settings = FlextLdapSettings()
        # Note: connection defaults to None, auth config available via methods
        assert settings.connection is None  # Default connection not set
        assert hasattr(settings, "get_effective_auth_config")  # Auth config via method
        assert settings.search is not None

    def test_settings_from_env_missing_vars(self) -> None:
        """Test from_env with missing environment variables."""
        # Test missing required environment variables (covers lines 266->277, 268)
        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(
                ValueError, match="FLEXT_LDAP_HOST environment variable is required"
            ),
        ):
            FlextLdapSettings.from_env()

    def test_settings_from_env_partial_vars(self) -> None:
        """Test from_env with partial environment variables."""
        # Test with some environment variables set (covers lines 274, 278)
        env_vars = {
            "FLEXT_LDAP_HOST": "test.com",
            # Missing other required vars
        }
        with patch.dict(os.environ, env_vars, clear=True):
            with pytest.raises(ValueError):
                FlextLdapSettings.from_env()

    def test_settings_from_env_complete_vars(self) -> None:
        """Test from_env with all required environment variables."""
        # Test with complete environment variables (covers lines 285, 289)
        env_vars = {
            "FLEXT_LDAP_HOST": "test.example.com",
            "FLEXT_LDAP_PORT": "389",
            "FLEXT_LDAP_BIND_DN": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test",
            "FLEXT_LDAP_BIND_PASSWORD": "secret123",
            "FLEXT_LDAP_BASE_DN": "dc=test,dc=com",
            "FLEXT_LDAP_USE_SSL": "false",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            settings = FlextLdapSettings.from_env()
            assert settings.connection.server == "test.example.com"
            assert settings.connection.port == 389
            assert settings.connection.base_dn == "dc=test,dc=com"
            assert settings.connection.auth.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test"
            assert (
                settings.connection.auth.bind_password.get_secret_value() == "secret123"
            )
            assert settings.connection.auth.use_ssl is False

    def test_settings_from_file_not_found(self) -> None:
        """Test from_file with non-existent file."""
        # Test file not found (covers lines 298-305)
        with pytest.raises(FileNotFoundError):
            FlextLdapSettings.from_file("/non/existent/file.yaml")

    def test_settings_from_file_invalid_format(self) -> None:
        """Test from_file with invalid YAML format."""
        # Create a temporary file with invalid YAML (covers lines 311, 316, 321)
        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("invalid: yaml: content:\n  - broken")
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Failed to parse configuration file"):
                FlextLdapSettings.from_file(temp_path)
        finally:
            pathlib.Path(temp_path).unlink()

    def test_settings_from_file_valid_yaml(self) -> None:
        """Test from_file with valid YAML configuration."""
        # Create valid YAML configuration (covers lines 327-350)
        yaml_config = """
default_connection:
  server: yaml.example.com
  port: 636
  base_dn: dc=yaml,dc=com
  auth:
    bind_dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=yaml
    bind_password: yaml_password
    use_ssl: true

search:
  size_limit: 500
  time_limit: 60
"""
        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(yaml_config)
            temp_path = f.name

        try:
            settings = FlextLdapSettings.from_file(temp_path)
            assert settings.connection.server == "yaml.example.com"
            assert settings.connection.port == 636
            assert settings.connection.base_dn == "dc=yaml,dc=com"
            assert settings.connection.auth.use_ssl is True
            assert settings.connection.auth.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=yaml"
            assert (
                settings.connection.auth.bind_password.get_secret_value()
                == "yaml_password"
            )
        finally:
            pathlib.Path(temp_path).unlink()

    def test_settings_to_dict_method(self) -> None:
        """Test to_dict method."""
        # Test conversion to dictionary (covers lines 355-378)

        auth_config = FlextLdapAuthConfig(
            bind_dn="cn=test", bind_password=SecretStr("pass")
        )
        connection_config = FlextLdapConnectionConfig(
            server="test.com", port=389, auth=auth_config
        )
        search_config = FlextLdapSearchConfig(size_limit=100)

        # Use the correct field name for FlextLdapSettings (default_connection)
        settings = FlextLdapSettings(
            default_connection=connection_config,
            search=search_config,
        )

        result_dict = settings.to_dict()
        assert isinstance(result_dict, dict)
        # Check for the connection using alias name
        assert "connection" in result_dict or "default_connection" in result_dict
        assert "search" in result_dict

        # Access connection data (could be under either key due to alias)
        connection_data = result_dict.get("connection") or result_dict.get(
            "default_connection"
        )
        assert connection_data["server"] == "test.com"

    def test_settings_from_dict_method(self) -> None:
        """Test from_dict method."""
        # Test construction from dictionary (covers lines 383-407)
        config_dict = {
            "name": "test-settings",
            "version": "1.0.0",
            "environment": "test",
            "timeout": 60,
            "search": {
                "size_limit": 200,
                "time_limit": 30,
            },
        }

        # Test that we can create settings from dict using model_validate
        settings = FlextLdapSettings.model_validate(config_dict)
        assert settings.name == "test-settings"
        assert settings.version == "1.0.0"
        assert settings.environment == "test"
        assert settings.timeout == 60
        assert settings.search.size_limit == 200
