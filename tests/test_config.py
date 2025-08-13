"""Test FLEXT LDAP Configuration - Configuration functionality."""

from __future__ import annotations

import pytest

from flext_ldap.config import FlextLdapConnectionConfig, FlextLdapSettings


class TestFlextLdapConnectionConfig:
    """Test LDAP connection configuration."""

    def test_config_creation_basic(self) -> None:
        """Test basic configuration creation."""
        config = FlextLdapConnectionConfig(
            server="ldap.example.com",
            port=389,
            use_ssl=False,
        )
        assert config.server == "ldap.example.com"
        assert config.port == 389
        assert config.use_ssl is False

    def test_config_with_ssl(self) -> None:
        """Test configuration with SSL."""
        config = FlextLdapConnectionConfig(
            server="ldaps.example.com",
            port=636,
            use_ssl=True,
        )
        assert config.server == "ldaps.example.com"
        assert config.port == 636
        assert config.use_ssl is True

    def test_config_validation_invalid_port(self) -> None:
        """Test configuration validation for invalid port."""
        with pytest.raises(ValueError):
            FlextLdapConnectionConfig(
                server="ldap.example.com",
                port=70000,  # Invalid port
                use_ssl=False,
            )


class TestFlextLdapSettings:
    """Test LDAP settings configuration."""

    def test_settings_creation_basic(self) -> None:
        """Test basic settings creation."""
        settings = FlextLdapSettings()
        assert settings is not None
        # Should have reasonable defaults

    def test_settings_with_connection_config(self) -> None:
        """Test settings with connection configuration."""
        conn_config = FlextLdapConnectionConfig(
            server="ldap.example.com",
            port=389,
            use_ssl=False,
        )
        settings = FlextLdapSettings(connection=conn_config)
        assert settings.connection == conn_config
