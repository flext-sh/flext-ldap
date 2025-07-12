"""Test configuration functionality."""

import pytest


class TestFlextLDAPSettings:
    """Test FlextLDAPSettings functionality."""

    @pytest.mark.unit
    def test_settings_import(self):
        """Test that FlextLDAPSettings can be imported."""
        from flext_ldap.config import FlextLDAPSettings
        
        assert FlextLDAPSettings is not None

    @pytest.mark.unit
    def test_settings_instantiation_defaults(self):
        """Test that FlextLDAPSettings can be instantiated with defaults."""
        from flext_ldap.config import FlextLDAPSettings
        
        settings = FlextLDAPSettings()
        assert settings is not None
        assert settings.connection.server == "localhost"
        assert settings.connection.port == 389
        
    @pytest.mark.unit
    def test_connection_config_custom(self):
        """Test LDAPConnectionConfig with custom values."""
        from flext_ldap.config import LDAPConnectionConfig
        
        config = LDAPConnectionConfig(
            server="ldap://test.example.com",
            port=636,
            use_ssl=True,
        )
        assert config.server == "ldap://test.example.com"
        assert config.port == 636
        assert config.use_ssl is True