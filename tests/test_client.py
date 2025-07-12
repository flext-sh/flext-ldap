"""Test LDAP client functionality."""

import pytest


class TestLDAPClient:
    """Test LDAPClient functionality."""

    @pytest.mark.unit
    def test_client_import(self) -> None:
        """Test that LDAPClient can be imported."""
        from flext_ldap.client import LDAPClient

        assert LDAPClient is not None

    @pytest.mark.unit
    def test_client_instantiation_with_settings(self, ldap_settings) -> None:
        """Test that LDAPClient can be instantiated with settings."""
        from flext_ldap.client import LDAPClient

        client = LDAPClient(ldap_settings)
        assert client is not None
        assert not client.is_connected()

    @pytest.mark.unit
    def test_client_instantiation_without_config(self) -> None:
        """Test that LDAPClient can be instantiated without config."""
        from flext_ldap.client import LDAPClient

        client = LDAPClient()
        assert client is not None
        assert not client.is_connected()

    @pytest.mark.unit
    def test_get_server_info_disconnected(self) -> None:
        """Test get_server_info when disconnected."""
        from flext_ldap.client import LDAPClient

        client = LDAPClient()
        info = client.get_server_info()
        assert info == {"status": "disconnected"}
