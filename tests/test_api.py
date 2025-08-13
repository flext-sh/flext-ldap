"""Test FLEXT LDAP API - Core API functionality."""

from __future__ import annotations

from flext_ldap import FlextLdapApi, get_ldap_api


class TestFlextLdapApi:
    """Test core API functionality."""

    def test_api_creation(self) -> None:
        """Test API instance creation."""
        api = FlextLdapApi()
        assert api is not None

    def test_get_ldap_api_factory(self) -> None:
        """Test API factory function."""
        api = get_ldap_api()
        assert api is not None
        assert isinstance(api, FlextLdapApi)

    def test_api_singleton_behavior(self) -> None:
        """Test that get_ldap_api returns same instance."""
        api1 = get_ldap_api()
        api2 = get_ldap_api()
        # Should be same instance due to container management
        assert isinstance(api1, FlextLdapApi)
        assert isinstance(api2, FlextLdapApi)
