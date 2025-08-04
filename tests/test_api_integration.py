"""Test API module integration.

Integration tests for flext_ldap.api to increase coverage.
"""

from flext_ldap import FlextLdapApi, get_ldap_api
from flext_ldap.config import FlextLdapSettings
from flext_ldap.entities import FlextLdapEntry, FlextLdapGroup, FlextLdapUser
from flext_ldap.values import FlextLdapCreateUserRequest


class TestFlextLdapApiBasics:
    """Test basic API functionality."""

    def test_api_initialization_default(self) -> None:
        """Test API initialization without config."""
        api = FlextLdapApi()
        assert api is not None
        assert hasattr(api, "_config")
        assert hasattr(api, "_client")
        assert hasattr(api, "_connections")

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with config."""
        config = FlextLdapSettings(host="test.example.com", port=389)
        api = FlextLdapApi(config)
        assert api is not None
        assert api._config is not None

    def test_get_ldap_api_factory(self) -> None:
        """Test factory function."""
        api = get_ldap_api()
        assert api is not None
        assert isinstance(api, FlextLdapApi)

    def test_health_check(self) -> None:
        """Test health check functionality."""
        api = FlextLdapApi()
        health_result = api.health()

        assert health_result.success
        assert health_result.data is not None
        assert "status" in health_result.data
        assert "service" in health_result.data
        assert "version" in health_result.data


class TestFlextLdapApiDomainEntities:
    """Test domain entity creation."""

    def test_ldap_entry_creation(self) -> None:
        """Test FlextLdapEntry creation."""
        entry = FlextLdapEntry(
            id="entry-id",
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]},
        )
        assert entry.dn == "cn=test,dc=example,dc=com"
        assert "cn" in entry.attributes
        assert entry.id == "entry-id"

    def test_ldap_user_creation(self) -> None:
        """Test FlextLdapUser creation."""
        user = FlextLdapUser(
            id="test-id",
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User",
        )
        assert user.uid == "test"
        assert user.cn == "Test User"
        assert user.sn == "User"
        assert user.dn == "cn=test,dc=example,dc=com"

    def test_ldap_group_creation(self) -> None:
        """Test FlextLdapGroup creation."""
        group = FlextLdapGroup(
            id="group-id", dn="cn=group,dc=example,dc=com", cn="Test Group"
        )
        assert group.cn == "Test Group"
        assert group.dn == "cn=group,dc=example,dc=com"
        assert group.id == "group-id"

    def test_create_user_request(self) -> None:
        """Test FlextLdapCreateUserRequest creation."""
        request = FlextLdapCreateUserRequest(
            dn="cn=test,dc=example,dc=com", uid="test", cn="Test User", sn="User"
        )
        assert request.uid == "test"
        assert request.cn == "Test User"
        assert request.sn == "User"
        assert request.dn == "cn=test,dc=example,dc=com"


class TestFlextLdapApiConfigIntegration:
    """Test API configuration integration."""

    def test_config_settings_integration(self) -> None:
        """Test that config integrates properly."""
        config = FlextLdapSettings(host="localhost", port=389, use_ssl=False)
        assert config.host == "localhost"
        assert config.port == 389
        assert config.use_ssl is False

    def test_api_with_custom_settings(self) -> None:
        """Test API with custom settings."""
        config = FlextLdapSettings(host="custom.example.com", port=636, use_ssl=True)
        api = FlextLdapApi(config)
        assert api._config.host == "custom.example.com"
        assert api._config.port == 636
        assert api._config.use_ssl is True
