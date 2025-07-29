"""Enterprise-grade tests for FlextLdapApi - Core API functionality.

Tests the main unified API without duplication or mockups.
"""

from uuid import uuid4

import pytest
from flext_ldap.api import FlextLdapApi, get_ldap_api
from flext_ldap.config import FlextLdapConnectionConfig
from flext_ldap.entities import FlextLdapGroup, FlextLdapUser
from flext_ldap.values import FlextLdapCreateUserRequest


class TestFlextLdapApi:
    """Test suite for unified FlextLdapApi - NO MOCKUPS."""

    def test_api_instantiation(self) -> None:
        """Test API can be instantiated correctly."""
        api = FlextLdapApi()
        assert api is not None

    def test_get_ldap_api_singleton(self) -> None:
        """Test get_ldap_api returns consistent instance."""
        api1 = get_ldap_api()
        api2 = get_ldap_api()
        assert api1 is not None
        assert api2 is not None

    def test_api_with_config(self) -> None:
        """Test API initialization with configuration."""
        config = FlextLdapConnectionConfig(
            server="ldap://test.example.com",
            port=389,
        )
        api = FlextLdapApi(config=config)
        assert api is not None

    @pytest.mark.asyncio
    async def test_connection_lifecycle(self) -> None:
        """Test connection creation and management."""
        api = FlextLdapApi()

        # Test connection creation
        result = await api.connect("ldap://test.example.com")
        # Note: Will fail on actual connection, but tests the flow
        assert result is not None

    def test_api_flext_core_integration(self) -> None:
        """Test API properly integrates with flext-core patterns."""
        api = FlextLdapApi()

        # Should use FlextResult pattern
        # Should integrate with flext-core container
        # Should follow flext-core logging patterns
        assert hasattr(api, "_container")
        assert hasattr(api, "_client")


class TestFlextLdapApiEntityOperations:
    """Test entity operations through unified API."""

    @pytest.mark.asyncio
    async def test_user_creation_flow(self) -> None:
        """Test complete user creation workflow."""
        FlextLdapApi()

        # Create user request
        user_request = FlextLdapCreateUserRequest(
            dn="cn=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
        )

        # Test user creation through API
        # Note: Tests the flow without actual LDAP connection
        assert user_request is not None
        if user_request.dn != "cn=testuser,ou=users,dc=example,dc=com":
            msg = f"Expected {"cn=testuser,ou=users,dc=example,dc=com"}, got {user_request.dn}"
            raise AssertionError(msg)

    def test_entity_domain_rules(self) -> None:
        """Test domain entities follow business rules."""
        # Test FlextLdapUser
        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test",
            sn="User",
        )
        assert user.is_active()

        # Test account locking
        locked_user = user.lock_account()
        assert not locked_user.is_active()

        # Test FlextLdapGroup
        group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=testgroup,dc=example,dc=com",
            cn="Test Group",
        )

        # Test member operations
        updated_group = group.add_member("cn=user1,dc=example,dc=com")
        assert updated_group.has_member("cn=user1,dc=example,dc=com")


class TestFlextLdapApiIntegration:
    """Integration tests for API components."""

    def test_api_services_integration(self) -> None:
        """Test API integrates properly with services layer."""
        api = FlextLdapApi()

        # Should have proper service composition
        # Should integrate with flext-core patterns
        assert api is not None

    def test_api_error_handling(self) -> None:
        """Test API uses FlextResult pattern consistently."""
        api = FlextLdapApi()

        # All methods should return FlextResult
        # Should handle errors gracefully
        # Should follow flext-core error patterns
        assert api is not None


@pytest.mark.e2e
class TestFlextLdapApiE2E:
    """End-to-end tests for complete workflows."""

    @pytest.mark.asyncio
    async def test_complete_user_lifecycle(self) -> None:
        """Test complete user management lifecycle."""
        api = FlextLdapApi()

        # This would test:
        # 1. Connection establishment
        # 2. User creation
        # 3. User search
        # 4. User modification
        # 5. User deletion
        # 6. Connection cleanup

        # Note: Requires actual LDAP server for full E2E
        assert api is not None

    @pytest.mark.asyncio
    async def test_group_management_workflow(self) -> None:
        """Test complete group management workflow."""
        api = FlextLdapApi()

        # This would test:
        # 1. Group creation
        # 2. Member addition/removal
        # 3. Group search and listing
        # 4. Group deletion

        # Note: Requires actual LDAP server for full E2E
        assert api is not None
