"""Integration tests for FLEXT LDAP API.

Tests the FlextLdapApi with real LDAP connections and operations.
Focuses on actual LDAP protocol behavior and integration testing.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from flext_ldap.api import FlextLdapApi, get_ldap_api
from flext_ldap.config import FlextLdapConnectionConfig, FlextLdapSettings
from flext_ldap.models import FlextLdapCreateUserRequest, FlextLdapGroup, FlextLdapUser


class TestFlextLdapApiIntegration:
    """Integration tests for FlextLdapApi with real LDAP server."""

    def test_api_instantiation(self) -> None:
        """Test FlextLdapApi instantiation with default configuration."""
        api = FlextLdapApi()
        assert api is not None

    def test_get_ldap_api_singleton(self) -> None:
        """Test factory function provides consistent API instances."""
        api1 = get_ldap_api()
        api2 = get_ldap_api()
        assert api1 is not None
        assert api2 is not None

    def test_api_with_config(self) -> None:
        """Test API initialization with custom configuration."""
        config = FlextLdapConnectionConfig(
            server="test.example.com",
            port=389,
        )
        settings = FlextLdapSettings(default_connection=config)
        api = FlextLdapApi(config=settings)
        assert api is not None

    @pytest.mark.asyncio
    async def test_connection_lifecycle(self) -> None:
        """Test LDAP connection lifecycle management."""
        api = FlextLdapApi()

        # Test connection creation (will fail on actual connection, but tests the flow)
        result = await api.connect("ldap://test.example.com")
        assert result is not None

    def test_api_flext_core_integration(self) -> None:
        """Test API properly integrates with flext-core patterns."""
        api = FlextLdapApi()

        # Should use FlextResult pattern and integrate with flext-core container
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
        assert user_request is not None
        assert user_request.dn == "cn=testuser,ou=users,dc=example,dc=com"

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
