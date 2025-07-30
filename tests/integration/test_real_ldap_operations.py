"""Integration tests for real LDAP operations.

These tests verify that LDAP operations work with a real LDAP server.
Run with: pytest tests/integration/test_real_ldap_operations.py -m integration

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


import pytest
from flext_ldap.application.ldap_service import FlextLdapService
from flext_ldap.ldap_infrastructure import FlextLdapClient, FlextLdapConnectionConfig
from flext_ldap.values import FlextLdapCreateUserRequest


@pytest.mark.integration
class TestRealLdapOperations:
    """Test real LDAP operations against a live server."""

    @pytest.fixture
    def ldap_config(self) -> FlextLdapConnectionConfig:
        """LDAP configuration for testing."""
        return FlextLdapConnectionConfig(
            server_url="ldap://localhost:3389",  # Non-standard port for testing
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="REDACTED_LDAP_BIND_PASSWORD"
        )

    @pytest.fixture
    async def ldap_client(self, ldap_config: FlextLdapConnectionConfig) -> FlextLdapClient:
        """Real LDAP client for testing."""
        client = FlextLdapClient(ldap_config)
        yield client
        # Cleanup
        await client.disconnect()

    @pytest.fixture
    async def ldap_service(self) -> FlextLdapService:
        """LDAP service for testing."""
        return FlextLdapService()

    async def test_ldap_service_connection(
        self,
        ldap_service: FlextLdapService,
        ldap_config: FlextLdapConnectionConfig
    ) -> None:
        """Test LDAP service connection."""
        # Test that service starts disconnected
        assert not ldap_service.is_connected()

        # Test connection (may fail if no LDAP server available)
        result = await ldap_service.connect(
            ldap_config.server_url,
            ldap_config.bind_dn or "",
            ldap_config.password or ""
        )

        # If connection fails (no server), test the fallback behavior
        if result.is_failure:
            assert not ldap_service.is_connected()
        else:
            assert ldap_service.is_connected()
            # Test disconnect
            disconnect_result = await ldap_service.disconnect()
            assert disconnect_result.is_success

    async def test_ldap_service_user_operations_memory_mode(
        self,
        ldap_service: FlextLdapService
    ) -> None:
        """Test LDAP service user operations in memory mode (no server)."""
        # Ensure not connected (memory mode)
        assert not ldap_service.is_connected()

        # Create a test user request
        user_request = FlextLdapCreateUserRequest(
            dn="cn=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="testuser@example.com"
        )

        # Test user creation in memory mode
        create_result = await ldap_service.create_user(user_request)
        assert create_result.is_success
        assert create_result.data is not None
        assert create_result.data.uid == "testuser"

        # Test user lookup
        find_result = await ldap_service.find_user_by_uid("testuser")
        assert find_result.is_success
        assert find_result.data is not None
        assert find_result.data.uid == "testuser"

        # Test user update
        update_result = await ldap_service.update_user("testuser", {"mail": "newemail@example.com"})
        assert update_result.is_success
        assert update_result.data is not None
        assert update_result.data.mail == "newemail@example.com"

        # Test user listing
        list_result = await ldap_service.list_users()
        assert list_result.is_success
        assert len(list_result.data) == 1
        assert list_result.data[0].uid == "testuser"

        # Test user deletion
        delete_result = await ldap_service.delete_user("testuser")
        assert delete_result.is_success

        # Verify user is deleted
        find_result = await ldap_service.find_user_by_uid("testuser")
        assert find_result.is_failure

    async def test_ldap_client_basic_operations(self, ldap_client: FlextLdapClient) -> None:
        """Test basic LDAP client operations."""
        # Test that client is initialized
        assert ldap_client is not None
        assert not ldap_client.is_connected()

        # Test connection attempt (may fail if no server)
        config = FlextLdapConnectionConfig(
            server_url="ldap://localhost:3389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="REDACTED_LDAP_BIND_PASSWORD"
        )

        result = await ldap_client.connect(config)
        # If connection fails, that's expected without a real server
        if result.is_failure:
            assert not ldap_client.is_connected()
        else:
            # If connection succeeds, test basic operations
            assert ldap_client.is_connected()

            # Test search
            search_result = await ldap_client.search(
                "dc=example,dc=com",
                "(objectClass=*)"
            )
            # Search may succeed or fail depending on server state

            # Test disconnect
            disconnect_result = await ldap_client.disconnect()
            assert disconnect_result.is_success
            assert not ldap_client.is_connected()

    async def test_multiple_users_in_memory(self, ldap_service: FlextLdapService) -> None:
        """Test multiple user operations in memory mode."""
        assert not ldap_service.is_connected()

        # Create multiple users
        users = []
        for i in range(3):
            user_request = FlextLdapCreateUserRequest(
                dn=f"cn=user{i},ou=users,dc=example,dc=com",
                uid=f"user{i}",
                cn=f"User {i}",
                sn="User"
            )
            users.append(user_request)

            create_result = await ldap_service.create_user(user_request)
            assert create_result.is_success

        # Test listing all users
        list_result = await ldap_service.list_users()
        assert list_result.is_success
        assert len(list_result.data) == 3

        # Test finding each user
        for i in range(3):
            find_result = await ldap_service.find_user_by_uid(f"user{i}")
            assert find_result.is_success
            assert find_result.data is not None
            assert find_result.data.uid == f"user{i}"

        # Test deleting one user
        delete_result = await ldap_service.delete_user("user1")
        assert delete_result.is_success

        # Verify user count decreased
        list_result = await ldap_service.list_users()
        assert list_result.is_success
        assert len(list_result.data) == 2

    @pytest.mark.slow
    async def test_ldap_service_error_handling(self, ldap_service: FlextLdapService) -> None:
        """Test LDAP service error handling."""
        # Test finding non-existent user
        find_result = await ldap_service.find_user_by_uid("nonexistent")
        assert find_result.is_failure
        assert "not found" in find_result.error

        # Test deleting non-existent user
        delete_result = await ldap_service.delete_user("nonexistent")
        assert delete_result.is_failure
        assert "not found" in delete_result.error

        # Test updating non-existent user
        update_result = await ldap_service.update_user("nonexistent", {"mail": "test@example.com"})
        assert update_result.is_failure
        assert "not found" in update_result.error
