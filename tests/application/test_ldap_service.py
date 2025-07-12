"""Test LDAP Service Integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import sys
from pathlib import Path

# Force use of local src instead of installed package
src_path = Path(__file__).parent.parent.parent / "src"
sys.path.insert(0, str(src_path))

import pytest

from flext_ldap.application.ldap_service import LDAPService
from flext_ldap.domain.value_objects import CreateUserRequest


class TestLDAPService:
    """Test the integrated LDAP service."""

    @pytest.fixture
    def ldap_service(self) -> LDAPService:
        """Create LDAP service for testing."""
        return LDAPService()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_service_initialization(self, ldap_service: LDAPService) -> None:
        """Test service initialization."""
        assert ldap_service is not None
        assert not ldap_service.is_connected()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_user_operations_without_connection(
        self, ldap_service: LDAPService,
    ) -> None:
        """Test user operations work in memory mode without LDAP connection."""
        # Create user request
        request = CreateUserRequest(
            dn="cn=testuser,ou=people,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="testuser@example.com",
        )

        # Create user (should work in memory mode)
        result = await ldap_service.create_user(request)
        assert result.is_success
        user = result.value
        assert user.uid == "testuser"
        assert user.mail == "testuser@example.com"

        # Find user by UID
        find_result = await ldap_service.find_user_by_uid("testuser")
        assert find_result.is_success
        found_user = find_result.value
        assert found_user is not None
        assert found_user.uid == "testuser"

        # Update user
        update_result = await ldap_service.update_user(
            user.id,
            {"title": "Senior Developer"},
        )
        if not update_result.is_success:
            print(f"Update error: {update_result.error_message}")
        assert update_result.is_success
        updated_user = update_result.value
        assert updated_user.title == "Senior Developer"

        # List users
        list_result = await ldap_service.list_users()
        assert list_result.is_success
        users = list_result.value
        assert len(users) == 1
        assert users[0].uid == "testuser"

        # Lock user
        lock_result = await ldap_service.lock_user(user.id)
        if not lock_result.is_success:
            print(f"Lock error: {lock_result.error_message}")
        assert lock_result.is_success

        # Unlock user
        unlock_result = await ldap_service.unlock_user(user.id)
        assert unlock_result.is_success

        # Delete user
        delete_result = await ldap_service.delete_user(user.id)
        assert delete_result.is_success

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_group_operations(self, ldap_service: LDAPService) -> None:
        """Test group operations."""
        # Create group
        result = await ldap_service.create_group(
            dn="cn=developers,ou=groups,dc=example,dc=com",
            cn="developers",
            ou="groups",
        )
        assert result.is_success
        group = result.value
        assert group.cn == "developers"

        # Find group by DN
        find_result = await ldap_service.find_group_by_dn(group.dn)
        assert find_result.is_success
        found_group = find_result.value
        assert found_group is not None
        assert found_group.cn == "developers"

        # Add member to group
        member_dn = "cn=testuser,ou=people,dc=example,dc=com"
        add_result = await ldap_service.add_user_to_group(group.id, member_dn)
        assert add_result.is_success
        updated_group = add_result.value
        assert member_dn in updated_group.members

        # Remove member from group
        remove_result = await ldap_service.remove_user_from_group(group.id, member_dn)
        assert remove_result.is_success
        updated_group = remove_result.value
        assert member_dn not in updated_group.members

        # List groups
        list_result = await ldap_service.list_groups()
        assert list_result.is_success
        groups = list_result.value
        assert len(groups) == 1
        assert groups[0].cn == "developers"

        # Delete group
        delete_result = await ldap_service.delete_group(group.id)
        assert delete_result.is_success

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_connection_management(self, ldap_service: LDAPService) -> None:
        """Test connection management (without real LDAP server)."""
        # Initially not connected
        assert not ldap_service.is_connected()

        # Get active connection (should be None)
        result = await ldap_service.get_active_connection()
        assert result.is_success
        assert result.value is None

        # List connections
        list_result = await ldap_service.list_connections()
        assert list_result.is_success
        assert len(list_result.value) == 0

        # Test connection without active connection
        test_result = await ldap_service.test_connection()
        assert test_result.failure
        assert "No active connection" in test_result.error_message

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_error_handling(self, ldap_service: LDAPService) -> None:
        """Test error handling in service operations."""
        # Try to find non-existent user
        result = await ldap_service.find_user_by_uid("nonexistent")
        assert result.is_success
        assert result.value is None

        # Try to find non-existent group
        group_result = await ldap_service.find_group_by_dn(
            "cn=nonexistent,dc=example,dc=com",
        )
        assert group_result.is_success
        assert group_result.value is None

        # Try to disconnect without connection
        disconnect_result = await ldap_service.disconnect_from_server()
        assert disconnect_result.failure
        assert "No active connection" in disconnect_result.error_message

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mock_ldap_connection(self, ldap_service: LDAPService) -> None:
        """Test LDAP connection with mock server (will fail gracefully)."""
        # This test demonstrates the connection API
        # In real testing, we would use testcontainers with a real LDAP server

        result = await ldap_service.connect_to_server(
            "ldap://nonexistent.example.com:389",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="REDACTED_LDAP_BIND_PASSWORD_password",  # noqa: S106
        )

        # Should fail to connect to non-existent server
        assert result.failure
        assert "Failed to connect to LDAP" in result.error_message

        # Should still not be connected
        assert not ldap_service.is_connected()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_create_user_with_all_attributes(
        self, ldap_service: LDAPService,
    ) -> None:
        """Test creating user with all optional attributes."""
        request = CreateUserRequest(
            dn="cn=john.doe,ou=people,dc=example,dc=com",
            uid="john.doe",
            cn="John Doe",
            sn="Doe",
            mail="john.doe@example.com",
            phone="+1-555-0123",
            ou="people",
            department="Engineering",
            title="Senior Software Engineer",
            object_classes=["inetOrgPerson", "organizationalPerson"],
        )

        result = await ldap_service.create_user(request)
        assert result.is_success
        user = result.value

        assert user.uid == "john.doe"
        assert user.cn == "John Doe"
        assert user.sn == "Doe"
        assert user.mail == "john.doe@example.com"
        assert user.phone == "+1-555-0123"
        assert user.ou == "people"
        assert user.department == "Engineering"
        assert user.title == "Senior Software Engineer"
        assert "inetOrgPerson" in user.object_classes
        assert "organizationalPerson" in user.object_classes

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_service_dependency_injection(self) -> None:
        """Test that service supports dependency injection."""
        # Test that we can create service with custom dependencies
        # This ensures the architecture supports proper DI patterns
        service = LDAPService()
        assert service is not None

        # Test with explicit None parameters (should create defaults)
        service2 = LDAPService(
            ldap_client=None,
            user_service=None,
            group_service=None,
            connection_service=None,
            operation_service=None,
        )
        assert service2 is not None
