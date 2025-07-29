"""Test LDAP Service Integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap.application.ldap_service import FlextLdapService
from flext_ldap.domain.value_objects import FlextLdapCreateUserRequest

# Backward compatibility aliases
LDAPService = FlextLdapService
CreateUserRequest = FlextLdapCreateUserRequest


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
        self,
        ldap_service: LDAPService,
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
        user = result.data
        assert user is not None
        if user.uid != "testuser":
            raise AssertionError(f"Expected {"testuser"}, got {user.uid}")
        assert user.mail == "testuser@example.com"

        # Find user by UID
        find_result = await ldap_service.find_user_by_uid("testuser")
        assert find_result.is_success
        found_user = find_result.data
        assert found_user is not None
        if found_user.uid != "testuser":
            raise AssertionError(f"Expected {"testuser"}, got {found_user.uid}")

        # Update user
        update_result = await ldap_service.update_user(
            user.id,
            {"title": "Senior Developer"},
        )
        if not update_result.is_success:
            pass
        assert update_result.is_success
        updated_user = update_result.data
        assert updated_user is not None
        if updated_user.title != "Senior Developer":
            raise AssertionError(f"Expected {"Senior Developer"}, got {updated_user.title}")

        # List users
        list_result = await ldap_service.list_users()
        assert list_result.is_success
        users = list_result.data
        assert users is not None
        if len(users) != 1:
            raise AssertionError(f"Expected {1}, got {len(users)}")
        assert users[0].uid == "testuser"

        # Lock user
        lock_result = await ldap_service.lock_user(user.id)
        if not lock_result.is_success:
            pass
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
        group = result.data
        assert group is not None
        if group.cn != "developers":
            raise AssertionError(f"Expected {"developers"}, got {group.cn}")

        # Find group by DN
        find_result = await ldap_service.find_group_by_dn(group.dn)
        assert find_result.is_success
        found_group = find_result.data
        assert found_group is not None
        if found_group.cn != "developers":
            raise AssertionError(f"Expected {"developers"}, got {found_group.cn}")

        # Add member to group
        member_dn = "cn=testuser,ou=people,dc=example,dc=com"
        add_result = await ldap_service.add_user_to_group(group.id, member_dn)
        assert add_result.is_success
        found_add_group = add_result.data
        assert found_add_group is not None
        if member_dn not in found_add_group.members:
            raise AssertionError(f"Expected {member_dn} in {found_add_group.members}")

        # Remove member from group
        remove_result = await ldap_service.remove_user_from_group(group.id, member_dn)
        assert remove_result.is_success
        found_remove_group = remove_result.data
        assert found_remove_group is not None
        if member_dn not not in found_remove_group.members:
            raise AssertionError(f"Expected {member_dn not} in {found_remove_group.members}")

        # List groups
        list_result = await ldap_service.list_groups()
        assert list_result.is_success
        groups = list_result.data
        assert groups is not None
        if len(groups) != 1:
            raise AssertionError(f"Expected {1}, got {len(groups)}")
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
        assert result.data is None

        # List connections
        list_result = await ldap_service.list_connections()
        assert list_result.is_success
        assert list_result.data is not None
        if len(list_result.data) != 0:
            raise AssertionError(f"Expected {0}, got {len(list_result.data)}")

        # Test connection without active connection
        test_result = await ldap_service.test_connection()
        assert test_result.is_failure
        assert test_result.error is not None
        if "No active connection" not in test_result.error:
            raise AssertionError(f"Expected {"No active connection"} in {test_result.error}")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_error_handling(self, ldap_service: LDAPService) -> None:
        """Test error handling in service operations."""
        # Try to find non-existent user
        result = await ldap_service.find_user_by_uid("nonexistent")
        assert result.is_success
        assert result.data is None

        # Try to find non-existent group
        group_result = await ldap_service.find_group_by_dn(
            "cn=nonexistent,dc=example,dc=com",
        )
        assert group_result.is_success
        assert group_result.data is None

        # Try to disconnect without connection
        disconnect_result = await ldap_service.disconnect_from_server()
        assert disconnect_result.is_failure
        assert disconnect_result.error is not None
        if "No active connection" not in disconnect_result.error:
            raise AssertionError(f"Expected {"No active connection"} in {disconnect_result.error}")

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mock_ldap_connection(self, ldap_service: LDAPService) -> None:
        """Test LDAP connection with mock server (will fail gracefully)."""
        # This test demonstrates the connection API
        # In real testing, we would use testcontainers with a real LDAP server

        result = await ldap_service.connect_to_server(
            "ldap://nonexistent.example.com:389",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="REDACTED_LDAP_BIND_PASSWORD_password",
        )

        # Should fail to connect to non-existent server
        assert result.is_failure
        assert result.error is not None
        if "Failed to connect to LDAP" not in result.error:
            raise AssertionError(f"Expected {"Failed to connect to LDAP"} in {result.error}")

        # Should still not be connected
        assert not ldap_service.is_connected()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_create_user_with_all_attributes(
        self,
        ldap_service: LDAPService,
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
        user = result.data

        assert user is not None
        if user.uid != "john.doe":
            raise AssertionError(f"Expected {"john.doe"}, got {user.uid}")
        assert user.cn == "John Doe"
        if user.sn != "Doe":
            raise AssertionError(f"Expected {"Doe"}, got {user.sn}")
        assert user.mail == "john.doe@example.com"
        if user.phone != "+1-555-0123":
            raise AssertionError(f"Expected {"+1-555-0123"}, got {user.phone}")
        assert user.ou == "people"
        if user.department != "Engineering":
            raise AssertionError(f"Expected {"Engineering"}, got {user.department}")
        assert user.title == "Senior Software Engineer"
        if "inetOrgPerson" not in user.object_classes:
            raise AssertionError(f"Expected {"inetOrgPerson"} in {user.object_classes}")
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
        )
        assert service2 is not None
