"""Tests for application services in FLEXT-LDAP."""

from typing import Any
from uuid import UUID, uuid4

import pytest

from flext_ldap.application.services import (
    FlextLdapConnectionApplicationService as FlextLdapConnectionService,
    FlextLdapGroupService,
    FlextLdapOperationService,
    FlextLdapUserApplicationService as FlextLdapUserService,
)
from flext_ldap.domain.value_objects import FlextLdapCreateUserRequest


class TestFlextLdapUserService:
    """Test FlextLdapUserService."""

    @pytest.fixture
    def user_service(self) -> FlextLdapUserService:
        """Create user service instance."""
        return FlextLdapUserService()

    @pytest.fixture
    def create_user_request(self) -> FlextLdapCreateUserRequest:
        """Create user request for testing."""
        return FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User",
            mail="test@example.org",
        )

    async def test_create_user(
        self,
        user_service: FlextLdapUserService,
        create_user_request: FlextLdapCreateUserRequest,
    ) -> None:
        """Test creating a user."""
        result = await user_service.create_user(create_user_request)

        assert result.success is True
        user = result.data
        assert user is not None
        assert user.uid == "test"
        assert user.cn == "Test User"
        assert user.is_active() is True

    async def test_get_user(
        self,
        user_service: FlextLdapUserService,
        create_user_request: FlextLdapCreateUserRequest,
    ) -> None:
        """Test getting a user by ID."""
        # Create user first
        create_result = await user_service.create_user(create_user_request)
        assert create_result.data is not None
        user_id = create_result.data.id

        # Get user
        result = await user_service.get_user(UUID(str(user_id)))
        assert result.success is True
        assert result.data is not None
        assert result.data.uid == "test"

    async def test_get_user_not_found(self, user_service: FlextLdapUserService) -> None:
        """Test getting non-existent user."""
        user_id = uuid4()
        result = await user_service.get_user(user_id)
        assert result.success is True
        assert result.data is None

    async def test_find_user_by_dn(
        self,
        user_service: FlextLdapUserService,
        create_user_request: FlextLdapCreateUserRequest,
    ) -> None:
        """Test finding user by DN."""
        # Create user first
        await user_service.create_user(create_user_request)

        # Find by DN
        result = await user_service.find_user_by_dn(create_user_request.dn)
        assert result.success is True
        assert result.data is not None
        assert result.data.uid == "test"

    async def test_find_user_by_uid(
        self,
        user_service: FlextLdapUserService,
        create_user_request: FlextLdapCreateUserRequest,
    ) -> None:
        """Test finding user by UID."""
        # Create user first
        await user_service.create_user(create_user_request)

        # Find by UID
        result = await user_service.find_user_by_uid("test")
        assert result.success is True
        assert result.data is not None
        assert result.data.uid == "test"

    async def test_update_user(
        self,
        user_service: FlextLdapUserService,
        create_user_request: FlextLdapCreateUserRequest,
    ) -> None:
        """Test updating a user."""
        # Create user first
        create_result = await user_service.create_user(create_user_request)
        assert create_result.data is not None
        user_id = create_result.data.id

        # Update user
        updates = {"mail": "updated@example.org"}
        result = await user_service.update_user(UUID(str(user_id)), updates)

        assert result.success is True
        assert result.data is not None
        assert result.data.mail == "updated@example.org"
        assert result.data.version == 2

    async def test_lock_unlock_user(
        self,
        user_service: FlextLdapUserService,
        create_user_request: FlextLdapCreateUserRequest,
    ) -> None:
        """Test locking and unlocking user."""
        # Create user first
        create_result = await user_service.create_user(create_user_request)
        assert create_result.data is not None
        user_id = create_result.data.id

        # Lock user
        lock_result = await user_service.lock_user(UUID(str(user_id)))
        assert lock_result.success is True
        assert lock_result.data is not None
        assert lock_result.data.is_active() is False

        # Unlock user
        unlock_result = await user_service.unlock_user(UUID(str(user_id)))
        assert unlock_result.success is True
        assert unlock_result.data is not None
        assert unlock_result.data.is_active() is True

    async def test_delete_user(
        self,
        user_service: FlextLdapUserService,
        create_user_request: FlextLdapCreateUserRequest,
    ) -> None:
        """Test deleting a user."""
        # Create user first
        create_result = await user_service.create_user(create_user_request)
        assert create_result.data is not None
        user_id = create_result.data.id

        # Delete user
        result = await user_service.delete_user(UUID(str(user_id)))
        assert result.success is True
        assert result.data is True

    async def test_list_users(
        self,
        user_service: FlextLdapUserService,
        create_user_request: FlextLdapCreateUserRequest,
    ) -> None:
        """Test listing users."""
        # Create user first
        await user_service.create_user(create_user_request)

        # List users
        result = await user_service.list_users()
        assert result.success is True
        assert result.data is not None
        assert len(result.data) >= 1


class TestFlextLdapGroupService:
    """Test FlextLdapGroupService."""

    @pytest.fixture
    def group_service(self) -> FlextLdapGroupService:
        """Create group service instance."""
        return FlextLdapGroupService()

    async def test_create_group(self, group_service: FlextLdapGroupService) -> None:
        """Test creating a group."""
        result = await group_service.create_group(
            dn="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=org",
            cn="REDACTED_LDAP_BIND_PASSWORDs",
            members=["uid=user1,ou=users,dc=example,dc=org"],
        )

        assert result.success is True
        group = result.data
        assert group is not None
        assert group.cn == "REDACTED_LDAP_BIND_PASSWORDs"
        assert len(group.members) == 1

    async def test_get_group(self, group_service: FlextLdapGroupService) -> None:
        """Test getting a group by ID."""
        # Create group first
        create_result = await group_service.create_group(
            dn="cn=test,ou=groups,dc=example,dc=org",
            cn="test",
        )
        assert create_result.data is not None
        group_id = create_result.data.id

        # Get group
        result = await group_service.get_group(UUID(str(group_id)))
        assert result.success is True
        assert result.data is not None
        assert result.data.cn == "test"

    async def test_add_remove_member(
        self, group_service: FlextLdapGroupService
    ) -> None:
        """Test adding and removing group members."""
        # Create group first
        create_result = await group_service.create_group(
            dn="cn=test,ou=groups,dc=example,dc=org",
            cn="test",
        )
        assert create_result.data is not None
        group_id = create_result.data.id

        # Add member
        member_dn = "uid=test,ou=users,dc=example,dc=org"
        add_result = await group_service.add_member(UUID(str(group_id)), member_dn)
        assert add_result.success is True
        assert add_result.data is not None
        assert member_dn in add_result.data.members

        # Remove member
        remove_result = await group_service.remove_member(UUID(str(group_id)), member_dn)
        assert remove_result.success is True
        assert remove_result.data is not None
        assert member_dn not in remove_result.data.members

    async def test_list_groups(self, group_service: FlextLdapGroupService) -> None:
        """Test listing groups."""
        # Create group first
        await group_service.create_group(
            dn="cn=test,ou=groups,dc=example,dc=org",
            cn="test",
        )

        # List groups
        result = await group_service.list_groups()
        assert result.success is True
        assert result.data is not None
        assert len(result.data) >= 1


class TestFlextLdapConnectionService:
    """Test FlextLdapConnectionService."""

    @pytest.fixture
    def connection_service(self) -> FlextLdapConnectionService:
        """Create connection service instance."""
        return FlextLdapConnectionService()

    async def test_create_connection_no_ldap_client(
        self, connection_service: FlextLdapConnectionService
    ) -> None:
        """Test creating a connection without real LDAP client."""
        # This will fail because no real LDAP client is configured
        result = await connection_service.create_connection(
            server_uri="ldap://localhost:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org",
            password="REDACTED_LDAP_BIND_PASSWORD",
        )

        # Should fail gracefully
        assert result.success is False

    async def test_get_connection(
        self, connection_service: FlextLdapConnectionService
    ) -> None:
        """Test getting connection by ID."""
        connection_id = uuid4()
        result = await connection_service.get_connection(connection_id)
        assert result.success is True
        assert result.data is None

    async def test_list_connections(
        self, connection_service: FlextLdapConnectionService
    ) -> None:
        """Test listing connections."""
        result = await connection_service.list_connections()
        assert result.success is True
        assert isinstance(result.data, list)


class TestFlextLdapOperationService:
    """Test FlextLdapOperationService."""

    @pytest.fixture
    def operation_service(self) -> FlextLdapOperationService:
        """Create operation service instance."""
        return FlextLdapOperationService()

    async def test_create_operation(
        self, operation_service: FlextLdapOperationService
    ) -> None:
        """Test creating an operation."""
        connection_id = uuid4()
        result = await operation_service.create_operation(
            operation_type="search",
            target_dn="ou=users,dc=example,dc=org",
            connection_id=connection_id,
            filter_expression="(objectClass=inetOrgPerson)",
        )

        assert result.success is True
        operation = result.data
        assert operation is not None
        assert operation.operation_type == "search"
        assert operation.target_dn == "ou=users,dc=example,dc=org"

    async def test_complete_operation(
        self, operation_service: FlextLdapOperationService
    ) -> None:
        """Test completing an operation."""
        connection_id = uuid4()

        # Create operation first
        create_result = await operation_service.create_operation(
            operation_type="search",
            target_dn="ou=users,dc=example,dc=org",
            connection_id=connection_id,
        )
        assert create_result.data is not None
        operation_id = create_result.data.id

        # Complete operation
        result = await operation_service.complete_operation(
            UUID(str(operation_id)),
            success=True,
            result_count=5,
        )

        assert result.success is True
        assert result.data is not None
        assert result.data.success is True
        assert result.data.result_count == 5

    async def test_get_operation(
        self, operation_service: FlextLdapOperationService
    ) -> None:
        """Test getting operation by ID."""
        connection_id = uuid4()

        # Create operation first
        create_result = await operation_service.create_operation(
            operation_type="add",
            target_dn="uid=test,ou=users,dc=example,dc=org",
            connection_id=connection_id,
        )
        assert create_result.data is not None
        operation_id = create_result.data.id

        # Get operation
        result = await operation_service.get_operation(UUID(str(operation_id)))
        assert result.success is True
        assert result.data is not None
        assert result.data.operation_type == "add"

    async def test_list_operations(
        self, operation_service: FlextLdapOperationService
    ) -> None:
        """Test listing operations."""
        connection_id = uuid4()

        # Create operation first
        await operation_service.create_operation(
            operation_type="search",
            target_dn="ou=users,dc=example,dc=org",
            connection_id=connection_id,
        )

        # List operations
        result = await operation_service.list_operations()
        assert result.success is True
        assert result.data is not None
        assert len(result.data) >= 1
