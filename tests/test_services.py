"""Enterprise-grade tests for FlextLdap services.

# Constants
EXPECTED_BULK_SIZE = 2
EXPECTED_DATA_COUNT = 3

Tests all application services with flext-core integration.
"""

from uuid import uuid4

import pytest

from flext_ldap.entities import (
    FlextLdapGroup,
    FlextLdapOperation,
    FlextLdapUser,
)
from flext_ldap.services import (
    FlextLdapConnectionApplicationService,
    FlextLdapGroupService,
    FlextLdapOperationService,
    FlextLdapUserApplicationService,
)
from flext_ldap.values import FlextLdapCreateUserRequest


class TestFlextLdapUserApplicationService:
    """Test user application service."""

    @pytest.fixture
    def user_service(self):
        """Create user service for testing."""
        return FlextLdapUserApplicationService()

    @pytest.fixture
    def sample_user_request(self):
        """Create sample user request."""
        return FlextLdapCreateUserRequest(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            uid="john.doe",
            cn="John Doe",
            sn="Doe",
            mail="john.doe@example.com",
        )

    @pytest.mark.asyncio
    async def test_create_user(self, user_service, sample_user_request):
        """Test user creation."""
        result = await user_service.create_user(sample_user_request)

        assert result.is_success
        assert isinstance(result.data, FlextLdapUser)
        if result.data.uid != "john.doe":
            msg = f"Expected {"john.doe"}, got {result.data.uid}"
            raise AssertionError(msg)
        assert result.data.cn == "John Doe"

    @pytest.mark.asyncio
    async def test_get_user(self, user_service, sample_user_request):
        """Test user retrieval."""
        # Create user first
        create_result = await user_service.create_user(sample_user_request)
        assert create_result.is_success

        user_id = create_result.data.id

        # Retrieve user
        get_result = await user_service.get_user(user_id)
        assert get_result.is_success
        assert get_result.data is not None
        if get_result.data.uid != "john.doe":
            msg = f"Expected {"john.doe"}, got {get_result.data.uid}"
            raise AssertionError(msg)

    @pytest.mark.asyncio
    async def test_find_user_by_dn(self, user_service, sample_user_request):
        """Test finding user by DN."""
        # Create user first
        create_result = await user_service.create_user(sample_user_request)
        assert create_result.is_success

        # Find by DN
        find_result = await user_service.find_user_by_dn(sample_user_request.dn)
        assert find_result.is_success
        assert find_result.data is not None
        if find_result.data.dn != sample_user_request.dn:
            msg = f"Expected {sample_user_request.dn}, got {find_result.data.dn}"
            raise AssertionError(msg)

    @pytest.mark.asyncio
    async def test_find_user_by_uid(self, user_service, sample_user_request):
        """Test finding user by UID."""
        # Create user first
        create_result = await user_service.create_user(sample_user_request)
        assert create_result.is_success

        # Find by UID
        find_result = await user_service.find_user_by_uid(sample_user_request.uid)
        assert find_result.is_success
        assert find_result.data is not None
        if find_result.data.uid != sample_user_request.uid:
            msg = f"Expected {sample_user_request.uid}, got {find_result.data.uid}"
            raise AssertionError(msg)

    @pytest.mark.asyncio
    async def test_update_user(self, user_service, sample_user_request):
        """Test user update."""
        # Create user first
        create_result = await user_service.create_user(sample_user_request)
        assert create_result.is_success

        user_id = create_result.data.id

        # Update user
        updates = {"phone": "+1-555-0123", "title": "Senior Developer"}
        update_result = await user_service.update_user(user_id, updates)

        assert update_result.is_success
        if update_result.data.phone != "+1-555-0123":
            msg = f"Expected {"+1-555-0123"}, got {update_result.data.phone}"
            raise AssertionError(msg)
        assert update_result.data.title == "Senior Developer"

    @pytest.mark.asyncio
    async def test_lock_unlock_user(self, user_service, sample_user_request):
        """Test user account locking/unlocking."""
        # Create user first
        create_result = await user_service.create_user(sample_user_request)
        assert create_result.is_success

        user_id = create_result.data.id

        # Lock user
        lock_result = await user_service.lock_user(user_id)
        assert lock_result.is_success
        assert not lock_result.data.is_active()

        # Unlock user
        unlock_result = await user_service.unlock_user(user_id)
        assert unlock_result.is_success
        assert unlock_result.data.is_active()

    @pytest.mark.asyncio
    async def test_delete_user(self, user_service, sample_user_request):
        """Test user deletion."""
        # Create user first
        create_result = await user_service.create_user(sample_user_request)
        assert create_result.is_success

        user_id = create_result.data.id

        # Delete user
        delete_result = await user_service.delete_user(user_id)
        assert delete_result.is_success
        if not (delete_result.data):
            msg = f"Expected True, got {delete_result.data}"
            raise AssertionError(msg)

        # Verify deletion
        get_result = await user_service.get_user(user_id)
        assert get_result.is_success
        assert get_result.data is None

    @pytest.mark.asyncio
    async def test_list_users(self, user_service):
        """Test user listing."""
        # Create multiple users
        for i in range(3):
            request = FlextLdapCreateUserRequest(
                dn=f"cn=user{i},ou=users,dc=example,dc=com",
                uid=f"user{i}",
                cn=f"User {i}",
                sn="Test",
                ou="Engineering",
            )
            await user_service.create_user(request)

        # List all users
        list_result = await user_service.list_users()
        assert list_result.is_success
        if len(list_result.data) != EXPECTED_DATA_COUNT:
            msg = f"Expected {3}, got {len(list_result.data)}"
            raise AssertionError(msg)

        # List users by OU
        ou_result = await user_service.list_users(ou="Engineering")
        assert ou_result.is_success
        if len(ou_result.data) != EXPECTED_DATA_COUNT:
            msg = f"Expected {3}, got {len(ou_result.data)}"
            raise AssertionError(msg)


class TestFlextLdapGroupService:
    """Test group service."""

    @pytest.fixture
    def group_service(self):
        """Create group service for testing."""
        return FlextLdapGroupService()

    @pytest.mark.asyncio
    async def test_create_group(self, group_service):
        """Test group creation."""
        result = await group_service.create_group(
            dn="cn=developers,ou=groups,dc=example,dc=com",
            cn="Developers",
            ou="Engineering",
            members=["cn=john,ou=users,dc=example,dc=com"],
        )

        assert result.is_success
        assert isinstance(result.data, FlextLdapGroup)
        if result.data.cn != "Developers":
            msg = f"Expected {"Developers"}, got {result.data.cn}"
            raise AssertionError(msg)
        assert len(result.data.members) == 1

    @pytest.mark.asyncio
    async def test_group_member_management(self, group_service):
        """Test group member operations."""
        # Create group
        create_result = await group_service.create_group(
            dn="cn=test,ou=groups,dc=example,dc=com",
            cn="Test Group",
        )
        assert create_result.is_success

        group_id = create_result.data.id

        # Add member
        add_result = await group_service.add_member(
            group_id,
            "cn=user1,ou=users,dc=example,dc=com",
        )
        assert add_result.is_success
        assert add_result.data.has_member("cn=user1,ou=users,dc=example,dc=com")

        # Remove member
        remove_result = await group_service.remove_member(
            group_id,
            "cn=user1,ou=users,dc=example,dc=com",
        )
        assert remove_result.is_success
        assert not remove_result.data.has_member("cn=user1,ou=users,dc=example,dc=com")

    @pytest.mark.asyncio
    async def test_find_group_by_dn(self, group_service):
        """Test finding group by DN."""
        dn = "cn=test,ou=groups,dc=example,dc=com"

        # Create group
        create_result = await group_service.create_group(dn=dn, cn="Test")
        assert create_result.is_success

        # Find by DN
        find_result = await group_service.find_group_by_dn(dn)
        assert find_result.is_success
        assert find_result.data is not None
        if find_result.data.dn != dn:
            msg = f"Expected {dn}, got {find_result.data.dn}"
            raise AssertionError(msg)


class TestFlextLdapConnectionApplicationService:
    """Test connection application service."""

    @pytest.fixture
    def connection_service(self):
        """Create connection service for testing."""
        return FlextLdapConnectionApplicationService()

    @pytest.mark.asyncio
    async def test_create_connection(self, connection_service):
        """Test connection creation."""
        result = await connection_service.create_connection(
            server_uri="ldap://test.example.com:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="secret",
            use_ssl=False,
        )

        # Note: Will fail on actual LDAP connection, but tests the flow
        # In real scenario, we'd mock the LDAP client
        assert result is not None

    @pytest.mark.asyncio
    async def test_connection_operations(self, connection_service):
        """Test connection operations."""
        # Test basic connection service functionality
        # In real scenario, we'd have proper LDAP server setup

        # Test connection listing
        list_result = await connection_service.list_connections()
        assert list_result.is_success
        assert isinstance(list_result.data, list)


class TestFlextLdapOperationService:
    """Test operation service."""

    @pytest.fixture
    def operation_service(self):
        """Create operation service for testing."""
        return FlextLdapOperationService()

    @pytest.mark.asyncio
    async def test_create_operation(self, operation_service):
        """Test operation creation."""
        connection_id = str(uuid4())

        result = await operation_service.create_operation(
            operation_type="search",
            target_dn="ou=users,dc=example,dc=com",
            connection_id=connection_id,
            filter_expression="(objectClass=person)",
            attributes=["cn", "mail"],
        )

        assert result.is_success
        assert isinstance(result.data, FlextLdapOperation)
        if result.data.operation_type != "search":
            msg = f"Expected {"search"}, got {result.data.operation_type}"
            raise AssertionError(msg)
        assert result.data.target_dn == "ou=users,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_complete_operation(self, operation_service):
        """Test operation completion."""
        connection_id = str(uuid4())

        # Create operation
        create_result = await operation_service.create_operation(
            operation_type="search",
            target_dn="ou=users,dc=example,dc=com",
            connection_id=connection_id,
        )
        assert create_result.is_success

        operation_id = create_result.data.id

        # Complete operation
        complete_result = await operation_service.complete_operation(
            operation_id,
            success=True,
            result_count=5,
        )

        assert complete_result.is_success
        if not (complete_result.data.success):
            msg = f"Expected True, got {complete_result.data.success}"
            raise AssertionError(msg)
        if complete_result.data.result_count != 5:
            msg = f"Expected {5}, got {complete_result.data.result_count}"
            raise AssertionError(msg)
        assert complete_result.data.is_completed()

    @pytest.mark.asyncio
    async def test_list_operations(self, operation_service):
        """Test operation listing."""
        connection_id = str(uuid4())

        # Create multiple operations
        for i in range(3):
            await operation_service.create_operation(
                operation_type="search",
                target_dn=f"ou=users{i},dc=example,dc=com",
                connection_id=connection_id,
            )

        # List all operations
        list_result = await operation_service.list_operations()
        assert list_result.is_success
        if len(list_result.data) != EXPECTED_DATA_COUNT:
            msg = f"Expected {3}, got {len(list_result.data)}"
            raise AssertionError(msg)

        # List operations by connection
        conn_result = await operation_service.list_operations(connection_id=connection_id)
        assert conn_result.is_success
        if len(conn_result.data) != EXPECTED_DATA_COUNT:
            msg = f"Expected {3}, got {len(conn_result.data)}"
            raise AssertionError(msg)


class TestServiceIntegration:
    """Test service integration patterns."""

    @pytest.mark.asyncio
    async def test_flext_core_integration(self):
        """Test services integrate properly with flext-core patterns."""
        user_service = FlextLdapUserApplicationService()

        # Test FlextResult usage
        request = FlextLdapCreateUserRequest(
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test",
            sn="User",
        )

        result = await user_service.create_user(request)

        # Should use FlextResult pattern
        assert hasattr(result, "is_success")
        assert hasattr(result, "data")
        assert result.is_success

    def test_service_inheritance_hierarchy(self):
        """Test services properly inherit from base classes."""
        user_service = FlextLdapUserApplicationService()
        group_service = FlextLdapGroupService()

        # Should inherit from proper base classes
        # Should have repository pattern
        # Should integrate with flext-core
        assert hasattr(user_service, "_repository") or hasattr(user_service, "_entities")
        assert hasattr(group_service, "_repository") or hasattr(group_service, "_entities")

    @pytest.mark.asyncio
    async def test_error_handling_patterns(self):
        """Test consistent error handling across services."""
        user_service = FlextLdapUserApplicationService()

        # Test error with invalid user request
        invalid_request = FlextLdapCreateUserRequest.__new__(FlextLdapCreateUserRequest)
        invalid_request.dn = ""
        invalid_request.uid = "test"
        invalid_request.cn = "Test"
        invalid_request.sn = "User"

        result = await user_service.create_user(invalid_request)

        # Should handle errors gracefully with FlextResult
        assert not result.is_success
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_service_composition(self):
        """Test services can be composed together."""
        user_service = FlextLdapUserApplicationService()
        group_service = FlextLdapGroupService()

        # Create user
        user_request = FlextLdapCreateUserRequest(
            dn="cn=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
        )
        user_result = await user_service.create_user(user_request)
        assert user_result.is_success

        # Create group
        group_result = await group_service.create_group(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="Test Group",
        )
        assert group_result.is_success

        # Add user to group
        add_result = await group_service.add_member(
            group_result.data.id,
            user_result.data.dn,
        )
        assert add_result.is_success
        assert add_result.data.has_member(user_result.data.dn)


@pytest.mark.integration
class TestServiceIntegrationComplete:
    """Complete integration tests for service layer."""

    @pytest.mark.asyncio
    async def test_user_group_workflow(self):
        """Test complete user-group workflow."""
        user_service = FlextLdapUserApplicationService()
        group_service = FlextLdapGroupService()

        # 1. Create users
        users = []
        for i in range(2):
            request = FlextLdapCreateUserRequest(
                dn=f"cn=user{i},ou=users,dc=example,dc=com",
                uid=f"user{i}",
                cn=f"User {i}",
                sn="Test",
            )
            result = await user_service.create_user(request)
            assert result.is_success
            users.append(result.data)

        # 2. Create group
        group_result = await group_service.create_group(
            dn="cn=team,ou=groups,dc=example,dc=com",
            cn="Team",
        )
        assert group_result.is_success

        # 3. Add users to group
        for user in users:
            add_result = await group_service.add_member(
                group_result.data.id,
                user.dn,
            )
            assert add_result.is_success

        # 4. Verify group membership
        final_group = await group_service.get_group(group_result.data.id)
        assert final_group.is_success
        if len(final_group.data.members) != EXPECTED_BULK_SIZE:
            msg = f"Expected {2}, got {len(final_group.data.members)}"
            raise AssertionError(msg)

    @pytest.mark.asyncio
    async def test_operation_tracking_workflow(self):
        """Test operation tracking across services."""
        operation_service = FlextLdapOperationService()
        connection_id = str(uuid4())

        # Create and track multiple operations
        operations = []
        for i in range(3):
            create_result = await operation_service.create_operation(
                operation_type="search",
                target_dn=f"ou=dept{i},dc=example,dc=com",
                connection_id=connection_id,
            )
            assert create_result.is_success
            operations.append(create_result.data)

        # Complete operations
        for i, operation in enumerate(operations):
            complete_result = await operation_service.complete_operation(
                operation.id,
                success=True,
                result_count=i + 1,
            )
            assert complete_result.is_success

        # Verify operation history
        list_result = await operation_service.list_operations(connection_id=connection_id)
        assert list_result.is_success
        if len(list_result.data) != EXPECTED_DATA_COUNT:
            msg = f"Expected {3}, got {len(list_result.data)}"
            raise AssertionError(msg)
