"""Unit tests for FLEXT-LDAP Operations.

Tests operation classes for proper functionality without external dependencies.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from flext_core import FlextEntityStatus, FlextModels

from flext_ldap.models import (
    FlextLdapCreateUserRequest,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapUser,
)
from flext_ldap.operations import (
    FlextLdapConnectionOperations,
    FlextLdapEntryOperations,
    FlextLdapGroupOperations,
    FlextLdapOperations,
    FlextLdapSearchOperations,
    FlextLdapUserOperations,
)
from flext_ldap.typings import LdapAttributeDict


class TestFlextLdapOperations:
    """Test operations class (base class now internal)."""

    def test_operations_base_initialization(self) -> None:
        """Test base operations initialization."""
        # FlextLdapOperationsBase is now internal - use concrete implementation
        ops = FlextLdapOperations()

        assert ops is not None
        assert hasattr(ops, "_container")
        assert hasattr(ops, "_id_generator")

    def test_generate_id_with_uuid_fallback(self) -> None:
        """Test ID generation with UUID fallback."""
        # FlextLdapOperationsBase is now internal - use concrete implementation
        ops = FlextLdapOperations()

        # Should generate a string ID
        id1 = ops._generate_id()
        id2 = ops._generate_id()

        assert isinstance(id1, str)
        assert isinstance(id2, str)
        assert id1 != id2  # Should be unique
        assert len(id1) > 0

    def test_validate_dn_or_fail_with_valid_dn(self) -> None:
        """Test DN validation with valid DN."""
        # FlextLdapOperationsBase is now internal - use concrete implementation
        ops = FlextLdapOperations()

        result = ops._validate_dn_or_fail("cn=test,dc=example,dc=com")

        assert result.is_success

    def test_validate_dn_or_fail_with_invalid_dn(self) -> None:
        """Test DN validation with invalid DN."""
        # FlextLdapOperationsBase is now internal - use concrete implementation
        ops = FlextLdapOperations()

        # This will raise a ValidationError directly from Pydantic
        with pytest.raises(Exception):  # Could be ValidationError from Pydantic
            ops._validate_dn_or_fail("")

    def test_validate_filter_or_fail_with_valid_filter(self) -> None:
        """Test filter validation with valid filter."""
        # FlextLdapOperationsBase is now internal - use concrete implementation
        ops = FlextLdapOperations()

        result = ops._validate_filter_or_fail("(cn=test)")

        assert result.is_success

    def test_validate_filter_or_fail_with_invalid_filter(self) -> None:
        """Test filter validation with invalid filter."""
        # FlextLdapOperationsBase is now internal - use concrete implementation
        ops = FlextLdapOperations()

        # This will raise a ValidationError directly from Pydantic
        with pytest.raises(Exception):  # Could be ValidationError from Pydantic
            ops._validate_filter_or_fail("")

    def test_validate_uri_or_fail_with_valid_uri(self) -> None:
        """Test URI validation with valid URI."""
        # FlextLdapOperationsBase is now internal - use concrete implementation
        ops = FlextLdapOperations()

        result = ops._validate_uri_or_fail("ldap://localhost:389")

        assert result.is_success

    def test_validate_uri_or_fail_with_invalid_uri(self) -> None:
        """Test URI validation with invalid URI."""
        # FlextLdapOperationsBase is now internal - use concrete implementation
        ops = FlextLdapOperations()

        result = ops._validate_uri_or_fail("invalid://test")

        assert not result.is_success
        assert "ldap://" in result.error

    def test_validate_uri_or_fail_with_empty_uri(self) -> None:
        """Test URI validation with empty URI."""
        # FlextLdapOperationsBase is now internal - use concrete implementation
        ops = FlextLdapOperations()

        result = ops._validate_uri_or_fail("")

        assert not result.is_success
        assert "empty" in result.error

    def test_handle_exception_with_context(self) -> None:
        """Test exception handling with context."""
        # FlextLdapOperationsBase is now internal - use concrete implementation
        ops = FlextLdapOperations()

        exception = ValueError("Test error")
        result = ops._handle_exception_with_context(
            "test operation", exception, "conn123"
        )

        assert isinstance(result, str)
        assert "test operation" in result.lower()
        assert "Test error" in result

    def test_log_operation_success(self) -> None:
        """Test successful operation logging."""
        # FlextLdapOperationsBase is now internal - use concrete implementation
        ops = FlextLdapOperations()

        # Should not raise exception
        try:
            ops._log_operation_success("test", "conn123", extra_field="value")
        except Exception as e:
            pytest.fail(f"log_operation_success raised {e}")


class TestFlextLdapConnectionOperations:
    """Test LDAP connection operations."""

    @pytest.mark.asyncio
    async def test_create_connection_with_valid_uri(self) -> None:
        """Test connection creation with valid URI."""
        ops = FlextLdapConnectionOperations()

        result = await ops.create_connection("ldap://localhost:389")

        assert result.is_success
        assert isinstance(result.value, str)
        assert len(result.value) > 0

    @pytest.mark.asyncio
    async def test_create_connection_with_bind_dn(self) -> None:
        """Test connection creation with bind DN."""
        ops = FlextLdapConnectionOperations()

        result = await ops.create_connection(
            "ldap://localhost:389",
            bind_dn="cn=admin,dc=example,dc=com",
            _bind_password="password",
        )

        assert result.is_success
        connection_id = result.value

        # Check connection info
        info_result = ops.get_connection_info(connection_id)
        assert info_result.is_success
        assert info_result.value["is_authenticated"] is True

    @pytest.mark.asyncio
    async def test_create_connection_with_invalid_uri(self) -> None:
        """Test connection creation with invalid URI."""
        ops = FlextLdapConnectionOperations()

        result = await ops.create_connection("invalid://test")

        assert not result.is_success
        assert "ldap://" in result.error

    @pytest.mark.asyncio
    async def test_create_connection_with_invalid_bind_dn(self) -> None:
        """Test connection creation with invalid bind DN."""
        ops = FlextLdapConnectionOperations()

        result = await ops.create_connection(
            "ldap://localhost:389", bind_dn="invalid_dn", _bind_password="password"
        )

        assert not result.is_success
        assert "DN" in result.error

    @pytest.mark.asyncio
    async def test_close_connection_success(self) -> None:
        """Test successful connection closure."""
        ops = FlextLdapConnectionOperations()

        # Create connection first
        create_result = await ops.create_connection("ldap://localhost:389")
        assert create_result.is_success
        connection_id = create_result.value

        # Close connection
        result = await ops.close_connection(connection_id)

        assert result.is_success

    @pytest.mark.asyncio
    async def test_close_connection_not_found(self) -> None:
        """Test closing non-existent connection."""
        ops = FlextLdapConnectionOperations()

        result = await ops.close_connection("nonexistent")

        assert not result.is_success
        assert "not found" in result.error

    def test_get_connection_info_success(self) -> None:
        """Test getting connection info for existing connection."""
        ops = FlextLdapConnectionOperations()

        # Manually add a connection
        connection_id = str(uuid.uuid4())
        ops._active_connections[connection_id] = {
            "server_uri": "ldap://test:389",
            "bind_dn": None,
            "created_at": datetime.now(UTC),
            "timeout": 30,
            "is_authenticated": False,
        }

        result = ops.get_connection_info(connection_id)

        assert result.is_success
        assert result.value["connection_id"] == connection_id
        assert result.value["active"] is True

    def test_get_connection_info_not_found(self) -> None:
        """Test getting connection info for non-existent connection."""
        ops = FlextLdapConnectionOperations()

        result = ops.get_connection_info("nonexistent")

        assert not result.is_success
        assert "not found" in result.error

    def test_list_active_connections_empty(self) -> None:
        """Test listing connections when none exist."""
        ops = FlextLdapConnectionOperations()

        result = ops.list_active_connections()

        assert result.is_success
        assert result.value == []

    def test_list_active_connections_with_connections(self) -> None:
        """Test listing connections when some exist."""
        ops = FlextLdapConnectionOperations()

        # Add test connections
        conn1_id = "conn1"
        conn2_id = "conn2"
        ops._active_connections[conn1_id] = {
            "server_uri": "ldap://test1:389",
            "bind_dn": None,
        }
        ops._active_connections[conn2_id] = {
            "server_uri": "ldap://test2:389",
            "bind_dn": "cn=admin,dc=test,dc=com",
        }

        result = ops.list_active_connections()

        assert result.is_success
        assert len(result.value) == 2
        connection_ids = [conn["connection_id"] for conn in result.value]
        assert conn1_id in connection_ids
        assert conn2_id in connection_ids

    def test_calculate_duration_with_datetime(self) -> None:
        """Test duration calculation with datetime object."""
        ops = FlextLdapConnectionOperations()

        created_at = datetime.now(UTC)
        duration = ops._calculate_duration(created_at)

        assert isinstance(duration, float)
        assert duration >= 0

    def test_calculate_duration_with_invalid_input(self) -> None:
        """Test duration calculation with invalid input."""
        ops = FlextLdapConnectionOperations()

        duration = ops._calculate_duration("invalid")

        assert duration == 0.0


class TestFlextLdapSearchOperations:
    """Test LDAP search operations."""

    @pytest.mark.asyncio
    async def test_search_entries_with_valid_parameters(self) -> None:
        """Test entry search with valid parameters."""
        ops = FlextLdapSearchOperations()

        result = await ops.search_entries(
            connection_id="test_conn",
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=*)",
        )

        assert result.is_success
        assert isinstance(result.value, list)

    @pytest.mark.asyncio
    async def test_search_entries_with_invalid_base_dn(self) -> None:
        """Test entry search with invalid base DN."""
        ops = FlextLdapSearchOperations()

        result = await ops.search_entries(
            connection_id="test_conn",
            base_dn="invalid_dn",
            search_filter="(objectClass=*)",
        )

        assert not result.is_success
        assert "DN" in result.error

    @pytest.mark.asyncio
    async def test_search_entries_with_invalid_filter(self) -> None:
        """Test entry search with invalid filter."""
        ops = FlextLdapSearchOperations()

        result = await ops.search_entries(
            connection_id="test_conn", base_dn="dc=example,dc=com", search_filter=""
        )

        assert not result.is_success
        assert "FlextLdapFilter" in result.error or "validation" in result.error

    @pytest.mark.asyncio
    async def test_search_users_with_valid_parameters(self) -> None:
        """Test user search with valid parameters."""
        ops = FlextLdapSearchOperations()

        result = await ops.search_users(
            connection_id="test_conn",
            base_dn="ou=users,dc=example,dc=com",
            filter_criteria={"cn": "John"},
        )

        assert result.is_success
        assert isinstance(result.value, list)

    @pytest.mark.asyncio
    async def test_search_users_with_no_criteria(self) -> None:
        """Test user search with no filter criteria."""
        ops = FlextLdapSearchOperations()

        result = await ops.search_users(
            connection_id="test_conn",
            base_dn="ou=users,dc=example,dc=com",
            filter_criteria=None,
        )

        assert result.is_success
        assert isinstance(result.value, list)

    @pytest.mark.asyncio
    async def test_search_groups_with_valid_parameters(self) -> None:
        """Test group search with valid parameters."""
        ops = FlextLdapSearchOperations()

        result = await ops.search_groups(
            connection_id="test_conn",
            base_dn="ou=groups,dc=example,dc=com",
            filter_criteria={"cn": "admin"},
        )

        assert result.is_success
        assert isinstance(result.value, list)

    @pytest.mark.asyncio
    async def test_get_entry_by_dn_valid_dn(self) -> None:
        """Test getting entry by DN with valid DN."""
        ops = FlextLdapSearchOperations()

        result = await ops.get_entry_by_dn(
            connection_id="test_conn",
            dn="cn=test,dc=example,dc=com",
            attributes=["cn", "mail"],
        )

        # Should succeed but return no entry (simulated)
        assert not result.is_success  # No entries found in simulation

    def test_build_user_filter_with_criteria(self) -> None:
        """Test user filter building with criteria."""
        ops = FlextLdapSearchOperations()

        filter_str = ops._build_user_filter({"cn": "John", "mail": "john"})

        assert filter_str.startswith("(&(objectClass=person)")
        assert "cn=*John*" in filter_str
        assert "mail=*john*" in filter_str
        assert filter_str.endswith(")")

    def test_build_user_filter_with_no_criteria(self) -> None:
        """Test user filter building with no criteria."""
        ops = FlextLdapSearchOperations()

        filter_str = ops._build_user_filter(None)

        assert filter_str == "(&(objectClass=person))"

    def test_build_group_filter_with_criteria(self) -> None:
        """Test group filter building with criteria."""
        ops = FlextLdapSearchOperations()

        filter_str = ops._build_group_filter({"cn": "admin"})

        assert filter_str.startswith("(&(objectClass=groupOfNames)")
        assert "cn=*admin*" in filter_str
        assert filter_str.endswith(")")

    def test_escape_ldap_filter_value(self) -> None:
        """Test LDAP filter value escaping."""
        ops = FlextLdapSearchOperations()

        escaped = ops._escape_ldap_filter_value("test(*)\\value")

        assert "\\28" in escaped  # (
        assert "\\29" in escaped  # )
        assert "\\2a" in escaped  # *
        assert "\\5c" in escaped  # \\

    def test_convert_entries_to_users(self) -> None:
        """Test converting entries to users."""
        ops = FlextLdapSearchOperations()

        # Create mock entries
        attributes: LdapAttributeDict = {
            "uid": ["john.doe"],
            "cn": ["John Doe"],
            "sn": ["Doe"],
            "mail": ["john@example.com"],
        }

        entry = FlextLdapEntry(
            id=FlextModels.EntityId("test"),
            dn="cn=john,dc=example,dc=com",
            object_classes=["person"],
            attributes=attributes,
            status=FlextEntityStatus.ACTIVE,
        )

        users = ops._convert_entries_to_users([entry])

        assert len(users) == 1
        assert isinstance(users[0], FlextLdapUser)
        assert users[0].uid == "john.doe"
        assert users[0].cn == "John Doe"

    def test_convert_entries_to_groups(self) -> None:
        """Test converting entries to groups."""
        ops = FlextLdapSearchOperations()

        # Create mock entries
        attributes: LdapAttributeDict = {
            "cn": ["admins"],
            "description": ["Admin group"],
            "member": ["cn=user1,dc=example,dc=com", "cn=user2,dc=example,dc=com"],
        }

        entry = FlextLdapEntry(
            id=FlextModels.EntityId("test"),
            dn="cn=admins,dc=example,dc=com",
            object_classes=["groupOfNames"],
            attributes=attributes,
            status=FlextEntityStatus.ACTIVE,
        )

        groups = ops._convert_entries_to_groups([entry])

        assert len(groups) == 1
        assert isinstance(groups[0], FlextLdapGroup)
        assert groups[0].cn == "admins"
        assert len(groups[0].members) == 2


class TestFlextLdapEntryOperations:
    """Test LDAP entry operations."""

    @pytest.mark.asyncio
    async def test_create_entry_with_valid_data(self) -> None:
        """Test entry creation with valid data."""
        ops = FlextLdapEntryOperations()

        attributes: LdapAttributeDict = {"cn": ["test"], "objectClass": ["person"]}

        result = await ops.create_entry(
            connection_id="test_conn",
            dn="cn=test,dc=example,dc=com",
            object_classes=["person"],
            attributes=attributes,
        )

        assert result.is_success
        assert isinstance(result.value, FlextLdapEntry)
        assert result.value.dn == "cn=test,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_create_entry_with_invalid_dn(self) -> None:
        """Test entry creation with invalid DN."""
        ops = FlextLdapEntryOperations()

        attributes: LdapAttributeDict = {"cn": ["test"]}

        result = await ops.create_entry(
            connection_id="test_conn",
            dn="invalid_dn",
            object_classes=["person"],
            attributes=attributes,
        )

        assert not result.is_success
        assert "DN" in result.error

    @pytest.mark.asyncio
    async def test_create_entry_with_no_object_classes(self) -> None:
        """Test entry creation with no object classes."""
        ops = FlextLdapEntryOperations()

        attributes: LdapAttributeDict = {"cn": ["test"]}

        result = await ops.create_entry(
            connection_id="test_conn",
            dn="cn=test,dc=example,dc=com",
            object_classes=[],
            attributes=attributes,
        )

        assert not result.is_success
        assert "object class" in result.error

    @pytest.mark.asyncio
    async def test_modify_entry_with_valid_data(self) -> None:
        """Test entry modification with valid data."""
        ops = FlextLdapEntryOperations()

        modifications = {"mail": ["new@example.com"]}

        result = await ops.modify_entry(
            connection_id="test_conn",
            dn="cn=test,dc=example,dc=com",
            modifications=modifications,
        )

        assert result.is_success

    @pytest.mark.asyncio
    async def test_modify_entry_with_invalid_dn(self) -> None:
        """Test entry modification with invalid DN."""
        ops = FlextLdapEntryOperations()

        modifications = {"mail": ["new@example.com"]}

        result = await ops.modify_entry(
            connection_id="test_conn", dn="invalid_dn", modifications=modifications
        )

        assert not result.is_success
        assert "DN" in result.error

    @pytest.mark.asyncio
    async def test_modify_entry_with_no_modifications(self) -> None:
        """Test entry modification with no modifications."""
        ops = FlextLdapEntryOperations()

        result = await ops.modify_entry(
            connection_id="test_conn", dn="cn=test,dc=example,dc=com", modifications={}
        )

        assert not result.is_success
        assert "modifications" in result.error

    @pytest.mark.asyncio
    async def test_delete_entry_with_valid_dn(self) -> None:
        """Test entry deletion with valid DN."""
        ops = FlextLdapEntryOperations()

        result = await ops.delete_entry(
            connection_id="test_conn", dn="cn=test,dc=example,dc=com"
        )

        assert result.is_success

    @pytest.mark.asyncio
    async def test_delete_entry_with_invalid_dn(self) -> None:
        """Test entry deletion with invalid DN."""
        ops = FlextLdapEntryOperations()

        result = await ops.delete_entry(connection_id="test_conn", dn="invalid_dn")

        assert not result.is_success
        assert "DN" in result.error


class TestFlextLdapUserOperations:
    """Test LDAP user operations."""

    @pytest.mark.asyncio
    async def test_create_user_with_valid_request(self) -> None:
        """Test user creation with valid request."""
        ops = FlextLdapUserOperations()

        user_request = FlextLdapCreateUserRequest(
            dn="cn=john,dc=example,dc=com",
            uid="john.doe",
            cn="John Doe",
            sn="Doe",
            given_name="John",
            mail="john@example.com",
        )

        result = await ops.create_user(
            connection_id="test_conn", user_request=user_request
        )

        assert result.is_success
        assert isinstance(result.value, FlextLdapUser)
        assert result.value.uid == "john.doe"
        assert result.value.cn == "John Doe"

    @pytest.mark.asyncio
    async def test_update_user_password_with_valid_password(self) -> None:
        """Test user password update with valid password."""
        ops = FlextLdapUserOperations()

        result = await ops.update_user_password(
            connection_id="test_conn",
            user_dn="cn=john,dc=example,dc=com",
            new_password="newpassword123",
        )

        assert result.is_success

    @pytest.mark.asyncio
    async def test_update_user_password_with_short_password(self) -> None:
        """Test user password update with short password."""
        ops = FlextLdapUserOperations()

        result = await ops.update_user_password(
            connection_id="test_conn",
            user_dn="cn=john,dc=example,dc=com",
            new_password="123",
        )

        assert not result.is_success
        assert str(ops.MIN_PASSWORD_LENGTH) in result.error

    @pytest.mark.asyncio
    async def test_update_user_email_with_valid_email(self) -> None:
        """Test user email update with valid email."""
        ops = FlextLdapUserOperations()

        result = await ops.update_user_email(
            connection_id="test_conn",
            user_dn="cn=john,dc=example,dc=com",
            email="newemail@example.com",
        )

        assert result.is_success

    @pytest.mark.asyncio
    async def test_update_user_email_with_invalid_email(self) -> None:
        """Test user email update with invalid email."""
        ops = FlextLdapUserOperations()

        result = await ops.update_user_email(
            connection_id="test_conn",
            user_dn="cn=john,dc=example,dc=com",
            email="invalid_email",
        )

        assert not result.is_success
        assert "email" in result.error

    @pytest.mark.asyncio
    async def test_activate_user(self) -> None:
        """Test user activation."""
        ops = FlextLdapUserOperations()

        result = await ops.activate_user(
            connection_id="test_conn", user_dn="cn=john,dc=example,dc=com"
        )

        assert result.is_success

    @pytest.mark.asyncio
    async def test_deactivate_user(self) -> None:
        """Test user deactivation."""
        ops = FlextLdapUserOperations()

        result = await ops.deactivate_user(
            connection_id="test_conn", user_dn="cn=john,dc=example,dc=com"
        )

        assert result.is_success

    def test_build_user_attributes(self) -> None:
        """Test user attribute building."""
        ops = FlextLdapUserOperations()

        user_request = FlextLdapCreateUserRequest(
            dn="cn=john,dc=example,dc=com",
            uid="john.doe",
            cn="John Doe",
            sn="Doe",
            given_name="John",
            mail="john@example.com",
        )

        attributes = ops._build_user_attributes(user_request)

        assert "uid" in attributes
        assert "cn" in attributes
        assert "sn" in attributes
        assert "givenName" in attributes
        assert "mail" in attributes
        assert attributes["uid"] == ["john.doe"]

    def test_build_user_entity(self) -> None:
        """Test user entity building."""
        ops = FlextLdapUserOperations()

        user_request = FlextLdapCreateUserRequest(
            dn="cn=john,dc=example,dc=com", uid="john.doe", cn="John Doe", sn="Doe"
        )

        attributes: LdapAttributeDict = {
            "uid": ["john.doe"],
            "cn": ["John Doe"],
            "sn": ["Doe"],
        }

        user = ops._build_user_entity(user_request, attributes)

        assert isinstance(user, FlextLdapUser)
        assert user.uid == "john.doe"
        assert user.cn == "John Doe"
        assert user.status == FlextEntityStatus.ACTIVE.value


class TestFlextLdapGroupOperations:
    """Test LDAP group operations."""

    @pytest.mark.asyncio
    async def test_create_group_with_valid_data(self) -> None:
        """Test group creation with valid data."""
        ops = FlextLdapGroupOperations()

        result = await ops.create_group(
            connection_id="test_conn",
            dn="cn=admins,dc=example,dc=com",
            cn="admins",
            description="Admin group",
            initial_members=["cn=user1,dc=example,dc=com"],
        )

        assert result.is_success
        assert isinstance(result.value, FlextLdapGroup)
        assert result.value.cn == "admins"
        assert "cn=user1,dc=example,dc=com" in result.value.members

    @pytest.mark.asyncio
    async def test_create_group_with_no_members(self) -> None:
        """Test group creation with no members (dummy member added)."""
        ops = FlextLdapGroupOperations()

        result = await ops.create_group(
            connection_id="test_conn", dn="cn=empty,dc=example,dc=com", cn="empty"
        )

        assert result.is_success
        assert len(result.value.members) == 1
        assert "cn=dummy" in result.value.members[0]

    def test_prepare_group_members_with_members(self) -> None:
        """Test group member preparation with provided members."""
        ops = FlextLdapGroupOperations()

        members = ops._prepare_group_members(["cn=user1,dc=example,dc=com"])

        assert len(members) == 1
        assert members[0] == "cn=user1,dc=example,dc=com"

    def test_prepare_group_members_with_no_members(self) -> None:
        """Test group member preparation with no members."""
        ops = FlextLdapGroupOperations()

        members = ops._prepare_group_members(None)

        assert len(members) == 1
        assert "cn=dummy" in members[0]

    def test_build_group_attributes(self) -> None:
        """Test group attribute building."""
        ops = FlextLdapGroupOperations()

        attributes = ops._build_group_attributes(
            cn="admins",
            description="Admin group",
            members=["cn=user1,dc=example,dc=com"],
        )

        assert "cn" in attributes
        assert "description" in attributes
        assert "member" in attributes
        assert attributes["cn"] == ["admins"]

    def test_build_group_entity(self) -> None:
        """Test group entity building."""
        ops = FlextLdapGroupOperations()

        attributes: LdapAttributeDict = {
            "cn": ["admins"],
            "member": ["cn=user1,dc=example,dc=com"],
        }

        group = ops._build_group_entity(
            dn="cn=admins,dc=example,dc=com",
            cn="admins",
            description="Admin group",
            members=["cn=user1,dc=example,dc=com"],
            attributes=attributes,
        )

        assert isinstance(group, FlextLdapGroup)
        assert group.cn == "admins"
        assert group.description == "Admin group"
        assert len(group.members) == 1

    def test_filter_dummy_members(self) -> None:
        """Test filtering dummy members."""
        ops = FlextLdapGroupOperations()

        members = [
            "cn=user1,dc=example,dc=com",
            "cn=dummy,ou=temp,dc=example,dc=com",
            "cn=user2,dc=example,dc=com",
        ]

        filtered = ops._filter_dummy_members(members)

        assert len(filtered) == 2
        assert "cn=user1,dc=example,dc=com" in filtered
        assert "cn=user2,dc=example,dc=com" in filtered
        assert not any("dummy" in m for m in filtered)

    def test_calculate_updated_members_add_action(self) -> None:
        """Test member calculation for add action."""
        ops = FlextLdapGroupOperations()

        current_members = ["cn=user1,dc=example,dc=com"]
        result = ops._calculate_updated_members(
            current_members, "cn=user2,dc=example,dc=com", "add"
        )

        assert result.is_success
        assert len(result.value) == 2
        assert "cn=user2,dc=example,dc=com" in result.value

    def test_calculate_updated_members_remove_action(self) -> None:
        """Test member calculation for remove action."""
        ops = FlextLdapGroupOperations()

        current_members = ["cn=user1,dc=example,dc=com", "cn=user2,dc=example,dc=com"]
        result = ops._calculate_updated_members(
            current_members, "cn=user1,dc=example,dc=com", "remove"
        )

        assert result.is_success
        assert len(result.value) == 1
        assert "cn=user2,dc=example,dc=com" in result.value

    def test_calculate_updated_members_invalid_action(self) -> None:
        """Test member calculation with invalid action."""
        ops = FlextLdapGroupOperations()

        result = ops._calculate_updated_members([], "user", "invalid")

        assert not result.is_success
        assert "Invalid action" in result.error

    def test_handle_add_member_duplicate(self) -> None:
        """Test adding member that already exists."""
        ops = FlextLdapGroupOperations()

        current_members = ["cn=user1,dc=example,dc=com"]
        result = ops._handle_add_member(current_members, "cn=user1,dc=example,dc=com")

        assert not result.is_success
        assert "already exists" in result.error

    def test_handle_remove_member_not_found(self) -> None:
        """Test removing member that doesn't exist."""
        ops = FlextLdapGroupOperations()

        current_members = ["cn=user1,dc=example,dc=com"]
        result = ops._handle_remove_member(
            current_members, "cn=user2,dc=example,dc=com"
        )

        assert not result.is_success
        assert "not found" in result.error

    def test_handle_remove_member_last_member(self) -> None:
        """Test removing last member (dummy added)."""
        ops = FlextLdapGroupOperations()

        current_members = ["cn=user1,dc=example,dc=com"]
        result = ops._handle_remove_member(
            current_members, "cn=user1,dc=example,dc=com"
        )

        assert result.is_success
        assert len(result.value) == 1
        assert "cn=dummy" in result.value[0]


class TestFlextLdapOperationsUnified:
    """Test unified LDAP operations interface."""

    @pytest.mark.asyncio
    async def test_create_connection_and_bind(self) -> None:
        """Test connection creation and binding."""
        ops = FlextLdapOperations()

        result = await ops.create_connection_and_bind(
            server_uri="ldap://localhost:389",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="password",
        )

        assert result.is_success
        assert isinstance(result.value, str)

    @pytest.mark.asyncio
    async def test_search_and_get_first_no_results(self) -> None:
        """Test search that returns no results."""
        ops = FlextLdapOperations()

        result = await ops.search_and_get_first(
            connection_id="test_conn",
            base_dn="dc=example,dc=com",
            search_filter="(cn=nonexistent)",
        )

        assert result.is_success
        assert result.value is None  # No entries found

    @pytest.mark.asyncio
    async def test_cleanup_connection(self) -> None:
        """Test connection cleanup."""
        ops = FlextLdapOperations()

        # Should not raise exception
        try:
            await ops.cleanup_connection("test_conn")
        except Exception as e:
            pytest.fail(f"cleanup_connection raised {e}")

    def test_operations_initialization(self) -> None:
        """Test unified operations initialization."""
        ops = FlextLdapOperations()

        assert ops.connections is not None
        assert ops.search is not None
        assert ops.entries is not None
        assert ops.users is not None
        assert ops.groups is not None

        assert isinstance(ops.connections, FlextLdapConnectionOperations)
        assert isinstance(ops.search, FlextLdapSearchOperations)
        assert isinstance(ops.entries, FlextLdapEntryOperations)
        assert isinstance(ops.users, FlextLdapUserOperations)
        assert isinstance(ops.groups, FlextLdapGroupOperations)
