"""Test module for flext-ldap functionality."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from flext_core import FlextUtilities

from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.operations import FlextLDAPOperations
from flext_ldap.typings import LdapAttributeDict

# SearchParams moved to entities.py


class TestFlextLDAPOperationsReal:
    """Test operations class with REAL code execution (base class now internal)."""

    def test_operations_base_initialization_real(self) -> None:
        """Test base operations initialization executes real code."""
        # FlextLDAPOperationsBase is now internal - use concrete implementation
        ops = FlextLDAPOperations()

        # Verify real initialization happened
        assert hasattr(ops, "connections")
        assert hasattr(ops, "search")
        assert hasattr(ops, "entries")
        assert hasattr(ops, "users")
        assert hasattr(ops, "groups")

        # Verify operation handlers are properly initialized
        assert ops.connections is not None
        assert ops.search is not None

    def test_generate_id_real_execution(self) -> None:
        """Test ID generation with real execution using FlextUtilities directly."""
        # Use FlextUtilities directly - NO WRAPPER METHODS
        id1 = FlextUtilities.Generators.generate_entity_id()
        id2 = FlextUtilities.Generators.generate_entity_id()

        # Verify real ID generation
        assert isinstance(id1, str)
        assert isinstance(id2, str)
        assert id1 != id2
        assert len(id1) > 0

        # Should be entity ID format from FlextUtilities (not UUID)
        assert id1.startswith("ent_"), f"ID should start with 'ent_': {id1}"
        assert id2.startswith("ent_"), f"ID should start with 'ent_': {id2}"
        assert len(id1) > 10, f"ID should be reasonably long: {id1}"
        assert len(id2) > 10, f"ID should be reasonably long: {id2}"

    def test_validate_uri_real_validation(self) -> None:
        """Test URI validation with real code execution."""
        # FlextLDAPOperationsBase is now internal - use concrete implementation
        ops = FlextLDAPOperations()

        connection_ops = ops.ConnectionOperations()

        # Test valid LDAP URI
        result = connection_ops.validate_uri_string("ldap://localhost:389")
        assert result.is_success

        # Test valid LDAPS URI
        result = connection_ops.validate_uri_string("ldaps://secure.example.com:636")
        assert result.is_success

        # Test invalid protocol
        result = connection_ops.validate_uri_string("http://localhost:80")
        assert not result.is_success
        assert "ldap://" in (result.error or "")

        # Test empty URI
        result = connection_ops.validate_uri_string("")
        assert not result.is_success
        assert "empty" in (result.error or "")

    def test_validate_dn_real_validation(self) -> None:
        """Test DN validation with real code execution."""
        # FlextLDAPOperationsBase is now internal - use concrete implementation
        ops = FlextLDAPOperations()

        # Test valid DNs
        valid_dns = [
            "cn=user,dc=example,dc=com",
            "uid=john.doe,ou=users,dc=company,dc=org",
            "cn=REDACTED_LDAP_BIND_PASSWORD,cn=users,dc=test,dc=local",
        ]

        for dn in valid_dns:
            connection_ops = ops.ConnectionOperations()
            result = connection_ops.validate_dn_string(dn)
            assert result.is_success, f"Valid DN failed: {dn}"

    def test_validate_filter_real_validation(self) -> None:
        """Test filter validation with real code execution."""
        # FlextLDAPOperationsBase is now internal - use concrete implementation
        ops = FlextLDAPOperations()

        # Test valid filters
        valid_filters = [
            "(cn=test)",
            "(objectClass=person)",
            "(&(cn=john)(mail=*))",
            "(|(uid=REDACTED_LDAP_BIND_PASSWORD)(cn=REDACTED_LDAP_BIND_PASSWORD))",
        ]

        for filter_str in valid_filters:
            connection_ops = ops.ConnectionOperations()
            result = connection_ops.validate_filter_string(filter_str)
            assert result.is_success, f"Valid filter failed: {filter_str}"

    def test_handle_exception_with_context_real(self) -> None:
        """Test exception handling with real implementation."""
        # FlextLDAPOperationsBase is now internal - use concrete implementation
        ops = FlextLDAPOperations()

        # Test with real exception
        test_exception = ValueError("Test error message")
        result = ops._handle_exception_with_context(
            "test operation",
            test_exception,
            "conn123",
        )

        assert isinstance(result, str)
        assert "test operation" in result.lower()
        assert "Test error message" in result
        # Connection ID is logged separately, not in the error message
        assert len(result) > 0

    def test_log_operation_success_real(self) -> None:
        """Test operation success logging with real implementation."""
        # FlextLDAPOperationsBase is now internal - use concrete implementation
        ops = FlextLDAPOperations()

        # Should execute without raising exceptions
        ops._log_operation_success("test operation", "conn123", extra_key="value")


class TestFlextLDAPConnectionOperationsReal:
    """Test connection operations with REAL code execution."""

    @pytest.mark.asyncio
    async def test_create_connection_valid_uri_real(self) -> None:
        """Test connection creation with valid URI - real execution."""
        ops = FlextLDAPOperations.ConnectionOperations()

        result = await ops.create_connection("ldap://localhost:389")

        assert result.is_success
        connection_id = result.value
        assert isinstance(connection_id, str)
        assert len(connection_id) > 0

        # Verify connection was stored
        assert connection_id in ops._active_connections
        connection_data = ops._active_connections[connection_id]
        assert connection_data.server_uri == "ldap://localhost:389"
        assert connection_data.is_authenticated is False

    @pytest.mark.asyncio
    async def test_create_connection_with_bind_real(self) -> None:
        """Test connection creation with bind DN - real execution."""
        ops = FlextLDAPOperations.ConnectionOperations()

        result = await ops.create_connection(
            "ldap://localhost:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            _bind_password="password",
        )

        assert result.is_success
        connection_id = result.value

        # Verify connection stored with bind info
        connection_data = ops._active_connections[connection_id]
        assert connection_data.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert connection_data.is_authenticated is True

    @pytest.mark.asyncio
    async def test_create_connection_invalid_uri_real(self) -> None:
        """Test connection creation with invalid URI - real validation."""
        ops = FlextLDAPOperations.ConnectionOperations()

        result = await ops.create_connection("http://invalid:80")

        assert not result.is_success
        assert "ldap://" in (result.error or "")

    def test_get_connection_info_real(self) -> None:
        """Test getting connection info - real execution."""
        ops = FlextLDAPOperations.ConnectionOperations()

        # Add test connection directly using ConnectionMetadata object
        connection_id = str(uuid.uuid4())
        metadata = ops.ConnectionMetadata(
            server_uri="ldap://test:389",
            bind_dn="cn=test,dc=example,dc=com",
            created_at=datetime.now(UTC),
            timeout_seconds=30,
            is_authenticated=True,
        )
        ops._active_connections[connection_id] = metadata

        result = ops.get_connection_info(connection_id)

        assert result.is_success
        info = result.value
        assert info["connection_id"] == connection_id
        assert info["server_uri"] == "ldap://test:389"
        assert info["bind_dn"] == "cn=test,dc=example,dc=com"
        assert info["is_authenticated"] is True
        assert "created_at" in info
        assert "age_seconds" in info

    def test_get_connection_info_not_found_real(self) -> None:
        """Test getting connection info for non-existent connection."""
        ops = FlextLDAPOperations.ConnectionOperations()

        result = ops.get_connection_info("nonexistent")

        assert not result.is_success
        assert "not found" in (result.error or "")

    def test_list_active_connections_real(self) -> None:
        """Test listing active connections - real execution."""
        ops = FlextLDAPOperations.ConnectionOperations()

        # Start with empty list
        result = ops.list_active_connections()
        assert result.is_success
        assert result.value == []

        # Add test connections using ConnectionMetadata objects
        conn1 = str(uuid.uuid4())
        conn2 = str(uuid.uuid4())

        # Create proper ConnectionMetadata objects
        metadata1 = ops.ConnectionMetadata(
            server_uri="ldap://test1:389",
            bind_dn=None,
            created_at=datetime.now(UTC),
            is_authenticated=False,
        )
        metadata2 = ops.ConnectionMetadata(
            server_uri="ldap://test2:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            created_at=datetime.now(UTC),
            is_authenticated=True,
        )

        ops._active_connections[conn1] = metadata1
        ops._active_connections[conn2] = metadata2

        result = ops.list_active_connections()
        assert result.is_success
        connections = result.value
        assert len(connections) == 2

        connection_ids = [conn["connection_id"] for conn in connections]
        assert conn1 in connection_ids
        assert conn2 in connection_ids

    @pytest.mark.asyncio
    async def test_close_connection_real(self) -> None:
        """Test closing connection - real execution."""
        ops = FlextLDAPOperations.ConnectionOperations()

        # Create connection first
        create_result = await ops.create_connection("ldap://localhost:389")
        assert create_result.is_success
        connection_id = create_result.value

        # Verify connection exists
        assert connection_id in ops._active_connections

        # Close connection
        result = await ops.close_connection(connection_id)
        assert result.is_success

        # Verify connection removed
        assert connection_id not in ops._active_connections

    @pytest.mark.asyncio
    async def test_close_connection_not_found_real(self) -> None:
        """Test closing non-existent connection."""
        ops = FlextLDAPOperations.ConnectionOperations()

        result = await ops.close_connection("nonexistent")

        assert not result.is_success
        assert "not found" in (result.error or "")

    def test_calculate_duration_real(self) -> None:
        """Test duration calculation with real implementation."""
        ops = FlextLDAPOperations.ConnectionOperations()

        # Test with datetime object
        past_time = datetime.now(UTC)
        duration = ops._calculate_duration(past_time)
        assert isinstance(duration, float)
        assert duration >= 0.0

        # Test with invalid input
        duration = ops._calculate_duration("invalid")
        assert duration == 0.0

        # Test with None
        duration = ops._calculate_duration(None)
        assert duration == 0.0


class TestFlextLDAPSearchOperationsReal:
    """Test search operations with REAL code execution."""

    @pytest.mark.asyncio
    async def test_search_entries_valid_params_real(self) -> None:
        """Test entry search with valid parameters - real execution."""
        ops = FlextLDAPOperations.SearchOperations()

        params = FlextLDAPEntities.SearchParams(
            connection_id="test_conn",
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=*)",
        )

        result = await ops.search_entries(params)

        # Should succeed but return empty results (no real LDAP)
        assert result.is_success
        # SearchResult has an entries property that is a list
        search_result = result.value
        assert hasattr(search_result, "entries")
        assert isinstance(search_result.entries, list)
        assert len(search_result.entries) == 0  # No real LDAP server

    @pytest.mark.asyncio
    async def test_search_entries_invalid_dn_real(self) -> None:
        """Test entry search with invalid base DN - real validation."""
        ops = FlextLDAPOperations.SearchOperations()

        # This should return a failed result rather than raise
        search_params = FlextLDAPEntities.SearchParams(
            connection_id="test_conn",
            base_dn="invalid_dn",  # Invalid DN format
            search_filter="(objectClass=*)",
        )
        result = await ops.search_entries(search_params)

        # Should handle gracefully and return failed result or empty results
        assert not result.is_success or result.value.entries == []

    def test_build_user_filter_real(self) -> None:
        """Test user filter building - real execution."""
        ops = FlextLDAPOperations.SearchOperations()

        # Test with criteria
        filter_str = ops._build_user_filter({"cn": "John", "mail": "john"})
        assert filter_str.startswith("(&(objectClass=person)")
        assert "cn=*John*" in filter_str
        assert "mail=*john*" in filter_str
        assert filter_str.endswith(")")

        # Test with no criteria
        filter_str = ops._build_user_filter(None)
        assert filter_str == "(&(objectClass=person))"

        # Test with empty criteria
        filter_str = ops._build_user_filter({})
        assert filter_str == "(&(objectClass=person))"

    def test_build_group_filter_real(self) -> None:
        """Test group filter building - real execution."""
        ops = FlextLDAPOperations.SearchOperations()

        # Test with criteria
        filter_str = ops._build_group_filter({"cn": "REDACTED_LDAP_BIND_PASSWORD", "description": "test"})
        assert filter_str.startswith("(&(objectClass=groupOfNames)")
        assert "cn=*REDACTED_LDAP_BIND_PASSWORD*" in filter_str
        assert "description=*test*" in filter_str

        # Test with no criteria
        filter_str = ops._build_group_filter(None)
        assert filter_str == "(&(objectClass=groupOfNames))"

    def test_escape_ldap_filter_value_real(self) -> None:
        """Test LDAP filter value escaping - real implementation."""
        ops = FlextLDAPOperations.SearchOperations()

        # Test special characters
        escaped = ops._escape_ldap_filter_value("test(*)\\value")
        assert "\\28" in escaped  # (
        assert "\\29" in escaped  # )
        assert "\\2a" in escaped  # *
        assert "\\5c" in escaped  # \\

        # Test that normal characters are preserved
        escaped = ops._escape_ldap_filter_value("normaltext")
        assert escaped == "normaltext"

    def test_convert_entries_to_users_real(self) -> None:
        """Test converting entries to users - real execution."""
        ops = FlextLDAPOperations.SearchOperations()

        # Create realistic entry data
        attributes: LdapAttributeDict = {
            "uid": ["john.doe"],
            "cn": ["John Doe"],
            "sn": ["Doe"],
            "givenName": ["John"],
            "mail": ["john@example.com"],
        }

        entry = FlextLDAPEntities.Entry(
            id=str(uuid.uuid4()),
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            object_classes=["person", "organizationalPerson"],
            attributes=attributes,
            status="active",
        )

        users = ops._convert_entries_to_users([entry])

        assert len(users) == 1
        user = users[0]
        assert isinstance(user, FlextLDAPEntities.User)
        assert user.uid == "john.doe"
        assert user.cn == "John Doe"
        assert user.sn == "Doe"
        assert user.given_name == "John"
        assert user.mail == "john@example.com"

    def test_convert_entries_to_groups_real(self) -> None:
        """Test converting entries to groups - real execution."""
        ops = FlextLDAPOperations.SearchOperations()

        # Create realistic group entry
        attributes: LdapAttributeDict = {
            "cn": ["REDACTED_LDAP_BIND_PASSWORDs"],
            "description": ["Administrator group"],
            "member": [
                "cn=john.doe,ou=users,dc=example,dc=com",
                "cn=jane.doe,ou=users,dc=example,dc=com",
            ],
        }

        entry = FlextLDAPEntities.Entry(
            id=str(uuid.uuid4()),
            dn="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com",
            object_classes=["groupOfNames"],
            attributes=attributes,
            status="active",
        )

        groups = ops._convert_entries_to_groups([entry])

        assert len(groups) == 1
        group = groups[0]
        assert isinstance(group, FlextLDAPEntities.Group)
        assert group.cn == "REDACTED_LDAP_BIND_PASSWORDs"
        assert group.description == "Administrator group"
        assert len(group.members) == 2
        assert "cn=john.doe,ou=users,dc=example,dc=com" in group.members


class TestFlextLDAPUserOperationsReal:
    """Test user operations with REAL code execution."""

    def test_build_user_attributes_real(self) -> None:
        """Test user attribute building - real execution."""
        ops = FlextLDAPOperations.UserOperations()

        user_request = FlextLDAPEntities.CreateUserRequest(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            uid="john.doe",
            cn="John Doe",
            sn="Doe",
            given_name="John",
            mail="john.doe@example.com",
        )

        attributes = ops._build_user_attributes(user_request)

        # Verify all attributes are properly set
        assert "uid" in attributes
        assert "cn" in attributes
        assert "sn" in attributes
        assert "givenName" in attributes
        assert "mail" in attributes

        assert attributes["uid"] == ["john.doe"]
        assert attributes["cn"] == ["John Doe"]
        assert attributes["sn"] == ["Doe"]
        assert attributes["givenName"] == ["John"]
        assert attributes["mail"] == ["john.doe@example.com"]

    def test_build_user_entity_real(self) -> None:
        """Test user entity building - real execution."""
        ops = FlextLDAPOperations.UserOperations()

        user_request = FlextLDAPEntities.CreateUserRequest(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            uid="john.doe",
            cn="John Doe",
            sn="Doe",
            given_name="John",
        )

        attributes: LdapAttributeDict = {
            "uid": ["john.doe"],
            "cn": ["John Doe"],
            "sn": ["Doe"],
            "givenName": ["John"],
        }

        user = ops._build_user_entity(user_request, attributes)

        assert isinstance(user, FlextLDAPEntities.User)
        assert user.uid == "john.doe"
        assert user.cn == "John Doe"
        assert user.sn == "Doe"
        assert user.given_name == "John"
        assert user.status == "active"


class TestFlextLDAPGroupOperationsReal:
    """Test group operations with REAL code execution."""

    def test_prepare_group_members_real(self) -> None:
        """Test group member preparation - real execution."""
        ops = FlextLDAPOperations.GroupOperations()

        # Test with provided members
        members = ops._prepare_group_members(
            [
                "cn=user1,ou=users,dc=example,dc=com",
                "cn=user2,ou=users,dc=example,dc=com",
            ],
        )

        assert len(members) == 2
        assert "cn=user1,ou=users,dc=example,dc=com" in members
        assert "cn=user2,ou=users,dc=example,dc=com" in members

        # Test with no members (dummy member added)
        members = ops._prepare_group_members(None)
        assert len(members) == 1
        assert members[0].startswith("cn=dummy")

    def test_build_group_attributes_real(self) -> None:
        """Test group attribute building - real execution."""
        ops = FlextLDAPOperations.GroupOperations()

        attributes = ops._build_group_attributes(
            cn="REDACTED_LDAP_BIND_PASSWORDs",
            description="Administrator group",
            members=["cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example,dc=com"],
        )

        assert "cn" in attributes
        assert "description" in attributes
        assert "member" in attributes

        assert attributes["cn"] == ["REDACTED_LDAP_BIND_PASSWORDs"]
        assert attributes["description"] == ["Administrator group"]
        assert attributes["member"] == ["cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example,dc=com"]

    def test_build_group_entity_real(self) -> None:
        """Test group entity building - real execution."""
        ops = FlextLDAPOperations.GroupOperations()

        attributes: LdapAttributeDict = {
            "cn": ["REDACTED_LDAP_BIND_PASSWORDs"],
            "description": ["Administrator group"],
            "member": ["cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example,dc=com"],
        }

        group = ops._build_group_entity(
            dn="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com",
            cn="REDACTED_LDAP_BIND_PASSWORDs",
            description="Administrator group",
            members=["cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example,dc=com"],
            attributes=attributes,
        )

        assert isinstance(group, FlextLDAPEntities.Group)
        assert group.cn == "REDACTED_LDAP_BIND_PASSWORDs"
        assert group.description == "Administrator group"
        assert len(group.members) == 1
        assert "cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example,dc=com" in group.members

    def test_filter_dummy_members_real(self) -> None:
        """Test filtering dummy members - real execution."""
        ops = FlextLDAPOperations.GroupOperations()

        members = [
            "cn=user1,ou=users,dc=example,dc=com",
            "cn=dummy,ou=temp,dc=example,dc=com",  # This will be filtered
            "cn=user2,ou=users,dc=example,dc=com",
            "cn=real-user,ou=system,dc=example,dc=com",  # This won't be filtered
        ]

        filtered = ops._filter_dummy_members(members)

        assert len(filtered) == 3  # Only cn=dummy,ou=temp is filtered
        assert "cn=user1,ou=users,dc=example,dc=com" in filtered
        assert "cn=user2,ou=users,dc=example,dc=com" in filtered
        assert "cn=real-user,ou=system,dc=example,dc=com" in filtered

        # Verify the specific dummy member pattern is removed
        assert "cn=dummy,ou=temp,dc=example,dc=com" not in filtered

    def test_calculate_updated_members_real(self) -> None:
        """Test member calculation for group operations - real execution."""
        ops = FlextLDAPOperations.GroupOperations()

        current_members = ["cn=user1,ou=users,dc=example,dc=com"]

        # Test add action
        result = ops._calculate_updated_members(
            current_members,
            "cn=user2,ou=users,dc=example,dc=com",
            "add",
        )
        assert result.is_success
        assert len(result.value) == 2
        assert "cn=user2,ou=users,dc=example,dc=com" in result.value

        # Test remove action
        result = ops._calculate_updated_members(
            current_members,
            "cn=user1,ou=users,dc=example,dc=com",
            "remove",
        )
        assert result.is_success
        # Should have dummy member when last real member removed
        assert len(result.value) == 1
        assert "cn=dummy" in result.value[0]

        # Test invalid action
        result = ops._calculate_updated_members(
            current_members,
            "cn=user1,ou=users,dc=example,dc=com",
            "invalid",
        )
        assert not result.is_success
        assert "Invalid action" in (result.error or "")


class TestFlextLDAPOperationsUnifiedReal:
    """Test unified operations interface with REAL code execution."""

    def test_operations_initialization_real(self) -> None:
        """Test unified operations initialization - real execution."""
        ops = FlextLDAPOperations()

        # Verify all operation classes are properly initialized
        assert ops.connections is not None
        assert ops.search is not None
        assert ops.entries is not None
        assert ops.users is not None
        assert ops.groups is not None

        # Verify correct types
        assert isinstance(ops.connections, FlextLDAPOperations.ConnectionOperations)
        assert isinstance(ops.search, FlextLDAPOperations.SearchOperations)
        assert isinstance(ops.entries, FlextLDAPOperations.EntryOperations)
        assert isinstance(ops.users, FlextLDAPOperations.UserOperations)
        assert isinstance(ops.groups, FlextLDAPOperations.GroupOperations)

    @pytest.mark.asyncio
    async def test_create_connection_and_bind_real(self) -> None:
        """Test connection creation and binding - real execution."""
        ops = FlextLDAPOperations()

        result = await ops.create_connection_and_bind(
            server_uri="ldap://localhost:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="password",
        )

        assert result.is_success
        connection_id = result.value
        assert isinstance(connection_id, str)
        assert len(connection_id) > 0

        # Verify connection was created in the connections manager
        info_result = ops.connections.get_connection_info(connection_id)
        assert info_result.is_success
        assert info_result.value["is_authenticated"] is True

    @pytest.mark.asyncio
    async def test_search_and_get_first_real(self) -> None:
        """Test search and get first entry - real execution."""
        ops = FlextLDAPOperations()

        result = await ops.search_and_get_first(
            connection_id="test_conn",
            base_dn="dc=example,dc=com",
            search_filter="(cn=nonexistent)",
        )

        # Should succeed but return None (no real LDAP)
        assert result.is_success
        assert result.value is None

    @pytest.mark.asyncio
    async def test_cleanup_connection_real(self) -> None:
        """Test connection cleanup - real execution."""
        ops = FlextLDAPOperations()

        # Create connection first
        create_result = await ops.create_connection_and_bind(
            server_uri="ldap://localhost:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="password",
        )
        assert create_result.is_success
        connection_id = create_result.value

        # Cleanup should succeed
        await ops.cleanup_connection(connection_id)

        # Verify connection was cleaned up
        info_result = ops.connections.get_connection_info(connection_id)
        assert not info_result.is_success  # Connection should be gone
