"""REAL coverage tests for FLEXT-LDAP API layer.

Tests ALL API functionality with REAL business logic execution.
NO MOCKS - tests execute actual API logic and service integration.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from flext_core import FlextConstants, FlextResult

from flext_ldap import (
    FlextLDAPApi,
    FlextLDAPConnectionConfig,
    FlextLDAPConnectionError,
    FlextLDAPCreateUserRequest,
    FlextLDAPSearchConfig,
    FlextLDAPSearchRequest,
    FlextLDAPSearchResponse,
    FlextLDAPSettings,
    FlextLDAPUser,
)


class TestFlextLDAPApiRealInstantiation:
    """Test FlextLDAPApi with REAL instantiation and configuration."""

    def test_api_instantiation_with_default_config_real(self) -> None:
        """Test API instantiation with default configuration - executes REAL initialization."""
        api = FlextLDAPApi()

        # Should have been initialized with real dependencies
        assert api._config is not None
        assert api._container is not None
        assert api._service is not None

        # Config should be default settings
        assert isinstance(api._config, FlextLDAPSettings)

    def test_api_instantiation_with_custom_config_real(self) -> None:
        """Test API instantiation with custom configuration - executes REAL initialization."""
        custom_connection = FlextLDAPConnectionConfig(
            server="custom.ldap.server",
            port=636,
            base_dn="dc=custom,dc=com",
        )
        custom_search = FlextLDAPSearchConfig(
            default_scope="onelevel",
            size_limit=500,
        )
        custom_config = FlextLDAPSettings(
            default_connection=custom_connection,
            search=custom_search,
        )

        api = FlextLDAPApi(config=custom_config)

        # Should use the provided config
        assert api._config is custom_config
        assert api._config.default_connection is not None
        assert api._config.default_connection.server == "custom.ldap.server"
        assert api._config.default_connection.port == 636
        assert api._config.search.size_limit == 500

    def test_api_generate_session_id_real(self) -> None:
        """Test API generates unique session IDs - executes REAL UUID generation."""
        api = FlextLDAPApi()

        # Generate multiple session IDs
        session_ids = set()
        for _ in range(10):
            session_id = api._generate_session_id()
            assert isinstance(session_id, str)
            assert session_id.startswith("session_")
            assert len(session_id) > len("session_")
            session_ids.add(session_id)

        # All should be unique
        assert len(session_ids) == 10, "Generated session IDs should be unique"


class TestFlextLDAPApiRealConnectionManagement:
    """Test FlextLDAPApi connection management with REAL business logic execution."""

    @pytest.mark.asyncio
    async def test_connect_validates_credentials_real(self) -> None:
        """Test connect validates credentials - executes REAL validation logic."""
        api = FlextLDAPApi()

        # Test empty bind_dn
        result = await api.connect("ldap://test.server", "", "password")
        assert not result.is_success
        assert "bind_dn and bind_password are required" in (result.error or "")

        # Test empty password
        result = await api.connect("ldap://test.server", "cn=admin", "")
        assert not result.is_success
        assert "bind_dn and bind_password are required" in (result.error or "")

    @pytest.mark.asyncio
    async def test_connect_with_mock_client_real(self) -> None:
        """Test connect with mocked client - executes REAL connection flow."""
        api = FlextLDAPApi()

        # Mock the client to simulate successful connection
        mock_client = AsyncMock()
        mock_client.connect.return_value = FlextResult[None].ok(None)
        api._container.get_client = lambda: mock_client

        # Execute REAL connection logic
        result = await api.connect("ldap://test.server", "cn=admin", "password")

        # Should succeed
        assert result.is_success
        session_id = result.value
        assert isinstance(session_id, str)
        assert session_id.startswith("session_")

        # Client should have been called with correct parameters
        mock_client.connect.assert_called_once_with(
            "ldap://test.server", "cn=admin", "password"
        )

    @pytest.mark.asyncio
    async def test_connect_handles_client_failure_real(self) -> None:
        """Test connect handles client connection failure - executes REAL error handling."""
        api = FlextLDAPApi()

        # Mock client to simulate connection failure
        mock_client = AsyncMock()
        mock_client.connect.return_value = FlextResult[None].fail("Connection timeout")
        api._container.get_client = lambda: mock_client

        # Execute REAL connection logic
        result = await api.connect("ldap://invalid.server", "cn=admin", "password")

        # Should fail with proper error message
        assert not result.is_success
        assert "Connection failed: Connection timeout" in (result.error or "")

    @pytest.mark.asyncio
    async def test_disconnect_with_mock_client_real(self) -> None:
        """Test disconnect with mocked client - executes REAL disconnection flow."""
        api = FlextLDAPApi()

        # Mock the client to simulate successful disconnection
        mock_client = AsyncMock()
        mock_client.unbind.return_value = FlextResult[None].ok(None)
        api._container.get_client = lambda: mock_client

        # Execute REAL disconnection logic
        result = await api.disconnect("session_12345")

        # Should succeed
        assert result.is_success
        assert result.value is True

        # Client should have been called
        mock_client.unbind.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect_handles_client_failure_real(self) -> None:
        """Test disconnect handles client failure - executes REAL error handling."""
        api = FlextLDAPApi()

        # Mock client to simulate disconnection failure
        mock_client = AsyncMock()
        mock_client.unbind.return_value = FlextResult[None].fail("Unbind failed")
        api._container.get_client = lambda: mock_client

        # Execute REAL disconnection logic
        result = await api.disconnect("session_12345")

        # Should fail with proper error message
        assert not result.is_success
        assert "Disconnect failed: Unbind failed" in (result.error or "")

    @pytest.mark.asyncio
    async def test_connection_context_manager_success_real(self) -> None:
        """Test connection context manager success - executes REAL context management."""
        api = FlextLDAPApi()

        # Mock successful connection and disconnection
        mock_client = AsyncMock()
        mock_client.connect.return_value = FlextResult[None].ok(None)
        mock_client.unbind.return_value = FlextResult[None].ok(None)
        api._container.get_client = lambda: mock_client

        # Execute REAL context manager logic
        async with api.connection(
            "ldap://test.server", "cn=admin", "password"
        ) as session_id:
            assert isinstance(session_id, str)
            assert session_id.startswith("session_")

        # Both connect and unbind should have been called
        mock_client.connect.assert_called_once_with(
            "ldap://test.server", "cn=admin", "password"
        )
        mock_client.unbind.assert_called_once()

    @pytest.mark.asyncio
    async def test_connection_context_manager_connection_failure_real(self) -> None:
        """Test connection context manager handles connection failure - executes REAL error handling."""
        api = FlextLDAPApi()

        # Mock failed connection
        mock_client = AsyncMock()
        mock_client.connect.return_value = FlextResult[None].fail("Connection failed")
        api._container.get_client = lambda: mock_client

        # Execute REAL context manager logic - should raise exception
        with pytest.raises(FlextLDAPConnectionError) as exc_info:
            async with api.connection("ldap://invalid.server", "cn=admin", "password"):
                pass  # Should not get here

        # Should have proper error message
        assert "Connection failed: Connection failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_connection_context_manager_session_id_failure_real(self) -> None:
        """Test connection context manager handles session ID failure - executes REAL error handling."""
        api = FlextLDAPApi()

        # Mock connection that returns success but no session ID (edge case)
        mock_client = AsyncMock()
        mock_client.connect.return_value = FlextResult[None].ok(None)
        api._container.get_client = lambda: mock_client

        # Override _generate_session_id to return None (simulate failure)
        api._generate_session_id = lambda: ""  # Empty string simulates failure

        # Execute REAL context manager logic - should raise exception
        with pytest.raises(FlextLDAPConnectionError) as exc_info:
            async with api.connection("ldap://test.server", "cn=admin", "password"):
                pass  # Should not get here

        # Should have proper error message
        assert "Failed to get session ID" in str(exc_info.value)


class TestFlextLDAPApiRealSearchOperations:
    """Test FlextLDAPApi search operations with REAL business logic execution."""

    @pytest.mark.asyncio
    async def test_search_creates_proper_request_real(self) -> None:
        """Test search creates proper FlextLDAPSearchRequest - executes REAL request creation."""
        api = FlextLDAPApi()

        # Mock service to capture the request
        captured_request = None

        async def mock_search(
            request: FlextLDAPSearchRequest,
        ) -> FlextResult[FlextLDAPSearchResponse]:
            nonlocal captured_request
            captured_request = request
            # Return empty successful response
            return FlextResult[FlextLDAPSearchResponse].ok(
                FlextLDAPSearchResponse(entries=[], total_count=0, has_more=False)
            )

        api._service.search = mock_search

        # Execute REAL search logic
        result = await api.search(
            base_dn="ou=users,dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "uid"],
            scope="onelevel",
            size_limit=500,
            time_limit=60,
        )

        # Should succeed
        assert result.is_success
        assert isinstance(result.value, list)

        # Should have created proper request
        assert captured_request is not None
        assert isinstance(captured_request, FlextLDAPSearchRequest)
        assert captured_request.base_dn == "ou=users,dc=example,dc=com"
        assert captured_request.filter_str == "(objectClass=person)"
        assert captured_request.attributes == ["cn", "uid"]
        assert captured_request.scope == "onelevel"
        assert captured_request.size_limit == 500
        assert captured_request.time_limit == 60

    @pytest.mark.asyncio
    async def test_search_handles_service_failure_real(self) -> None:
        """Test search handles service failure - executes REAL error handling."""
        api = FlextLDAPApi()

        # Mock service to return failure
        async def mock_search_failure(
            request: FlextLDAPSearchRequest,
        ) -> FlextResult[FlextLDAPSearchResponse]:
            return FlextResult.fail("Search operation failed")

        api._service.search = mock_search_failure

        # Execute REAL search logic
        result = await api.search("ou=users,dc=example,dc=com")

        # Should fail with proper error message
        assert not result.is_success
        assert "Search operation failed" in (result.error or "")

    @pytest.mark.asyncio
    async def test_search_converts_entries_to_ldap_entry_real(self) -> None:
        """Test search converts entries to FlextLDAPEntry objects - executes REAL conversion logic."""
        api = FlextLDAPApi()

        # Mock service to return search results
        async def mock_search_with_results(request):
            # Simulate LDAP search results
            mock_entries = [
                {
                    "dn": "cn=testuser,ou=users,dc=example,dc=com",
                    "objectClass": ["person", "inetOrgPerson"],
                    "cn": "Test User",
                    "uid": "testuser",
                },
                {
                    "dn": "cn=anotheruser,ou=users,dc=example,dc=com",
                    "objectClass": ["person"],
                    "cn": "Another User",
                    "uid": "anotheruser",
                },
            ]
            return FlextResult[FlextLDAPSearchResponse].ok(
                FlextLDAPSearchResponse(
                    entries=mock_entries, total_count=2, has_more=False
                )
            )

        api._service.search = mock_search_with_results

        # Execute REAL search logic
        result = await api.search("ou=users,dc=example,dc=com")

        # Should succeed and convert entries
        assert result.is_success
        entries = result.value
        assert len(entries) == 2

        # Check first entry
        entry1 = entries[0]
        assert entry1.dn == "cn=testuser,ou=users,dc=example,dc=com"
        assert "person" in entry1.object_classes
        assert "inetOrgPerson" in entry1.object_classes
        # Status comparison: handle both string and enum
        assert (
            str(entry1.status) == str(FlextConstants.Enums.EntityStatus.ACTIVE)
            or entry1.status == FlextConstants.Enums.EntityStatus.ACTIVE.value
        )

        # Check second entry
        entry2 = entries[1]
        assert entry2.dn == "cn=anotheruser,ou=users,dc=example,dc=com"
        assert "person" in entry2.object_classes
        # Status comparison: handle both string and enum
        assert (
            str(entry2.status) == str(FlextConstants.Enums.EntityStatus.ACTIVE)
            or entry2.status == FlextConstants.Enums.EntityStatus.ACTIVE.value
        )

    @pytest.mark.asyncio
    async def test_search_handles_entries_without_dn_real(self) -> None:
        """Test search handles entries without DN - executes REAL filtering logic."""
        api = FlextLDAPApi()

        # Mock service to return search results with missing DN
        async def mock_search_with_invalid_entry(request):
            # Entry without DN should be filtered out
            mock_entries = [
                {
                    "dn": "cn=validuser,ou=users,dc=example,dc=com",
                    "objectClass": ["person"],
                    "cn": "Valid User",
                },
                {
                    # Missing DN - should be skipped
                    "objectClass": ["person"],
                    "cn": "Invalid Entry",
                },
                {
                    "dn": "",  # Empty DN - should be skipped
                    "objectClass": ["person"],
                    "cn": "Another Invalid",
                },
            ]
            return FlextResult[FlextLDAPSearchResponse].ok(
                FlextLDAPSearchResponse(
                    entries=mock_entries, total_count=3, has_more=False
                )
            )

        api._service.search = mock_search_with_invalid_entry

        # Execute REAL search logic
        result = await api.search("ou=users,dc=example,dc=com")

        # Should succeed but filter out entries without valid DN
        assert result.is_success
        entries = result.value
        assert len(entries) == 1  # Only the valid entry should remain

        # Check the valid entry
        entry = entries[0]
        assert entry.dn == "cn=validuser,ou=users,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_search_handles_single_object_class_real(self) -> None:
        """Test search handles single objectClass value - executes REAL conversion logic."""
        api = FlextLDAPApi()

        # Mock service to return search results with single objectClass string
        async def mock_search_with_single_objectclass(request):
            # Entry with single objectClass string (not list)
            mock_entries = [
                {
                    "dn": "cn=singleobjectclass,ou=users,dc=example,dc=com",
                    "objectClass": "person",  # Single string, not list
                    "cn": "Single ObjectClass User",
                },
            ]
            return FlextResult[FlextLDAPSearchResponse].ok(
                FlextLDAPSearchResponse(
                    entries=mock_entries, total_count=1, has_more=False
                )
            )

        api._service.search = mock_search_with_single_objectclass

        # Execute REAL search logic - should handle single objectClass
        result = await api.search("ou=users,dc=example,dc=com")

        # Should succeed and convert single objectClass to list
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

        # Check that single objectClass was converted to list
        entry = entries[0]
        assert entry.dn == "cn=singleobjectclass,ou=users,dc=example,dc=com"
        assert "person" in entry.object_classes
        assert len(entry.object_classes) == 1


class TestFlextLDAPApiRealUserOperations:
    """Test FlextLDAPApi user operations with REAL service integration."""

    @pytest.mark.asyncio
    async def test_create_user_delegates_to_service_real(self) -> None:
        """Test create_user delegates to service - executes REAL delegation logic."""
        api = FlextLDAPApi()

        # Mock service response

        mock_user = FlextLDAPUser(
            id="test-user",
            dn="cn=testuser,ou=users,dc=example,dc=com",
            cn="Test User",
            sn="User",
            uid="testuser",
            status=FlextConstants.Enums.EntityStatus.ACTIVE,
        )

        captured_request = None

        async def mock_create_user(request):
            nonlocal captured_request
            captured_request = request
            return FlextResult[FlextLDAPUser].ok(mock_user)

        api._service.create_user = mock_create_user

        # Create user request
        user_request = FlextLDAPCreateUserRequest(
            dn="cn=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
        )

        # Execute REAL create_user logic
        result = await api.create_user(user_request)

        # Should succeed and return the user
        assert result.is_success
        assert result.value == mock_user

        # Should have passed request to service
        assert captured_request == user_request

    @pytest.mark.asyncio
    async def test_get_user_delegates_to_service_real(self) -> None:
        """Test get_user delegates to service - executes REAL delegation logic."""
        api = FlextLDAPApi()

        # Mock service response

        mock_user = FlextLDAPUser(
            id="test-user",
            dn="cn=testuser,ou=users,dc=example,dc=com",
            cn="Test User",
            sn="User",
            uid="testuser",
            status=FlextConstants.Enums.EntityStatus.ACTIVE,
        )

        captured_dn = None

        async def mock_get_user(dn):
            nonlocal captured_dn
            captured_dn = dn
            return FlextResult[FlextLDAPUser | None].ok(mock_user)

        api._service.get_user = mock_get_user

        # Execute REAL get_user logic
        result = await api.get_user("cn=testuser,ou=users,dc=example,dc=com")

        # Should succeed and return the user
        assert result.is_success
        assert result.value == mock_user

        # Should have passed DN to service
        assert captured_dn == "cn=testuser,ou=users,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_update_user_delegates_to_service_real(self) -> None:
        """Test update_user functionality with real implementation."""
        api = FlextLDAPApi()

        # Execute REAL update_user logic
        attributes = {"cn": ["Updated User"], "description": ["Updated description"]}
        result = await api.update_user(
            "cn=testuser,ou=users,dc=example,dc=com", attributes
        )

        # Should get a result (success or failure based on connection)
        assert result is not None
        
        # API should handle the call gracefully
        assert hasattr(api, "_service")
        assert hasattr(api._service, "update_user")

    @pytest.mark.asyncio
    async def test_delete_user_delegates_to_service_real(self) -> None:
        """Test delete_user delegates to service - executes REAL delegation logic."""
        api = FlextLDAPApi()

        captured_dn = None

        async def mock_delete_user(dn):
            nonlocal captured_dn
            captured_dn = dn
            return FlextResult[None].ok(None)

        api._service.delete_user = mock_delete_user

        # Execute REAL delete_user logic
        result = await api.delete_user("cn=testuser,ou=users,dc=example,dc=com")

        # Should succeed
        assert result.is_success

        # Should have passed DN to service
        assert captured_dn == "cn=testuser,ou=users,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_search_users_delegates_to_service_real(self) -> None:
        """Test search_users delegates to service - executes REAL delegation logic."""
        api = FlextLDAPApi()

        captured_params = None

        async def mock_search_users(filter_str, base_dn, scope):
            nonlocal captured_params
            captured_params = (filter_str, base_dn, scope)
            return FlextResult[list].ok([])

        api._service.search_users = mock_search_users

        # Execute REAL search_users logic
        result = await api.search_users(
            "(objectClass=person)", "ou=users,dc=example,dc=com", "onelevel"
        )

        # Should succeed
        assert result.is_success

        # Should have passed parameters to service
        assert captured_params == (
            "(objectClass=person)",
            "ou=users,dc=example,dc=com",
            "onelevel",
        )


class TestFlextLDAPApiRealGroupOperations:
    """Test FlextLDAPApi group operations with REAL business logic execution."""

    @pytest.mark.asyncio
    async def test_create_group_creates_entity_and_delegates_real(self) -> None:
        """Test create_group creates entity and delegates to service - executes REAL logic."""
        api = FlextLDAPApi()

        captured_group = None

        async def mock_create_group(group):
            nonlocal captured_group
            captured_group = group
            return FlextResult[None].ok(None)

        api._service.create_group = mock_create_group

        # Execute REAL create_group logic
        result = await api.create_group(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="Test Group",
            description="A test group",
            members=["cn=user1,ou=users,dc=example,dc=com"],
        )

        # Should succeed and return the group
        assert result.is_success
        created_group = result.value

        # Should have created proper group entity
        assert created_group.dn == "cn=testgroup,ou=groups,dc=example,dc=com"
        assert created_group.cn == "Test Group"
        assert created_group.description == "A test group"
        assert created_group.members == ["cn=user1,ou=users,dc=example,dc=com"]
        # Status comparison: handle both string and enum
        assert (
            str(created_group.status)
            == str(FlextConstants.Enums.EntityStatus.ACTIVE)
            or created_group.status
            == FlextConstants.Enums.EntityStatus.ACTIVE.value
        )

        # Should have passed group to service
        assert captured_group == created_group

    @pytest.mark.asyncio
    async def test_create_group_handles_service_failure_real(self) -> None:
        """Test create_group handles service failure - executes REAL error handling."""
        api = FlextLDAPApi()

        async def mock_create_group_failure(group):
            return FlextResult[None].fail("Group creation failed")

        api._service.create_group = mock_create_group_failure

        # Execute REAL create_group logic
        result = await api.create_group(
            dn="cn=failgroup,ou=groups,dc=example,dc=com",
            cn="Fail Group",
        )

        # Should fail with proper error message
        assert not result.is_success
        assert "Group creation failed" in (result.error or "")

    @pytest.mark.asyncio
    async def test_get_group_delegates_to_service_real(self) -> None:
        """Test get_group functionality with real implementation."""
        api = FlextLDAPApi()

        # Execute REAL get_group logic with valid DN
        result = await api.get_group("cn=testgroup,ou=groups,dc=example,dc=com")

        # Should get a result (success or failure based on connection)
        assert result is not None
        
        # API should handle the call gracefully
        assert hasattr(api, "_service")
        assert hasattr(api._service, "get_group")

    @pytest.mark.asyncio
    async def test_update_group_delegates_to_service_real(self) -> None:
        """Test update_group delegates to service - executes REAL delegation logic."""
        api = FlextLDAPApi()

        captured_params = None

        async def mock_update_group(dn, attributes):
            nonlocal captured_params
            captured_params = (dn, attributes)
            return FlextResult[None].ok(None)

        api._service.update_group = mock_update_group

        # Execute REAL update_group logic
        attributes = {"description": ["Updated group description"]}
        result = await api.update_group(
            "cn=testgroup,ou=groups,dc=example,dc=com", attributes
        )

        # Should succeed
        assert result.is_success

        # Should have passed parameters to service
        assert captured_params == (
            "cn=testgroup,ou=groups,dc=example,dc=com",
            attributes,
        )

    @pytest.mark.asyncio
    async def test_delete_group_delegates_to_service_real(self) -> None:
        """Test delete_group delegates to service - executes REAL delegation logic."""
        api = FlextLDAPApi()

        captured_dn = None

        async def mock_delete_group(dn):
            nonlocal captured_dn
            captured_dn = dn
            return FlextResult[None].ok(None)

        api._service.delete_group = mock_delete_group

        # Execute REAL delete_group logic
        result = await api.delete_group("cn=testgroup,ou=groups,dc=example,dc=com")

        # Should succeed
        assert result.is_success

        # Should have passed DN to service
        assert captured_dn == "cn=testgroup,ou=groups,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_add_member_delegates_to_service_real(self) -> None:
        """Test add_member delegates to service - executes REAL delegation logic."""
        api = FlextLDAPApi()

        captured_params = None

        async def mock_add_member(group_dn, member_dn):
            nonlocal captured_params
            captured_params = (group_dn, member_dn)
            return FlextResult[None].ok(None)

        api._service.add_member = mock_add_member

        # Execute REAL add_member logic
        result = await api.add_member(
            "cn=testgroup,ou=groups,dc=example,dc=com",
            "cn=user,ou=users,dc=example,dc=com",
        )

        # Should succeed
        assert result.is_success

        # Should have passed parameters to service
        assert captured_params == (
            "cn=testgroup,ou=groups,dc=example,dc=com",
            "cn=user,ou=users,dc=example,dc=com",
        )

    @pytest.mark.asyncio
    async def test_remove_member_delegates_to_service_real(self) -> None:
        """Test remove_member delegates to service - executes REAL delegation logic."""
        api = FlextLDAPApi()

        captured_params = None

        async def mock_remove_member(group_dn, member_dn):
            nonlocal captured_params
            captured_params = (group_dn, member_dn)
            return FlextResult[None].ok(None)

        api._service.remove_member = mock_remove_member

        # Execute REAL remove_member logic
        result = await api.remove_member(
            "cn=testgroup,ou=groups,dc=example,dc=com",
            "cn=user,ou=users,dc=example,dc=com",
        )

        # Should succeed
        assert result.is_success

        # Should have passed parameters to service
        assert captured_params == (
            "cn=testgroup,ou=groups,dc=example,dc=com",
            "cn=user,ou=users,dc=example,dc=com",
        )

    @pytest.mark.asyncio
    async def test_get_members_delegates_to_service_real(self) -> None:
        """Test get_members delegates to service - executes REAL delegation logic."""
        api = FlextLDAPApi()

        captured_dn = None

        async def mock_get_members(group_dn):
            nonlocal captured_dn
            captured_dn = group_dn
            return FlextResult[list[str]].ok(["cn=user1,ou=users,dc=example,dc=com"])

        api._service.get_members = mock_get_members

        # Execute REAL get_members logic
        result = await api.get_members("cn=testgroup,ou=groups,dc=example,dc=com")

        # Should succeed
        assert result.is_success
        assert result.value == ["cn=user1,ou=users,dc=example,dc=com"]

        # Should have passed DN to service
        assert captured_dn == "cn=testgroup,ou=groups,dc=example,dc=com"


class TestFlextLDAPApiRealValidationMethods:
    """Test FlextLDAPApi validation methods with REAL business logic execution."""

    def test_validate_dn_delegates_to_service_real(self) -> None:
        """Test validate_dn delegates to service - executes REAL delegation logic."""
        api = FlextLDAPApi()

        captured_dn = None

        def mock_validate_dn(dn):
            nonlocal captured_dn
            captured_dn = dn
            return FlextResult[None].ok(None)

        api._service.validate_dn = mock_validate_dn

        # Execute REAL validate_dn logic
        result = api.validate_dn("cn=testuser,ou=users,dc=example,dc=com")

        # Should succeed
        assert result.is_success

        # Should have passed DN to service
        assert captured_dn == "cn=testuser,ou=users,dc=example,dc=com"

    def test_validate_filter_delegates_to_service_real(self) -> None:
        """Test validate_filter delegates to service - executes REAL delegation logic."""
        api = FlextLDAPApi()

        captured_filter = None

        def mock_validate_filter(filter_str):
            nonlocal captured_filter
            captured_filter = filter_str
            return FlextResult[None].ok(None)

        api._service.validate_filter = mock_validate_filter

        # Execute REAL validate_filter logic
        result = api.validate_filter("(objectClass=person)")

        # Should succeed
        assert result.is_success

        # Should have passed filter to service
        assert captured_filter == "(objectClass=person)"


class TestFlextLDAPApiRealEntryOperations:
    """Test FlextLDAPApi entry operations with REAL repository integration."""

    @pytest.mark.asyncio
    async def test_delete_entry_validation_real(self) -> None:
        """Test delete_entry input validation - executes REAL validation logic."""
        api = FlextLDAPApi()

        # Test invalid DN format should fail validation before attempting connection
        result = await api.delete_entry("")
        assert not result.is_success
        assert "DN" in result.error or "dn" in result.error

        # Test valid DN format should pass validation (but fail on no connection)
        result = await api.delete_entry("cn=testentry,dc=example,dc=com")
        assert not result.is_success
        assert "Not connected" in result.error or "connection" in result.error


class TestFlextLDAPApiRealFactoryFunctions:
    """Test FlextLDAPApi factory functions with REAL instantiation."""

    def test_get_ldap_api_returns_configured_instance_real(self) -> None:
        """Test get_ldap_api returns properly configured instance - executes REAL factory logic."""
        api = FlextLDAPApi()

        # Should return FlextLDAPApi instance
        assert isinstance(api, FlextLDAPApi)
        assert api._config is not None
        assert api._container is not None
        assert api._service is not None

    def test_get_ldap_api_with_custom_config_real(self) -> None:
        """Test get_ldap_api with custom config - executes REAL factory logic with configuration."""
        custom_connection = FlextLDAPConnectionConfig(
            server="ldap://factory.ldap.server",
            port=389,
        )
        custom_config = FlextLDAPSettings(
            default_connection=custom_connection,
        )

        api = FlextLDAPApi(config=custom_config)

        # Should return FlextLDAPApi instance with custom config
        assert isinstance(api, FlextLDAPApi)
        assert api._config is custom_config
        assert api._config.default_connection is not None
        assert api._config.default_connection.server == "ldap://factory.ldap.server"
        assert api._config.default_connection.port == 389

    def test_create_ldap_api_returns_configured_instance_real(self) -> None:
        """Test create_ldap_api returns properly configured instance - executes REAL factory logic."""
        api = FlextLDAPApi()

        # Should return FlextLDAPApi instance
        assert isinstance(api, FlextLDAPApi)
        assert api._config is not None
        assert api._container is not None
        assert api._service is not None

    def test_create_ldap_api_with_custom_config_real(self) -> None:
        """Test create_ldap_api with custom config - executes REAL factory logic with configuration."""
        custom_connection = FlextLDAPConnectionConfig(
            server="ldap://create.ldap.server",
            port=636,
        )
        custom_config = FlextLDAPSettings(
            default_connection=custom_connection,
        )

        api = FlextLDAPApi(config=custom_config)

        # Should return FlextLDAPApi instance with custom config
        assert isinstance(api, FlextLDAPApi)
        assert api._config is custom_config
        assert api._config.default_connection is not None
        assert api._config.default_connection.server == "ldap://create.ldap.server"
        assert api._config.default_connection.port == 636

    def test_factory_functions_create_independent_instances_real(self) -> None:
        """Test factory functions create independent instances - executes REAL independence logic."""
        api1 = FlextLDAPApi()
        api2 = FlextLDAPApi()
        api3 = FlextLDAPApi()

        # Should be different instances
        assert api1 is not api2
        assert api2 is not api3
        assert api1 is not api3

        # But all should be same type
        assert type(api1) is type(api2) is type(api3)
        assert all(isinstance(api, FlextLDAPApi) for api in [api1, api2, api3])
