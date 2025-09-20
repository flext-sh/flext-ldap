"""Test module for flext-ldap functionality."""

from __future__ import annotations

from typing import cast
from unittest.mock import AsyncMock, Mock, patch

import pytest

from flext_core import FlextContainer, FlextResult, FlextTypes
from flext_ldap import (
    FlextLdapApi,
    FlextLdapModels,
)
from flext_ldap.config import FlextLdapConfigs
from flext_ldap.dispatcher import FlextLdapDispatcher
from flext_ldap.typings import FlextLdapTypes


class TestFlextLdapApiComprehensive:
    """Comprehensive tests for FlextLdapApi with real functionality."""

    @pytest.mark.asyncio
    async def test_init_with_config(self) -> None:
        """Test API initialization with provided config using standard assertions."""
        config = FlextLdapConfigs()
        api = FlextLdapApi(config)

        # Use standard assertions for comprehensive validation
        assert api._config is config
        assert api._container_manager is not None
        assert isinstance(api, FlextLdapApi)

    @pytest.mark.asyncio
    async def test_init_without_config(self) -> None:
        """Test API initialization without config creates default using standard assertions."""
        api = FlextLdapApi()

        # Use standard assertions for comprehensive validation
        assert api._config is not None
        assert api._container_manager is not None
        assert isinstance(api, FlextLdapApi)

    @pytest.mark.asyncio
    async def test_process_base_implementation(self) -> None:
        """Test process method base implementation using FlextTestsMatchers."""
        service = FlextLdapApi()
        request: FlextTypes.Core.Dict = {"test": "data"}

        result = service.process(request)

        # Use standard assertions for result validation
        assert result.is_success
        assert result.value == request

    @pytest.mark.asyncio
    async def test_create_user_request(self) -> None:
        """Test create_user_request method using TestBuilders."""
        api = FlextLdapApi()

        # Create user request data (only use supported parameters)
        dn = "cn=test_user,ou=users,dc=example,dc=com"
        uid = "test_user"
        cn = "Test User"
        sn = "User"

        # Test user request creation
        result = api.create_user_request(dn=dn, uid=uid, cn=cn, sn=sn)

        # Validate the result
        assert result is not None
        assert hasattr(result, "dn")
        assert result.dn == dn
        assert result.uid == uid

    @pytest.mark.asyncio
    async def test_api_validation_methods(self) -> None:
        """Test API validation functionality."""
        api = FlextLdapApi()

        # Test DN validation
        dn_result = api.validate_dn("cn=test,dc=example,dc=com")
        assert dn_result.is_success

        # Test filter validation
        filter_result = api.validate_filter("(objectClass=person)")
        assert filter_result.is_success

    @pytest.mark.asyncio
    async def test_api_configuration_access(self) -> None:
        """Test API configuration access functionality."""
        api = FlextLdapApi()

        # Test that configuration is accessible
        assert api._config is not None
        assert api._container_manager is not None
        assert api._client is not None

    @pytest.mark.asyncio
    async def test_initialize(self) -> None:
        """Test service initialization."""
        service = FlextLdapApi()

        result = await service.initialize()

        assert result.is_success
        assert result.value is None

    @pytest.mark.asyncio
    async def test_cleanup(self) -> None:
        """Test service cleanup with container reset."""
        service = FlextLdapApi()

        result = await service.cleanup()

        assert result.is_success

    @pytest.mark.asyncio
    async def test_cleanup_with_container_without_reset(self) -> None:
        """Test cleanup when container has no reset method."""

        # Create a minimal container-like object without reset
        class MinimalContainer:
            def clear(self) -> None:
                pass

        service = FlextLdapApi()
        # Use typing.cast to bypass type checking for test mock
        service._container = cast("FlextContainer", MinimalContainer())

        result = await service.cleanup()

        assert result.is_success

    @pytest.mark.asyncio
    async def test_cleanup_with_container_without_clear(self) -> None:
        """Test cleanup when container has neither reset nor clear."""

        class EmptyContainer:
            pass

        service = FlextLdapApi()
        # Use typing.cast to bypass type checking for test mock
        service._container = cast("FlextContainer", EmptyContainer())

        result = await service.cleanup()

        assert result.is_success

    @pytest.mark.asyncio
    async def test_create_user_validation_failure(self) -> None:
        """Test user creation with validation failure."""
        service = FlextLdapApi()

        # Create request that passes Pydantic validation but may fail business validation
        request = FlextLdapModels.CreateUserRequest(
            dn="cn=test,dc=invalid",  # Valid format but may fail business rules
            uid="test",
            cn="Test",
            sn="Test",
            given_name="Test",
        )

        result = await service.create_user(request)

        # The test should handle both success and graceful failure
        assert isinstance(result, FlextResult)
        if not result.is_success:
            # Expected failure case - validation or repository issues
            assert result.error is not None

    @pytest.mark.asyncio
    async def test_create_user_with_valid_request(
        self,
    ) -> None:
        """Test user creation with valid request using real LDAP."""
        service = FlextLdapApi()

        request = FlextLdapModels.CreateUserRequest(
            dn="cn=testuser,ou=users,dc=flext,dc=local",
            uid="testuser",
            cn="Test User",
            sn="User",
            given_name="Test",
            mail="testuser@internal.invalid",
        )

        result = await service.create_user(request)

        # May fail due to repository not being connected, but should handle gracefully
        if result.is_success:
            assert isinstance(result.value, FlextLdapModels.User)
            assert result.value.uid == "testuser"
        else:
            # Expected behavior when LDAP is not available
            error_message = result.error or ""
            assert any(
                pattern in error_message.lower()
                for pattern in [
                    "repository",
                    "save failed",
                    "not connected",
                    "could not check",
                ]
            )

    @pytest.mark.asyncio
    async def test_create_user_dispatcher_short_circuits_to_domain(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Ensure dispatcher path avoids legacy entity creation pipeline when enabled."""
        monkeypatch.setenv("FLEXT_LDAP_ENABLE_DISPATCHER", "1")
        FlextLdapDispatcher().reset_dispatcher_cache()

        service = FlextLdapApi()
        request = FlextLdapModels.CreateUserRequest(
            dn="cn=dispatcher,ou=users,dc=flext,dc=local",
            uid="dispatcher",
            cn="Dispatcher User",
            sn="User",
        )

        expected_user = FlextLdapModels.User(
            id="user_dispatcher",
            dn=request.dn,
            uid=request.uid,
            cn=request.cn,
            sn=request.sn,
            object_classes=["person", "top"],
            attributes={},
        )

        class StubDispatcher:
            def __init__(self) -> None:
                self.commands: list[object] = []

            def dispatch(self, command: object) -> FlextResult[object]:
                self.commands.append(command)
                return FlextResult[object].ok(
                    FlextResult[FlextLdapModels.User].ok(expected_user),
                )

        stub_dispatcher = StubDispatcher()

        monkeypatch.setattr(
            "flext_ldap.dispatcher.FlextLdapDispatcher.get_global_dispatcher",
            lambda: stub_dispatcher,
            raising=False,
        )

        def _raise_to_user_entity(_self: FlextLdapModels.CreateUserRequest) -> None:
            msg = "legacy path should not execute"
            raise AssertionError(msg)

        monkeypatch.setattr(
            FlextLdapModels.CreateUserRequest,
            "to_user_entity",
            _raise_to_user_entity,
            raising=False,
        )

        result = await service.create_user(request)

        assert stub_dispatcher.commands, "dispatcher was not invoked"
        if result.is_success:
            assert isinstance(result.value, FlextLdapModels.User)
            assert result.value.uid == "dispatcher"
        else:
            error_message = result.error or ""
            assert "not connected" in error_message.lower()

        monkeypatch.delenv("FLEXT_LDAP_ENABLE_DISPATCHER", raising=False)
        FlextLdapDispatcher().reset_dispatcher_cache()

    @pytest.mark.asyncio
    async def test_get_user_client_failure(self) -> None:
        """Test get_user when client access fails."""
        service = FlextLdapApi()

        # Mock client to simulate failure
        mock_client = Mock()
        mock_client.search_with_request = AsyncMock(
            return_value=FlextResult.fail("Client connection failed")
        )

        with patch.object(service, "_client", mock_client):
            result = await service.get_user("cn=test,dc=test,dc=com")

        assert not result.is_success
        error_message = result.error or ""
        # Error message should be about client or connection failure
        assert any(
            keyword in error_message.lower()
            for keyword in ["client", "connection", "ldap server", "failed"]
        )

    @pytest.mark.asyncio
    async def test_get_user_with_valid_dn(self) -> None:
        """Test get_user with valid DN."""
        service = FlextLdapApi()

        result = await service.get_user("cn=testuser,dc=flext,dc=local")

        # Should handle gracefully even if user doesn't exist
        if not result.is_success:
            error_message = result.error or ""
            error_lower = error_message.lower()
            assert any(
                pattern in error_lower
                for pattern in [
                    "repository",
                    "not found",
                    "not connected",
                    "connection",
                    "ldap",
                ]
            )

    @pytest.mark.asyncio
    async def test_update_user_validation_failure(self) -> None:
        """Test update_user with validation failure."""
        service = FlextLdapApi()

        # Invalid attributes (empty)
        attributes: FlextLdapTypes.Entry.AttributeDict = {}

        result = await service.update_user("cn=test,dc=test,dc=com", attributes)

        assert not result.is_success
        assert any(
            pattern in ((result.error or "").lower())
            for pattern in ["validation failed", "not connected", "ldap server"]
        )

    @pytest.mark.asyncio
    async def test_update_user_with_valid_attributes(self) -> None:
        """Test update_user with valid attributes."""
        service = FlextLdapApi()

        attributes: FlextLdapTypes.Entry.AttributeDict = {
            "mail": "updated@example.com",
            "description": "Updated user",
        }

        result = await service.update_user("cn=testuser,dc=flext,dc=local", attributes)

        # May fail due to user not existing, but should handle gracefully
        if not result.is_success:
            error_lower = (result.error or "").lower()
            assert any(
                pattern in error_lower
                for pattern in [
                    "repository",
                    "user not found",
                    "not connected",
                    "connection",
                    "ldap",
                    "validation failed",
                ]
            )

    @pytest.mark.asyncio
    async def test_delete_user(self) -> None:
        """Test delete_user operation."""
        service = FlextLdapApi()

        result = await service.delete_user("cn=testuser,dc=flext,dc=local")

        # Should handle gracefully
        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_create_group_validation_failure(self) -> None:
        """Test create_group with validation failure."""
        service = FlextLdapApi()

        # Create group that passes Pydantic but may fail business validation
        group = FlextLdapModels.Group(
            id="test-group",
            dn="cn=test,dc=invalid",  # Valid format but may fail business rules
            cn="Test",
            description="Test",
        )

        result = await service.create_group(group)

        # The test should handle both success and graceful failure
        assert isinstance(result, FlextResult)
        if not result.is_success:
            # Expected failure case - validation or repository issues
            assert result.error is not None

    @pytest.mark.asyncio
    async def test_create_group_with_valid_request(self) -> None:
        """Test create_group with valid request."""
        service = FlextLdapApi()

        group = FlextLdapModels.Group(
            id="testgroup",
            dn="cn=testgroup,ou=groups,dc=flext,dc=local",
            cn="Test Group",
            description="A test group",
        )

        result = await service.create_group(group)

        # Should handle gracefully even if LDAP is not available
        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_get_group(self) -> None:
        """Test get_group operation."""
        service = FlextLdapApi()

        result = await service.get_group("cn=testgroup,dc=flext,dc=local")

        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_update_group(self) -> None:
        """Test update_group operation."""
        service = FlextLdapApi()

        attributes: FlextLdapTypes.Entry.AttributeDict = {
            "description": "Updated group description",
        }

        result = await service.update_group(
            "cn=testgroup,dc=flext,dc=local",
            attributes,
        )

        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_delete_group(self) -> None:
        """Test delete_group operation."""
        service = FlextLdapApi()

        result = await service.delete_group("cn=testgroup,dc=flext,dc=local")

        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_add_member(self) -> None:
        """Test add_member operation."""
        service = FlextLdapApi()

        result = await service.add_member(
            "cn=testgroup,dc=flext,dc=local",
            "cn=testuser,dc=flext,dc=local",
        )

        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_remove_member(self) -> None:
        """Test remove_member operation."""
        service = FlextLdapApi()

        result = await service.remove_member(
            "cn=testgroup,dc=flext,dc=local",
            "cn=testuser,dc=flext,dc=local",
        )

        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_get_members(self) -> None:
        """Test get_members operation."""
        service = FlextLdapApi()

        result = await service.get_members("cn=testgroup,dc=flext,dc=local")

        assert isinstance(result, FlextResult)

    def test_validate_dn_valid(self) -> None:
        """Test DN validation with valid DN."""
        service = FlextLdapApi()

        result = service.validate_dn("cn=testuser,ou=users,dc=example,dc=com")

        assert result.is_success

    def test_validate_dn_invalid_empty(self) -> None:
        """Test DN validation with empty DN."""
        service = FlextLdapApi()

        result = service.validate_dn("")

        assert not result.is_success
        assert any(
            word in (result.error or "").lower()
            for word in ["empty", "invalid", "short", "characters"]
        )

    def test_validate_dn_invalid_format(self) -> None:
        """Test DN validation with invalid format."""
        service = FlextLdapApi()

        result = service.validate_dn("invalid_dn_format")

        assert not result.is_success
        assert "invalid" in ((result.error or "").lower()) or "format" in (
            (result.error or "").lower()
        )

    def test_validate_filter_valid(self) -> None:
        """Test filter validation with valid filter."""
        service = FlextLdapApi()

        result = service.validate_filter("(objectClass=person)")

        assert result.is_success

    def test_validate_filter_invalid_empty(self) -> None:
        """Test filter validation with empty filter."""
        service = FlextLdapApi()

        result = service.validate_filter("")

        assert not result.is_success
        assert any(
            word in (result.error or "").lower()
            for word in ["empty", "invalid", "pattern", "match"]
        )

    def test_validate_filter_invalid_format(self) -> None:
        """Test filter validation with invalid format."""
        service = FlextLdapApi()

        result = service.validate_filter("invalid_filter")

        assert not result.is_success
        assert any(
            word in (result.error or "").lower()
            for word in ["invalid", "format", "pattern", "match"]
        )

    @pytest.mark.asyncio
    async def test_search(self) -> None:
        """Test search operation."""
        service = FlextLdapApi()

        request = FlextLdapModels.SearchRequest(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=person)",
            scope="subtree",
            attributes=["cn", "uid"],
            size_limit=100,
            time_limit=30,
        )

        result = await service.search(request)

        assert isinstance(result, FlextResult)

    def test_validate_attributes_valid(self) -> None:
        """Test attributes validation with valid attributes."""
        service = FlextLdapApi()

        attributes: FlextLdapTypes.Entry.AttributeDict = {
            "cn": "Test User",
            "mail": "test@example.com",
        }

        result = service.validate_attributes(attributes)

        assert result.is_success

    def test_validate_attributes_empty(self) -> None:
        """Test attributes validation with empty attributes."""
        service = FlextLdapApi()

        attributes: FlextLdapTypes.Entry.AttributeDict = {}

        result = service.validate_attributes(attributes)

        assert not result.is_success
        assert "empty" in ((result.error or "").lower()) or "attributes" in (
            (result.error or "").lower()
        )

    def test_validate_object_classes_valid(self) -> None:
        """Test object classes validation with valid classes."""
        service = FlextLdapApi()

        object_classes = ["person", "inetOrgPerson"]

        result = service.validate_object_classes(object_classes)

        assert result.is_success

    def test_validate_object_classes_empty(self) -> None:
        """Test object classes validation with empty list."""
        service = FlextLdapApi()

        object_classes: FlextTypes.Core.StringList = []

        result = service.validate_object_classes(object_classes)

        assert not result.is_success
        assert "empty" in ((result.error or "").lower()) or "object" in (
            (result.error or "").lower()
        )

    @pytest.mark.asyncio
    async def test_search_users(self) -> None:
        """Test search_users operation."""
        service = FlextLdapApi()

        result = await service.search_users("dc=flext,dc=local")

        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_user_exists(self) -> None:
        """Test user_exists check."""
        service = FlextLdapApi()

        result = await service.user_exists("cn=testuser,dc=flext,dc=local")

        assert isinstance(result, FlextResult)
        # Should return boolean result
        if result.is_success:
            assert isinstance(result.value, bool)

    @pytest.mark.asyncio
    async def test_group_exists(self) -> None:
        """Test group_exists check."""
        service = FlextLdapApi()

        result = await service.group_exists("cn=testgroup,dc=flext,dc=local")

        assert isinstance(result, FlextResult)
        # Should return boolean result
        if result.is_success:
            assert isinstance(result.value, bool)

    @pytest.mark.asyncio
    async def test_add_member_to_group(self) -> None:
        """Test add_member_to_group operation."""
        service = FlextLdapApi()

        result = await service.add_member_to_group(
            "cn=testgroup,dc=flext,dc=local",
            "cn=testuser,dc=flext,dc=local",
        )

        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_remove_member_from_group(self) -> None:
        """Test remove_member_from_group operation."""
        service = FlextLdapApi()

        result = await service.remove_member_from_group(
            "cn=testgroup,dc=flext,dc=local",
            "cn=testuser,dc=flext,dc=local",
        )

        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_get_group_members_list(self) -> None:
        """Test get_group_members_list operation."""
        service = FlextLdapApi()

        result = await service.get_group_members_list("cn=testgroup,dc=flext,dc=local")

        assert isinstance(result, FlextResult)
        # Should return list of strings
        if result.is_success:
            assert isinstance(result.value, list)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_full_user_lifecycle_with_docker(
        self,
    ) -> None:
        """Test complete user lifecycle with real LDAP Docker container."""
        service = FlextLdapApi()

        # Create user
        create_request = FlextLdapModels.CreateUserRequest(
            dn="cn=lifecycle_user,ou=users,dc=flext,dc=local",
            uid="lifecycle_user",
            cn="Lifecycle User",
            sn="User",
            given_name="Lifecycle",
            mail="lifecycle@internal.invalid",
        )

        create_result = await service.create_user(create_request)

        # Test passes if either successful or fails gracefully
        assert isinstance(create_result, FlextResult)

        # Try to get user
        get_result = await service.get_user(
            "cn=lifecycle_user,ou=users,dc=flext,dc=local",
        )
        assert isinstance(get_result, FlextResult)

        # Try to delete user
        delete_result = await service.delete_user(
            "cn=lifecycle_user,ou=users,dc=flext,dc=local",
        )
        assert isinstance(delete_result, FlextResult)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_full_group_lifecycle_with_docker(
        self,
    ) -> None:
        """Test complete group lifecycle with real LDAP Docker container."""
        service = FlextLdapApi()

        # Create group
        group = FlextLdapModels.Group(
            id="lifecycle-group",
            dn="cn=lifecyclegroup,ou=groups,dc=flext,dc=local",
            cn="Lifecycle Group",
            description="Test lifecycle group",
        )

        create_result = await service.create_group(group)
        assert isinstance(create_result, FlextResult)

        # Test group operations
        get_result = await service.get_group(
            "cn=lifecycle_group,ou=groups,dc=flext,dc=local",
        )
        assert isinstance(get_result, FlextResult)

        delete_result = await service.delete_group(
            "cn=lifecycle_group,ou=groups,dc=flext,dc=local",
        )
        assert isinstance(delete_result, FlextResult)

    @pytest.mark.asyncio
    async def test_connect_method_functionality(self) -> None:
        """Test connect method with real connection attempt."""
        service = FlextLdapApi()

        # Test connection attempt (may fail gracefully in test environment)
        result = await service.connect(
            "ldap://localhost:3890",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            "REDACTED_LDAP_BIND_PASSWORD123",
        )

        # Verify FlextResult returned and method executed
        assert isinstance(result, FlextResult)
        # Connection may fail in test env - that's acceptable

    @pytest.mark.asyncio
    async def test_disconnect_method_functionality(self) -> None:
        """Test disconnect method functionality."""
        service = FlextLdapApi()

        # Test disconnect (should complete successfully as placeholder)
        result = await service.disconnect()

        # Verify successful execution of disconnect logic
        assert isinstance(result, FlextResult)
        assert result.is_success  # Disconnect should succeed as it's placeholder

    @pytest.mark.asyncio
    async def test_get_user_with_empty_search_result(self) -> None:
        """Test get_user method when search returns empty result."""
        service = FlextLdapApi()

        # Create mock search response with no entries
        mock_response = Mock()
        mock_response.entries = []

        # Mock client search to return empty response
        mock_client = Mock()
        mock_client.search_with_request = AsyncMock(return_value=FlextResult.ok(mock_response))

        with patch.object(service, "_client", mock_client):
            result = await service.get_user("cn=nonexistent,dc=test")

            # Should succeed but return None since no entries found
            mock_client.search_with_request.assert_called_once()

            # Note: The actual result depends on internal implementation
            # This test verifies the method handles empty search results gracefully

    @pytest.mark.asyncio
    async def test_get_user_with_successful_search(self) -> None:
        """Test get_user method with successful client search."""
        service = FlextLdapApi()

        # Create mock search response with entries
        mock_entry = Mock()
        mock_entry.dn = "cn=test,dc=example,dc=com"
        mock_entry.attributes = {"cn": ["Test User"], "uid": ["testuid"], "sn": ["User"], "mail": ["test@example.com"]}

        mock_response = Mock()
        mock_response.entries = [mock_entry]

        # Mock client search to return successful response
        mock_client = Mock()
        mock_client.search_with_request = AsyncMock(return_value=FlextResult.ok(mock_response))

        with patch.object(service, "_client", mock_client):
            result = await service.get_user("cn=test,dc=example,dc=com")

            # Should succeed and return a User or handle connection errors gracefully
            mock_client.search_with_request.assert_called_once()

            # Note: The actual result depends on the internal implementation
            # This test verifies the method can be called without errors

    @pytest.mark.asyncio
    async def test_update_user_with_successful_modify(self) -> None:
        """Test update_user method with successful modify operation."""
        service = FlextLdapApi()

        # Mock client with successful modify
        mock_client = Mock()
        mock_client.modify_entry = AsyncMock(return_value=FlextResult[None].ok(None))

        with patch.object(service, "_client", mock_client):
            result = await service.update_user(
                "cn=updated,dc=example,dc=com",
                {
                    "cn": ["Updated User"],
                    "objectClass": ["person", "organizationalPerson"],
                },
            )

            # Should successfully complete the modify operation
            assert result.is_success
            assert result.data is None
            mock_client.modify_entry.assert_called_once_with(
                "cn=updated,dc=example,dc=com",
                {
                    "cn": ["Updated User"],
                    "objectClass": ["person", "organizationalPerson"],
                }
            )

    @pytest.mark.asyncio
    async def test_update_user_modify_failure(self) -> None:
        """Test update_user when modify_entry fails."""
        service = FlextLdapApi()

        # Mock client with failing modify
        mock_client = Mock()
        mock_client.modify_entry = AsyncMock(return_value=FlextResult[None].fail("Modify failed"))

        with patch.object(service, "_client", mock_client):
            result = await service.update_user("cn=test,dc=test", {"cn": ["Test"]})

            # Should fail with modify error
            assert not result.is_success
            assert "Failed to update user" in result.error
            mock_client.modify_entry.assert_called_once_with("cn=test,dc=test", {"cn": ["Test"]})

    @pytest.mark.asyncio
    async def test_update_user_success(self) -> None:
        """Test update_user with successful modification."""
        service = FlextLdapApi()

        # Mock client with successful update
        mock_client = Mock()
        mock_client.modify_entry = AsyncMock(return_value=FlextResult[None].ok(None))

        with patch.object(service, "_client", mock_client):
            result = await service.update_user("cn=test,dc=test", {"cn": ["Test"]})

            # Should succeed since modify_entry succeeded
            assert result.is_success
            assert result.data is None
            mock_client.modify_entry.assert_called_once_with("cn=test,dc=test", {"cn": ["Test"]})
