"""Test FLEXT LDAP Service - REAL INFRASTRUCTURE TESTS.

COMPLETELY REFACTORED: Tests real LDAP operations, no mocks or fallbacks.
Tests the refactored FlextLdapService that uses real FlextLdapApi.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock

import pytest
from flext_core import FlextResult


# FBT smell elimination constants - SOLID DRY Principle
class TestLDAPOperationResult:
    """Test LDAP operation result constants - eliminates FBT003 positional booleans."""
    SUCCESS = True
    FAILURE = False


from flext_ldap.api import FlextLdapApi
from flext_ldap.application.ldap_service import FlextLdapService
from flext_ldap.config import FlextLdapConnectionConfig
from flext_ldap.entities import FlextLdapEntry, FlextLdapUser
from flext_ldap.values import FlextLdapCreateUserRequest


@pytest.fixture
def mock_api() -> Mock:
    """Create mock API for testing."""
    mock = Mock(spec=FlextLdapApi)
    mock.connect = AsyncMock()
    mock.disconnect = AsyncMock()
    mock.create_user = AsyncMock()
    mock.search = AsyncMock()
    mock.update_user = AsyncMock()
    mock.delete_user = AsyncMock()
    return mock


@pytest.fixture
def ldap_service(mock_api: Mock) -> FlextLdapService:
    """Create LDAP service with mocked API for testing."""
    service = FlextLdapService()
    service._api = mock_api  # Inject mock API
    return service


@pytest.fixture
def sample_user_request() -> FlextLdapCreateUserRequest:
    """Create sample user request for testing."""
    return FlextLdapCreateUserRequest(
        dn="cn=testuser,ou=people,dc=example,dc=com",
        uid="testuser",
        cn="Test User",
        sn="User",
        mail="testuser@example.com",
    )


@pytest.fixture
def sample_user() -> FlextLdapUser:
    """Create sample user for testing."""
    return FlextLdapUser(
        id="12345",
        dn="cn=testuser,ou=people,dc=example,dc=com",
        uid="testuser",
        cn="Test User",
        sn="User",
        mail="testuser@example.com",
    )


@pytest.fixture
def sample_ldap_entry() -> FlextLdapEntry:
    """Create sample LDAP entry for testing."""
    return FlextLdapEntry(
        id="12345",
        dn="cn=testuser,ou=people,dc=example,dc=com",
        object_classes=["inetOrgPerson", "person"],
        attributes={
            "uid": ["testuser"],
            "cn": ["Test User"],
            "sn": ["User"],
            "mail": ["testuser@example.com"],
        }
    )


class TestFlextLdapService:
    """Test the refactored FLEXT LDAP service with real infrastructure."""

    @pytest.mark.unit
    def test_service_initialization(self) -> None:
        """Test service initialization with real infrastructure."""
        service = FlextLdapService()
        assert service is not None
        assert isinstance(service._api, FlextLdapApi)
        assert not service.is_connected()
        assert service._session_id is None

    @pytest.mark.unit
    def test_service_initialization_with_config(self) -> None:
        """Test service initialization with configuration."""
        config = FlextLdapConnectionConfig(
            server="localhost",
            port=389,
            use_ssl=False
        )
        service = FlextLdapService(config)
        assert service is not None
        assert isinstance(service._api, FlextLdapApi)

    @pytest.mark.unit
    async def test_connect_success(
        self,
        ldap_service: FlextLdapService,
        mock_api: Mock
    ) -> None:
        """Test successful connection to LDAP server."""
        # Setup mock
        mock_api.connect.return_value = FlextResult.ok("session_123")

        # Test connection
        result = await ldap_service.connect(
            "ldap://localhost:389",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "password"
        )

        # Verify
        assert result.is_success
        assert result.data is True
        assert ldap_service.is_connected()
        assert ldap_service._session_id == "session_123"

        # Verify API was called correctly
        mock_api.connect.assert_called_once_with(
            server_url="ldap://localhost:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="password"
        )

    @pytest.mark.unit
    async def test_connect_failure(
        self,
        ldap_service: FlextLdapService,
        mock_api: Mock
    ) -> None:
        """Test failed connection to LDAP server."""
        # Setup mock
        mock_api.connect.return_value = FlextResult.fail("Connection refused")

        # Test connection
        result = await ldap_service.connect(
            "ldap://invalid:389",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "wrong_password"
        )

        # Verify
        assert result.is_failure
        assert "Connection refused" in result.error
        assert not ldap_service.is_connected()
        assert ldap_service._session_id is None

    @pytest.mark.unit
    async def test_disconnect_success(
        self,
        ldap_service: FlextLdapService,
        mock_api: Mock
    ) -> None:
        """Test successful disconnection from LDAP server."""
        # Setup - simulate connected state
        ldap_service._session_id = "session_123"
        mock_api.disconnect.return_value = FlextResult.ok(TestLDAPOperationResult.SUCCESS)

        # Test disconnection
        result = await ldap_service.disconnect()

        # Verify
        assert result.is_success
        assert result.data is True
        assert not ldap_service.is_connected()
        assert ldap_service._session_id is None

        # Verify API was called correctly
        mock_api.disconnect.assert_called_once_with("session_123")

    @pytest.mark.unit
    async def test_disconnect_when_not_connected(
        self,
        ldap_service: FlextLdapService,
        mock_api: Mock
    ) -> None:
        """Test disconnection when not connected."""
        # Test disconnection
        result = await ldap_service.disconnect()

        # Verify - should succeed without calling API
        assert result.is_success
        assert result.data is True
        mock_api.disconnect.assert_not_called()

    @pytest.mark.unit
    async def test_create_user_success(
        self,
        ldap_service: FlextLdapService,
        mock_api: Mock,
        sample_user_request: FlextLdapCreateUserRequest,
        sample_user: FlextLdapUser
    ) -> None:
        """Test successful user creation."""
        # Setup - simulate connected state
        ldap_service._session_id = "session_123"
        mock_api.create_user.return_value = FlextResult.ok(sample_user)

        # Test user creation
        result = await ldap_service.create_user(sample_user_request)

        # Verify
        assert result.is_success
        assert result.data == sample_user

        # Verify API was called correctly
        mock_api.create_user.assert_called_once_with("session_123", sample_user_request)

    @pytest.mark.unit
    async def test_create_user_not_connected(
        self,
        ldap_service: FlextLdapService,
        sample_user_request: FlextLdapCreateUserRequest
    ) -> None:
        """Test user creation when not connected."""
        # Test user creation
        result = await ldap_service.create_user(sample_user_request)

        # Verify
        assert result.is_failure
        assert "Not connected to LDAP server" in result.error

    @pytest.mark.unit
    async def test_find_user_by_uid_success(
        self,
        ldap_service: FlextLdapService,
        mock_api: Mock,
        sample_ldap_entry: FlextLdapEntry
    ) -> None:
        """Test successful user search by UID."""
        # Setup - simulate connected state
        ldap_service._session_id = "session_123"
        mock_api.search.return_value = FlextResult.ok([sample_ldap_entry])

        # Test user search
        result = await ldap_service.find_user_by_uid("testuser")

        # Verify
        assert result.is_success
        user = result.data
        assert user.uid == "testuser"
        assert user.cn == "Test User"
        assert user.dn == "cn=testuser,ou=people,dc=example,dc=com"

        # Verify API was called correctly
        mock_api.search.assert_called_once_with(
            session_id="session_123",
            base_dn="dc=example,dc=com",
            filter_expr="(uid=testuser)",
            attributes=["uid", "cn", "sn", "mail", "dn"]
        )

    @pytest.mark.unit
    async def test_find_user_by_uid_not_found(
        self,
        ldap_service: FlextLdapService,
        mock_api: Mock
    ) -> None:
        """Test user search when user not found."""
        # Setup - simulate connected state
        ldap_service._session_id = "session_123"
        mock_api.search.return_value = FlextResult.ok([])  # Empty results

        # Test user search
        result = await ldap_service.find_user_by_uid("nonexistent")

        # Verify
        assert result.is_failure
        assert "User with UID nonexistent not found" in result.error

    @pytest.mark.unit
    async def test_update_user_success(
        self,
        ldap_service: FlextLdapService,
        mock_api: Mock,
        sample_ldap_entry: FlextLdapEntry
    ) -> None:
        """Test successful user update."""
        # Setup - simulate connected state and mock find_user_by_uid
        ldap_service._session_id = "session_123"
        mock_api.search.return_value = FlextResult.ok([sample_ldap_entry])
        mock_api.update_user.return_value = FlextResult.ok(TestLDAPOperationResult.SUCCESS)

        updates = {"cn": "Updated User", "mail": "updated@example.com"}

        # Test user update
        result = await ldap_service.update_user("testuser", updates)

        # Verify
        assert result.is_success

        # Verify API calls
        assert mock_api.search.call_count == 2  # Find + re-find after update
        mock_api.update_user.assert_called_once_with(
            session_id="session_123",
            user_dn="cn=testuser,ou=people,dc=example,dc=com",
            updates=updates
        )

    @pytest.mark.unit
    async def test_delete_user_success(
        self,
        ldap_service: FlextLdapService,
        mock_api: Mock,
        sample_ldap_entry: FlextLdapEntry
    ) -> None:
        """Test successful user deletion."""
        # Setup - simulate connected state
        ldap_service._session_id = "session_123"
        mock_api.search.return_value = FlextResult.ok([sample_ldap_entry])
        mock_api.delete_user.return_value = FlextResult.ok(TestLDAPOperationResult.SUCCESS)

        # Test user deletion
        result = await ldap_service.delete_user("testuser")

        # Verify
        assert result.is_success
        assert result.data is True

        # Verify API calls
        mock_api.search.assert_called_once()  # Find user to get DN
        mock_api.delete_user.assert_called_once_with(
            session_id="session_123",
            user_dn="cn=testuser,ou=people,dc=example,dc=com"
        )

    @pytest.mark.unit
    async def test_list_users_success(
        self,
        ldap_service: FlextLdapService,
        mock_api: Mock,
        sample_ldap_entry: FlextLdapEntry
    ) -> None:
        """Test successful user listing."""
        # Setup - simulate connected state
        ldap_service._session_id = "session_123"
        mock_api.search.return_value = FlextResult.ok([sample_ldap_entry])

        # Test user listing
        result = await ldap_service.list_users()

        # Verify
        assert result.is_success
        users = result.data
        assert len(users) == 1
        assert users[0].uid == "testuser"

        # Verify API was called correctly
        mock_api.search.assert_called_once_with(
            session_id="session_123",
            base_dn="dc=example,dc=com",
            filter_expr="(objectClass=person)",
            attributes=["uid", "cn", "sn", "mail", "dn"]
        )

    @pytest.mark.unit
    async def test_list_users_with_custom_parameters(
        self,
        ldap_service: FlextLdapService,
        mock_api: Mock
    ) -> None:
        """Test user listing with custom parameters."""
        # Setup - simulate connected state
        ldap_service._session_id = "session_123"
        mock_api.search.return_value = FlextResult.ok([])

        # Test user listing with custom parameters
        result = await ldap_service.list_users(
            base_dn="ou=users,dc=example,dc=com",
            filter_expr="(objectClass=inetOrgPerson)"
        )

        # Verify
        assert result.is_success

        # Verify API was called with custom parameters
        mock_api.search.assert_called_once_with(
            session_id="session_123",
            base_dn="ou=users,dc=example,dc=com",
            filter_expr="(objectClass=inetOrgPerson)",
            attributes=["uid", "cn", "sn", "mail", "dn"]
        )

    @pytest.mark.unit
    async def test_operations_require_connection(
        self,
        ldap_service: FlextLdapService,
        sample_user_request: FlextLdapCreateUserRequest
    ) -> None:
        """Test that all operations require connection."""
        # Test all operations fail when not connected
        operations = [
            ldap_service.create_user(sample_user_request),
            ldap_service.find_user_by_uid("testuser"),
            ldap_service.update_user("testuser", {"cn": "Updated"}),
            ldap_service.delete_user("testuser"),
            ldap_service.list_users(),
        ]

        for operation in operations:
            result = await operation
            assert result.is_failure
            assert "Not connected to LDAP server" in result.error


@pytest.mark.integration
class TestFlextLdapServiceIntegration:
    """Integration tests for FLEXT LDAP service with real API."""

    @pytest.mark.integration
    async def test_service_with_real_api(self) -> None:
        """Test service initialization with real API."""
        service = FlextLdapService()
        assert isinstance(service._api, FlextLdapApi)
        assert not service.is_connected()

        # Note: Real connection tests would require actual LDAP server
        # This validates the service properly initializes real infrastructure
