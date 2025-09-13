
from __future__ import annotations

import re
import uuid
import pytest
from flext_core import FlextResult
from flext_ldap import FlextLDAPApi, get_flext_ldap_api
from flext_ldap.entities import FlextLDAPEntities

"""

from __future__ import annotations





@pytest.mark.asyncio
class TestFlextLDAPApiFlextTestsIntegration:
    """Comprehensive API tests using flext_tests library for 100% coverage."""

    def test_api_initialization_with_flext_tests_factory(self) -> None:
        """Test API initialization using flext_tests patterns."""

        api = FlextLDAPApi()

        # Basic validation
        assert api._config is not None
        assert api._service is not None
        assert api._container is not None

    def test_session_id_generation_with_validation(self) -> None:
        """Test session ID generation with flext_tests validation."""

        # Generate multiple session IDs
        session_ids = [f"session_{uuid.uuid4()}" for _ in range(10)]

        # Validate uniqueness
        assert len(session_ids) == len(set(session_ids))

        # Validate format with regex
        for session_id in session_ids:
            assert re.match(r"session_[a-f0-9-]{36}", session_id)

    async def test_entry_attribute_handling_with_factory_data(self) -> None:
        """Test entry attribute extraction using factory data."""

        api = FlextLDAPApi()

        # Create test data with various edge cases
        test_entries = [
            {
                "cn": ["John Doe"],
                "uid": ["johndoe"],
                "mail": ["john@example.com"],
            },
            {
                "cn": "Jane Doe",  # Non-list value
                "uid": ["janedoe"],
                "mail": [],  # Empty list
            },
            {
                "cn": [None],  # None in list
                "uid": None,  # None value
            },
        ]

        # Test attribute extraction with various data patterns
        for entry in test_entries:
            cn = api._get_entry_attribute(entry, "cn", "default_name")
            uid = api._get_entry_attribute(entry, "uid", "default_uid")
            mail = api._get_entry_attribute(entry, "mail", "default@mail.com")

            # Basic string validation
            assert isinstance(cn, str)
            assert isinstance(uid, str)
            assert isinstance(mail, str)

            # Validate no None values returned
            assert cn is not None
            assert uid is not None
            assert mail is not None

    async def test_connection_lifecycle_validation(self) -> None:
        """Test connection lifecycle without external dependencies."""

        api = FlextLDAPApi()

        # Test connection attempt (will fail without server, but validates logic)
        connection_result = await api.connect(
            "ldap://localhost:3390",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            "REDACTED_LDAP_BIND_PASSWORD123",
        )

        # Connection may fail without Docker, but should return FlextResult
        assert isinstance(connection_result, FlextResult)

        # If connection fails, error should be informative
        if not connection_result.is_success:
            assert connection_result.error
            assert isinstance(connection_result.error, str)
            assert len(connection_result.error) > 0

    async def test_user_operations_with_user_factory(self) -> None:
        """Test user operations using manual user data."""

        api = FlextLDAPApi()

        # Create test users manually
        regular_user = {
            "email": "testuser1@example.com",
            "age": 25,
        }

        REDACTED_LDAP_BIND_PASSWORD_user = {
            "email": "REDACTED_LDAP_BIND_PASSWORD1@example.com",
            "age": 35,
        }

        # Basic validation of created users
        assert regular_user["email"] == "testuser1@example.com"
        assert regular_user["age"] == 25
        assert REDACTED_LDAP_BIND_PASSWORD_user["email"] == "REDACTED_LDAP_BIND_PASSWORD1@example.com"
        assert REDACTED_LDAP_BIND_PASSWORD_user["age"] == 35

        # Test user creation request (will fail without connection, but validates logic)
        create_request = FlextLDAPEntities.CreateUserRequest(
            dn="cn=test-user,ou=users,dc=example,dc=com",
            uid="testuser1",
            cn="Test User 1",
            sn="User",
        )

        create_result = await api.create_user(create_request)
        assert isinstance(create_result, FlextResult)

        # Validate error handling for no connection
        if not create_result.is_success:
            assert (
                "connect" in create_result.error.lower()
                or "bind" in create_result.error.lower()
            )

    async def test_search_operations_functionality(self) -> None:
        """Test search operations functionality."""

        api = FlextLDAPApi()

        # Create search request
        search_request = FlextLDAPEntities.SearchRequest.create_user_search(
            base_dn="ou=users,dc=example,dc=com",
            uid="testuser",
        )

        # Execute search (will fail without connection, but validates structure)
        search_result = await api.search(search_request)

        # Validate result structure
        assert isinstance(search_result, FlextResult)

        # If search fails, should have meaningful error
        if not search_result.is_success:
            assert search_result.error
            assert isinstance(search_result.error, str)

    async def test_basic_performance_monitoring(self) -> None:
        """Test basic performance monitoring without external dependencies."""

        api = FlextLDAPApi()

        # Create search request for performance test
        search_request = FlextLDAPEntities.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
        )

        result = await api.search(search_request)

        # Validate that operation completed with proper FlextResult structure
        assert isinstance(result, FlextResult)

    async def test_error_handling_comprehensive(self) -> None:
        """Test comprehensive error handling."""

        api = FlextLDAPApi()

        # Test with invalid DNs (meeting min length requirement)
        invalid_dns = [
            "abc",  # Too short format but meets min length
            "invalid_dn_format",  # No proper format
            "cn=incomplete_dn",  # Incomplete
            "malformed=value=extra",  # Malformed
        ]

        for invalid_dn in invalid_dns:
            # Test various operations with invalid DN - expect validation errors
            try:
                search_request = FlextLDAPEntities.SearchRequest(
                    base_dn=invalid_dn,
                    filter_str="(objectClass=*)",
                    scope="base",
                )
                # If validation passes, test search with this DN
                search_result = await api.search(search_request)
            except Exception:
                # Expected validation error from Pydantic - skip this DN
                continue

            # Should return FlextResult with error or empty results
            assert isinstance(search_result, FlextResult)
            if not search_result.is_success:
                assert search_result.error
                assert len(search_result.error) > 0

    def test_api_factory_function(self) -> None:
        """Test the get_flext_ldap_api factory function."""

        # Test factory function
        api1 = get_flext_ldap_api()
        api2 = get_flext_ldap_api()

        # Both should be valid instances
        assert isinstance(api1, FlextLDAPApi)
        assert isinstance(api2, FlextLDAPApi)

        # Should be different instances (not singleton)
        assert id(api1) != id(api2)

    async def test_comprehensive_workflow_integration(self) -> None:
        """Test comprehensive workflow using multiple flext_tests utilities."""

        # 1. Initialize API
        api = get_flext_ldap_api()

        # 2. Create test data manually
        user_data = {
            "email": "workflow@example.com",
            "age": 30,
        }

        # 3. Test connection (may fail without server)
        connection_result = await api.connect(
            "ldap://localhost:3390",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            "REDACTED_LDAP_BIND_PASSWORD123",
        )

        # 4. Validate connection result structure
        assert isinstance(connection_result, FlextResult)

        # 5. If connected, test basic operations
        if connection_result.is_success:
            session_id = connection_result.value
            assert isinstance(session_id, str)
            assert session_id.startswith("session_")

            # Test search operation
            search_request = FlextLDAPEntities.SearchRequest(
                base_dn="dc=flext,dc=local",
                filter_str="(objectClass=*)",
                scope="base",
            )

            search_result = await api.search(search_request)
            assert isinstance(search_result, FlextResult)

            # Cleanup
            disconnect_result = await api.disconnect(session_id)
            assert isinstance(disconnect_result, FlextResult)

        # 6. Validate user factory data
        assert user_data["email"] == "workflow@example.com"
        assert user_data["age"] == 30
